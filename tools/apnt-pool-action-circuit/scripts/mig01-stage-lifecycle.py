"""Bounded cancellation bookkeeping for the existing MIG01 logged_stage runner.

Only that runner publishes owned process groups. Records and source backups are
private, never certification output. No process search or unowned group kill.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import time

STATE_ENV = 'MIG01_STAGE_STATE'
DEADLINE_ENV = 'MIG01_STAGE_DEADLINE'
TEARDOWN = 120

# Until registration completes this process stays in its launcher's group.
# Launcher death closes the sole pipe writer: an empty/partial payload cannot
# exec a stage. Once released, its pid/group is already durably discoverable.
# Carry the original environment through the private pipe, because Python's
# startup may otherwise coerce locale variables before exec. No extra process
# survives: setsid + exec retain this child's pid.
LAUNCH_GUARD = '''import json,os,sys
with os.fdopen(int(sys.argv[1]), 'rb') as gate: payload = gate.read()
if not payload: os._exit(125)
environment = json.loads(payload)
os.setsid()
os.execvpe(sys.argv[2], sys.argv[2:], environment)
'''

class Cancelled(BaseException):
    pass

class CleanupRefused(BaseException):
    pass

def require(ok):
    if not ok: raise RuntimeError('mig01-stage-state-refused')

def private_write(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as sink:
        sink.write(data)

def private_read(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 2**22)
        return source.read()

def group_gone(pid):
    try: os.killpg(pid, 0)
    except ProcessLookupError: return True
    except PermissionError: pass
    return False

def send(pid, sig):
    try: os.killpg(pid, sig)
    except ProcessLookupError: pass

class Scope:
    def __init__(self, directory, deadline, *, owner=False, teardown=TEARDOWN):
        self.directory, self.deadline, self.owner = Path(directory), deadline, owner
        require(0 < teardown <= TEARDOWN and time.monotonic() < deadline <= time.monotonic() + 14401)
        self.teardown = teardown
        if owner: self.directory.mkdir(mode=0o700)
        info = self.directory.lstat()
        require(self.directory.resolve() == self.directory and stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
        self.signals, self.active = {}, {}

    def cancel(self, *_):
        # One shared deadline, never a fresh allowance at each nesting level.
        path = self.directory / 'cancel'
        try: private_write(path, str(min(time.monotonic(), self.deadline) + self.teardown).encode())
        except FileExistsError: pass

    def aborting(self):
        if time.monotonic() >= self.deadline: self.cancel()
        return (self.directory / 'cancel').exists()

    def check(self):
        if self.aborting(): raise Cancelled()

    def remaining_cleanup(self):
        self.cancel()
        deadline = float(private_read(self.directory / 'cancel'))
        require(deadline <= self.deadline + TEARDOWN)
        return max(0, deadline - time.monotonic())

    def environment(self, env):
        return dict(env, **{STATE_ENV: str(self.directory), DEADLINE_ENV: str(self.deadline)})

    def register(self, child):
        self.active[child.pid] = child
        path = self.directory / ('group-' + str(child.pid))
        private_write(path, json.dumps({'pid': child.pid, 'owner': os.getpid()}).encode())
        return path

    def release(self, gate, environment, deadline):
        # Publication precedes even the first payload byte. Bounded nonblocking
        # writes preserve both the stage limit and whole-invocation deadline.
        payload = memoryview(json.dumps(environment).encode())
        os.set_blocking(gate, False)
        while payload:
            self.check()
            remaining = min(deadline, self.deadline) - time.monotonic()
            if remaining <= 0:
                self.cancel()
                raise Cancelled()
            if select.select([], [gate], [], min(.1, remaining))[1]:
                try: payload = payload[os.write(gate, payload):]
                except BlockingIOError: pass

    def forget(self, path):
        path.unlink()
        if path.name.startswith('group-'): self.active.pop(int(path.name[6:]), None)

    def stop(self, child, *, cooperative):
        self.cancel()
        send(child.pid, signal.SIGTERM)
        # A Python driver must unwind its nested stage and source finally first.
        grace = min(90 if cooperative else 2, self.remaining_cleanup())
        try: child.wait(timeout=grace)
        except subprocess.TimeoutExpired: pass
        send(child.pid, signal.SIGKILL)
        try: child.wait(timeout=self.remaining_cleanup())
        except subprocess.TimeoutExpired: raise CleanupRefused()
        while not group_gone(child.pid):
            if self.remaining_cleanup() <= 0: raise CleanupRefused()
            time.sleep(0.02)

    def remember(self, fixture, originals):
        # Only disposable source inside this invocation can enter the journal.
        fixture = Path(fixture)
        require(fixture.resolve() == fixture and self.directory.parent in fixture.parents)
        key = 'restore-' + str(os.getpid())
        path = self.directory / key
        payload = []
        for relative, content in originals.items():
            target = fixture / relative
            require(target.resolve() == target and fixture in target.parents and target.is_file())
            payload.append({'target': str(target), 'bytes': content.hex()})
        private_write(path, json.dumps(payload).encode())
        return path

    def restore(self, path):
        for row in json.loads(private_read(path)):
            target = Path(row['target'])
            require(target.resolve() == target and self.directory.parent in target.parents)
            with os.fdopen(os.open(target, os.O_WRONLY | os.O_NOFOLLOW), 'wb') as sink:
                info = os.fstat(sink.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1)
                os.ftruncate(sink.fileno(), 0)
                sink.write(bytes.fromhex(row['bytes']))
        path.unlink()

    def drain(self):
        # Backstop for a nested driver that died before running its own finally.
        records = list(self.directory.glob('group-*'))
        pids = set(self.active)
        for path in records:
            row = json.loads(private_read(path))
            require(set(row) == {'pid', 'owner'} and path.name == 'group-' + str(row['pid'])
                    and all(type(row[key]) is int and row[key] > 1 for key in ('pid', 'owner')))
            pids.add(row['pid'])
        for pid in pids: send(pid, signal.SIGKILL)
        for child in self.active.values():
            try: child.wait(timeout=self.remaining_cleanup())
            except subprocess.TimeoutExpired: raise CleanupRefused()
        for pid in pids:
            while not group_gone(pid):
                if self.remaining_cleanup() <= 0: raise CleanupRefused()
                time.sleep(0.02)
        for path in records: path.unlink()
        self.active.clear()
        for path in self.directory.glob('restore-*'): self.restore(path)

    def hold(self):
        # Teardown has failed/expired. Do NOT return to the slot wrapper, which
        # releases on child exit. No further cleanup work or expensive stage;
        # an explicit supervisor intervention must account for owned survivors.
        private_write(self.directory / 'cleanup-blocked', b'{"status":"owned-cleanup-blocked"}\n')
        print('MIG01 owned cleanup BLOCKED; retain the slot and reconcile owned survivors', flush=True)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP): signal.signal(sig, signal.SIG_IGN)
        while True: signal.pause()

    def __enter__(self):
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            self.signals[sig] = signal.signal(sig, self.cancel)
        return self

    def __exit__(self, kind, value, trace):
        try:
            pending = self.owner and (self.active or list(self.directory.glob('group-*')) or list(self.directory.glob('restore-*')))
            if kind is not None or self.aborting() or pending:
                self.cancel()
                if self.owner:
                    try: self.drain()
                    except BaseException: self.hold()
        finally:
            for sig, handler in self.signals.items(): signal.signal(sig, handler)
        if kind is None: self.check()

@contextmanager
def inherited_scope(root):
    state, deadline = os.environ.get(STATE_ENV), os.environ.get(DEADLINE_ENV)
    if state is None and deadline is None:
        yield None
    else:
        require(state is not None and deadline is not None and Path(state) == Path(root).parent / 'stage-state')
        yield Scope(state, float(deadline))
