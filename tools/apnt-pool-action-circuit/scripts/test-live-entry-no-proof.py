#!/usr/bin/python3
"""MIG01 R3 production exclusion and ordinary runtime/mutation controls.

Run outside an agent Seatbelt sandbox on macOS, while the host test slot is
free or held by this run's caller. A new disposable clean-main checkout
receives only repository source/public fixture material, an offline
installation, and freshly rebuilt dist. Component baselines run on that exact
source tree, whose production selectors are fixed at generation 2 (C1).
Everything else runs on the runtime entry's private test composition, which
production now carries: it is verified in place and committed as an empty
commit, so the composed tree is the source tree. No lane selector,
environment or argv selects it. The runtime entry's controls
run here too (native inventory supplement, the genuine runtime suite exactly
once, its registered observers and their poison/restore controls), so with
--mutations this one run also covers all 42 mutation groups (41 runner, one
Sage). A group counts only when it fails exactly its bound rows at its guard's
assertion with the bound error and value; any other failure is an invalid
result, never a firing. The real stock runner and resource, ancestry, marker
and FD9 gates remain in force. P13 retains its startup/per-case floors and
every ordinary slot check stays. The resource negatives are a separate
certification step with genuine prove dispatch; their admission and receipts
cannot be inferred from this baseline.
Commands, streams and test reports stay private in the run directory. The one
closed summary holds only fixed identifiers, counts, statuses and digests of
public code and build outputs, and is written after every group is restored,
rebuilt and re-verified and every stage's process group is reaped.
"""
import hashlib
import importlib.util
from contextlib import contextmanager
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[3]
NODE = Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.nvm/versions/node/v22.22.3/bin/node'
PNPM = NODE.with_name('pnpm')
GO = '/opt/homebrew/bin/go'
CIRCUIT = 'tools/apnt-pool-action-circuit/'
SHELL = CIRCUIT + 'scripts/measure-pk-load.sh'
TAGGED_GO = CIRCUIT + 'cmd/pool-pk-load/runner_admission_tagged_test.go'
RUNTIME = 'tools/pool-action-modules/test/mig01-runtime-controls.test.ts'
RUNTIME_ROWS, OBSERVER_ROWS = 115, 9
RUNTIME_SELECTION = 'ordinary' # C: resource certification is a separate admitted step.
RESULT = 'tools/pool-action-modules/test/private-runner-result.test.ts'
H1 = 'packages/reference-wallet/test/apnt_pool_wallet_payment_prepare_ownership_v2.test.ts'
SAGE = 'packages/pool-wallet-ink/test/live/sage-execution-v2.test.tsx'
GO_EXEC = 'go:TestMIG01ActualExec'
GROUPS = 42
# The runtime entry's private test composition, verbatim. Since C1 (GO) production
# carries it: compose() verifies it in place, nothing is edited, and the
# composition commit is empty. The two digests are then the production files'.
COMPOSITION = ((SHELL, 'readonly PRIVATE_RUNNER_GENERATION=1', 'readonly PRIVATE_RUNNER_GENERATION=2'),
               (CIRCUIT + 'cmd/pool-pk-load/main.go', 'result := run(os.Args, runDeps{', 'result := runV2(os.Args, runDeps{'))
BASELINES = (
    ('h1-preparation-controls', (H1,)),
    ('host-dispatch-controls', ('packages/pool-wallet-host/test/execution-dispatch-v2.test.ts',)),
    ('runner-component-controls', tuple('tools/pool-action-modules/test/' + name + '.test.ts' for name in (
        'private-runner-plan', 'private-runner-route', 'private-runner-bootstrap', 'private-runner-construction',
        'private-runner-currentness', 'private-runner-result', 'private-runner-lock-process', 'owner-execution-composition-v2'))),
    ('sage-execution-controls', (SAGE,)),
)
ARTIFACTS = {'macosObserver': 'macos-observer', 'ordinaryPoolPkLoad': 'ordinary-pool-pk-load',
             'ordinaryLibraryProbe': 'ordinary-library-probe', 'taggedDispatch': 'tagged-dispatch.test'}
ACCOUNT = pwd.getpwuid(os.geteuid())
# No caller GIT_* variable or hook can redirect the source archive or a fixture commit.
GIT_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'TMPDIR': '/private/tmp', 'HOME': ACCOUNT.pw_dir}
COMMIT = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=MIG01 Fixture', '-c', 'user.email=fixture@invalid',
          '-c', 'commit.gpgsign=false', 'commit', '-m']
# Private: the failing assertion's class, message, serialized actual value and
# stack, which the JSON report truncates or drops. Never report material.
FIRING_REPORTER = r'''import { writeFileSync } from "node:fs";
export default class FiringReporter {
  onFinished(files = []) {
    const failures = [];
    const visit = (task, names) => {
      if (task.type === "suite") { for (const child of task.tasks ?? []) visit(child, [...names, task.name]); return; }
      if (task.result?.state !== "fail") return;
      failures.push({ fullName: [...names, task.name].join(" "), errors: (task.result.errors ?? []).map(error => ({
        name: String(error?.name ?? ""), message: String(error?.message ?? "").split("\n")[0],
        actual: typeof error?.actual === "string" ? error.actual : null, stack: String(error?.stack ?? "") })) });
    };
    for (const file of files) for (const task of file.tasks ?? []) visit(task, []);
    writeFileSync(process.env.MIG01_FIRING_REPORT, JSON.stringify({ schema: "mig01-firing-failures-v1", failures }), { flag: "wx", mode: 0o600 });
  }
}
'''

def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value

# The source checkout must stay clean for its exact-head archive: no bytecode
# is written beside the loaded runtime entry. Stages get fixed environments.
sys.dont_write_bytecode = True
# The isolated runtime entry: its slot predicate, native supplement and observers.
RUNTIME_ENTRY = _load('mig01_runtime_entry', Path(__file__).with_name('test-private-runner-runtime-no-proof.py'))
LIFECYCLE = _load('mig01_stage_lifecycle', Path(__file__).with_name('mig01-stage-lifecycle.py'))
STAGE_SCOPE = None

@contextmanager
def stage_scope(scope):
    global STAGE_SCOPE
    previous = STAGE_SCOPE
    STAGE_SCOPE = scope
    try:
        if scope is None: yield None
        else:
            with scope: yield scope
    finally:
        STAGE_SCOPE = previous

def aborting():
    return STAGE_SCOPE is not None and STAGE_SCOPE.aborting()


def require(ok):
    if not ok:
        raise RuntimeError('mig01-no-proof-control-refused')

def digest(content):
    return hashlib.sha256(content).hexdigest()

def progress(label, exit_code, elapsed):
    # Closed labels only: never a command, child output, or private pathname.
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*', label) is not None)
    print(f'{label} exit={exit_code} elapsed={elapsed:.3f}s', flush=True)

def reap_group(child, seconds=10.0):
    """Kill and outwait every process left in a stage's own process group."""
    # The stage leader started a new session, so its pid names the group, and a
    # group id is not reused while any member remains. macOS answers EPERM for
    # a group whose remaining members are zombies awaiting their parent.
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    child.wait()
    deadline = time.monotonic() + seconds
    while True:
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            return
        except PermissionError:
            pass
        require(time.monotonic() < deadline)
        time.sleep(0.05)

def logged_stage(label, args, cwd, env, log, timeout, *, child_umask=0o077, cooperative=False):
    """Existing private stage runner, with bounded cooperative cancellation.

    Ordinary gates alone request 022. Private logs are explicitly 0600 even
    when the caller's mask is 022; nested drivers retain their private mask/env.
    """
    started, exit_code, child, registration = time.monotonic(), 127, None, None
    gate_read, gate_write = None, None
    scope = STAGE_SCOPE
    try:
        if scope is not None: scope.check()
        child_env = scope.environment(env) if scope is not None and cooperative else env
        command = args
        if scope is not None:
            gate_read, gate_write = os.pipe()
            command = [sys.executable, '-I', '-S', '-c', LIFECYCLE.LAUNCH_GUARD, str(gate_read), *args]
        with os.fdopen(os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as output:
            child = subprocess.Popen(command, cwd=cwd, env=child_env, stdin=subprocess.DEVNULL, stdout=output,
                                     stderr=subprocess.STDOUT, start_new_session=scope is None, umask=child_umask,
                                     pass_fds=() if gate_read is None else (gate_read,))
        if scope is not None:
            os.close(gate_read); gate_read = None
            registration = scope.register(child)
            scope.release(gate_write, child_env, started + timeout)
            os.close(gate_write); gate_write = None
        exit_code = 1
        if scope is None:
            status = child.wait(timeout=timeout)
        else:
            while True:
                scope.check()
                remaining = min(timeout - (time.monotonic() - started), scope.deadline - time.monotonic())
                if remaining <= 0: raise subprocess.TimeoutExpired(args, timeout)
                try:
                    status = child.wait(timeout=min(0.1, remaining))
                    scope.check()
                    break
                except subprocess.TimeoutExpired:
                    if time.monotonic() - started >= timeout: raise
        exit_code = status
        return subprocess.CompletedProcess(args, status)
    except subprocess.TimeoutExpired:
        exit_code = 124
        if scope is not None: scope.cancel()
        raise
    except LIFECYCLE.Cancelled:
        exit_code = 124
        raise
    finally:
        try:
            # Also closes the barrier on a failed/cancelled registration. The
            # gated child cannot detach or execute on an empty/partial payload.
            for gate in (gate_read, gate_write):
                if gate is not None: os.close(gate)
            if child is not None:
                if scope is not None and (scope.aborting() or child.poll() is None):
                    scope.stop(child, cooperative=cooperative)
                else:
                    reap_group(child)
                if registration is not None: scope.forget(registration)
        finally:
            progress(label, exit_code, time.monotonic() - started)

@contextmanager
def mutation_progress(label):
    started = time.monotonic()
    progress(label + '-start', 0, 0.0)
    exit_code = 1
    try:
        yield
        exit_code = 0
    finally:
        progress(label + '-end', exit_code, time.monotonic() - started)

def git_output(directory, *args, timeout=None):
    return subprocess.check_output(['/usr/bin/git', '-C', str(directory), *args], env=GIT_ENV, stderr=subprocess.DEVNULL, timeout=timeout)

def source_fixture(repo, fixture):
    """Exact committed tree, including non-code assets and tracked dotfiles."""
    require(git_output(repo, 'status', '--porcelain') == b'')
    source_head = git_output(repo, 'rev-parse', 'HEAD').decode().strip()
    archive = git_output(repo, 'archive', '--format=tar', source_head)
    subprocess.run(['/usr/bin/tar', '-xf', '-', '-C', str(fixture)], input=archive, env=GIT_ENV, stderr=subprocess.DEVNULL, check=True)
    entries = git_output(repo, 'ls-tree', '-rz', source_head).split(b'\0')
    inventory = []
    for entry in entries:
        if not entry: continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, object_id = metadata.decode().split()
        require(kind == 'blob' and b'.local-live' not in name.split(b'/'))
        inventory.append({'path': name.decode(), 'mode': mode, 'gitObject': object_id})
    return source_head, inventory, digest(archive)

def verify_source_tree(repo, fixture, source_head):
    require(git_output(repo, 'rev-parse', source_head + '^{tree}') == git_output(fixture, 'rev-parse', 'HEAD^{tree}'))

def require_regular(fixture, paths):
    """A target the driver rewrites is a regular file of its own fixture, never a link out of it."""
    for relative in paths:
        info = os.lstat(fixture / relative)
        require(stat.S_ISREG(info.st_mode) and (fixture / relative).resolve() == fixture / relative)

def compose(fixture):
    """Verify that production carries the fixed composition (C1); nothing is edited."""
    require_regular(fixture, [relative for relative, _, _ in COMPOSITION])
    for relative, old, new in COMPOSITION:
        text = (fixture / relative).read_text()
        require(text.count(new) == 1 and old not in text)
    return [relative for relative, _, _ in COMPOSITION]

def between(text, start, end):
    require(text.count(start) == 1 and text.count(end) == 1 and text.index(start) < text.index(end))
    return text[text.index(start):text.index(end)]

def reopened(section, loop, reopen):
    require(section.count(loop) == 1)
    return section.replace(loop, reopen)

def mutation_groups(shell):
    """The unchanged B1 inventory on the composed tree: 41 runner groups, then Sage.

    Each row is (name, selected test, [(path, before, after)], selection).
    Stale strings follow the staged tree only where the firing target is the
    same guard; every such update is named below.
    """
    g, runtime = CIRCUIT, RUNTIME
    route, plan = 'tools/pool-action-modules/lib/private-runner-route.mjs', 'tools/pool-action-modules/lib/private-runner-plan.mjs'
    supervisor, eligibility = 'tools/pool-action-modules/harness-private-runner.mjs', 'tools/pool-action-modules/lib/private-runner-eligibility.mjs'
    payer, host = 'packages/reference-wallet/src/apnt_pool_wallet_payer_v1.ts', 'packages/pool-wallet-host/src/host.ts'
    groups = [
        # Expiry is an authenticated JS refusal decoded into a Go Refusal,
        # not a call to OwnershipRefusal(). Mutate its actual dispatch return.
        # The local constructor has a separate literal oracle in
        # TestMIG01R3PrivateOwnershipTuple (included in bridge-exec-controls).
        ('C2-a-exact-tuple', runtime, [(g+'cmd/pool-pk-load/main.go', 'return runResult{status: 1, refusal: refusal}',
            'return runResult{status: 1, refusal: &runneradmission.Refusal{Code: refusal.Code, Retry: refusal.Retry, Cause: "pool-wallet-payment-binding"}}')], 'PH11-X tagged genuine'),
        ('C2-b-before-writer', runtime, [(g+'cmd/pool-pk-load/main.go', 'return runResult{status: 1, refusal: refusal}', '/* refusal return disabled */')], 'PH11-X tagged genuine'),
        # Staged: the composed main dispatch is runV2; the guard is the same dispatch.
        ('C2-c-main-dispatch', runtime, [(g+'cmd/pool-pk-load/main.go', 'result := runV2(os.Args, runDeps{stderr: os.Stderr, resultWriter: writeNew})', 'result := runResult{status: 1}')], 'PH11-X-PROD/P0 genuine stock'),
        ('C2-d-production-prerequisite', runtime, [(g+'internal/runneradmission/prerequisite.go', 'return requireLiveHarness(sourceCheckout)', 'return nil')], 'raw ordinary caller with a LIVE registry'),
        ('C2-e-library-prerequisite', runtime, [(g+'devprove/live.go', 'if err := runneradmission.Require(SourceCheckout()); err != nil {\n\t\t\treturn nil, nil, err\n\t\t}', '/* library prerequisite disabled */')], 'direct ordinary library with a LIVE registry'),
        ('C2-f-ordinary-hook', runtime, [(g+'internal/runneradmission/prerequisite.go', '//go:build !private_runner_admission_test', '//go:build private_runner_never'),
            (g+'internal/runneradmission/prerequisite_testbuild.go', '//go:build private_runner_admission_test', '//go:build !private_runner_never')], 'ordinary artifact excludes the tagged hook'),
        # Staged: the private diagnostic boundary now contains this outer reader's
        # traceback, so the runtime rows cannot observe it; the same shell block's
        # exact closed reason is asserted by these result cases.
        ('C3-outer-diagnostics', RESULT, [(SHELL, '    except Exception:\n        sys.exit(1)', '    except Exception:\n        raise')], 'closed child refusal reason (result-write|empty) survives the missing-receipt boundary'),
        ('C1-inbox-writer', runtime, [(route, INBOX_SOURCE, INBOX_MUTANT)], 'genuine inbox source reaches'),
        ('C4-authenticated-singlecase', runtime, [(plan, 'if (lines.length !== 1) fail();', '/* single-case guard disabled */')], 'PH11-ONECASE authenticated (two|repeat|mixed)'),
        ('C4-original-ttl', runtime, [(supervisor, 'performance.now() - started >= RUNNER_LIMITS.ttl', 'false')], 'PH11-ONECASE original TTL equality'),
        ('C4-distinct-latches', runtime, [(supervisor, 'request.phase !== ["P", "A", "W"][phase]', 'false')], 'a second A cannot acquire again'),
        ('C5-final-capture-basis', runtime, [(supervisor, 'if (paymentDigest(current.construction) !== paymentDigest(original.construction) || paymentDigest(current.construction) !== fresh.construction) refusal("pool-wallet-execution-offer-basis-stale");', '/* final basis guard disabled */')], 'authenticated construction basis changes'),
        ('C5-same-height-hash', runtime, [(eligibility, 'if (previous !== null && tip.height === previous.tip.height && tip.blockHash !== previous.tip.blockHash) refuse("pool-wallet-execution-offer-basis-stale");', '/* same-height hash guard disabled */')], 'same-height independently mined hash change'),
        ('C5-anchor', runtime, [('packages/reference-wallet/src/apnt_pool_wallet_owner_v1.ts', 'if (hex(anchor.root32) !== hex(decodeAPNTPoolActionRecordV1(input.record).anchor32)) refuse("wallet-command-component-refused", "pool-wallet-anchor-stale");', '/* anchor guard disabled in disposable control */')], 'exact native anchor predicate fires independently'),
        ('C5-fresh-read-cause', runtime, [(eligibility, 'catch { refuse("pool-wallet-chain-stale"); }', 'catch { refuse("pool-wallet-payment-binding"); }')], 'PH11-HREAD real narrow reader fails independently'),
        ('C5-deadline-equality', runtime, [(eligibility, 'tip.height >= c.expiryHeight || tip.height >= c.cancelHeight', 'tip.height > c.expiryHeight || tip.height > c.cancelHeight')], 'PH11-HREAD fresh verified deadline equality'),
        ('H1-before-membership', H1, [(payer, '    requireWriterSession();\n', '    /* initial admission removed in scratch */\n')], 'H1 disconnected'),
        ('H1-locked-session', H1, [(payer, '  member.requireWriterSession();', '  /* locked session check removed in scratch */')], 'H1 writer revoked'),
        # Staged: close retires the session through its directory scope, not a
        # delete in close(); dropping that scope is the same close revocation.
        ('H1-close-revocation', H1, [(host, 'directory: () => closing === null ? opened?.paths.store : undefined', 'directory: () => opened?.paths.store')], 'H1 writer revoked'),
        ('H1-sync-revocation', H1, [(host, '    if (writerIdentity !== undefined) paymentWriterSessions.delete(writerIdentity);', '    /* synchronous revocation removed in scratch */')], 'H1 stopped-sync'),
        ('H1-connection', H1, [(host, '  try { requireWalletConnection(held!.connection, identity!); }', '  try { /* connection check removed in scratch */ }')], 'H1 forged-connection'),
        ('H1-epoch-binding', H1, [(payer, 'invocation.handleBinding?.epoch === authority.identity.epoch && invocation.handleBinding?.connection === authority.connection.id', 'invocation.handleBinding?.connection === authority.connection.id')], 'H1 foreign-epoch'),
        ('C10-refusal-authentication', runtime, [(route, 'requireValue(timingSafeEqual(expected, Buffer.from(envelope.binding, "hex"))); return envelope.value;', '/* MAC check removed in scratch */ return envelope.value;')], 'PH11-REFUSAL real bridge collapses independent bad-mac'),
        ('C10-refusal-challenge', runtime, [(route, 'v.challenge === pending.challenge && v.phase === pending.phase', 'v.phase === pending.phase')], 'PH11-REFUSAL real bridge collapses independent challenge-mismatch'),
        ('C10-refusal-keys', runtime, [(route, 'keysOf(v) === "challenge,epoch,error,phase,schema,source" && payload.length === 0', 'payload.length === 0')], 'PH11-REFUSAL real bridge collapses independent value-extra'),
        ('C10-refusal-error-keys', runtime, [(route, 'keysOf(v.error) === "cause,code,retry"', 'true')], 'PH11-REFUSAL real bridge collapses independent error-extra'),
        ('C10-immutable-tuple', runtime, [(supervisor, 'request.source !== source || !equal(request.arguments, argumentsExpected)', 'request.source !== source')], 'PH11-REFUSAL immutable A tuple position 2'),
        ('C8-close-inheritance', GO_EXEC, [(g+'internal/runneradmission/bridge.go', 'func closeBridgeInheritance() error {', 'func closeBridgeInheritance() error {\n return nil')], 'TestMIG01ActualExec'),
        ('C8-loader-stderr', GO_EXEC, [(g+'internal/runneradmission/bridge.go', 'command.Stdin, command.Stdout, command.Stderr = null, null, null', 'command.Stdin, command.Stdout, command.Stderr = null, null, os.Stderr')], 'TestMIG01ActualExec'),
        ('C3-guarded-diagnostics', RESULT, [('tools/pool-action-modules/private-runner-result.py', '    except Exception:\n        sys.exit(1)', '    except Exception:\n        raise')], 'independently refuses absent'),
        ('C3-raced-size', RESULT, [('tools/pool-action-modules/private-runner-result.py', 'if len(raw) != info.st_size:', 'if False:')], 'raced native result append-after-stat'),
        # Staged: the continuation environment is a fixed allowlist, not a strip
        # list; re-admitting the caller's NODE_OPTIONS is the same preload strip.
        ('C6-preload-stripping', 'tools/pool-action-modules/test/private-runner-bootstrap.test.ts', [('tools/pool-action-modules/private-runner-bootstrap.mjs', 'const cleanEnvironment = () => ({ HOME: userInfo().homedir, LANG: "C", TMPDIR: "/private/tmp",', 'const cleanEnvironment = () => ({ ...Object.fromEntries(Object.entries(process.env).filter(([key]) => key === "NODE_OPTIONS")), HOME: userInfo().homedir, LANG: "C", TMPDIR: "/private/tmp",')], 'continuation fixes PATH'),
        ('C7-bridge-interruption', 'tools/pool-action-modules/test/private-runner-lock-process.test.ts', [('tools/pool-action-modules/private-runner-bridge.mjs', '    await new Promise(resolve => setImmediate(() => setImmediate(resolve)));\n    if (terminated) throw new PrivateRunnerRefusal();', '    await new Promise(resolve => setImmediate(() => setImmediate(resolve)));')], 'bridge delivered signals'),
        ('C7-supervisor-initial-interruption', 'tools/pool-action-modules/test/private-runner-lock-process.test.ts', [(supervisor, '  await new Promise(resolve => setImmediate(resolve));\n  if (interrupted) refusal();\n  const acquired', '  await new Promise(resolve => setImmediate(resolve));\n  const acquired')], 'supervisor delivered signals .* at exclusive acquisition [123]'),
        ('C7-supervisor-route-interruption', 'tools/pool-action-modules/test/private-runner-lock-process.test.ts', [(supervisor, '  const acquired = readPrivateRunnerRoute(plan); key = acquired.key;\n  await new Promise(resolve => setImmediate(resolve));\n  if (interrupted) refusal();', '  const acquired = readPrivateRunnerRoute(plan); key = acquired.key;\n  await new Promise(resolve => setImmediate(resolve));')], 'supervisor delivered signals .* at exclusive acquisition 4'),
    ]
    anchor = '# ---- the plan, checked before anything runs ----'
    kernel = 'PH11-X-PROD/P0 genuine kernel'
    # Staged: generation-2 loops read plan_source's captured FD8 lines. As in
    # the donor, each control reopens the original PLAN path instead.
    validation = between(shell, 'names=()', 'if [[ $PRIVATE_RUNNER_GENERATION == 2 ]] && $has_live; then ((${#names[@]} == 1))')
    execution = between(shell, '# The plan is read on fd 3 so that nothing a case runs can consume it.', '/usr/bin/python3 - "$results" "${names[@]}"')
    groups += [
        ('C9-source-detector', runtime, [(g+'scripts/mig01-macos-observer.c', 'value.pvi.vi_stat.vst_ino==(uint64_t)source.st_ino) source_descriptors++;', '0) source_descriptors++;')], kernel),
        ('C9-transport-detector', runtime, [(g+'scripts/mig01-macos-observer.c', 'if(matches) matching8++; else different8++;', 'if(matches || !S_ISREG(transport.vst_mode)) matching8++; else different8++;')], kernel),
        ('C9-stat', runtime, [(SHELL, anchor, '[[ -f "$plan" ]] || die "live-plan-refused"\n' + anchor)], kernel),
        ('C9-grep', runtime, [(SHELL, "< <(printf '%s\\n' \"${plan_lines[@]}\"); then has_live=true; fi", '< "$plan"; then has_live=true; fi')], kernel),
        ('C9-validation', runtime, [(SHELL, validation, reopened(validation, 'done < <(plan_source)', 'done < "$plan"'))], kernel),
        ('C9-execution-reopen', runtime, [(SHELL, execution, reopened(execution, 'done 3< <(plan_source)', 'done 3< "$plan"'))], kernel),
        # The Sage group runs after every mandatory runner group; it cannot
        # preempt the H1/C1-C10 evidence collection above.
        ('Sage-import-completion', SAGE, [('packages/pool-wallet-ink/src/sage/live-app.tsx', "Import step complete. Follow this wallet's observed delivery state.",
            "Proof verified and public hand-off recorded. Follow this wallet's observed transitions.")], 'ENG-1266'),
    ]
    return groups

# The runtime entry's two registered-observer poison controls, kept beside the
# 42 groups because this driver replaces that entry in the certification run.
POISON = tuple((name, RUNTIME, [(TAGGED_GO, 'func ' + test + '(t *testing.T) {', 'func ' + test + '(t *testing.T) {\n t.Fatal("synthetic-poisoned-observer")')], selection)
               for name, test, selection in (('observer-poison-library', 'TestMIG01R3RegisteredLibraryObservation', 'PH11-X direct tagged library'),
                                             ('observer-poison-dispatch', 'TestMIG01R3RegisteredDispatchObservation', 'PH11-X tagged genuine')))

# Assertion sites, each the last line of an anchor occurring once in its test file.
OBSERVER_VERDICT = 'expect([r.status,result.passed,result.failed,result.skipped]).toEqual([0,1,0,0]);'
TAGGED_CALL = "await registeredObserver(f,'TestMIG01R3RegisteredDispatchObservation',phase,failure?'ownership':'success');"
LIBRARY_CALL = "await registeredObserver(f,'TestMIG01R3RegisteredLibraryObservation','A',after?'ownership':'success');"
SETUP_HELPER_SITE = 'expect({status,...JSON.parse(runnerDiagnostic(f))}).toMatchObject({status:1,'
SETUP_P0_CALLER = "runtimeStep('runner-complete');\n    requireFailClosed(f,status);"
TERMINAL_LEAK = 'expect(leaks(Buffer.concat(observation.stderr))).toBe(false);'
INBOX_ROUTE = 'tools/pool-action-modules/lib/private-runner-route.mjs'
INBOX_TITLE = 'PH11-ROUTE-WRITER genuine inbox source reaches the authenticated P/A/W issuer'
INBOX_SOURCE = '''function sourceConstruction(token, store, request, kind) {
  try {
    if (kind === "withdrawal") {
      requireValue(typeof withdrawalConstruction.requireHarnessWithdrawalConstruction === "function");
      const source = withdrawalConstruction.requireHarnessWithdrawalConstruction(token, store, request);
      requireValue(source.kind === "withdrawal" && hex(source.deliveryDigest, 32));
      return source;
    }
    return kind === "invoice-payment" ? requireHarnessPaymentConstruction(token, store, request)
      : kind === "inbox-deposit" ? requireHarnessInboxConstruction(token, store, request) : (() => { throw new PrivateRunnerRefusal(); })();
  } catch { throw new PrivateRunnerRefusal(); }
}'''
# Run the genuine guard first. Its successful return is observed by the test's
# synchronous passthrough, separately from the deliberately injected refusal.
INBOX_MUTANT = INBOX_SOURCE.replace('requireHarnessInboxConstruction(token, store, request)',
    '(() => { requireHarnessInboxConstruction(token, store, request); throw new PrivateRunnerRefusal(); })()')
INBOX_WRITE = '  try {\n    writeHarnessProverRequest(f.paths,f.actionId,f.request,f.token,f.context);'
INBOX_REGISTERED = "if(f.context.kind==='inbox-deposit')writeObservedInboxRequest(f);"
INBOX_CHAIN = (
    (INBOX_ROUTE, INBOX_MUTANT.rsplit('\n}', 1)[0]),  # actual catch/rethrow, not the injection
    (INBOX_ROUTE, 'const constructed = sourceConstruction(token, paths.store, request, context.kind);'),
    (INBOX_ROUTE, 'try { return writeHarnessSource(paths, actionId, request, token, context); }'),
    (RUNTIME, INBOX_WRITE), (RUNTIME, INBOX_REGISTERED),
    (RUNTIME, "test('" + INBOX_TITLE + "',async()=>{\n  await registered('manual','',async f=>{"),
)
# Pure decoding shared by the future one-row probe and frozen-oracle binder.
# The flags describe helper-input diagnostics; the contract is the nine-field
# assertion subset forwarded by pinned Vitest, never measured mutant values.
HELPER_FLAGS = tuple('outerRefusal memoryFloor outputCreated runCreated admissionCreated resultCreated summaryCreated workFailure openStage'.split())
HELPER_CONTRACT = dict(status=1, contacts=[1,1,1], deliveries=[1,1,1], outerRefusal=True,
    admissionCreated=True, resultCreated=True, summaryCreated=False, memoryFloor=False, workFailure=False)
SETUP_HELPER_ROWS = {'C2-c-main-dispatch':'stock', **dict.fromkeys(('C9-stat','C9-grep','C9-validation','C9-execution-reopen'),'kernel')}
SETUP_HELPER_TITLE = 'PH11-X-PROD/P0 genuine {} stock runner reaches P/A/W and writes its check-live result then fails closed before the summary'

def capture_json(text):
    def pairs(items):
        require(len(items) == len(dict(items)))
        return dict(items)
    try:
        return json.loads(text, object_pairs_hook=pairs)
    except (ValueError, TypeError):
        require(False)

def capture_helper(value):
    """Validate exactly the nine assertion keys received by the reporter.

    P/A/W positions stay ordered. The four helper-only diagnostics are absent
    from Vitest's error.actual and are refused here, never reconstructed.
    No numeric mutant oracle or baseline/mutant decision belongs to decoding.
    """
    keys = set(HELPER_CONTRACT)
    require(type(value) is dict)
    require(set(value) <= keys)  # unknown keys
    require(keys <= set(value))  # missing keys
    for key, item in ((key, value[key]) for key in HELPER_CONTRACT if key in value):
        if key == 'status':
            require(type(item) is int and item >= 0)
        elif key in ('contacts','deliveries'):
            require(type(item) is list and len(item) == 3)
            require(all(type(count) is int and count >= 0 for count in item))
        else:
            require(type(item) is bool)
    projection = {key: value[key][:] if type(value[key]) is list else value[key] for key in HELPER_CONTRACT if key in value}
    return {'actual': value, 'projection': projection}

def decode_setup_actual(control, title, alternative, text):
    """Closed pretty-format actual for one selected stock/kernel observation.

    Error class, observed stack/site/span/caller and phase provenance must be
    authenticated separately by the probe/binder; decoding proves none of them.
    """
    require(type(control) is str and control in SETUP_HELPER_ROWS)
    require(title == SETUP_HELPER_TITLE.format(SETUP_HELPER_ROWS[control]))
    require(type(text) is str)
    if alternative == 'terminal-leak':
        require(control == 'C9-grep' and text == 'true')
        return {'actual': True, 'projection': {}}
    require(alternative == 'helper')
    require(text.startswith('Object {'))
    require(all(re.fullmatch(r'"[A-Za-z][A-Za-z0-9]*"', token) for token in re.findall(r'"(?:\\.|[^"\\])*"', text)))
    value = capture_json(re.sub(r',\s*([}\]])', r'\1', text.replace('Object {','{').replace('Array [','[')))
    return capture_helper(value)

H1_HELPER = 'expect(error?.code).toBe(code);'
H1_MODE = 'await refusal(() => payer.preparePaymentExecution({ ...input, invocation }), "wallet-command-component-refused", "pool-wallet-payment-host-authority-required");'
H1_REVOKED = 'await refusal(() => prepareLegacyPaymentExecution({ ...f.input, afterCommit: () => { void f.stopHost(); } } as any), "wallet-command-component-refused", "pool-wallet-payment-host-authority-required");'
# Serialized actual values (pretty-format): what each disabled guard lets through.
OBSERVER_FAILED = r'^Array \[\n  1,\n  0,\n  1,\n  0,\n\]$'
DELIVERED = r'^Object \{\n  "bytes": [1-9][0-9]*,\n  "error": null,\n\}$'
EXIT_ONE = r'^1$'
def refusal_value(cause, retry):
    return ('^Object \\{\n  "bytes": 0,\n  "error": Object \\{\n    "cause": "' + cause
            + '",\n    "code": "wallet-command-component-refused",\n    "retry": "' + retry + '",\n  \\},\n\\}$')
EXEC = 'TestMIG01ActualExecDescriptorsAndLoader'
CANARY_SITE = 'expect(canary.status, JSON.stringify({source:canaryFacts.sourceFstatDetectorFires===true,transport:canaryFacts.transportFstatDiffers===true,diagnosticBytes:canary.stderr.length})).toBe(0);'

def lock_values(role, acquisitions, completed, servers, issuer_checks):
    """Exact per-signal lifecycle effects of bypassing the selected interruption guard.

    Bridge: one issuer-directory check. Initial supervisor: one extra lock read.
    Route supervisor: both listeners open before stillCurrent refuses. All locks
    drain and the actual OS signal is delivered after release in every case.
    """
    values = {}
    for nth in acquisitions:
        for signal in ('SIGINT', 'SIGTERM'):
            fields = {'acquired': completed, 'closed': completed, 'unlinked': completed, 'servers': servers,
                      'contacts': 0, 'issuerChecks': issuer_checks, 'sent': 1, 'delivered': 1, 'firedAt': nth,
                      'deliveryAfterRelease': True, 'heldAtExit': 0}
            actual = 'Object {\n' + ''.join('  ' + json.dumps(key) + ': ' + json.dumps(value) + ',\n'
                                            for key, value in sorted(fields.items())) + '}'
            title = f'PH11-LOCK {role} delivered signals {signal} at exclusive acquisition {nth} drain before exit'
            values[title] = '^' + re.escape(actual) + '$'
    return values

def binding(sites, rows=None, error='AssertionError', message=None, thrown=None, observers=None):
    """sites: alternatives (assertion anchor, caller anchor or None, actual regex or exact title-to-regex map).
    Setup helpers instead map the exact title to its frozen typed projection.
    Non-assertion exceptions bind their exact serialized value, kind and
    message (and actual rethrow site, if any), not a normalized absent value."""
    return {'sites': sites, 'rows': rows, 'error': error, 'message': message, 'thrown': thrown, 'observers': observers, 'native': None}

def native(failing):
    """failing: exact Go test name -> its one fatal message, or None when it fails only through subtests."""
    return {'sites': (), 'rows': None, 'error': None, 'message': None, 'thrown': None, 'observers': None, 'native': failing}

# ARCH-748 B, amended by SO1545u (ARCH-752) and SO0455g; REV-1107 R2.
# Each entry below is copied from FROZEN-ORACLES-R2.json / entries[control].
SETUP_FREEZE_SHA256 = 'a9dac3e1992ee8f0fabb7513df1ef445f4e3b6bd039359339a395c70e7c57b33'
SETUP_ORACLES = {
    'C2-c-main-dispatch': {
        'control': 'C2-c-main-dispatch',
        'row': 'PH11-X-PROD/P0 genuine stock stock runner reaches P/A/W and writes its check-live result then fails closed before the summary',
        'sourceRecordSha256': 'b585430ddeff32ac269df8289d8038770da6b635069d909b5f82c034efeed352',
        'observation': {
            'actual': {'admissionCreated': False, 'contacts': [1, 0, 0], 'deliveries': [1, 0, 0], 'memoryFloor': False, 'outerRefusal': True, 'resultCreated': False, 'status': 1, 'summaryCreated': False, 'workFailure': False},
            'alternative': 'helper',
            'error': 'AssertionError',
            'frames': [['tools/pool-action-modules/test/mig01-runtime-controls.test.ts', 566, 55], ['tools/pool-action-modules/test/mig01-runtime-controls.test.ts', 590, 5]],
            'inbox': None,
            'projection': {'admissionCreated': False, 'contacts': [1, 0, 0], 'deliveries': [1, 0, 0], 'memoryFloor': False, 'outerRefusal': True, 'resultCreated': False, 'status': 1, 'summaryCreated': False, 'workFailure': False},
        },
    },
    'C1-inbox-writer': {
        'control': 'C1-inbox-writer',
        'row': 'PH11-ROUTE-WRITER genuine inbox source reaches the authenticated P/A/W issuer',
        'sourceRecordSha256': '02d76f65bae17da05a8f384f99ad8bf43daea0293be37d04dc1813792886cf6c',
        'observation': {
            'actual': 'undefined',
            'alternative': 'inbox',
            'error': 'PrivateRunnerRefusal',
            'frames': [['tools/pool-action-modules/lib/private-runner-route.mjs', 141, 19], ['tools/pool-action-modules/lib/private-runner-route.mjs', 170, 23], ['tools/pool-action-modules/lib/private-runner-route.mjs', 160, 16], ['tools/pool-action-modules/test/mig01-runtime-controls.test.ts', 200, 5], ['tools/pool-action-modules/test/mig01-runtime-controls.test.ts', 281, 41], ['tools/pool-action-modules/test/mig01-runtime-controls.test.ts', 741, 3]],
            'inbox': {'rows': [{'assertionActualAbsent': True, 'contacts': 0, 'deliveries': 0, 'guardCalls': 1, 'guardReturns': 1, 'invocation': 1, 'matchingReturns': 1, 'outcome': 'refused', 'planAbsent': True, 'receiptAbsent': True, 'requestAbsent': True, 'requestsAbsent': True, 'routeAbsent': True, 'row': 'PH11-ROUTE-WRITER genuine inbox source reaches the authenticated P/A/W issuer', 'runnerAbsent': True, 'stateUnchanged': True, 'stderrBytes': 0, 'stdoutBytes': 0}], 'schema': 'mig01-inbox-writer-v1'},
            'projection': {},
        },
    },
    'C9-stat': {
        'control': 'C9-stat',
        'row': 'PH11-X-PROD/P0 genuine kernel stock runner reaches P/A/W and writes its check-live result then fails closed before the summary',
        'sourceRecordSha256': 'a50fe83d723886e7176ae6d2cf36b78e79635e1dfdb3127819439a3b9fa9a299',
        'observation': {
            'actual': {'admissionCreated': False, 'contacts': [1, 0, 0], 'deliveries': [1, 0, 0], 'memoryFloor': False, 'outerRefusal': True, 'resultCreated': False, 'status': 1, 'summaryCreated': False, 'workFailure': False},
            'alternative': 'helper',
            'error': 'AssertionError',
            'frames': [['tools/pool-action-modules/test/mig01-runtime-controls.test.ts', 566, 55], ['tools/pool-action-modules/test/mig01-runtime-controls.test.ts', 590, 5]],
            'inbox': None,
            'projection': {'admissionCreated': False, 'contacts': [1, 0, 0], 'deliveries': [1, 0, 0], 'memoryFloor': False, 'outerRefusal': True, 'resultCreated': False, 'status': 1, 'summaryCreated': False, 'workFailure': False},
        },
    },
    'C9-grep': {
        'control': 'C9-grep',
        'row': 'PH11-X-PROD/P0 genuine kernel stock runner reaches P/A/W and writes its check-live result then fails closed before the summary',
        'sourceRecordSha256': '9ac6de9bf34bf579e2dde589aff991e63a95d00551494e38e6d502f4fbc7e7f4',
        'observation': {
            'actual': {'admissionCreated': True, 'contacts': [1, 1, 1], 'deliveries': [1, 1, 1], 'memoryFloor': False, 'outerRefusal': False, 'resultCreated': True, 'status': 1, 'summaryCreated': False, 'workFailure': False},
            'alternative': 'helper',
            'error': 'AssertionError',
            'frames': [['tools/pool-action-modules/test/mig01-runtime-controls.test.ts', 566, 55], ['tools/pool-action-modules/test/mig01-runtime-controls.test.ts', 590, 5]],
            'inbox': None,
            'projection': {'admissionCreated': True, 'contacts': [1, 1, 1], 'deliveries': [1, 1, 1], 'memoryFloor': False, 'outerRefusal': False, 'resultCreated': True, 'status': 1, 'summaryCreated': False, 'workFailure': False},
        },
    },
    'C9-validation': {
        'control': 'C9-validation',
        'row': 'PH11-X-PROD/P0 genuine kernel stock runner reaches P/A/W and writes its check-live result then fails closed before the summary',
        'sourceRecordSha256': '21ce17da1466e87ce09db7fba03c56eac79da557a437b474bf16e14aa12b65dc',
        'observation': {
            'actual': {'admissionCreated': False, 'contacts': [1, 0, 0], 'deliveries': [1, 0, 0], 'memoryFloor': False, 'outerRefusal': True, 'resultCreated': False, 'status': 1, 'summaryCreated': False, 'workFailure': False},
            'alternative': 'helper',
            'error': 'AssertionError',
            'frames': [['tools/pool-action-modules/test/mig01-runtime-controls.test.ts', 566, 55], ['tools/pool-action-modules/test/mig01-runtime-controls.test.ts', 590, 5]],
            'inbox': None,
            'projection': {'admissionCreated': False, 'contacts': [1, 0, 0], 'deliveries': [1, 0, 0], 'memoryFloor': False, 'outerRefusal': True, 'resultCreated': False, 'status': 1, 'summaryCreated': False, 'workFailure': False},
        },
    },
    'C9-execution-reopen': {
        'control': 'C9-execution-reopen',
        'row': 'PH11-X-PROD/P0 genuine kernel stock runner reaches P/A/W and writes its check-live result then fails closed before the summary',
        'sourceRecordSha256': '307865b14137e37c475e0c49b2f0affee295985bb168166b6f8597efa09cb778',
        'observation': {
            'actual': {'admissionCreated': False, 'contacts': [1, 0, 0], 'deliveries': [1, 0, 0], 'memoryFloor': False, 'outerRefusal': True, 'resultCreated': False, 'status': 1, 'summaryCreated': False, 'workFailure': False},
            'alternative': 'helper',
            'error': 'AssertionError',
            'frames': [['tools/pool-action-modules/test/mig01-runtime-controls.test.ts', 566, 55], ['tools/pool-action-modules/test/mig01-runtime-controls.test.ts', 590, 5]],
            'inbox': None,
            'projection': {'admissionCreated': False, 'contacts': [1, 0, 0], 'deliveries': [1, 0, 0], 'memoryFloor': False, 'outerRefusal': True, 'resultCreated': False, 'status': 1, 'summaryCreated': False, 'workFailure': False},
        },
    },
}

def setup_binding(name):
    oracle = SETUP_ORACLES[name]
    return binding([(SETUP_HELPER_SITE, SETUP_P0_CALLER,
        {oracle['row']: oracle['observation']['projection']})])

def require_setup_oracle(name, entry):
    """Offline provenance and per-field equality; the caller authenticates freeze bytes."""
    oracle = SETUP_ORACLES[name]
    require(entry['bindingEligible'] is True and entry['control'] == name)
    require(entry['sourceRecordSha256'] == oracle['sourceRecordSha256'])
    for key in ('control', 'row'):
        require(json.dumps(entry[key], sort_keys=True) == json.dumps(oracle[key], sort_keys=True))
    require(set(entry['observation']) == set(oracle['observation']))
    for key in oracle['observation']:
        require(json.dumps(entry['observation'][key], sort_keys=True) == json.dumps(oracle['observation'][key], sort_keys=True))

FIRING = {
    'C2-a-exact-tuple': binding([(OBSERVER_VERDICT, TAGGED_CALL, OBSERVER_FAILED)], rows=r'expiry after "[PA]"', observers='ownership'),
    'C2-b-before-writer': binding([(OBSERVER_VERDICT, TAGGED_CALL, OBSERVER_FAILED)], rows=r'expiry after "[PA]"', observers='ownership'),
    'C2-c-main-dispatch': setup_binding('C2-c-main-dispatch'),
    'C2-d-production-prerequisite': binding([('expect([r.status,r.out.length,r.err.length]).toEqual([1,0,0]);expect(observation.contacts).toEqual([]);', None, r'^Array \[\n  "A",\n\]$')]),
    'C2-e-library-prerequisite': binding([("expect(observation.contacts.length).toBe(contacts);", None, r'^2$')]),
    'C2-f-ordinary-hook': binding([("expect(files.stdout.includes('prerequisite_testbuild.go')).toBe(false);", None, r'^true$')]),
    'C3-outer-diagnostics': binding([('expect([child.status, child.stdout, child.stderr]).toEqual([1, "", `measure-pk-load: live-plan-refused reason=${reason}\\n`]);', None,
                                      r'^Array \[\n  1,\n  "",\n  "measure-pk-load: live-plan-refused reason=unclassified\n",\n\]$')]),
    # Vitest serializes a missing error.actual as the literal string undefined.
    # C1 also checks absence on the raw caught object before that serialization.
    'C1-inbox-writer': binding([(INBOX_WRITE, INBOX_REGISTERED, r'^undefined$')], error='PrivateRunnerRefusal',
                               message=r'^private-runner-refused$', thrown=INBOX_CHAIN[0]),
    'C4-authenticated-singlecase': binding([("expect(await bridgeFrame(f,'P')).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-payment-binding'}});", None, DELIVERED)]),
    'C4-original-ttl': binding([("expect(result).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-payment-host-authority-required'}});", None, DELIVERED)]),
    'C4-distinct-latches': binding([("expect((await bridgeFrame(f,'A')).error.cause).toBe('pool-wallet-payment-host-authority-required');", None, r'^undefined$')],
                                   error='TypeError', message=r"^Cannot read properties of null \(reading 'cause'\)$"),
    'C5-final-capture-basis': binding([("if(phase===stale){expect(result).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'resnapshot',cause:'pool-wallet-execution-offer-basis-stale'}});break;}", None, DELIVERED)]),
    'C5-same-height-hash': binding([("expect(await bridgeFrame(f,'A')).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'resnapshot',cause:'pool-wallet-execution-offer-basis-stale'}});", None, refusal_value('pool-wallet-chain-stale', 'after-sync'))]),
    'C5-anchor': binding([("if(phase===stale){expect(result).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-anchor-stale'}});break;}", None, DELIVERED)]),
    'C5-fresh-read-cause': binding([("if(phase===failedPhase){expect(metadata).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'after-sync',cause:'pool-wallet-chain-stale'}});break;}", None,
                                     refusal_value('pool-wallet-payment-binding', 'none'))]),
    'C5-deadline-equality': binding([("if(phase===failedPhase){expect(metadata).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'reconcile',cause:'pool-wallet-execution-deadline'}});break;}", None, DELIVERED)]),
    # The selected row invokes both current and legacy entry points.
    'H1-before-membership': binding([('expect(minted, "PH02 admission must precede membership creation").toBe(0);', None, r'^2$')]),
    'H1-locked-session': binding([(H1_HELPER, H1_REVOKED, r'^undefined$')]),
    'H1-close-revocation': binding([(H1_HELPER, H1_REVOKED, r'^undefined$')]),
    'H1-sync-revocation': binding([(H1_HELPER, H1_MODE, r'^undefined$')]),
    'H1-connection': binding([(H1_HELPER, H1_MODE, r'^undefined$')]),
    # The focal oracle must reach the exact refusal-code assertion, rather than
    # fail in setup or a later effect.
    'H1-epoch-binding': binding([(H1_HELPER, H1_MODE, r'^undefined$')], message=r"^expected undefined to be 'wallet-command-component-refused'"),
    **{name: binding([("expect(await bridgeFrame(f,'P')).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-payment-host-authority-required'}});", None,
                       refusal_value('pool-wallet-chain-stale', 'after-sync'))])
       for name in ('C10-refusal-authentication', 'C10-refusal-challenge', 'C10-refusal-keys', 'C10-refusal-error-keys')},
    'C10-immutable-tuple': binding([('expect(observation.freshReads).toBe(before.length);', None, r'^2$')]),
    'C8-close-inheritance': native({EXEC: None, EXEC + '/descriptor-and-orphan': r'^exec descriptor identity mismatch: decoded=true null=true transport=true inherited=true$'}),
    'C8-loader-stderr': native({EXEC: None, EXEC + '/descriptor-and-orphan': r'^exec descriptor identity mismatch: decoded=true null=false transport=true inherited=false$',
                                **{EXEC + '/' + variant: r'^terminal diagnostic escaped$' for variant in ('early-loader', 'uncaught-error', 'unhandled-rejection')}}),
    'C3-guarded-diagnostics': binding([('if (kind === "mode") chmodSync(f.result, 0o644);\n    const child = f.run(); expect([child.status, child.stdout.length, child.stderr.length]).toEqual([1, 0, 0]);',
                                        None, r'^Array \[\n  1,\n  0,\n  [1-9][0-9]*,\n\]$')]),
    'C3-raced-size': binding([('const child = spawnSync("/usr/bin/python3", ["-B", "-c", program, ENTRY, f.result], { encoding: "utf8" });\n    expect([child.status, child.stdout.length, child.stderr.length]).toEqual([1, 0, 0]);',
                               None, r'^Array \[\n  0,\n  0,\n  0,\n\]$')]),
    'C6-preload-stripping': binding([('expect(Object.keys(env).sort()).toEqual(["HOME", "LANG", "MEASURE_PK_LOAD_HERE", "MEASURE_PK_LOAD_SELF", "PATH", "TMPDIR"]);', None, r'^Array \[\n  "HOME",\n  "LANG",\n  "MEASURE_PK_LOAD_HERE",\n  "MEASURE_PK_LOAD_SELF",\n  "NODE_OPTIONS",\n  "PATH",\n  "TMPDIR",\n\]$')]),
    **{name: binding([('expect(result.metadata).toEqual({acquired:completed,closed:completed,unlinked:completed,servers:0,contacts:0,issuerChecks:0,', None, values)])
       for name, values in (('C7-bridge-interruption', lock_values('bridge', (1,), 1, 0, 1)),
                            ('C7-supervisor-initial-interruption', lock_values('supervisor', (1, 2, 3), 4, 0, 0)),
                            ('C7-supervisor-route-interruption', lock_values('supervisor', (4,), 4, 2, 2)))},
    'C9-source-detector': binding([(CANARY_SITE, None, r'^1$')], message=r'^\{"source":false,"transport":true,"diagnosticBytes":0\}: expected 1 to be \+?0'),
    'C9-transport-detector': binding([(CANARY_SITE, None, r'^1$')], message=r'^\{"source":true,"transport":false,"diagnosticBytes":0\}: expected 1 to be \+?0'),
    'C9-stat': setup_binding('C9-stat'),
    # Brain Chat SO0455g: only the independently observed helper is bindable.
    'C9-grep': setup_binding('C9-grep'),
    'C9-validation': setup_binding('C9-validation'),
    'C9-execution-reopen': setup_binding('C9-execution-reopen'),
    'Sage-import-completion': binding([('expect(shown.includes("Import step complete. Follow this wallet\'s observed delivery state.")).toBe(true);', None, r'^false$')]),
    'observer-poison-library': binding([(OBSERVER_VERDICT, LIBRARY_CALL, OBSERVER_FAILED)], observers='all'),
    'observer-poison-dispatch': binding([(OBSERVER_VERDICT, TAGGED_CALL, OBSERVER_FAILED)], observers='all'),
}

def require_inventory(groups):
    """Exactly 42 uniquely named groups: 41 runner groups, then the one Sage group."""
    names = [group[0] for group in groups]
    require(len(groups) == GROUPS and len(set(names)) == GROUPS and names[-1] == 'Sage-import-completion'
            and sum(name.startswith('Sage-') for name in names) == 1)
    for name, selected, edits, selection in groups:
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*', name) is not None and type(selection) is str and selection)
        re.compile(selection)
        require(selected == GO_EXEC or selected.endswith(('.test.ts', '.test.tsx')))
        require(edits and len({path for path, _, _ in edits}) == len(edits))

def require_targets(read, groups):
    """Every selected test exists and every target occurs exactly once where it is mutated."""
    for _name, selected, edits, _selection in groups:
        require(selected == GO_EXEC or read(selected) is not None)
        for path, before, after in edits:
            text = read(path)
            require(text is not None and before and before != after and text.count(before) == 1)

def anchor_line(text, anchor):
    """The line ending a once-occurring anchor: the bound assertion or call site."""
    require(text is not None and text.count(anchor) == 1)
    return text[:text.index(anchor) + len(anchor)].count('\n') + 1

def anchor_span(text, anchor):
    line = anchor_line(text, anchor)
    end = text.index(anchor) + len(anchor)
    start = max(text.index(anchor), text.rfind('\n', 0, end) + 1,
                text.index(anchor) + anchor.rfind('expect('))
    base = text.rfind('\n', 0, end) + 1
    return line, start - base + 1, end - base + 1

def require_bindings(read, groups):
    """Every group and poison control has a binding whose anchors resolve exactly once."""
    require(set(FIRING) == {group[0] for group in (*groups, *POISON)})
    for name, selected, edits, _selection in (*groups, *POISON):
        bound = FIRING[name]
        if bound['native'] is not None:
            require(selected == GO_EXEC and bound['native'].get(EXEC, 'missing') is None and len(bound['native']) > 1)
            for title, value in bound['native'].items():
                if title == EXEC: continue  # Parent fails only through its bound children.
                require(title.startswith(EXEC + '/') and type(value) is str and value.startswith('^') and value.endswith('$'))
                re.compile(value)
            continue
        require(selected != GO_EXEC and bound['sites'] and bound['error'] in ('AssertionError', 'TypeError', 'PrivateRunnerRefusal'))
        for site, caller, actual in bound['sites']:
            anchor_line(read(selected), site)
            require((site in (H1_HELPER, OBSERVER_VERDICT, INBOX_WRITE, SETUP_HELPER_SITE)) == (caller is not None))
            if caller is not None: anchor_line(read(selected), caller)
            if name in SETUP_HELPER_ROWS:
                oracle = SETUP_ORACLES[name]
                require(oracle['control'] == name and selected == RUNTIME and bound['error'] == oracle['observation']['error'])
                require(site == SETUP_HELPER_SITE and caller == SETUP_P0_CALLER)
                require([anchor_line(read(selected), anchor) for anchor in (site, caller)]
                        == [frame[1] for frame in oracle['observation']['frames']])
                require(type(actual) is dict and set(actual) == {oracle['row']})
                capture_helper(actual[oracle['row']])
                continue
            if bound['error'] == 'AssertionError':
                require(type(actual) is str or type(actual) is dict and actual)
                values = actual.values() if type(actual) is dict else (actual,)
                if type(actual) is dict:
                    require(all(type(title) is str and re.search(_selection, title) for title in actual))
                for value in values:
                    require(type(value) is str and value.startswith('^') and value.endswith('$'))
                    re.compile(value)
                    require(re.fullmatch(value, '') is None and re.fullmatch(value, 'arbitrary-unrelated-actual') is None)
            else:
                require((actual == r'^undefined$' if name in ('C1-inbox-writer', 'C4-distinct-latches') else actual is None)
                        and type(bound['message']) is str and bound['message'].startswith('^') and bound['message'].endswith('$'))
                require((bound['error'] == 'PrivateRunnerRefusal') == (bound['thrown'] is not None))
        if bound['thrown'] is not None:
            path, after = bound['thrown']
            if name == 'C1-inbox-writer':
                require(edits == [(INBOX_ROUTE, INBOX_SOURCE, INBOX_MUTANT)] and bound['thrown'] == INBOX_CHAIN[0])
                original = read(INBOX_ROUTE)
                require(original.count(INBOX_SOURCE) == 1)
                mutated = original.replace(INBOX_SOURCE, INBOX_MUTANT)
                for file, anchor in INBOX_CHAIN: anchor_line(mutated if file == INBOX_ROUTE else read(file), anchor)
            else:
                require(any(path == target and after == mutated for target, _, mutated in edits))

def suite_directory(path):
    """Package tests run from their package, under its own vitest config, as the
    canonical package gates run them; tool tests run from the checkout root."""
    parts = path.split('/')
    return '/'.join(parts[:2]) if parts[0] == 'packages' else ''

def vitest_rows(report, fixture):
    """Executed passed/failed rows by checkout path. Skipped and pending rows
    were deselected: they are never executed and never a pass."""
    require(type(report) is dict and type(report.get('testResults')) is list and type(report.get('success')) is bool)
    require(all(type(report.get(key)) is int and report[key] >= 0
                for key in ('numTotalTests', 'numPassedTests', 'numFailedTests', 'numPendingTests', 'numFailedTestSuites')))
    executed, deselected = {}, 0
    for suite in report['testResults']:
        require(type(suite) is dict and type(suite.get('name')) is str and type(suite.get('assertionResults')) is list)
        path = Path(suite['name']).relative_to(fixture).as_posix()
        for row in suite['assertionResults']:
            require(type(row) is dict and type(row.get('fullName')) is str and row.get('status') in ('passed', 'failed', 'skipped', 'pending'))
            if row['status'] in ('passed', 'failed'):
                executed.setdefault(path, []).append(row)
            else:
                deselected += 1
    rows = [row for file_rows in executed.values() for row in file_rows]
    require(len(rows) == report['numPassedTests'] + report['numFailedTests']
            and sum(row['status'] == 'failed' for row in rows) == report['numFailedTests']
            and deselected == report['numPendingTests'] and len(rows) + deselected == report['numTotalTests'])
    return executed

def go_rows(output):
    """go test -json rows with each test's own fatal messages. A skipped required
    test is never a pass; a timeout is no oracle."""
    rows, fatal = [], {}
    for line in output.splitlines():
        event = json.loads(line)
        require(type(event) is dict and 'timed out' not in str(event.get('Output', '')).lower())
        test = event.get('Test')
        if test and event.get('Action') == 'output':
            output = str(event.get('Output', ''))
            if not re.fullmatch(r'(?:=== (?:RUN|PAUSE|CONT) +.*|\s*--- (?:PASS|FAIL|SKIP): .*|PASS|FAIL)\n?', output):
                fatal.setdefault(test, []).append(output)
        if test and event.get('Action') in ('pass', 'fail', 'skip'):
            require(event['Action'] != 'skip')
            rows.append({'fullName': test, 'status': 'passed' if event['Action'] == 'pass' else 'failed', 'fatal': fatal.get(test, [])})
    return rows

def family(names, selection):
    """The measured baseline rows one selection must execute; never empty."""
    selected = sorted(name for name in names if re.search(selection, name))
    require(selected)
    return selected

def stack_frames(stack):
    """(absolute path, line, column), innermost first; private until matched."""
    frames = []
    for line in stack.splitlines()[1:]:
        found = re.search(r'\bat (?:.* \()?(?:file://)?(/[^():]+):([0-9]+):([0-9]+)\)?$', line.strip())
        if found: frames.append((found[1], int(found[2]), int(found[3])))
    return frames

def require_inbox_witness(value):
    """Closed, invocation-bound observations from the passthrough and early
    writer checks. No path, token, request, state hash or mutant marker enters."""
    row = {'row': INBOX_TITLE, 'invocation': 1, 'outcome': 'refused', 'guardCalls': 1, 'guardReturns': 1, 'matchingReturns': 1,
           **dict.fromkeys(('assertionActualAbsent', 'stateUnchanged', 'requestAbsent', 'receiptAbsent', 'routeAbsent', 'requestsAbsent', 'planAbsent', 'runnerAbsent'), True),
           **dict.fromkeys(('contacts', 'deliveries', 'stdoutBytes', 'stderrBytes'), 0)}
    require(type(value) is dict and set(value) == {'schema', 'rows'} and value['schema'] == 'mig01-inbox-writer-v1'
            and type(value['rows']) is list and len(value['rows']) == 1)
    found = value['rows'][0]
    require(type(found) is dict and set(found) == set(row)
            and all(type(found[key]) is type(want) and found[key] == want for key, want in row.items()))

def require_bound_firing(name, rows, expected, selection, failures, read, fixture, selected, inbox=None):
    """The firing oracle: exactly the selected family ran, exactly its bound rows
    failed, and each failure is the bound guard's own assertion or refusal, with
    the bound error and serialized value. A fixture, setup, timeout or other
    assertion failure is an invalid result, never a firing."""
    bound = FIRING[name]
    if name in SETUP_ORACLES:
        oracle = SETUP_ORACLES[name]
        require(oracle['control'] == name and expected == [oracle['row']] and selected == RUNTIME)
    if name == 'C1-inbox-writer':
        require(expected == [INBOX_TITLE] and selected == RUNTIME and read(INBOX_ROUTE).count(INBOX_MUTANT) == 1)
        require_inbox_witness(inbox)
    require(sorted(row['fullName'] for row in rows) == expected)
    failing = sorted(row['fullName'] for row in rows if row['status'] == 'failed')
    require(failing and failing == (sorted(bound['native']) if bound['native'] is not None
                                    else sorted(row for row in expected if bound['rows'] is None or re.search(bound['rows'], row))))
    require(all(re.search(selection, row) for row in failing))
    if bound['native'] is not None:
        # Each failing Go test reports exactly its bound fatal message; a parent
        # fails only through its subtests. Fixture and exec refusals are invalid.
        for row in rows:
            want = bound['native'].get(row['fullName'])
            if want is None:
                require(row['fatal'] == [])
            else:
                anchor = 't.Fatal("terminal diagnostic escaped")' if 'terminal diagnostic' in want else 't.Fatalf("exec descriptor identity mismatch:'
                line = anchor_line(read(CIRCUIT + 'internal/runneradmission/exec_process_test.go'), anchor)
                require(len(row['fatal']) == 1)
                message = re.fullmatch(r'\s+exec_process_test\.go:' + str(line) + r': (.*)\n?', row['fatal'][0])
                require(message is not None and re.search(want, message[1]) is not None)
        return 'bound-native'
    require(type(failures) is list and sorted(failure['fullName'] for failure in failures) == failing)
    require(bound['error'] != 'AssertionError' or all(actual is not None for _, _, actual in bound['sites']))
    for _, _, actual in bound['sites']:
        if type(actual) is dict: require(set(actual) == set(failing))
    sites = [(anchor_span(read(selected), site), None if caller is None else anchor_line(read(selected), caller), actual)
             for site, caller, actual in bound['sites']]
    thrown = None if bound['thrown'] is None else (str(fixture / bound['thrown'][0]), anchor_line(read(bound['thrown'][0]), bound['thrown'][1]))
    for failure in failures:
        require(type(failure.get('errors')) is list and len(failure['errors']) == 1)
        error = failure['errors'][0]
        require(error['name'] == bound['error'] and 'timed out' not in error['message'].lower()
                and (bound['message'] is None or re.search(bound['message'], error['message']) is not None))
        decoded = (decode_setup_actual(name, failure['fullName'], 'helper', error['actual'])['projection']
                   if name in SETUP_HELPER_ROWS else None)
        frames = stack_frames(error['stack'])
        if name in SETUP_HELPER_ROWS:
            wanted = [frame[1] for frame in SETUP_ORACLES[name]['observation']['frames']]
            observed = [(i, frame) for i, frame in enumerate(frames)
                        if frame[0] == str(fixture / RUNTIME) and frame[1] in wanted]
            require(len(observed) == 2 and [frame[1] for _, frame in observed] == wanted
                    and observed[1][0] == observed[0][0] + 1)
            _, start, end = anchor_span(read(selected), SETUP_P0_CALLER)
            require(start <= observed[1][1][2] <= end)
        if name == 'C1-inbox-writer':
            require(len(frames) >= len(INBOX_CHAIN))
            for frame, (path, anchor) in zip(frames, INBOX_CHAIN):
                line, start, end = anchor_span(read(path), anchor)
                require(frame[0] == str(fixture / path) and frame[1] == line and start <= frame[2] <= end)
        locations = [(line, column) for path, line, column in frames if path == str(fixture / selected)]
        require(thrown is None or (frames and frames[0][:2] == thrown))
        require(any(locations and locations[0][0] == site[0] and site[1] <= locations[0][1] <= site[2]
                    and (caller is None or [line for line, _ in locations[1:2]] == [caller])
                    and (decoded == actual[failure['fullName']] if name in SETUP_HELPER_ROWS else
                         error['actual'] is None if actual is None else
                         type(error['actual']) is str and re.fullmatch(actual[failure['fullName']] if type(actual) is dict else actual, error['actual']) is not None)
                    for site, caller, actual in sites))
    return 'bound-refusal' if thrown else 'bound-assertion'

def require_observer_rows(rows, expectation, diagnostics, read, name):
    """The private observer record: ownership observations failed while the same
    fixture's success observations passed, or every poisoned observation failed."""
    require(type(rows) is list and rows and all(type(row) is dict and set(row) == {'name', 'expectation', 'passed', 'failed', 'skipped'} for row in rows))
    require(type(diagnostics) is list and len(diagnostics) == len(rows))
    for row, diagnostic in zip(rows, diagnostics):
        require(type(diagnostic) is dict and set(diagnostic) == {'name', 'expectation', 'output', 'stderr'}
                and diagnostic['name'] == row['name'] and diagnostic['expectation'] == row['expectation'] and diagnostic['stderr'] == '')
        failed = expectation == 'all' or row['expectation'] == 'ownership'
        message = ('synthetic-poisoned-observer' if expectation == 'all' else 'dispatch prerequisite or console boundary'
                   if name == 'C2-b-before-writer' else 'exact registered dispatch refusal or no-write boundary')
        anchor = 't.Fatal("' + message + '")'
        line = anchor_line(read(TAGGED_GO), anchor)
        output = diagnostic['output'].splitlines()
        required = ['=== RUN   ' + row['name']]
        if failed: required.append('    runner_admission_tagged_test.go:' + str(line) + ': ' + message)
        require(output[:len(required)] == required and len(output) == len(required) + 2
                and re.fullmatch(r'--- ' + ('FAIL' if failed else 'PASS') + ': ' + row['name'] + r' \([0-9.]+s\)', output[-2]) is not None
                and output[-1] == ('FAIL' if failed else 'PASS'))
        require(row['skipped'] == 0 and [row['passed'], row['failed']] == ([0, 1] if failed else [1, 0]))
    require(expectation == 'all' or {row['expectation'] for row in rows} == {'success', 'ownership'})

def require_restored(rows, expected):
    """Every row of the restored family executed and passed; none was skipped."""
    require(sorted(row['fullName'] for row in rows) == expected and all(row['status'] == 'passed' for row in rows))
    return len(rows)

BASE_STAGES = ('init', 'add', 'source-commit', 'offline-install', 'source-install', 'source-ink', 'bridge-exec-controls',
               *(label for label, _ in BASELINES), 'composition-add', 'composition-commit', 'composition-install', 'composition-ink',
               'composition-observer', 'composition-ordinary', 'composition-library', 'composition-tagged',
               'native-inventory-guard-controls', 'runtime-controls')
GROUP_STAGES = ('add', 'commit', 'install', 'ink', 'observer', 'ordinary', 'library', 'tagged', 'firing-controls',
                'restore-add', 'restore-commit', 'restored-install', 'restored-ink', 'restored-observer', 'restored-ordinary',
                'restored-library', 'restored-tagged', 'restored-controls')
HEX40, HEX64 = r'[0-9a-f]{40}', r'[0-9a-f]{64}'

def require_closed_summary(summary, names):
    """The closed schema, exactly: fixed identifiers, counts, statuses and digests
    of public code and build outputs. Any path, argv, stream or unknown field refuses."""
    def keys(value, expected): require(type(value) is dict and set(value) == set(expected))
    def text(value, pattern): require(type(value) is str and re.fullmatch(pattern, value) is not None)
    def count(value): require(type(value) is int and value >= 0)
    keys(summary, ('schema', 'mode', 'sourceHead', 'sourceTree', 'sourceArchiveSha256', 'composedTree', 'compositionSha256', 'toolchain',
                   'stages', 'buildIdentities', 'suites', 'nativeInventoryControls', 'registeredObservers', 'kernelObservation', 'groups', 'observerPoison', 'runtimeSelection'))
    text(summary['schema'], 'mig01-no-proof-controls-v2'); text(summary['mode'], 'mutations|baseline')
    for key in ('sourceHead', 'sourceTree', 'composedTree'): text(summary[key], HEX40)
    text(summary['sourceArchiveSha256'], HEX64)
    keys(summary['compositionSha256'], ('shell', 'dispatch')); [text(value, HEX64) for value in summary['compositionSha256'].values()]
    keys(summary['toolchain'], ('node', 'go', 'clang')); text(summary['toolchain']['node'], r'v22\.22\.3')
    text(summary['toolchain']['go'], r'go[0-9]+\.[0-9]+(\.[0-9]+)?'); text(summary['toolchain']['clang'], r'clang-[0-9]+(\.[0-9]+)*')
    labels = set(BASE_STAGES) | {name + '-' + suffix for name in names for suffix in GROUP_STAGES}
    require(type(summary['stages']) is list and summary['stages'])
    for stage in summary['stages']:
        keys(stage, ('stage', 'exit')); require(stage['stage'] in labels and type(stage['exit']) is int)
    keys(summary['buildIdentities'], ('source', 'composition'))
    for phase, extra in (('source', ()), ('composition', tuple(ARTIFACTS))):
        identity = summary['buildIdentities'][phase]
        keys(identity, ('fixtureHead', 'privateRunnerProcess', *extra)); text(identity['fixtureHead'], HEX40)
        [text(value, HEX64) for key, value in identity.items() if key != 'fixtureHead']
    require(type(summary['suites']) is list and summary['suites'])
    for suite in summary['suites']:
        keys(suite, ('suite', 'tests', 'passed'))
        require(suite['suite'] in ('bridge-exec-controls', 'runtime-controls', *(label for label, _ in BASELINES)))
        count(suite['tests']); count(suite['passed'])
    selection=summary['runtimeSelection']
    keys(selection, ('class','total','selected','deselected','inventorySha256','sourceSha256','selectedSha256','deselectedSha256'))
    require(selection['class']=='ordinary' and all(type(selection[key]) is int for key in ('total','selected','deselected'))
            and (selection['total'],selection['selected'],selection['deselected'])==(119,115,4))
    for key in ('inventorySha256','sourceSha256','selectedSha256','deselectedSha256'): text(selection[key], HEX64)
    require([suite for suite in summary['suites'] if suite['suite']=='runtime-controls']==[{'suite':'runtime-controls','tests':115,'passed':115}])
    keys(summary['nativeInventoryControls'], ('selected', 'exit')); count(summary['nativeInventoryControls']['selected']); count(summary['nativeInventoryControls']['exit'])
    keys(summary['registeredObservers'], ('rows', 'passed')); count(summary['registeredObservers']['rows']); count(summary['registeredObservers']['passed'])
    kernel = summary['kernelObservation']
    keys(kernel, ('readControls', 'planCaptures', 'requestCaptures', 'planAcquisitions', 'requestAcquisitions', 'observer'))
    keys(kernel['readControls'], ('allow', 'deny', 'aliasAllow', 'aliasDeny')); [count(value) for value in kernel['readControls'].values()]
    [count(kernel[key]) for key in ('planCaptures', 'requestCaptures', 'planAcquisitions', 'requestAcquisitions')]
    keys(kernel['observer'], ('samples', 'observedProcesses', 'fd8PipeProcesses', 'fd8SocketProcesses', 'fd8IdentitiesCompared', 'fd8IdentitiesDifferent',
                              'fd8SourceIdentityMatches', 'sourceDescriptorMatches', 'nullStdioPrivateBridgeProcesses', 'inheritedProverLockBridges', 'observerRefused'))
    for key, value in kernel['observer'].items(): require(type(value) is bool if key == 'observerRefused' else (type(value) is int and value >= 0))
    for field, allowed in (('groups', names[:GROUPS]), ('observerPoison', names[GROUPS:])):
        require(type(summary[field]) is list and [row.get('group') if type(row) is dict else None for row in summary[field]] == list(allowed))
        for row in summary[field]:
            keys(row, ('group', 'family', 'restoredFamily', 'failingRows', 'result', 'firing', 'targetsSha256'))
            count(row['family']); count(row['restoredFamily']); count(row['failingRows'])
            text(row['result'], 'fired-restored|inventoried'); text(row['firing'], 'bound-assertion|bound-refusal|bound-native|not-run')
            keys(row['targetsSha256'], ('original', 'mutated', 'restored')); [text(value, HEX64 + '|not-run') for value in row['targetsSha256'].values()]
            fired = summary['mode'] == 'mutations' or field == 'observerPoison'
            require((row['result'], row['firing'] != 'not-run', row['targetsSha256']['restored'] != 'not-run')
                    == (('fired-restored', True, True) if fired else ('inventoried', False, False)))
            require(not fired or (row['failingRows'] > 0 and row['targetsSha256']['restored'] == row['targetsSha256']['original'] != row['targetsSha256']['mutated']))
    require(not re.search(r'[/\\]|file:|\.\.', json.dumps(summary)))

def closed_summary(state, names):
    """An allowlist projection of the private run state; nothing else is copied."""
    kernel, observer = state['kernel'], state['kernel']['observer']
    summary = {'schema': 'mig01-no-proof-controls-v2', 'mode': state['mode'], 'sourceHead': state['sourceHead'], 'sourceTree': state['sourceTree'],
               'sourceArchiveSha256': state['sourceArchiveSha256'], 'runtimeSelection':state['runtimeSelection'], 'composedTree': state['composedTree'],
               'compositionSha256': {'shell': state['composition'][0], 'dispatch': state['composition'][1]},
               'toolchain': {'node': state['toolchain']['node'], 'go': re.search(r'go[0-9]+\.[0-9]+(\.[0-9]+)?', state['toolchain']['go'])[0],
                             'clang': re.search(r'clang-[0-9]+(\.[0-9]+)*', state['toolchain']['clang'])[0]},
               'stages': [{'stage': stage['label'], 'exit': stage['exit']} for stage in state['stages']],
               'buildIdentities': {phase: dict(identity) for phase, identity in state['identities'].items()},
               'suites': [{'suite': suite['label'], 'tests': len(suite['rows']), 'passed': sum(row['status'] == 'passed' for row in suite['rows'])}
                          for suite in state['suites']],
               'nativeInventoryControls': {'selected': state['native']['selected'], 'exit': state['native']['exit']},
               'registeredObservers': {'rows': len(state['observers']), 'passed': sum(row['passed'] == 1 for row in state['observers'])},
               'kernelObservation': {'readControls': {key: kernel['readControls'][key] for key in ('allow', 'deny', 'aliasAllow', 'aliasDeny')},
                                     **{key: kernel[key] for key in ('planCaptures', 'requestCaptures', 'planAcquisitions', 'requestAcquisitions')},
                                     'observer': {key: observer[key] for key in ('samples', 'observedProcesses', 'fd8PipeProcesses', 'fd8SocketProcesses',
                                         'fd8IdentitiesCompared', 'fd8IdentitiesDifferent', 'fd8SourceIdentityMatches', 'sourceDescriptorMatches',
                                         'nullStdioPrivateBridgeProcesses', 'inheritedProverLockBridges', 'observerRefused')}},
               **{field: [{key: row[key] for key in ('group', 'family', 'restoredFamily', 'failingRows', 'result', 'firing')}
                          | {'targetsSha256': {key: row['targetsSha256'][key] for key in ('original', 'mutated', 'restored')}} for row in state[field]]
                  for field in ('groups', 'observerPoison')}}
    require_closed_summary(summary, names)
    return summary

def _main(argv):
    os.umask(0o077)
    require(len(argv) in (1, 2) and (len(argv) == 1 or argv[1] == '--mutations'))
    mutations = len(argv) == 2
    root = Path(argv[0])
    require(root.is_absolute() and root.resolve() == root and not os.path.lexists(root) and root.parent.is_dir())
    require(subprocess.run(['/usr/bin/git', '-C', str(root.parent), 'rev-parse', '--git-dir'], env=GIT_ENV,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0)
    require(RUNTIME_ENTRY.slot_available())
    # Only fixed entries reach a stage: no caller shell hook, preload or Git redirection.
    env = {'HOME': ACCOUNT.pw_dir, 'USER': ACCOUNT.pw_name, 'LOGNAME': ACCOUNT.pw_name,
           'PATH': str(NODE.parent) + ':/opt/homebrew/bin:/usr/bin:/bin', 'LANG': 'C', 'TMPDIR': '/private/tmp',
           'GOENV': 'off', 'GOFLAGS': '', 'GOPROXY': 'off', 'GOCACHE': str(root / 'go-cache'), 'RAYON_NUM_THREADS': '4', 'CARGO_BUILD_JOBS': '4'}
    state = {'mode': 'mutations' if mutations else 'baseline', 'stages': [], 'suites': [], 'groups': [], 'observerPoison': [],
             'toolchain': {'node': subprocess.check_output([str(NODE), '--version'], env=env).decode().strip(),
                           'go': subprocess.check_output([GO, 'version'], env=env).decode().strip(),
                           'clang': subprocess.check_output(['/usr/bin/clang', '--version'], env=env).decode().splitlines()[0]}}
    require(state['toolchain']['node'] == 'v22.22.3')
    root.mkdir(mode=0o700)
    fixture, raw, artifacts = root / 'fixture-main', root / 'raw', root / 'observation-artifacts'
    for path in (fixture, raw, artifacts): path.mkdir(mode=0o700)
    circuit, reporter = fixture / CIRCUIT, raw / 'firing-reporter.mjs'
    with reporter.open('x') as sink: sink.write(FIRING_REPORTER)
    baseline = {}
    def run(label, args, cwd=fixture, timeout=1800, want=0, extra=None):
        require(RUNTIME_ENTRY.slot_available())
        result = logged_stage(label, args, cwd, dict(env, **(extra or {})), raw / (label + '.log'), timeout)
        state['stages'].append({'label': label, 'exit': result.returncode})
        require(result.returncode == want)
    def read(path):
        return (fixture / path).read_text() if (fixture / path).is_file() else None
    def fixture_git(*args):
        return git_output(fixture, *args).decode().strip()
    def commit(label, paths, message, allow_empty=False):
        run(label + '-add', ['/usr/bin/git', 'add', '--', *paths])
        run(label + '-commit', [*COMMIT[:-1], '--allow-empty', COMMIT[-1], message] if allow_empty else [*COMMIT, message])
    def build(label, observation=True):
        run(label + '-install', ['/usr/bin/python3', 'tools/pool-action-modules/private-runner-installation.py', '--build'])
        run(label + '-ink', [str(PNPM), '--filter', '@bch-cloak/pool-wallet-ink', 'build'])
        if observation:
            run(label + '-observer', ['/usr/bin/clang', '-O2', '-Wall', '-Wextra', '-Werror', 'scripts/mig01-macos-observer.c', '-lproc', '-o', str(artifacts / 'macos-observer')], circuit)
            run(label + '-ordinary', [GO, 'build', '-tags=', '-o', str(artifacts / 'ordinary-pool-pk-load'), './cmd/pool-pk-load'], circuit)
            run(label + '-library', [GO, 'build', '-tags=', '-o', str(artifacts / 'ordinary-library-probe'), 'scripts/mig01-library-probe.go'], circuit)
            run(label + '-tagged', [GO, 'test', '-c', '-tags=private_runner_admission_test', '-o', str(artifacts / 'tagged-dispatch.test'), './cmd/pool-pk-load'], circuit)
    def build_identity(observation):
        # Fresh outputs are bound to the exact fixture commit they were built from.
        record = json.loads((fixture / 'tools/pool-action-modules/dist/private-runner-installation.json').read_bytes())
        require(record['revision'] == fixture_git('rev-parse', 'HEAD'))
        identity = {'fixtureHead': record['revision'],
                    'privateRunnerProcess': digest((fixture / 'tools/pool-action-modules/dist/private-runner-process').read_bytes())}
        if observation:
            identity.update({key: digest((artifacts / name).read_bytes()) for key, name in ARTIFACTS.items()})
        return identity
    def vitest(label, files, selection=None, want=0, failures=False):
        directory = suite_directory(files[0])
        require(all(suite_directory(path) == directory for path in files))
        output, report = raw / (label + '.json'), raw / (label + '.failures.json')
        args = [str(PNPM), 'exec', 'vitest', 'run', *(path[len(directory) + 1:] if directory else path for path in files),
                '--maxWorkers=1', '--minWorkers=1', '--testTimeout=30000', '--reporter=json', '--outputFile=' + str(output)]
        if failures: args.append('--reporter=' + str(reporter))
        run(label, args + (['-t', selection] if selection is not None else []), fixture / directory, want=want,
            extra={'MIG01_FIRING_REPORT': str(report)} if failures else None)
        result = json.loads(output.read_bytes())
        found = None
        if failures:
            found = json.loads(report.read_bytes())
            require(type(found) is dict and set(found) == {'schema', 'failures'} and found['schema'] == 'mig01-firing-failures-v1')
            found = found['failures']
        return result, vitest_rows(result, fixture), found
    def go_control(label, selection, want=0, timeout=180):
        run(label, [GO, 'test', '-json', '-tags=', './internal/runneradmission', '-run', selection, '-count=1'], circuit, timeout, want)
        return go_rows((raw / (label + '.log')).read_bytes())
    def baseline_suite(label, files):
        report, executed, _ = vitest(label, list(files))
        rows = [row for file_rows in executed.values() for row in file_rows]
        require(report['success'] is True and report['numFailedTestSuites'] == 0 and report['numPendingTests'] == 0
                and sorted(executed) == sorted(files) and rows and all(row['status'] == 'passed' for row in rows))
        for path, file_rows in executed.items():
            baseline[path] = sorted(row['fullName'] for row in file_rows)
        state['suites'].append({'label': label, 'rows': rows})
    def selected_rows(selected, report_rows):
        if selected == GO_EXEC: return report_rows
        require(set(report_rows) <= {selected})
        return report_rows.get(selected, [])
    def observers():
        return json.loads((artifacts / 'registered-observers.json').read_bytes())

    # ---- the exact source tree: production selectors are fixed at generation 2 ----
    source_head, _inventory, state['sourceArchiveSha256'] = source_fixture(REPO, fixture)
    run('init', ['/usr/bin/git', 'init', '-b', 'main'])
    run('add', ['/usr/bin/git', 'add', '--force', '.'])
    run('source-commit', [*COMMIT, 'Disposable MIG01 no-proof source fixture'])
    verify_source_tree(REPO, fixture, source_head)
    state['sourceHead'], state['sourceTree'] = source_head, fixture_git('rev-parse', 'HEAD^{tree}')
    run('offline-install', [str(PNPM), 'install', '--offline', '--frozen-lockfile', '--ignore-scripts', '--store-dir', str((REPO / '.pnpm-store').resolve())])
    build('source', observation=False)
    state['identities'] = {'source': build_identity(False)}
    native_rows = go_control('bridge-exec-controls', 'TestMIG01(ActualExec|R3Private)', timeout=1800)
    require(native_rows and all(row['status'] == 'passed' and not row['fatal'] for row in native_rows))
    baseline[GO_EXEC] = sorted(row['fullName'] for row in native_rows)
    state['suites'].append({'label': 'bridge-exec-controls', 'rows': native_rows})
    for label, files in BASELINES:
        baseline_suite(label, files)
    require(fixture_git('status', '--porcelain') == '' and fixture_git('rev-parse', 'HEAD^{tree}') == state['sourceTree'])

    # ---- private test composition, verified in place (empty commit): the runtime entry's controls, exactly one runtime baseline ----
    composed = compose(fixture)
    commit('composition', composed, 'Disposable MIG01 private test composition', allow_empty=True)
    composed_tree = state['composedTree'] = fixture_git('rev-parse', 'HEAD^{tree}')
    require(fixture_git('diff', '--name-only', 'HEAD~1', 'HEAD') == '' and composed_tree == state['sourceTree'])
    state['composition'] = [digest((fixture / path).read_bytes()) for path in composed]
    build('composition')
    state['identities']['composition'] = build_identity(True)
    env['MIG01_TEST_OUTPUT_ROOT'] = str(artifacts)
    command = RUNTIME_ENTRY.native_control_command()
    run('native-inventory-guard-controls', command)
    state['native'] = {'selected': len(command) - 3, 'exit': 0}
    env['MIG01_RUNTIME_SELECTION']=RUNTIME_SELECTION
    report, executed, _ = vitest('runtime-controls', [RUNTIME], RUNTIME_ENTRY.runtime_pattern(RUNTIME_SELECTION))
    state['runtimeSelection']=RUNTIME_ENTRY.require_runtime_selection(report,RUNTIME_SELECTION)
    runtime_rows = executed.get(RUNTIME, [])
    require(report['success'] is True and report['numFailedTestSuites'] == 0 and report['numPendingTests'] == 4 and sorted(executed) == [RUNTIME]
            and len(runtime_rows) == RUNTIME_ROWS and all(row['status'] == 'passed' for row in runtime_rows))
    baseline[RUNTIME] = sorted(row['fullName'] for row in runtime_rows)
    state['suites'].append({'label': 'runtime-controls', 'rows': runtime_rows})
    state['observers'] = observers()
    require(type(state['observers']) is list and len(state['observers']) == OBSERVER_ROWS
            and all(type(row) is dict and [row.get('passed'), row.get('failed'), row.get('skipped')] == [1, 0, 0] for row in state['observers']))
    state['kernel'] = json.loads((artifacts / 'kernel-closed.json').read_bytes())
    require(type(state['kernel']) is dict and state['kernel'].get('schema') == 'mig01-kernel-observer-v1')

    # ---- the 42-group inventory and its bindings, measured against the composed tree ----
    groups = mutation_groups(read(SHELL))
    resource=set(RUNTIME_ENTRY.runtime_titles('resource'))
    require(all(not resource.intersection(family(baseline[RUNTIME],selection)) for _,selected,_,selection in groups if selected==RUNTIME))
    require_inventory(groups)
    require_targets(read, (*groups, *POISON))
    require_bindings(read, groups)
    def restored_selection(name, selection):
        return selection + '|PH02 genuine owner prepare' if name == 'H1-epoch-binding' else selection
    def mutate(name, selected, edits, selection):
        native = selected == GO_EXEC
        expected, expected_restored = family(baseline[selected], selection), family(baseline[selected], restored_selection(name, selection))
        require(name != 'H1-epoch-binding' or len(expected_restored) == 2)
        require_regular(fixture, [path for path, _, _ in edits])
        originals = {path: (fixture / path).read_bytes() for path, _, _ in edits}
        targets = lambda: digest(''.join(digest((fixture / path).read_bytes()) for path in sorted(originals)).encode())
        record = {'group': name, 'family': len(expected), 'restoredFamily': len(expected_restored), 'result': 'fired-restored',
                  'targetsSha256': {'original': targets()}}
        committed = False
        journal = STAGE_SCOPE.remember(fixture, originals) if STAGE_SCOPE is not None else None
        try:
            for path, before, after in edits:
                text = (fixture / path).read_text(); require(text.count(before) == 1)
                (fixture / path).write_text(text.replace(before, after))
            commit(name, list(originals), name)
            committed = True
            record['targetsSha256']['mutated'] = targets()
            build(name)
            build_identity(True)
            if native:
                fired, failures = go_control(name + '-firing-controls', selection, want=1), None
            else:
                # The observer record must come from this firing run, never an earlier one.
                for sidecar in (['inbox-writer-observations.json'] if name == 'C1-inbox-writer' else
                                ['registered-observers.json'] if FIRING[name]['observers'] is not None else []):
                    if os.path.lexists(artifacts / sidecar):
                        require(stat.S_ISREG(os.lstat(artifacts / sidecar).st_mode))
                        (artifacts / sidecar).unlink()
                _, found, failures = vitest(name + '-firing-controls', [selected], selection, want=1, failures=True)
                fired = selected_rows(selected, found)
            record['firing'] = require_bound_firing(name, fired, expected, selection, failures, read, fixture, selected,
                inbox=json.loads((artifacts / 'inbox-writer-observations.json').read_bytes()) if name == 'C1-inbox-writer' else None)
            record['failingRows'] = sum(row['status'] == 'failed' for row in fired)
            if FIRING[name]['observers'] is not None:
                require_observer_rows(observers(), FIRING[name]['observers'],
                    json.loads((artifacts / 'registered-observer-diagnostics.json').read_bytes()), read, name)
        finally:
            if journal is not None:
                STAGE_SCOPE.restore(journal)
            else:
                for path, content in originals.items(): (fixture / path).write_bytes(content)
            # Aborted fixtures regain their source bytes, but cannot certify a
            # restored build. Never start another expensive stage after cancel.
            if not aborting():
                if committed: commit(name + '-restore', list(originals), 'Restore ' + name)
                require(fixture_git('rev-parse', 'HEAD^{tree}') == composed_tree and fixture_git('status', '--porcelain') == '')
                if committed:
                    build(name + '-restored')
                    build_identity(True)
        if native:
            restored = go_control(name + '-restored-controls', restored_selection(name, selection))
            require(all(not row['fatal'] for row in restored))
        else:
            restored = selected_rows(selected, vitest(name + '-restored-controls', [selected], restored_selection(name, selection))[1])
        require_restored(restored, expected_restored)
        record['targetsSha256']['restored'] = targets()
        require(record['targetsSha256']['restored'] == record['targetsSha256']['original'])
        return record
    for name, selected, edits, selection in POISON:
        with mutation_progress(name):
            state['observerPoison'].append(mutate(name, selected, edits, selection))
    for name, selected, edits, selection in groups:
        if mutations:
            with mutation_progress(name):
                state['groups'].append(mutate(name, selected, edits, selection))
        else:
            state['groups'].append({'group': name, 'family': len(family(baseline[selected], selection)),
                                    'restoredFamily': len(family(baseline[selected], restored_selection(name, selection))), 'failingRows': 0,
                                    'result': 'inventoried', 'firing': 'not-run', 'targetsSha256': dict.fromkeys(('original', 'mutated', 'restored'), 'not-run')})
    require([row['group'] for row in state['groups']] == [group[0] for group in groups])

    # Cleanup is complete: every mutation restored and rebuilt, every stage
    # group reaped. Only now is the one closed summary written.
    require(fixture_git('rev-parse', 'HEAD^{tree}') == composed_tree and fixture_git('status', '--porcelain') == '')
    if STAGE_SCOPE is not None: STAGE_SCOPE.check()
    summary = closed_summary(state, [group[0] for group in (*groups, *POISON)])
    started = time.monotonic()
    with (root / 'closed-summary.json').open('x') as sink:
        sink.write(json.dumps(summary, sort_keys=True, indent=2) + '\n')
    progress('closed-summary', 0, time.monotonic() - started)

def main(argv):
    require(argv.count('--runtime-selection=ordinary')<=1)
    argv=[arg for arg in argv if arg!='--runtime-selection=ordinary']
    require(len(argv) in (1, 2))
    with LIFECYCLE.inherited_scope(Path(argv[0])) as scope, stage_scope(scope):
        _main(argv)

if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (Exception, LIFECYCLE.Cancelled, LIFECYCLE.CleanupRefused):
        print('MIG01 no-proof controls FAIL; inspect locally without printing raw private inputs', file=sys.stderr)
        sys.exit(1)
