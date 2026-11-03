#!/usr/bin/env python3
"""Print candidate settings or supervise ONE execute-only measurement (never prove)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import time

MARKER = Path('/private/tmp/bch-cloak-sp1-prover-exclusive-v1')
GIB = 1024**3
WORKSPACE = Path(__file__).resolve().parent
REMOVED = ('SHARD_BATCH_SIZE', 'SHARD_CHUNKING_MULTIPLIER', 'RECONSTRUCT_COMMITMENTS',
           'SP1_DUMP', 'SP1_RECORD_WRITE_DIR', 'SP1_RECORD_WRITE_FREQUENCY',
           'SP1_RECORD_MAX_ARITY_INPUT', 'SP1_RECORD_SHRINK_INPUT', 'GOMEMLIMIT')


def profile(name):
    values = {
        'RAYON_NUM_THREADS': '4', 'CARGO_BUILD_JOBS': '4', 'GOMAXPROCS': '4',
        'SP1_PROVER': 'cpu', 'SP1_WORKER_VERIFY_INTERMEDIATES': 'true',
        'APNT_SP1_STAGE_LOG': '1',
        'RUST_LOG': 'off,sp1_prover::worker=debug,sp1_sdk::cpu=info', 'RUST_LOGGER': 'flat',
        'SP1_WORKER_USE_FIXED_PK': 'false',
        'SP1_WORKER_MAX_REDUCE_ARITY': '4', 'SP1_WORKER_MAX_COMPOSE_ARITY': '4',
        'SHARD_SIZE': '1048576', 'ELEMENT_THRESHOLD': '100663296',
        'HEIGHT_THRESHOLD': '1048576', 'MINIMAL_TRACE_CHUNK_THRESHOLD': '4194304',
        'TRACE_CHUNK_SLOTS': '2', 'MEMORY_LIMIT': str(24 * GIB),
    }
    for suffix in (
        'NUM_SPLICING_WORKERS', 'SPLICING_BUFFER_SIZE',
        'NUMBER_OF_SEND_SPLICE_WORKERS_PER_SPLICE', 'SEND_SPLICE_INPUT_BUFFER_SIZE_PER_SPLICE',
        'NUM_CORE_WORKERS', 'CORE_BUFFER_SIZE', 'NUM_SETUP_WORKERS', 'SETUP_BUFFER_SIZE',
        'NORMALIZE_PROGRAM_CACHE_SIZE', 'NUM_PREPARE_REDUCE_WORKERS', 'PREPARE_REDUCE_BUFFER_SIZE',
        'NUM_RECURSION_EXECUTOR_WORKERS', 'RECURSION_EXECUTOR_BUFFER_SIZE',
        'NUM_RECURSION_PROVER_WORKERS', 'RECURSION_PROVER_BUFFER_SIZE',
        'NUM_DEFERRED_WORKERS', 'DEFERRED_BUFFER_SIZE',
    ):
        values['SP1_WORKER_' + suffix] = '1'
    values['SP1_WORKER_GLOBAL_MEMORY_BUFFER_SIZE'] = '2'
    if name == 'm2':
        values.update(SHARD_SIZE='524288', ELEMENT_THRESHOLD='50331648',
                      HEIGHT_THRESHOLD='524288', MINIMAL_TRACE_CHUNK_THRESHOLD='2097152')
    elif name == 'm3':
        values.update(RAYON_NUM_THREADS='2', GOMAXPROCS='2')
    elif name != 'm1':
        raise ValueError('unknown-profile')
    return values


def memory():
    vm = subprocess.check_output(['/usr/bin/vm_stat'], text=True)
    page_size = int(re.search(r'page size of (\d+) bytes', vm)[1])
    pages = sum(int(re.search(r'^Pages ' + field + r':\s*(\d+)', vm, re.M)[1])
                for field in ('free', 'inactive', 'speculative', 'purgeable'))
    swap = subprocess.check_output(['/usr/sbin/sysctl', '-n', 'vm.swapusage'], text=True)
    match = re.search(r'used\s*=\s*([\d.]+)([KMG])', swap)
    return pages * page_size, int(float(match[1]) * {'K': 1024, 'M': 1024**2, 'G': GIB}[match[2]])


def stop(process):
    # This tool creates this group; never signal a supervisor or an unrelated process.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    # A leader can exit on TERM while a descendant ignores it. Kill the owned
    # group even when wait() already returned; leader exit is not group exit.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run(binary, output, settings, seconds=55):
    if MARKER.exists() or MARKER.is_symlink():
        raise RuntimeError('exclusive-prover-marker-present')
    available, baseline = memory()
    if available < 20 * GIB:
        raise RuntimeError('below-20-gib-admission-floor')
    output.mkdir(mode=0o700)  # Refuse replacement of any previous evidence.
    env = os.environ.copy()
    for key in REMOVED:
        env.pop(key, None)
    env.update(settings)
    # Only the measurement example's execute-a subcommand is callable here.
    started = time.monotonic()
    samples = []
    reason = None
    stopping_signal = None
    previous_handlers = {}
    process = None

    def request_stop(signum, _frame):
        nonlocal stopping_signal
        # Do not raise inside Popen: cleanup needs the returned process handle.
        if stopping_signal is None:
            stopping_signal = signum

    try:
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            previous_handlers[signum] = signal.signal(signum, request_stop)
        with (output / 'events.jsonl').open('x') as events, (output / 'stderr.log').open('x') as errors:
            process = subprocess.Popen(['/usr/bin/nice', '-n', '10', str(binary.resolve()), 'execute-a'],
                                       cwd=WORKSPACE, env=env, stdout=events, stderr=errors,
                                       start_new_session=True)
            try:
                while process.poll() is None:
                    if stopping_signal is not None:
                        reason = f'signal-{stopping_signal}'
                        break
                    elapsed = time.monotonic() - started
                    if elapsed >= seconds:
                        reason = '55-second-execute-budget'
                        break
                    if MARKER.exists() or MARKER.is_symlink():
                        reason = 'exclusive-prover-marker-appeared'
                        break
                    _, swap = memory()
                    rss = subprocess.run(['/bin/ps', '-o', 'rss=', '-p', str(process.pid)],
                                         text=True, capture_output=True)
                    if rss.returncode and process.poll() is not None:
                        break
                    if rss.returncode or not rss.stdout.strip():
                        raise RuntimeError('rss-measurement-failed')
                    rss_bytes = int(rss.stdout.strip()) * 1024
                    samples.append({'elapsedSeconds': elapsed, 'rssBytes': rss_bytes, 'swapUsedBytes': swap})
                    # Research-only ceilings; the production supervisor guards are untouched.
                    if rss_bytes >= 8 * GIB:
                        reason = '8-gib-execute-rss-trip'
                        break
                    if swap - baseline > GIB:
                        reason = '1-gib-execute-swap-growth-trip'
                        break
                    time.sleep(min(1, max(0, seconds - (time.monotonic() - started))))
            finally:
                stop(process)
                if stopping_signal is not None:
                    reason = f'signal-{stopping_signal}'
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    rows = [json.loads(line) for line in (output / 'events.jsonl').read_text().splitlines()]
    completed = [row for row in rows if row.get('kind') == 'completed']
    success = reason is None and process.returncode == 0 and len(completed) == 1
    record = {'schema': 'aggregate-memory-execute-v1', 'settings': settings,
              'binarySha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'elapsedSeconds': time.monotonic() - started, 'rawExitCode': process.returncode,
              'complete': success, 'stopReason': reason, 'swapBaselineBytes': baseline,
              'sampledPeakRssBytes': max((x['rssBytes'] for x in samples), default=0),
              'sampledPeakSwapBytes': max([baseline] + [x['swapUsedBytes'] for x in samples]),
              'samples': samples, 'setupCalled': False, 'proveCalled': False}
    (output / 'observation.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: v for k, v in record.items() if k != 'samples'}))
    return 0 if success else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    for mode in ('env', 'json'):
        p = sub.add_parser(mode)
        p.add_argument('profile', choices=('m1', 'm2', 'm3'))
    p = sub.add_parser('execute')
    p.add_argument('profile', choices=('m1', 'm2'))
    p.add_argument('binary', type=Path)
    p.add_argument('output', type=Path)
    args = parser.parse_args()
    settings = profile(args.profile)
    if args.mode == 'env':
        print('unset ' + ' '.join(REMOVED))
        for key, value in settings.items():
            print('export ' + key + '=' + shlex.quote(value))
    elif args.mode == 'json':
        print(json.dumps(settings, indent=2))
    else:
        os.umask(0o077)
        raise SystemExit(run(args.binary, args.output, settings))


if __name__ == '__main__':
    main()
