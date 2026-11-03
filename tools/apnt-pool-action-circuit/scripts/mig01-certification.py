#!/usr/bin/python3
"""Bounded MIG01 certification: fixed --vd, or the retained aggregate C1 recipe.

The sealed LANE_VALIDATE command runs this helper with --pre-slot after legacy
prepare, then runs it again inside the existing test-slot wrapper, with the
SAME new absolute ROOT, --expected-head H and --expected-base B. Add --vd for VD;
omit it for aggregate C1. The ordinary mutation baseline is followed by one
separate resource entry through the supported shared-slot wrapper.
See the recipe decision/report for the exact operator command and admission.
"""
import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[3]
MODULES = 'pnpm validate:pool-action-modules'
ENTRY = 'python3 tools/apnt-pool-action-circuit/scripts/test-private-runner-runtime-no-proof.py'
RESOURCE = 'node scripts/test-slot/test-slot.mjs run validate:pool-action-modules:resource -- python3 tools/apnt-pool-action-circuit/scripts/test-private-runner-runtime-resource.py'
VD_GATES = ('validate:build', 'validate:pool-action-circuit', 'validate:pool-wallet-host', 'validate:pool-wallet-ink')
EXECUTION_SECONDS, TEARDOWN_SECONDS = 14400, 120
STAGE_SECONDS = 1800
SLOT = Path('/private/tmp/bch-cloak-test-slot.lock')
spec = importlib.util.spec_from_file_location('mig01_driver', Path(__file__).with_name('test-live-entry-no-proof.py'))
DRIVER = importlib.util.module_from_spec(spec); spec.loader.exec_module(DRIVER)
require = DRIVER.require


def dependent_typechecks(repo):
    # The reviewed workspace is exactly packages/*. A new workspace layout or
    # an affected dependent without a typecheck requires explicit recipe review.
    require((repo / 'pnpm-workspace.yaml').read_text().strip() == 'packages:\n  - "packages/*"')
    affected = {'@bch-cloak/pool-wallet-host', '@bch-cloak/pool-wallet-ink'}
    commands = []
    for path in sorted((repo / 'packages').glob('*/package.json')):
        package = json.loads(path.read_bytes())
        dependencies = {name for field in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies')
                        for name in package.get(field, {})}
        if package['name'] not in affected and dependencies & affected:
            require(re.fullmatch(r'@bch-cloak/[a-z0-9-]+', package['name']) is not None and package.get('scripts', {}).get('typecheck'))
            commands.append('pnpm --filter ' + package['name'] + ' typecheck')
    return commands


def recipe(scripts, vd=False, dependents=()):
    modules = scripts['validate:pool-action-modules'].split(' && ')
    require(modules[-1] == ENTRY and modules.count(ENTRY) == 1 and 'mig01-producers.test.ts' in modules[-2]
            and not any('test-live-entry-no-proof' in step for step in modules))
    require(scripts.get('validate:pool-action-modules:resource')==RESOURCE)
    if vd:
        require(all(type(scripts.get(key)) is str and scripts[key] for key in VD_GATES))
        steps = ['pnpm ' + key for key in VD_GATES] + list(dependents) + [MODULES]
    else:
        steps = scripts['validate:all-safe:steps'].split(' && ')
        require(steps.count(MODULES) == 1 and all(re.fullmatch(r'pnpm (?:validate|test):[a-z0-9-]+', step) for step in steps))
    plan = []
    for step in steps:
        plan += ([('gate', item) for item in modules[:-1]] + [('rollback-oracle', None), ('mutation-driver', None), ('resource-controls', None)]
                 if step == MODULES else [('gate', step)])
    return plan


def binding(repo, head, base):
    require(all(re.fullmatch(DRIVER.HEX40, value) is not None for value in (head, base)))
    require(DRIVER.git_output(repo, 'rev-parse', 'HEAD', timeout=10).decode().strip() == head
            and DRIVER.git_output(repo, 'rev-parse', 'refs/heads/main', timeout=10).decode().strip() == base
            and DRIVER.git_output(repo, 'merge-base', base, head, timeout=10).decode().strip() == base
            and DRIVER.git_output(repo, 'status', '--porcelain', timeout=10) == b'')
    require(subprocess.run(['/usr/bin/git', '-C', str(repo), 'diff', '--check', base, head], env=DRIVER.GIT_ENV,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode == 0)


def toolchain(repo):
    require((repo / '.nvmrc').read_text().strip() == '22.22.3'
            and Path(shutil.which('node')).resolve() == DRIVER.NODE.resolve()
            and Path(shutil.which('pnpm')).resolve() == DRIVER.PNPM.resolve())
    require(subprocess.check_output(['node', '-v'], timeout=10).strip() == b'v22.22.3')
    package = json.loads((repo / 'package.json').read_bytes())['packageManager']
    require(package.startswith('pnpm@') and subprocess.check_output(['pnpm', '--version'], timeout=10).decode().strip() == package[5:])


def memory_admission(repo):
    # Invoke ONLY the existing free+inactive+speculative formula, not the runner.
    source = (repo / DRIVER.SHELL).read_text()
    start, end = 'available_bytes() {\n', '\n}\n\nswap_used_bytes() {'
    require(source.count(start) == 1 and source.count(end) == 1)
    body = source[source.index(start):source.index(end) + 2]
    value = subprocess.check_output(['/bin/bash', '-c', 'set -euo pipefail\n' + body + '\navailable_bytes'],
                                    env=DRIVER.GIT_ENV, stderr=subprocess.DEVNULL, timeout=10).strip()
    require(re.fullmatch(rb'[0-9]+', value) is not None and int(value) >= 20 * 1024**3)


def granted_deadline(lock=SLOT):
    # No free-slot admission here. The existing holder's actual grant is the
    # clock origin, including inherited nested-slot execution. Never print it.
    require(DRIVER.RUNTIME_ENTRY.slot_available(str(lock)))
    with os.fdopen(os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 65536)
        holder = json.load(source)
    require(os.environ.get('BCH_CLOAK_TEST_SLOT_TOKEN') and holder.get('token') == os.environ['BCH_CLOAK_TEST_SLOT_TOKEN']
            and type(holder.get('pid')) is int and holder['pid'] > 1)
    os.kill(holder['pid'], 0)
    granted = datetime.fromisoformat(holder['acquiredAt'].replace('Z', '+00:00'))
    require(granted.tzinfo is not None)
    elapsed = time.time() - granted.timestamp()
    require(0 <= elapsed < EXECUTION_SECONDS)
    return time.monotonic() + EXECUTION_SECONDS - elapsed


def require_record(record, plan=None):
    require(type(record) is dict and set(record) == {'schema', 'mode', 'sourceHead', 'sourceBase', 'executionSeconds', 'teardownSeconds', 'runtimeBaselines', 'resourceControls', 'steps'}
            and record['schema'] == 'mig01-certification-v3' and record['mode'] in ('vd', 'aggregate')
            and all(re.fullmatch(DRIVER.HEX40, record[key]) is not None for key in ('sourceHead', 'sourceBase'))
            and record['executionSeconds'] == EXECUTION_SECONDS and record['teardownSeconds'] == TEARDOWN_SECONDS
            and type(record['runtimeBaselines']) is int and record['runtimeBaselines'] == 1 and type(record['steps']) is list)
    for index, row in enumerate(record['steps']):
        require(type(row) is dict and set(row) == {'step', 'kind', 'commandSha256', 'exit'} and type(row['step']) is int and row['step'] == index
                and row['kind'] in ('gate', 'rollback-oracle', 'mutation-driver', 'resource-controls') and type(row['exit']) is int and row['exit'] == 0
                and (type(row['commandSha256']) is str and re.fullmatch(DRIVER.HEX64, row['commandSha256']) is not None
                     if row['kind'] == 'gate' else row['commandSha256'] is None))
    kinds = [row['kind'] for row in record['steps']]
    require('mutation-driver' in kinds and kinds.index('mutation-driver') > 0
            and kinds[kinds.index('mutation-driver') - 1] == 'rollback-oracle'
            and kinds[kinds.index('mutation-driver') + 1:kinds.index('mutation-driver') + 2] == ['resource-controls']
            and (record['mode'] != 'vd' or kinds[-3:] == ['rollback-oracle', 'mutation-driver', 'resource-controls'])
            and sum(row['kind'] == 'mutation-driver' for row in record['steps']) == 1
            and sum(row['kind'] == 'rollback-oracle' for row in record['steps']) == 1
            and sum(row['kind'] == 'resource-controls' for row in record['steps']) == 1)
    DRIVER.RUNTIME_ENTRY.require_resource_receipt(record['resourceControls'],record['sourceHead'])
    if plan is not None:
        require([(row['kind'], row['commandSha256']) for row in record['steps']] ==
                [(kind, hashlib.sha256(step.encode()).hexdigest() if step else None) for kind, step in plan])


def run_recipe(root, head, base, plan, vd, deadline):
    root.mkdir(mode=0o700)
    scope = DRIVER.LIFECYCLE.Scope(root / 'stage-state', deadline, owner=True)
    output = root / 'certification-record.json'
    record = []
    try:
        with DRIVER.stage_scope(scope):
            for index, (kind, step) in enumerate(plan):
                scope.check()
                binding(REPO, head, base)
                command = (['/bin/bash', '-c', step] if kind == 'gate' else
                           ['python3', 'tools/pool-action-modules/test/restore-reservation-oracles.py', str(root / 'rollback-oracle'), '--expected-head', head]
                           if kind == 'rollback-oracle' else
                           ['pnpm','validate:pool-action-modules:resource',str(root/'resource-controls')]
                           if kind == 'resource-controls' else ['python3', DRIVER.__file__, str(root / 'mutation-driver'), '--runtime-selection=ordinary', '--mutations'])
                limit = scope.deadline - time.monotonic() if kind == 'mutation-driver' else STAGE_SECONDS
                result = DRIVER.logged_stage('step-%03d' % index, command, REPO, dict(os.environ), root / ('step-%03d.log' % index),
                                             limit, child_umask=0o022 if kind == 'gate' else 0o077, cooperative=kind != 'gate')
                record.append({'step': index, 'kind': kind, 'commandSha256': hashlib.sha256(step.encode()).hexdigest() if step else None, 'exit': result.returncode})
                require(result.returncode == 0)
            binding(REPO, head, base)
            scope.check()
            summary = json.loads((root / 'mutation-driver' / 'closed-summary.json').read_bytes())
            names = [group[0] for group in DRIVER.mutation_groups((REPO / DRIVER.SHELL).read_text())] + [group[0] for group in DRIVER.POISON]
            DRIVER.require_closed_summary(summary, names)
            require(summary['mode'] == 'mutations' and summary['sourceHead'] == head
                    and summary['runtimeSelection']['class']=='ordinary' and summary['runtimeSelection']['selected']==115)
            resource=json.loads((root/'resource-controls'/'resource-receipt.json').read_bytes())
            DRIVER.RUNTIME_ENTRY.require_resource_receipt(resource,head)
            require(resource['sourceTree']==summary['sourceTree']
                    and all(resource['selection'][key]==summary['runtimeSelection'][key] for key in ('inventorySha256','sourceSha256'))
                    and resource['selection']['selectedSha256']==summary['runtimeSelection']['deselectedSha256']
                    and resource['selection']['deselectedSha256']==summary['runtimeSelection']['selectedSha256'])
            closed = {'schema': 'mig01-certification-v3', 'mode': 'vd' if vd else 'aggregate', 'sourceHead': head, 'sourceBase': base,
                      'executionSeconds': EXECUTION_SECONDS, 'teardownSeconds': TEARDOWN_SECONDS, 'runtimeBaselines': 1,
                      'resourceControls':resource,'steps': record}
            require_record(closed, plan)
            require(not list(scope.directory.glob('group-*')) and not list(scope.directory.glob('restore-*')))
            scope.check()
            DRIVER.LIFECYCLE.private_write(output, (json.dumps(closed, indent=2) + '\n').encode())
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def main(argv):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--vd', action='store_true')
    parser.add_argument('--pre-slot', action='store_true')
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-base', required=True)
    args = parser.parse_args(argv)
    root = args.root
    require(root.is_absolute() and root.resolve() == root and not os.path.lexists(root) and root.parent.is_dir())
    require(subprocess.run(['/usr/bin/git', '-C', str(root.parent), 'rev-parse', '--git-dir'], env=DRIVER.GIT_ENV,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode != 0)
    binding(REPO, args.expected_head, args.expected_base)
    deadline = None if args.pre_slot else granted_deadline()
    toolchain(REPO)
    memory_admission(REPO)
    if args.pre_slot:
        print('mig01-pre-slot-binding-and-admission PASS', flush=True)
        return
    plan = recipe(json.loads((REPO / 'package.json').read_bytes())['scripts'], args.vd, dependent_typechecks(REPO) if args.vd else ())
    run_recipe(root, args.expected_head, args.expected_base, plan, args.vd, deadline)

if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (Exception, DRIVER.LIFECYCLE.Cancelled, DRIVER.LIFECYCLE.CleanupRefused):
        print('MIG01 certification recipe FAIL; inspect locally without printing raw private inputs', file=sys.stderr)
        sys.exit(1)
