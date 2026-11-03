#!/usr/bin/python3
"""Deterministic recipe/lifecycle controls; no real slot, memory probe or runtime."""
from contextlib import redirect_stdout
import copy
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('certification', SCRIPTS / 'mig01-certification.py')
cert = importlib.util.module_from_spec(spec); spec.loader.exec_module(cert)
driver, life = cert.DRIVER, cert.DRIVER.LIFECYCLE

class RecipeControls(unittest.TestCase):
    def resource_fixture(self, head='a'*40):
        runtime=driver.RUNTIME_ENTRY
        def selection(kind):
            selected=set(runtime.runtime_titles(kind))
            return runtime.require_runtime_selection({'testResults':[{'assertionResults':[
                {'fullName':title,'status':'passed' if title in selected else 'pending'} for title in runtime.runtime_titles('union')]}],
                'numPassedTests':len(selected),'numFailedTests':0,'numPendingTests':119-len(selected),'success':True},kind)
        resource={'schema':'mig01-resource-controls-v1','sourceHead':head,'sourceTree':'2'*40,'fixtureHead':'3'*40,
            'selection':selection('resource'),'buildIdentities':dict.fromkeys(('process','installation','native'),'a'*64),
            'cases':[{'title':title,'stop':'open' if 'valid prove failure' in title else 'W-expiry','stockNativeSha256':'b'*64}
                for title in runtime.runtime_titles('resource')]}
        return resource,selection('ordinary')

    def test_fixed_vd_and_aggregate_expansions(self):
        scripts = json.loads((cert.REPO / 'package.json').read_bytes())['scripts']
        modules = scripts['validate:pool-action-modules'].split(' && ')
        plan = cert.recipe(scripts, True)
        self.assertEqual(plan, [('gate', 'pnpm ' + key) for key in cert.VD_GATES] +
                         [('gate', step) for step in modules[:-1]] + [('rollback-oracle', None), ('mutation-driver', None), ('resource-controls', None)])
        self.assertIn('mig01-producers.test.ts', plan[-4][1])
        self.assertEqual(sum('restore-reservation-oracles.py --self-test' in (step or '') for _, step in plan), 1)
        self.assertFalse(any(cert.ENTRY == step for _, step in plan))
        self.assertEqual(sum(kind == 'mutation-driver' for kind, _ in plan), 1)
        self.assertEqual(cert.dependent_typechecks(cert.REPO), [])
        self.assertGreater(len(cert.recipe(scripts)), len(plan))
        for bad in (modules + [cert.ENTRY], modules[:-1], [cert.ENTRY] + modules):
            with self.assertRaises(RuntimeError): cert.recipe({**scripts, 'validate:pool-action-modules': ' && '.join(bad)}, True)
        for bad in ('',cert.ENTRY,cert.RESOURCE+' --bypass'):
            with self.assertRaises(RuntimeError):cert.recipe({**scripts,'validate:pool-action-modules:resource':bad},True)

    def test_direct_dependent_typechecks_are_derived_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'packages/consumer').mkdir(parents=True)
            (root / 'pnpm-workspace.yaml').write_text('packages:\n  - "packages/*"\n')
            path = root / 'packages/consumer/package.json'
            value = {'name': '@bch-cloak/consumer', 'dependencies': {'@bch-cloak/pool-wallet-host': 'workspace:*'}, 'scripts': {'typecheck': 'tsc --noEmit'}}
            path.write_text(json.dumps(value))
            self.assertEqual(cert.dependent_typechecks(root), ['pnpm --filter @bch-cloak/consumer typecheck'])
            del value['scripts']['typecheck']; path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError): cert.dependent_typechecks(root)

    def test_exact_head_base_clean_and_diff_guards(self):
        head, base = 'a' * 40, 'b' * 40
        for changed in ('valid', 'head', 'base', 'ancestor', 'dirty', 'diff'):
            def git(_, *args, **kwargs):
                self.assertEqual(kwargs, {'timeout': 10})
                if args == ('rev-parse', 'HEAD'): return ((head if changed != 'head' else base) + '\n').encode()
                if args == ('rev-parse', 'refs/heads/main'): return ((base if changed != 'base' else head) + '\n').encode()
                if args[0] == 'merge-base': return ((base if changed != 'ancestor' else head) + '\n').encode()
                return b'?? synthetic\n' if changed == 'dirty' else b''
            with patch.object(driver, 'git_output', side_effect=git), patch.object(cert.subprocess, 'run', return_value=subprocess.CompletedProcess([], int(changed == 'diff'))) as check:
                if changed == 'valid': cert.binding(cert.REPO, head, base)
                else:
                    with self.assertRaises(RuntimeError): cert.binding(cert.REPO, head, base)
                if changed in ('valid', 'diff'): self.assertIn('--check', check.call_args.args[0])

    def test_pre_slot_and_admitted_order_refuse_before_stages(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = str(Path(tmp) / 'new'); calls = []
            args = [root, '--vd', '--expected-head', 'a' * 40, '--expected-base', 'b' * 40]
            def note(name): return lambda *a, **k: calls.append(name)
            with patch.object(cert.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)), \
                 patch.object(cert, 'binding', side_effect=note('binding')), patch.object(cert, 'toolchain', side_effect=note('toolchain')), \
                 patch.object(cert, 'memory_admission', side_effect=note('memory')), patch.object(cert, 'granted_deadline', side_effect=note('grant')), \
                 patch.object(cert, 'run_recipe', side_effect=note('stages')), redirect_stdout(io.StringIO()):
                cert.main(args + ['--pre-slot']); self.assertEqual(calls, ['binding', 'toolchain', 'memory'])
                calls.clear(); cert.main(args); self.assertEqual(calls, ['binding', 'grant', 'toolchain', 'memory', 'stages'])
                calls.clear()
                with patch.object(cert, 'binding', side_effect=RuntimeError('changed')):
                    with self.assertRaises(RuntimeError): cert.main(args)
                self.assertEqual(calls, [])
            self.assertFalse(Path(root).exists())

    def test_slot_grant_is_required_and_budget_is_not_reset(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            lock = Path(tmp) / 'synthetic-slot'
            holder = {'pid': os.getpid(), 'token': 'synthetic-only', 'acquiredAt': datetime.fromtimestamp(time.time() - 300, timezone.utc).isoformat()}
            lock.write_text(json.dumps(holder))
            with patch.dict(os.environ, {'BCH_CLOAK_TEST_SLOT_TOKEN': 'synthetic-only'}), patch.object(driver.RUNTIME_ENTRY, 'slot_available', return_value=True):
                left = cert.granted_deadline(lock) - time.monotonic()
                self.assertGreater(left, 14098); self.assertLessEqual(left, 14100)
                holder['token'] = 'wrong'; lock.write_text(json.dumps(holder))
                with self.assertRaises(RuntimeError): cert.granted_deadline(lock)
                holder['token'] = 'synthetic-only'; holder['acquiredAt'] = datetime.fromtimestamp(time.time() - 14401, timezone.utc).isoformat(); lock.write_text(json.dumps(holder))
                with self.assertRaises(RuntimeError): cert.granted_deadline(lock)
            with self.assertRaises((OSError, RuntimeError)): cert.granted_deadline(Path(tmp) / 'absent')

    def test_memory_formula_and_floor_are_the_existing_ones(self):
        for value, valid in ((str(20 * 1024**3).encode(), True), (str(20 * 1024**3 - 1).encode(), False), (b'unknown', False)):
            with patch.object(cert.subprocess, 'check_output', return_value=value) as call:
                if valid: cert.memory_admission(cert.REPO)
                else:
                    with self.assertRaises(RuntimeError): cert.memory_admission(cert.REPO)
                command = call.call_args.args[0]
                self.assertIn('/^Pages (free|inactive|speculative):/', command[2])
                self.assertNotIn('run_case', command[2])

    def test_pinned_toolchain_refuses_wrong_version_or_resolution(self):
        def which(name): return str(driver.NODE if name == 'node' else driver.PNPM)
        version = json.loads((cert.REPO / 'package.json').read_bytes())['packageManager'][5:].encode()
        for invalid in ('none', 'node', 'pnpm', 'resolution'):
            def output(command, **_):
                return (b'v0' if invalid == 'node' else b'v22.22.3') if command[0] == 'node' else (b'0' if invalid == 'pnpm' else version)
            with patch.object(cert.shutil, 'which', side_effect=(lambda _: '/bin/sh') if invalid == 'resolution' else which), patch.object(cert.subprocess, 'check_output', side_effect=output):
                if invalid == 'none': cert.toolchain(cert.REPO)
                else:
                    with self.assertRaises(RuntimeError): cert.toolchain(cert.REPO)

    def test_final_binding_and_incomplete_run_never_certify(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp) / 'new'; calls = []
            def check(*_):
                calls.append('binding')
                if len(calls) == 2: raise RuntimeError('moved-after-stage')
            def stage(*args, **kwargs):
                self.assertEqual(kwargs['child_umask'], 0o022)
                self.assertFalse(kwargs['cooperative'])
                return subprocess.CompletedProcess([], 0)
            with patch.object(cert, 'binding', side_effect=check), patch.object(driver, 'logged_stage', side_effect=stage):
                with self.assertRaisesRegex(RuntimeError, 'moved-after-stage'):
                    cert.run_recipe(root, 'a' * 40, 'b' * 40, [('gate', 'synthetic')], True, time.monotonic() + 10)
            self.assertEqual(calls, ['binding', 'binding'])
            self.assertFalse((root / 'certification-record.json').exists())

    def test_complete_synthetic_recipe_masks_bindings_and_closed_success(self):
        # Only stage dispatch is replaced; the complete canonical plan, final
        # driver-summary validator and certification writer execute normally.
        setup = driver._load('certification_summary_fixture', SCRIPTS / 'test-private-runner-driver-setup.py')
        plan = cert.recipe(json.loads((cert.REPO / 'package.json').read_bytes())['scripts'], True)
        head, base = 'a' * 40, 'b' * 40
        for refuse in ('none','head','resource-exit','resource-missing','resource-head','resource-tree','resource-selection'):
            with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
                root = Path(tmp) / 'new'; calls = []
                def stage(label, command, cwd, env, log, timeout, **kwargs):
                    kind, _ = plan[len(calls)]
                    calls.append(kind)
                    self.assertEqual(kwargs, {'child_umask': 0o022 if kind == 'gate' else 0o077, 'cooperative': kind != 'gate'})
                    self.assertEqual(env, dict(os.environ))
                    if kind != 'mutation-driver': self.assertEqual(timeout, 1800)
                    if kind == 'rollback-oracle': self.assertEqual(command[-2:], ['--expected-head', head])
                    if kind == 'mutation-driver':
                        self.assertEqual(command[-2:], ['--runtime-selection=ordinary','--mutations'])
                        value, _ = setup.ClosedControls().valid(); value['sourceHead'] = base if refuse=='head' else head
                        value['runtimeSelection']=self.resource_fixture(head)[1]
                        private = root / 'mutation-driver'; private.mkdir(mode=0o700)
                        life.private_write(private / 'closed-summary.json', json.dumps(value).encode())
                    if kind=='resource-controls':
                        self.assertEqual(command,['pnpm','validate:pool-action-modules:resource',str(root/'resource-controls')])
                        if refuse=='resource-exit':return subprocess.CompletedProcess(command,75)
                        resource,_=self.resource_fixture(head)
                        if refuse=='resource-head':resource['sourceHead']=base
                        if refuse=='resource-tree':resource['sourceTree']='f'*40
                        if refuse=='resource-selection':resource['selection']['selectedSha256']='f'*64
                        private=root/'resource-controls';private.mkdir(mode=0o700)
                        if refuse!='resource-missing':life.private_write(private/'resource-receipt.json',json.dumps(resource).encode())
                    return subprocess.CompletedProcess(command, 0)
                with patch.object(cert, 'binding') as binding, patch.object(driver, 'logged_stage', side_effect=stage):
                    if refuse!='none':
                        with self.assertRaises((RuntimeError,FileNotFoundError)): cert.run_recipe(root, head, base, plan, True, time.monotonic() + 20)
                    else: cert.run_recipe(root, head, base, plan, True, time.monotonic() + 20)
                self.assertEqual(calls, [kind for kind, _ in plan])
                self.assertEqual(binding.call_count, len(plan) + (refuse!='resource-exit'))
                output = root / 'certification-record.json'
                self.assertEqual(output.exists(), refuse=='none')
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
                if refuse=='none':
                    self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                    cert.require_record(json.loads(output.read_bytes()), plan)
                    self.assertEqual(list((root / 'stage-state').iterdir()), [])

    def test_resource_receipt_complete_schema_and_missing_step_oracles(self):
        resource,_=self.resource_fixture()
        runtime=driver.RUNTIME_ENTRY
        runtime.require_resource_receipt(resource,'a'*40)
        summary={**{key:resource[key] for key in ('sourceHead','sourceTree','fixtureHead')},
            'commands':[{'label':'runtime','exit':0}],
            'suites':[{'label':'runtime','tests':4,'passed':4,'failed':0,'deselected':115,'selection':resource['selection'],
                'rows':[{'name':title,'status':'passed'} for title in runtime.runtime_titles('resource')]}],
            'buildIdentities':{'tools/pool-action-modules/dist/private-runner-process':'a'*64,
                'tools/pool-action-modules/dist/private-runner-installation.json':'a'*64},
            'preRuntimeArtifactSha256':{'ordinary-pool-pk-load':'a'*64},'private':'/private/tmp/SYNTHETIC'}
        summary['resourceCases']=resource['cases']
        self.assertEqual(runtime.resource_receipt(summary),resource)
        for change in ('passed','failed','deselected','title','status','exit','missing','duplicate'):
            bad=copy.deepcopy(summary);suite=bad['suites'][0]
            if change in ('passed','failed','deselected'):suite[change]+=1
            elif change=='title':suite['rows'][0]['name']='unknown'
            elif change=='status':suite['rows'][0]['status']='skipped'
            elif change=='exit':bad['commands'][0]['exit']=75
            elif change=='missing':bad['suites']=[]
            else:suite['rows'].append(suite['rows'][0])
            with self.assertRaisesRegex(RuntimeError,'^mig01-runtime-control-refused$'):runtime.resource_receipt(bad)
        def locations(value,path=()):
            yield path,value
            if type(value) is dict:
                for key,item in value.items():yield from locations(item,path+(key,))
            elif type(value) is list:
                for key,item in enumerate(value):yield from locations(item,path+(key,))
        for path,value in locations(resource):
            changes=[None,True,'/private/tmp/SYNTHETIC','%2Fprivate%2FSYNTHETIC']
            if type(value) is dict:
                changes += [{**value,'unknown':0},*({key:item for key,item in value.items() if key!=missing} for missing in value)]
            for replacement in changes:
                bad=copy.deepcopy(resource);parent=bad
                for key in path[:-1]:parent=parent[key]
                if path:parent[path[-1]]=replacement
                else:bad=replacement
                with self.assertRaisesRegex(RuntimeError,'^mig01-runtime-control-refused$'):runtime.require_resource_receipt(bad,'a'*40)
        plan=[('rollback-oracle',None),('mutation-driver',None),('resource-controls',None)]
        record={'schema':'mig01-certification-v3','mode':'vd','sourceHead':'a'*40,'sourceBase':'b'*40,
            'executionSeconds':14400,'teardownSeconds':120,'runtimeBaselines':1,'resourceControls':resource,
            'steps':[{'step':i,'kind':kind,'commandSha256':None,'exit':0} for i,(kind,_) in enumerate(plan)]}
        cert.require_record(record,plan)
        for change in ('missing','duplicate','order','exit','receipt'):
            bad=copy.deepcopy(record)
            if change=='missing':bad['steps'].pop()
            elif change=='duplicate':bad['steps'].append({**bad['steps'][-1],'step':3})
            elif change=='order':bad['steps'][1]['kind'],bad['steps'][2]['kind']=bad['steps'][2]['kind'],bad['steps'][1]['kind']
            elif change=='exit':bad['steps'][-1]['exit']=75
            else:del bad['resourceControls']
            with self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):cert.require_record(bad)
        # Disable exactly the resource-step cardinality/order condition in a
        # scratch function. The missing-step regression must then fail.
        import ast
        source=Path(runtime.__file__).read_text();tree=ast.parse(source)
        producer=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='resource_receipt')
        producer_checks=[node for node in producer.body if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call)
            and ast.unparse(node.value).startswith("require((suite['tests']")]
        self.assertEqual(len(producer_checks),1)
        producer.body.remove(producer_checks[0])
        namespace=dict(vars(runtime));exec(compile(ast.Module(body=[producer],type_ignores=[]),'resource-producer-mutant','exec'),namespace)
        bad=copy.deepcopy(summary);bad['suites'][0]['passed']=3
        def producer_regression(check):
            with self.assertRaisesRegex(RuntimeError,'^mig01-runtime-control-refused$'):check(bad)
        producer_regression(runtime.resource_receipt)
        with self.assertRaises(AssertionError):producer_regression(namespace['resource_receipt'])
        producer_regression(runtime.resource_receipt)
        source=(SCRIPTS/'mig01-certification.py').read_text()
        tree=ast.parse(source)
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='require_record')
        checks=[node for node in function.body if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call)
                and ast.unparse(node.value).startswith("require('mutation-driver' in kinds")]
        self.assertEqual(len(checks),1)
        function.body.remove(checks[0])
        namespace=dict(vars(cert));exec(compile(ast.Module(body=[function],type_ignores=[]),'resource-step-mutant','exec'),namespace)
        bad=copy.deepcopy(record);bad['steps'].pop()
        def regression(check):
            with self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):check(bad)
        regression(cert.require_record)
        with self.assertRaises(AssertionError):regression(namespace['require_record'])
        regression(cert.require_record)

class LifecycleControls(unittest.TestCase):
    def test_launch_window_before_and_after_registration_and_old_order_negative(self):
        # REV-804's paired probe: forced death at register entry vs after the
        # real register returns. Check the PID as well as its prospective PGID:
        # the unreleased child deliberately has not detached yet.
        def gone(pid):
            try: os.kill(pid, 0)
            except ProcessLookupError: return True
            return False
        for mode, old_order in (('before', False), ('after', False), ('before', True), ('before', False), ('after', False)):
            with self.subTest(mode=mode, old_order=old_order), tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
                root = Path(tmp); script = root / 'nested.py'; pid = None
                script.write_text('''import importlib.util,os,signal,sys
from pathlib import Path
p=Path(sys.argv[1]);spec=importlib.util.spec_from_file_location('driver',sys.argv[2]);d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
p.mkdir();fixture=p/'fixture';fixture.mkdir();source=fixture/'source';source.write_bytes(b'original')
with d.LIFECYCLE.inherited_scope(p) as scope,d.stage_scope(scope):
 journal=scope.remember(fixture,{'source':b'original'});source.write_bytes(b'mutated')
 register=scope.register
 def boundary(child):
  if sys.argv[3]=='after':register(child)
  (p/'leaf-pid').write_text(str(child.pid))
  os.kill(os.getpid(),signal.SIGKILL)
 scope.register=boundary
 if sys.argv[4]=='old-order':
  original=d.subprocess.Popen
  def detached(command,**options):
   assert command[4]==d.LIFECYCLE.LAUNCH_GUARD
   options.update(start_new_session=True,pass_fds=())
   return original(command[6:],**options)
  d.subprocess.Popen=detached
 try:d.logged_stage('leaf',[sys.executable,'-c','import time;time.sleep(60)'],p,{},p/'leaf.log',30)
 finally:scope.restore(journal)
''')
                scope = life.Scope(root / 'stage-state', time.monotonic() + 15, owner=True, teardown=5)
                try:
                    with redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, '^mig01-no-proof-control-refused$'), driver.stage_scope(scope):
                        result = driver.logged_stage('nested', [sys.executable, '-B', str(script), str(root / 'nested'), str(SCRIPTS / 'test-live-entry-no-proof.py'), mode, 'old-order' if old_order else 'guarded'], root, dict(os.environ), root / 'nested.log', 10, cooperative=True)
                        driver.require(result.returncode == 0)
                    pid = int((root / 'nested/leaf-pid').read_text())
                    def reaped():
                        self.assertTrue(gone(pid) and life.group_gone(pid), 'launch-window-child-survived')
                    if old_order:
                        with self.assertRaisesRegex(AssertionError, 'launch-window-child-survived'): reaped()
                    else: reaped()
                    self.assertEqual((root / 'nested/fixture/source').read_bytes(), b'original')
                    self.assertFalse(list(scope.directory.glob('group-*')))
                    self.assertFalse(list(scope.directory.glob('restore-*')))
                    self.assertFalse((root / 'certification-record.json').exists())
                finally:
                    if pid is None and (root / 'nested/leaf-pid').exists(): pid = int((root / 'nested/leaf-pid').read_text())
                    if pid is not None:
                        life.send(pid, signal.SIGKILL)
                        until = time.monotonic() + 5
                        while not gone(pid) and time.monotonic() < until: time.sleep(.02)
                        self.assertTrue(gone(pid) and life.group_gone(pid))

    def test_registered_launch_preserves_environment_masks_and_private_log(self):
        # Includes a payload larger than a pipe buffer, without publishing any
        # environment value or relying on Python's own locale normalization.
        for mask in (0o022, 0o077):
            with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
                root = Path(tmp); scope = life.Scope(root / 'stage-state', time.monotonic() + 10, owner=True)
                env = {'LANG': 'C', 'SYNTHETIC_CANARY': 'x' * 65536}
                log, mask_log = root / 'env.log', root / 'mask.log'
                with redirect_stdout(io.StringIO()), driver.stage_scope(scope):
                    result = driver.logged_stage('environment', ['/usr/bin/env'], root, env, log, 5, child_umask=mask, cooperative=True)
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(dict(line.split('=', 1) for line in log.read_text().splitlines()), scope.environment(env))
                    result = driver.logged_stage('mask', ['/bin/sh', '-c', 'umask'], root, env, mask_log, 5, child_umask=mask)
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(int(mask_log.read_text().strip(), 8), mask)
                self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(mask_log.stat().st_mode), 0o600)
                self.assertEqual(list(scope.directory.iterdir()), [])

    def test_cancel_after_publication_before_release_never_executes_stage(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp); scope = life.Scope(root / 'stage-state', time.monotonic() + 10, owner=True, teardown=5)
            registered = []; register = scope.register
            def capture(child):
                registered.append(child)
                return register(child)
            def cancel(*_):
                scope.cancel()
                scope.check()
            with patch.object(scope, 'register', side_effect=capture), patch.object(scope, 'release', side_effect=cancel), redirect_stdout(io.StringIO()):
                with self.assertRaises(life.Cancelled), driver.stage_scope(scope):
                    driver.logged_stage('unreleased', ['/usr/bin/touch', str(root / 'stage-executed')], root, {}, root / 'child.log', 5)
            self.assertEqual(len(registered), 1)
            self.assertIsNotNone(registered[0].poll())
            self.assertTrue(life.group_gone(registered[0].pid))
            self.assertFalse((root / 'stage-executed').exists())
            self.assertFalse(list(scope.directory.glob('group-*')))

    def test_full_rollback_abort_restores_prepared_source_before_exit(self):
        oracle = driver._load('certification_rollback', cert.REPO / 'tools/pool-action-modules/test/restore-reservation-oracles.py')
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp); work = root / 'rollback-oracle'
            scope = oracle.DRIVER.LIFECYCLE.Scope(root / 'stage-state', time.monotonic() + 10, owner=True)
            originals = {name: oracle.imports_from_checkout((cert.REPO / source).read_text(), cert.REPO / source).encode()
                         for name, source in (('dead-hook.mjs', oracle.FIXTURE), ('restore-rollback.test.ts', oracle.RESTORE), ('reservation-rollback.test.ts', oracle.RESERVATION))}
            def output(command, **_):
                if command == ['git', 'rev-parse', 'HEAD']: return 'a' * 40
                if command == ['git', 'status', '--porcelain']: return ''
                if command == ['node', '-v']: return 'v22.22.3'
                self.fail('unexpected-command')
            def cancel(*_):
                self.assertEqual(len(list(scope.directory.glob('restore-*'))), 1)
                self.assertTrue(all((work / name).read_bytes() != content for name, content in originals.items()))
                raise oracle.DRIVER.LIFECYCLE.Cancelled()
            args = unittest.mock.Mock(scratch=str(work), expected_head='a' * 40, prepare_only=False)
            with patch.object(oracle.subprocess, 'check_output', side_effect=output), patch.object(oracle.DRIVER, 'logged_stage', side_effect=cancel), redirect_stdout(io.StringIO()):
                with self.assertRaises(oracle.DRIVER.LIFECYCLE.Cancelled), oracle.DRIVER.stage_scope(scope): oracle.execute(args)
            self.assertTrue(all((work / name).read_bytes() == content for name, content in originals.items()))
            self.assertFalse((work / 'closed-summary.json').exists())
            self.assertFalse(list(scope.directory.glob('restore-*')))

    def test_ordinary_mask_private_modes_and_firing_negatives(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp); old = os.umask(0o077)
            try:
                def run(name, child_mask):
                    target, log = root / name, root / (name + '.log')
                    command = [sys.executable, '-c', 'import os,sys;fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644);os.close(fd)', str(target)]
                    with redirect_stdout(io.StringIO()): driver.logged_stage('mask', command, root, {}, log, 5, child_umask=child_mask)
                    return stat.S_IMODE(target.stat().st_mode), stat.S_IMODE(log.stat().st_mode)
                self.assertEqual(run('ordinary', 0o022), (0o644, 0o600))
                self.assertEqual(run('private', 0o077), (0o600, 0o600))
                with self.assertRaises(AssertionError): self.assertEqual(run('mask-disabled', 0o077), (0o644, 0o600))
                os.umask(0o022)
                real_open = os.open
                def changed(path, flags, mode=0o777, **kwargs):
                    return real_open(path, flags, 0o666 if str(path).endswith('.log') else mode, **kwargs)
                with patch.object(driver.os, 'open', side_effect=changed):
                    with self.assertRaises(AssertionError): self.assertEqual(run('log-mode-disabled', 0o022), (0o644, 0o600))
                scope = life.Scope(root / 'state', time.monotonic() + 5, owner=True)
                self.assertEqual(stat.S_IMODE(scope.directory.stat().st_mode), 0o700)
            finally: os.umask(old)

    def nested(self, root, death=False):
        # Real detached grandchild through the real logged_stage, not a mock PID.
        script = root / 'nested.py'
        script.write_text('''import importlib.util,os,sys,time
from pathlib import Path
p=Path(sys.argv[1]);spec=importlib.util.spec_from_file_location('driver',sys.argv[2]);d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
p.mkdir();fixture=p/'fixture';fixture.mkdir();source=fixture/'source';source.write_bytes(b'original')
with d.LIFECYCLE.inherited_scope(p) as scope,d.stage_scope(scope):
 journal=scope.remember(fixture,{'source':b'original'});source.write_bytes(b'mutated')
 try:
  code="import os,time;from pathlib import Path;Path("+repr(str(p/'leaf'))+").write_text(str(os.getpid()));"+("time.sleep(.2);os.kill(os.getppid(),9);" if sys.argv[3]=='death' else "")+"time.sleep(60)"
  d.logged_stage('leaf',[sys.executable,'-c',code],p,{},p/'leaf.log',30)
 finally:scope.restore(journal)
''')
        return [sys.executable, '-B', str(script), str(root / 'nested'), str(SCRIPTS / 'test-live-entry-no-proof.py'), 'death' if death else 'wait']

    def assert_nested_clean(self, root):
        pid = int((root / 'nested/leaf').read_text())
        self.assertTrue(life.group_gone(pid), 'owned-group-survived')
        self.assertEqual((root / 'nested/fixture/source').read_bytes(), b'original', 'source-not-restored')
        self.assertFalse(list((root / 'stage-state').glob('group-*')))
        self.assertFalse(list((root / 'stage-state').glob('restore-*')))

    def test_nested_signal_cancellation_restores_and_reaps(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp); scope = life.Scope(root / 'stage-state', time.monotonic() + 15, owner=True, teardown=5)
            def interrupt():
                until = time.monotonic() + 10
                while not (root / 'nested/leaf').exists() and time.monotonic() < until: time.sleep(.02)
                os.kill(os.getpid(), signal.SIGTERM)
            timer = threading.Thread(target=interrupt); timer.start()
            try:
                with redirect_stdout(io.StringIO()), self.assertRaises(life.Cancelled), driver.stage_scope(scope):
                    driver.logged_stage('nested', self.nested(root), root, dict(os.environ), root / 'nested.log', 15, cooperative=True)
            finally: timer.join()
            self.assert_nested_clean(root)

    def test_nested_deadline_cancellation_restores_and_reaps(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp); scope = life.Scope(root / 'stage-state', time.monotonic() + 2, owner=True, teardown=5)
            started = time.monotonic()
            with redirect_stdout(io.StringIO()), self.assertRaises((life.Cancelled, subprocess.TimeoutExpired)), driver.stage_scope(scope):
                driver.logged_stage('nested', self.nested(root), root, dict(os.environ), root / 'nested.log', 15, cooperative=True)
            self.assertLess(time.monotonic() - started, 7)
            self.assert_nested_clean(root)

    def test_nested_driver_death_backstop_and_cleanup_firing_negatives(self):
        for disabled in ('none', 'reap', 'none', 'restore', 'none'):
            with self.subTest(disabled=disabled), tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
                root = Path(tmp); scope = life.Scope(root / 'stage-state', time.monotonic() + 10, owner=True, teardown=5)
                original_drain, original_restore = scope.drain, scope.restore
                if disabled == 'reap': scope.drain = lambda: None
                if disabled == 'restore': scope.restore = lambda path: path.unlink()
                try:
                    with redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError), driver.stage_scope(scope):
                        result = driver.logged_stage('nested', self.nested(root, True), root, dict(os.environ), root / 'nested.log', 10, cooperative=True)
                        driver.require(result.returncode == 0)
                    if disabled == 'none': self.assert_nested_clean(root)
                    else:
                        with self.assertRaisesRegex(AssertionError, 'owned-group-survived' if disabled == 'reap' else 'source-not-restored'): self.assert_nested_clean(root)
                finally:
                    scope.drain, scope.restore = original_drain, original_restore
                    original_drain()

    def test_cleanup_refusal_holds_before_terminal_exit_with_firing_negative(self):
        for disabled in (False, True, False):
            with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
                root = Path(tmp)
                script = root / 'blocked.py'
                script.write_text("""import importlib.util,sys,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('life',sys.argv[1]);life=importlib.util.module_from_spec(spec);spec.loader.exec_module(life)
root=Path(sys.argv[2]);scope=life.Scope(root/'state',time.monotonic()+10,owner=True)
def refused():raise life.CleanupRefused()
scope.drain=refused
if sys.argv[3]=='disabled':scope.hold=lambda:None
try:
 with scope:raise RuntimeError('synthetic-stage-refusal')
except BaseException:(root/'terminal').write_text('failure')
""")
                with (root / 'log').open('wb') as log:
                    child = subprocess.Popen([sys.executable, '-B', str(script), str(SCRIPTS / 'mig01-stage-lifecycle.py'), str(root), 'disabled' if disabled else 'valid'], stdout=log, stderr=log, start_new_session=True)
                try:
                    until = time.monotonic() + 5
                    while not (root / 'state/cleanup-blocked').exists() and not (root / 'terminal').exists() and time.monotonic() < until: time.sleep(.02)
                    def intact():
                        self.assertIsNone(child.poll(), 'slot-child-exited-before-cleanup')
                        self.assertFalse((root / 'terminal').exists(), 'terminal-before-cleanup')
                        self.assertTrue((root / 'state/cleanup-blocked').exists())
                    if disabled:
                        child.wait(timeout=2)
                        with self.assertRaisesRegex(AssertionError, 'slot-child-exited-before-cleanup'): intact()
                    else: intact()
                finally:
                    os.killpg(child.pid, signal.SIGKILL) if child.poll() is None else None
                    child.wait(timeout=5)

    def test_unreaped_group_cannot_return_cleanup_success(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            scope = life.Scope(Path(tmp) / 'state', time.monotonic() + 2, owner=True, teardown=.1)
            child = unittest.mock.Mock(pid=12345); child.wait.return_value = 0
            with patch.object(life, 'send'), patch.object(life, 'group_gone', return_value=False):
                with self.assertRaises(life.CleanupRefused): scope.stop(child, cooperative=False)

if __name__ == '__main__': unittest.main()
