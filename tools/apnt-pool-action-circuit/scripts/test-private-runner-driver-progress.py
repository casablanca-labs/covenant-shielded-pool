#!/usr/bin/python3
"""Closed driver progress controls; synthetic children, no wallet or runner."""
from contextlib import redirect_stdout
import ast
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

# Loaded modules write no bytecode into the checkout under test.
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('driver', Path(__file__).with_name('test-live-entry-no-proof.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)

class FlushedOutput(io.StringIO):
    def __init__(self):
        super().__init__()
        self.flushes = 0
    def flush(self):
        self.flushes += 1

def gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False

class ProgressControls(unittest.TestCase):
    def test_resource_children_use_registered_stages_and_keep_slot_check(self):
        # Execute the resource branch of the actual nested runtime run helper.
        # No export, runtime, build, slot file or private input is constructed.
        source=Path(__file__).with_name('test-private-runner-runtime-no-proof.py')
        tree=ast.parse(source.read_text())
        main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
        run=next(node for node in main.body if isinstance(node,ast.FunctionDef) and node.name=='run')
        require=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='require')
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root=Path(tmp);namespace={'fixture':root,'root':root,'raw':root,'env':{'LANG':'C'},'time':time,
                'json':__import__('json'),'summary':{'commands':[]},'STAGE_DRIVER':driver,'slot_available':lambda:True}
            exec(compile(ast.Module(body=[require,run],type_ignores=[]),'resource-runtime-stage','exec'),namespace)
            with patch.object(driver,'logged_stage',return_value=subprocess.CompletedProcess([],0)) as stage:
                self.assertEqual(namespace['run']('synthetic',['synthetic-leaf']),0)
                stage.assert_called_once_with('synthetic',['synthetic-leaf'],root,{'LANG':'C'},root/'synthetic.log',1800)
                namespace['slot_available']=lambda:False
                with self.assertRaisesRegex(RuntimeError,'^mig01-runtime-control-refused$'):namespace['run']('synthetic',['synthetic-leaf'])
                self.assertEqual(stage.call_count,1)
            self.assertEqual(len(namespace['summary']['commands']),1)
        # Stop extraction after this branch so disabling it cannot launch an
        # unmanaged child. Require the actual delegation, then restore it.
        branch=next(node for node in run.body if isinstance(node,ast.If) and ast.unparse(node.test)=='STAGE_DRIVER is not None')
        self.assertTrue(any(isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='logged_stage' for node in ast.walk(branch)))
        scoped=copy.deepcopy(run);scoped.body=scoped.body[:run.body.index(branch)+1]
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root=Path(tmp)
            for disabled in (False,True,False):
                candidate=copy.deepcopy(scoped)
                if disabled:candidate.body[-1].test=ast.Constant(False)
                namespace={'fixture':root,'root':root,'raw':root,'env':{},'time':time,'json':__import__('json'),
                    'summary':{'commands':[]},'STAGE_DRIVER':driver,'slot_available':lambda:True}
                exec(compile(ast.fix_missing_locations(ast.Module(body=[require,candidate],type_ignores=[])),'resource-stage-mutant','exec'),namespace)
                with patch.object(driver,'logged_stage',return_value=subprocess.CompletedProcess([],0)) as stage:
                    value=namespace['run']('synthetic',['synthetic-leaf'])
                    observed=(value,stage.call_count)
                    self.assertEqual(observed,(None,0) if disabled else (0,1))
                    if disabled:
                        with self.assertRaises(AssertionError):self.assertEqual(observed,(0,1))

    def assert_events(self, output, labels, codes):
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), len(labels))
        self.assertEqual(output.flushes, len(labels))
        for line, label, code in zip(lines, labels, codes):
            self.assertRegex(line, r'^' + label + r' exit=' + str(code) + r' elapsed=\d+\.\d{3}s$')

    def test_stage_success_and_failure_print_only_closed_flushed_status(self):
        with tempfile.TemporaryDirectory(prefix='sage-owner-execution-v2-r1728-progress-', dir='/private/tmp') as root:
            for code in (0, 7):
                output = FlushedOutput()
                log = Path(root) / ('child-' + str(code) + '.log')
                with redirect_stdout(output):
                    result = driver.logged_stage('synthetic-stage', ['/bin/sh', '-c', 'echo SYNTHETIC_PRIVATE_PATH; echo SYNTHETIC_CHILD_ERROR >&2; exit ' + str(code)], Path(root), {}, log, 10)
                self.assertEqual(result.returncode, code)
                self.assert_events(output, ['synthetic-stage'], [code])
                self.assertEqual(log.read_bytes(), b'SYNTHETIC_PRIVATE_PATH\nSYNTHETIC_CHILD_ERROR\n')

    def test_timeout_and_launch_failure_have_one_closed_flushed_line(self):
        with tempfile.TemporaryDirectory(prefix='sage-owner-execution-v2-r1728-progress-', dir='/private/tmp') as root:
            output = FlushedOutput()
            with redirect_stdout(output), patch.object(driver.subprocess, 'Popen', side_effect=OSError('SYNTHETIC_PRIVATE_PATH')):
                with self.assertRaises(OSError):
                    driver.logged_stage('synthetic-stage', ['/bin/sh'], Path(root), {}, Path(root) / 'launch.log', 1)
            self.assert_events(output, ['synthetic-stage'], [127])
            output, log = FlushedOutput(), Path(root) / 'timeout.log'
            with redirect_stdout(output):
                with self.assertRaises(subprocess.TimeoutExpired):
                    driver.logged_stage('synthetic-stage', ['/bin/sh', '-c', '/bin/sleep 60 >/dev/null 2>&1 & echo $!; exec /bin/sleep 3'], Path(root), {}, log, 1)
            orphan = int(log.read_text().strip())
            try:
                self.assert_events(output, ['synthetic-stage'], [124])
                # The leader's whole group, including a child it never waits for, is gone on return.
                self.assertTrue(gone(orphan))
            finally:
                if not gone(orphan): os.kill(orphan, 9)

    def test_stage_group_is_reaped_before_a_successful_return(self):
        with tempfile.TemporaryDirectory(prefix='sage-owner-execution-v2-r1728-progress-', dir='/private/tmp') as root:
            log = Path(root) / 'orphan.log'
            with redirect_stdout(FlushedOutput()):
                result = driver.logged_stage('synthetic-stage', ['/bin/sh', '-c', '/bin/sleep 60 & echo $!'], Path(root), {}, log, 10)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(gone(int(log.read_text().strip())))
            # Positive control: the same orphan outlives a plain run of that leader.
            survivor = int(subprocess.run(['/bin/sh', '-c', '/bin/sleep 60 >/dev/null 2>&1 & echo $!'], stdout=subprocess.PIPE, start_new_session=True, check=True).stdout)
            try:
                self.assertFalse(gone(survivor))
            finally:
                os.kill(survivor, 9)
                deadline = time.monotonic() + 10
                while not gone(survivor) and time.monotonic() < deadline: time.sleep(0.05)

    def test_unreaped_group_refuses_after_its_deadline(self):
        child = subprocess.Popen(['/usr/bin/true'], start_new_session=True)
        child.wait()
        with patch.object(driver.os, 'killpg', return_value=None):
            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, 'mig01-no-proof-control-refused'):
                driver.reap_group(child, 0.2)
        self.assertLess(time.monotonic() - started, 5)
        for error in (ProcessLookupError, PermissionError):
            calls = []
            def killpg(pid, signal, error=error):
                calls.append(signal)
                if signal != 0 or len(calls) > 3: raise ProcessLookupError()
                raise error()
            with patch.object(driver.os, 'killpg', side_effect=killpg):
                driver.reap_group(child, 5)
            self.assertEqual(calls[0], 9)

    def test_planted_log_link_refuses_without_writing_its_target(self):
        with tempfile.TemporaryDirectory(prefix='sage-owner-execution-v2-r1728-progress-', dir='/private/tmp') as root:
            target = Path(root) / 'target'; target.write_bytes(b'safe canary')
            for planted in ('link', 'file'):
                log = Path(root) / (planted + '.log')
                if planted == 'link': log.symlink_to(target)
                else: log.write_bytes(b'earlier log')
                output = FlushedOutput()
                with redirect_stdout(output), self.assertRaises(FileExistsError):
                    driver.logged_stage('synthetic-stage', ['/bin/sh', '-c', 'echo SYNTHETIC_PRIVATE_PATH'], Path(root), {}, log, 10)
                self.assert_events(output, ['synthetic-stage'], [127])
            self.assertEqual(target.read_bytes(), b'safe canary')
            self.assertEqual((Path(root) / 'file.log').read_bytes(), b'earlier log')

    def test_group_start_and_end_are_once_and_flushed_on_success_or_failure(self):
        for fail in (False, True):
            output = FlushedOutput()
            with redirect_stdout(output):
                if fail:
                    with self.assertRaisesRegex(RuntimeError, 'synthetic refusal'):
                        with driver.mutation_progress('synthetic-group'):
                            raise RuntimeError('synthetic refusal')
                else:
                    with driver.mutation_progress('synthetic-group'):
                        pass
            self.assert_events(output, ['synthetic-group-start', 'synthetic-group-end'], [0, int(fail)])

    def test_private_path_or_multiline_label_refuses_without_printing(self):
        for label in ('/private/tmp/synthetic', 'stage\nsynthetic', 'stage synthetic'):
            output = FlushedOutput()
            with redirect_stdout(output), self.assertRaisesRegex(RuntimeError, 'mig01-no-proof-control-refused'):
                driver.progress(label, 0, 0)
            self.assertEqual(output.getvalue(), '')
            self.assertEqual(output.flushes, 0)
        # SYNTHETIC decoder fixture; these are deliberately asymmetric counts,
        # not a measured mutation oracle. The framework child below is synthetic.
        synthetic = dict(status=2, contacts=[3,5,7], deliveries=[11,13,17],
            outerRefusal=True, memoryFloor=False, admissionCreated=True,
            resultCreated=False, summaryCreated=True, workFailure=False)
        diagnostics = dict(terminalBytes=19, outputCreated=True, runCreated=False, openStage=True)
        pretty = lambda value: 'Object ' + json.dumps(value, indent=2).replace(': [', ': Array [').replace('\n}', ',\n}')
        title = 'PH11-X-PROD/P0 genuine kernel stock runner reaches P/A/W and writes its check-live result then fails closed before the summary'
        decode = lambda text: driver.decode_setup_actual('C9-grep',title,'helper',text)
        valid = pretty(synthetic)
        unsafe = valid.replace('"status"', '"\\u0073tatus"')
        self.assertEqual(decode(valid)['actual'], synthetic)
        self.assertEqual(list(decode(valid)['projection'].values()), [2,[3,5,7],[11,13,17],True,True,False,True,False,False])
        for key in ('contacts','deliveries'):
            for items in ([7,3,5], [5,7,3], [17,11,13]):
                value = {**synthetic,key:items}
                self.assertEqual(decode(pretty(value)), {'actual':value,'projection':{k:value[k] for k in driver.HELPER_CONTRACT}})
        invalid = [valid.replace('"status": 2', '"status": 2, "status": 2'), pretty({**synthetic,'extra':True}),
            unsafe, valid+' trailing', valid.replace('Object {','{',1), pretty({**synthetic,**diagnostics})]
        invalid.extend(pretty({**synthetic,key:value}) for key,value in diagnostics.items())
        for key in synthetic:
            invalid.append(pretty({k:v for k,v in synthetic.items() if k != key}))
            invalid.append(pretty({**synthetic,key:True if type(synthetic[key]) is int else 1}))
        for key in ('contacts','deliveries'):
            for items in ([], [3,5], [3,5,7,11], [-1,5,7], [3,-1,7], [3,5,-1],
                          [True,5,7], [3,False,7], [3,5,True], [3,5,'unsafe'], [3,1.5,7], [None,5,7]):
                invalid.append(pretty({**synthetic,key:items}))
        for value in (-1, 1.5, 'SYNTHETIC_PRIVATE_PATH', None):
            invalid.append(pretty({**synthetic,'status':value}))
        for key in ('outerRefusal','memoryFloor','admissionCreated','resultCreated','summaryCreated','workFailure'):
            invalid.extend(pretty({**synthetic,key:value}) for value in (0,1,'false',None,[],{}))
        for text in invalid:
            with self.subTest(synthetic_invalid=invalid.index(text)), self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):
                decode(text)
        for alternative, text, row in (('other',valid,title),('helper',valid,title.replace('kernel','stock')),
                                       ('terminal-leak','false',title)):
            with self.subTest(synthetic_alternative=alternative,row=row), self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):
                driver.decode_setup_actual('C9-grep',row,alternative,text)
        for control in ('C1-inbox-writer','unknown',True):
            with self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):
                driver.decode_setup_actual(control,title,'helper',valid)
        # Execute each pure guard removal in isolation, with its own oracle.
        source = Path(driver.__file__).read_text()
        controls = [
            ('keys = set(HELPER_CONTRACT)', "keys = {'status','contacts','deliveries','terminalBytes',*HELPER_FLAGS}", None),
            ('require(len(items) == len(dict(items)))', 'pass', lambda d: d(valid.replace('"status": 2', '"status": 2, "status": 2'))),
            ('require(set(value) <= keys)', 'pass', lambda d: d(pretty({**synthetic,'extra':True}))),
            *[('require(set(value) <= keys)', 'pass', lambda d, extra=extra: d(pretty({**synthetic,**extra})))
              for extra in [diagnostics,*({key:value} for key,value in diagnostics.items())]],
            ('require(keys <= set(value))', 'pass', lambda d: d(pretty({k:v for k,v in synthetic.items() if k != 'status'}))),
            *[('require(keys <= set(value))', 'pass', lambda d, key=key: d(pretty({k:v for k,v in synthetic.items() if k != key})))
              for key in synthetic if key != 'status'],
            ('type(item) is int and item >= 0', 'item >= 0', lambda d: d(pretty({**synthetic,'status':True}))),
            ('require(type(item) is list and len(item) == 3)', 'pass', lambda d: d(pretty({**synthetic,'contacts':[3,5]}))),
            ('type(count) is int and count >= 0', 'count >= 0', lambda d: d(pretty({**synthetic,'deliveries':[True,13,17]}))),
            ('require(type(item) is bool)', 'pass', lambda d: d(pretty({**synthetic,'outerRefusal':1}))),
            ('value[key][:] if type(value[key]) is list', 'value[key][::-1] if type(value[key]) is list', None),
            ('require(all(re.fullmatch', '# require(all(re.fullmatch', lambda d: d(unsafe)),
            ("require(alternative == 'helper')", 'pass', lambda d: d(valid,'other')),
            ("require(control == 'C9-grep' and text == 'true')", 'pass', lambda d: d('false','terminal-leak')),
            ('require(title == SETUP_HELPER_TITLE.format(SETUP_HELPER_ROWS[control]))', 'pass', lambda d: d(valid,'helper',title.replace('kernel','stock'))),
            ("require(text.startswith('Object {'))", 'pass', lambda d: d(valid.replace('Object {','{',1))),
            ("require(type(control) is str and control in SETUP_HELPER_ROWS)", 'pass', lambda d: d(valid,control=1)),
            ("require(type(control) is str and control in SETUP_HELPER_ROWS)", 'pass', lambda d: d(valid,control='unknown')),
        ]
        names = {'require','capture_json','capture_helper','decode_setup_actual','HELPER_FLAGS','HELPER_CONTRACT','SETUP_HELPER_ROWS','SETUP_HELPER_TITLE'}
        decoder_program = r'''
import ast, collections, json, re, sys
case=json.loads(sys.argv[1]);source=case['source'];label='oracle-decoder-'+str(case['index'])
if case['disabled']:source=source.replace(case['before'],case['after'],1)
nodes=[node for node in ast.parse(source).body if getattr(node,'name',None) in case['names'] or isinstance(node,ast.Assign) and any(getattr(target,'id',None) in case['names'] for target in node.targets)]
ns={'json':json,'re':re};exec(compile(ast.Module(body=nodes,type_ignores=[]),'SYNTHETIC-decoder-guard','exec'),ns)
# A missing-key fallback isolates control membership/type from the title guard.
ns['SETUP_HELPER_ROWS']=collections.defaultdict(lambda:'kernel',ns['SETUP_HELPER_ROWS'])
if case['request'] is None:
    try: found=ns['decode_setup_actual']('C9-grep',case['title'],'helper',case['valid'])
    except RuntimeError as error: raise AssertionError(label+': measured shape refused') from error
    assert found['actual']==case['synthetic'] and list(found['projection'].values())==case['expected'], label+': tuple order or shape'
else:
    try: ns['decode_setup_actual'](*case['request'])
    except RuntimeError as error: assert str(error)=='mig01-no-proof-control-refused', label+': wrong refusal'
    else: raise AssertionError(label+': accepted')
'''
        for index, (before, after, probe) in enumerate(controls):
            self.assertEqual(source.count(before), 1)
            request = None if probe is None else probe(lambda text, alternative='helper', row_title=title, control='C9-grep': [control,row_title,alternative,text])
            for disabled in (False,True,False):
                case=dict(source=source,before=before,after=after,disabled=disabled,index=index,names=sorted(names),
                    request=request,title=title,valid=valid,synthetic=synthetic,expected=[2,[3,5,7],[11,13,17],True,True,False,True,False,False])
                result=subprocess.run([sys.executable,'-B','-c',decoder_program,json.dumps(case)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                self.assertEqual(result.returncode,int(disabled),(index,disabled,result.stderr.decode()))
                if disabled:self.assertIn(('AssertionError: oracle-decoder-'+str(index)).encode(),result.stderr)

        # Each child is a synthetic oracle: original PASS, one disabled guard
        # fails its named assertion, restored PASS. No genuine collection.
        probe=Path(__file__).with_name('measure-setup-control.py'); source=probe.read_text(); tree=ast.parse(source)
        # Brain binds JSON.stringify(script), not the unquoted command bytes.
        import hashlib
        manifest=json.loads((probe.parents[3]/'package.json').read_text())
        controls=('C2-c-main-dispatch','C1-inbox-writer','C9-stat','C9-grep','C9-validation','C9-execution-reopen')
        names={'measure:setup-control:'+control.lower() for control in controls}
        self.assertEqual(set(manifest['resources']),names)
        self.assertEqual({name for name,command in manifest['scripts'].items() if name.startswith('measure:setup-control:') or 'measure-setup-control.py' in command},names)
        for control in controls:
            name='measure:setup-control:'+control.lower(); command=manifest['scripts'][name]; profile=manifest['resources'][name]
            self.assertEqual(profile['command_sha256'],hashlib.sha256(json.dumps(command).encode()).hexdigest(),'setup-recipe-digest')
            self.assertEqual(command,'python3 -B tools/apnt-pool-action-circuit/scripts/measure-setup-control.py observe --control '+control+' /private/tmp/setupplan-oracles-'+control)
            self.assertEqual(profile,dict(id='bch-cloak/'+name,revision=1,
                command_sha256=hashlib.sha256(json.dumps(command).encode()).hexdigest(),admission_class='EXCLUSIVE',
                M_bytes=None,C=None,worker_caps={},named_claims=[],evidence=['ARCH-748: explicit execution reservation','ENG-2035: fixed oracle-only recipe']))
        forbidden={'main','_main','setup_hold','setup_capture_tail','logged_stage','native_control_command','runtime_pattern'}
        self.assertFalse({n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)} & forbidden)
        self.assertEqual([n.module for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)],['pathlib'])
        program=r'''
import ast, copy, json, os, subprocess, sys, tempfile, time
from pathlib import Path
from unittest.mock import patch
path=Path(sys.argv[1]); scenario,before,after,disabled=sys.argv[2:]; source=path.read_text()
ns={'__file__':str(path),'__name__':'synthetic_probe'}
exec(compile(source.replace(before,after,1) if disabled=='1' else source,str(path),'exec'),ns)
D,R,I=ns['D'],ns['R'],ns['I']; control='C9-stat'; title=ns['CONTROLS'][control]
assert set(ns['CONTROLS'])=={'C2-c-main-dispatch','C1-inbox-writer','C9-stat','C9-grep','C9-validation','C9-execution-reopen'}
def refused(code,fn):
    try: fn()
    except RuntimeError as error: assert str(error)==code, 'oracle-'+scenario+': wrong refusal'
    else: raise AssertionError('oracle-'+scenario+': accepted')
actual=dict(status=2,contacts=[3,5,7],deliveries=[11,13,17],outerRefusal=True,admissionCreated=True,
    resultCreated=False,summaryCreated=True,memoryFloor=False,workFailure=False)
observation=dict(alternative='helper',error='AssertionError',actual=actual,projection=D.capture_helper(actual)['projection'],frames=[[D.RUNTIME,566,7],[D.RUNTIME,590,5]],inbox=None)
build=dict(installation='a'*64,receipt='b'*64,observer='c'*64)
manifest=dict(head='a'*40,tree='c'*40,fixture='e'*40,archive='b'*64,collector=D.digest(path.read_bytes()),selection=D.digest(R.SELECTION_FILE.read_bytes()),build=build)
record=dict(schema='setup-control-measurement-v1',control=control,row=title,identity=manifest,builds=[build,{**build,'receipt':'d'*64},build],trees=['c'*40,'d'*40,'c'*40],revisions=['e'*40,'f'*40,'e'*40],restored=True,
    phases=[dict(phase=name,exit=int(name=='mutant'),total=119,selected=1,deselected=118,passed=int(name!='mutant'),failed=int(name=='mutant'),observation=observation if name=='mutant' else None) for name in ns['PHASES']])
ns['check_record'](record)
with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
    root=Path(tmp); fixture=root/'fixture-main'; fixture.mkdir(); (root/'macos-observer').write_bytes(b'public observer');(root/'git-1.log').write_bytes(b'prepare canary')
    if scenario=='shape':
        for bad in ({**record,'extra':1},{k:v for k,v in record.items() if k!='schema'}): refused('setup-control-record-keys',lambda:ns['check_record'](bad))
        for key in ('total','selected','deselected','passed','failed'):
            bad=copy.deepcopy(record);bad['phases'][0][key]=True;refused('setup-control-phase-shape',lambda:ns['check_record'](bad))
        for field,code in (('identity','identity-keys'),('observation','observation-keys')):
            bad=copy.deepcopy(record); (bad['identity'] if field=='identity' else bad['phases'][1]['observation'])['extra']=1
            refused('setup-control-'+code,lambda:ns['check_record'](bad))
        bad=copy.deepcopy(record);bad['phases'][1]['observation']['projection']['status']=2.0;refused('setup-control-actual',lambda:ns['check_record'](bad))
    elif scenario=='row':
        bad={**record,'row':D.INBOX_TITLE}; refused('setup-control-record-binding',lambda:ns['check_record'](bad))
    elif scenario=='target':
        (fixture/D.RUNTIME).parent.mkdir(parents=True);(fixture/D.RUNTIME).write_text('synthetic row')
        (fixture/D.SHELL).parent.mkdir(parents=True);(fixture/D.SHELL).write_text('UNIQUE UNIQUE')
        with patch.object(D,'mutation_groups',return_value=[(control,D.RUNTIME,[(D.SHELL,'UNIQUE','MUTANT')],'.')]):
            refused('mig01-no-proof-control-refused',lambda:ns['target'](fixture,control))
            (fixture/D.SHELL).write_text('UNIQUE'); assert len(ns['target'](fixture,control))==1
    elif scenario=='build':
        (fixture/I.RECORD).parent.mkdir(parents=True); (fixture/I.RECORD).write_text(json.dumps(dict(schema='private-runner-installation-record-v1',revision='stale',entries=[])))
        with patch.object(I,'graph',return_value=[]),patch.object(D,'git_output',return_value=b'fresh\n'): refused('setup-control-stale-build',lambda:ns['identity'](fixture))
    elif scenario=='timeout':
        with patch.object(ns['subprocess'],'run',return_value=subprocess.CompletedProcess([],0)): refused('setup-control-timeout',lambda:ns['command'](root,['synthetic'],{},time.monotonic()-1,'timeout'))
        import contextlib, io
        for message,want in (('setup-control-timeout','setup-control-timeout'),('synthetic-private-canary','setup-control-refused')):
            def fail(argv): raise RuntimeError(message)
            output=io.StringIO()
            with patch.dict(ns,__name__='__main__',main=fail),contextlib.redirect_stderr(output):
                try: exec(compile(ast.Module(body=[ast.parse(source).body[-1]],type_ignores=[]),'synthetic-entry','exec'),ns)
                except SystemExit as stopped: assert stopped.code==1, 'oracle-timeout: entry status'
                else: raise AssertionError('oracle-timeout: entry returned')
            assert output.getvalue()==want+'\n', 'oracle-timeout: closed entry code'
    elif scenario=='restore':
        snapshot=root/'snapshot';snapshot.mkdir();(snapshot/'macos-observer').write_bytes(b'changed public observer')
        with patch.object(D,'git_output',return_value=b''),patch.dict(ns,identity=lambda *a:build): refused('setup-control-restoration',lambda:ns['verify_restoration'](root,fixture,snapshot,[],record['builds']))
        assert not (root/'measurement.json').exists(), 'oracle-restore: verified refusal'
    elif scenario=='terminal':
        bad={**record,'restored':False};refused('setup-control-restoration',lambda:ns['terminal'](root,bad,time.monotonic()+60))
        assert (root/'measurement.pending.json').is_file() and not (root/'measurement.json').exists(), 'oracle-terminal: premature final'
    elif scenario in ('link','stale','duplicate'):
        file=root/'fresh';file.write_bytes(b'public');since=0;seen=set()
        if scenario=='link': os.link(file,root/'alias')
        elif scenario=='stale': since=time.time_ns()+1000000000
        else: ns['fresh'](file,0,seen)
        refused('setup-control-duplicate-file' if scenario=='duplicate' else 'setup-control-fresh-file',lambda:ns['fresh'](file,since,seen))
    elif scenario=='phase':
        started=[None]
        def child(*args,**kwargs):
            directory=root/'baseline'; rows=[dict(fullName=t,status='passed' if t==title else 'pending') for t in R.runtime_titles('union')]
            (directory/'result.json').write_text(json.dumps(dict(startTime=time.time_ns()//1000000 if started[0] is None else started[0],success=True,numTotalTests=119,numPassedTests=1,numFailedTests=0,numPendingTests=118,numFailedTestSuites=0,testResults=[dict(name=str(fixture/D.RUNTIME),assertionResults=rows)])))
        with patch.dict(ns,command=child): assert ns['phase'](root,fixture,control,'baseline',{},time.monotonic()+1)==record['phases'][0]
        __import__('shutil').rmtree(root/'baseline');started[0]=0
        with patch.dict(ns,command=child): refused('setup-control-phase',lambda:ns['phase'](root,fixture,control,'baseline',{},time.monotonic()+1))
    elif scenario=='head':
        # Stop at the first subject read; no fixture or real observe is run.
        argv=['observe','--control',control,str(root)]
        with patch.object(D,'git_output',side_effect=RuntimeError('synthetic-subject')) as subject:
            for value in (None,'','a'*39,'a'*41,'g'*40):
                with patch.dict(os.environ,{} if value is None else {'SETUP_HEAD':value},clear=True):
                    refused('setup-control-arguments',lambda:ns['main'](argv))
            assert subject.call_count==0, 'oracle-head: subject reached'
            with patch.dict(os.environ,{'SETUP_HEAD':manifest['head']},clear=True):
                refused('synthetic-subject',lambda:ns['main'](argv))
            assert subject.call_count==1, 'oracle-head: valid head refused'
    elif scenario=='location':
        assert json.loads((D.REPO/'node_modules/vitest/package.json').read_text())['version']=='2.1.9', 'oracle-location: pinned Vitest'
        diagnostics=dict(terminalBytes=19,outputCreated=True,runCreated=False,openStage=True)
        helper_input={**actual,**diagnostics}
        assert len(helper_input)==13 and len(actual)==9, 'oracle-location: assertion/diagnostic census'
        unit="import {expect,test} from 'vitest';\nfunction runnerDiagnostic(f:any){return JSON.stringify(f)}\nfunction runtimeStep(_name:string){}\n"
        unit+='\n'*(564-unit.count('\n'))+'function requireFailClosed(f:any,status:number) {\n  '+ns['HELPER']+'\n}\n'
        unit+='\n'*(587-unit.count('\n'))+'test('+json.dumps(title)+',()=>{const f='+json.dumps(helper_input)+';const status=2;\n    '+ns['CALLER']+'\n});\n'
        (fixture/D.RUNTIME).parent.mkdir(parents=True);(fixture/D.RUNTIME).write_text(unit);(fixture/'node_modules').symlink_to(D.REPO/'node_modules')
        reporter=root/'reporter.mjs';reporter.write_text(D.FIRING_REPORTER);report=root/'firing.json'
        result=subprocess.run([str(D.PNPM),'exec','vitest','run',D.RUNTIME,'--root',str(fixture),'--maxWorkers=1','--minWorkers=1','--reporter='+str(reporter)],cwd=D.REPO,env=dict(os.environ,MIG01_FIRING_REPORT=str(report)),capture_output=True)
        assert result.returncode==1 and report.is_file(), 'oracle-location: synthetic Vitest failure missing'
        failure=json.loads(report.read_text());error=failure['failures'][0]['errors'][0];frames=D.stack_frames(error['stack'])
        assert len(frames)>=5 and all(frame[0]!=str(fixture/D.RUNTIME) for frame in frames[:3]) and [frame[1:] for frame in frames[3:5]]==[(566,55),(590,5)], 'oracle-location: framework/source census'
        assert D.decode_setup_actual(control,title,'helper',error['actual'])==dict(actual=actual,projection=observation['projection']), 'oracle-location: nine-key reporter capture'
        try:
            found=ns['firing'](control,failure,fixture,None)
        except RuntimeError as error: raise AssertionError('oracle-location: valid reporter refused') from error
        assert found['frames']==[[D.RUNTIME,566,55],[D.RUNTIME,590,5]], 'oracle-location: source pair'
        assert found['actual']==actual and len(found['actual'])==9, 'oracle-location: captured assertion subset'
        error=failure['failures'][0]['errors'][0]; captured=error['actual'];error['actual']='Object '+json.dumps(helper_input)
        refused('mig01-no-proof-control-refused',lambda:ns['firing'](control,failure,fixture,None))
        error['actual']=captured
        for bad in (frames[:3]+frames[4:],frames[:4],frames+[frames[3]],frames+[frames[4]],frames[:3]+frames[3:][::-1],frames[:4]+[frames[0],frames[4]],frames[:3]+[(frames[3][0],568,55),frames[4]],frames[:3]+[(frames[3][0],566,1),frames[4]],frames[:3]+[('/wrong/source.ts',566,55),frames[4]],frames[:3]+[(frames[3][0],566,1000),frames[4]],frames[:4]+[(frames[4][0],591,5)],frames[:4]+[(frames[4][0],590,0)],frames[:4]+[(frames[4][0],590,1000)],frames[:4]+[('/wrong/source.ts',590,5)]):
            error['stack']='AssertionError: synthetic\n'+''.join('    at '+p+':'+str(line)+':'+str(column)+'\n' for p,line,column in bad)
            refused('setup-control-location',lambda:ns['firing'](control,failure,fixture,None))
    elif scenario in ('mains','deadline-verify','deadline-record','deadline-rename'):
        def tripwire(*args,**kwargs): raise AssertionError('oracle-mains: forbidden driver entry')
        D.main=R.main=D.setup_hold=D.setup_capture_tail=tripwire
        (fixture/'.git').mkdir();(fixture/D.SHELL).parent.mkdir(parents=True);(fixture/D.SHELL).write_text('UNIQUE');(fixture/I.RECORD).parent.mkdir(parents=True);(fixture/I.RECORD).write_bytes(b'public receipt')
        (root/'prepared.json').write_text(json.dumps(dict(control=control,identity=manifest))); revision=[manifest['fixture']]
        def git(where,*args):
            if args==('status','--porcelain'): return b''
            if args==('rev-parse','--show-toplevel'): return str(fixture).encode()
            if args==('branch','--show-current'): return b'main\n'
            if args==('ls-files','-z'): return D.SHELL.encode()+b'\0'
            if args in (('write-tree',),('rev-parse','HEAD^{tree}')): return (manifest['tree'] if revision[0]==manifest['fixture'] else 'd'*40).encode()
            return (manifest['head'] if where==D.REPO else revision[0]).encode()
        def command(root,args,*rest,**kwargs):
            with (root/(rest[-1]+'.log')).open('xb'): pass
            if args[1:3]==['commit','-m']: revision[0]='f'*40
            if args[1:3]==['reset','--hard']: revision[0]=manifest['fixture']
        clock=[0];verified=[0];original_verify=ns['verify_restoration'];original_fresh=ns['fresh']
        def phase(r,f,c,n,*a):
            if scenario=='deadline-verify' and n=='restored': clock[0]=1201
            return copy.deepcopy(record['phases'][ns['PHASES'].index(n)])
        def verify(*a):
            original_verify(*a);verified[0]+=1
            if scenario=='deadline-record' and verified[0]==2: clock[0]=1201
        def fresh(*a,**kw):
            value=original_fresh(*a,**kw)
            if scenario=='deadline-rename' and a[0].name=='measurement.pending.json': clock[0]=1201
            return value
        with patch.object(D,'git_output',side_effect=git),patch.object(D,'verify_source_tree'),patch.object(D,'compose'),patch.object(I,'graph',return_value=[]),patch.object(ns['subprocess'],'check_output',return_value=b'v22.22.3\n'),patch.object(time,'monotonic',side_effect=lambda:clock[0]),patch.dict(ns,command=command,target=lambda *a:[(D.SHELL,'UNIQUE','MUTANT')],identity=lambda *a:build,phase=phase,verify_restoration=verify,fresh=fresh):
            with patch.dict(os.environ,{'SETUP_HEAD':manifest['head']}):
                if scenario!='mains':
                    import contextlib, io
                    output=io.StringIO()
                    with patch.object(sys,'argv',[str(path),'observe','--control',control,str(root)]),contextlib.redirect_stderr(output):
                        try: exec(compile(ast.Module(body=[ast.parse(source).body[-1]],type_ignores=[]),'synthetic-entry','exec'),dict(ns,__name__='__main__'))
                        except SystemExit as stopped: assert stopped.code==1, 'oracle-'+scenario+': entry status'
                        else: raise AssertionError('oracle-'+scenario+': accepted')
                    assert output.getvalue()=='setup-control-timeout\n', 'oracle-'+scenario+': timeout code'
                    assert verified[0]==(1 if scenario=='deadline-verify' else 2) and not (root/'measurement.json').exists(), 'oracle-'+scenario+': final record'
                    assert (root/'measurement.pending.json').exists()==(scenario=='deadline-rename'), 'oracle-'+scenario+': publication stage'
                    sys.exit(0)
                ns['main'](['observe','--control',control,str(root)])
        assert (root/'measurement.json').is_file() and not (root/'measurement.pending.json').exists(), 'oracle-mains: terminal'
        linked=root/'symlink';linked.symlink_to(root/'measurement.json');refused('setup-control-fresh-file',lambda:ns['fresh'](linked))
    else: raise AssertionError('unknown synthetic scenario')
'''
        guards=[('shape',"set(value)=={'schema','control','row','identity','builds','trees','revisions','phases','restored'}",'True'),
            ('row',"and value['row']==CONTROLS[value['control']]",''),('target','D.require_targets(read,rows); ',''),
            ('build',"need(receipt=={'schema':'private-runner-installation-record-v1','revision':D.git_output(fixture,'rev-parse','HEAD').decode().strip(),'entries':entries}, 'stale-build')",'pass'),
            ('timeout',"need(remaining>0, 'timeout')",'pass'),('restore',"need(builds[2]==builds[0] and identity(fixture)==builds[0] and all(I.file_bytes(fixture,path)==I.file_bytes(snapshot,path) for path in paths) and fresh(root/'macos-observer')==fresh(snapshot/'macos-observer') and D.git_output(fixture,'status','--porcelain')==b'', 'restoration')",'pass'),
            ('terminal','    check_record(record)\n','    pass\n'),('link','info.st_nlink==1','True'),('stale','info.st_mtime_ns>=since','True'),
            ('duplicate',"need(identity not in seen, 'duplicate-file')",'pass'),('phase',"since//1000000<=value['startTime']<=time.time_ns()//1000000 and ",''),
            ('mains','    parser=argparse.ArgumentParser(allow_abbrev=False);','    D.main([]); parser=argparse.ArgumentParser(allow_abbrev=False);'),
            ('head','re.fullmatch(D.HEX40,args.expected_head)','True'),
            ('location',source[source.index('    locations=[];'):source.index('    decoded=')],"    locations=[]\n    for (absolute,line,column),(path,anchor) in zip(frames,anchors):\n        expected,start,end=D.anchor_span(read(path),anchor.splitlines()[0] if anchor==HELPER else anchor)\n        need(absolute==str(fixture/path) and line==expected and start<=column<=end, 'location'); locations.append([path,line,column])\n"),
            ('deadline-verify',"    need(deadline-time.monotonic()>0, 'timeout')\n    verify_restoration",'    verify_restoration'),
            ('deadline-record',"    need(deadline-time.monotonic()>0, 'timeout')\n    terminal",'    terminal'),
            ('deadline-rename',"    need(deadline-time.monotonic()>0, 'timeout')\n    pending.rename",'    pending.rename')]
        for scenario,before,after in guards:
            self.assertEqual(source.count(before),1,scenario)
            for disabled in (False,True,False):
                result=subprocess.run([sys.executable,'-B','-c',program,str(probe),scenario,before,after,str(int(disabled))],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                self.assertEqual(result.returncode,int(disabled),(scenario,disabled,result.stderr.decode()))
                if disabled:self.assertIn(('AssertionError: oracle-'+scenario).encode(),result.stderr)

if __name__ == '__main__':
    unittest.main()
