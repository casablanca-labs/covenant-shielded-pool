#!/usr/bin/python3
"""Inventory and wiring oracles; no runtime fixture, build or host invocation."""
import ast
import contextlib
import copy
import importlib.util
import io
import json
import os
import re
import stat
import sys
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
SCRIPTS=Path(__file__).resolve().parent
ROOT=SCRIPTS.parents[2]
spec=importlib.util.spec_from_file_location('ordinary',SCRIPTS/'test-private-runner-ordinary.py')
ORDINARY=importlib.util.module_from_spec(spec);spec.loader.exec_module(ORDINARY)
spec=importlib.util.spec_from_file_location('runtime',SCRIPTS/'test-private-runner-runtime-no-proof.py')
RUNTIME=importlib.util.module_from_spec(spec);spec.loader.exec_module(RUNTIME)

def selected_result(selected,deselected):
    return {'testResults':[{'assertionResults':[
        {'fullName':'selected-synthetic','status':selected},
        *({'fullName':'deselected-synthetic-'+str(index),'status':status} for index,status in enumerate(deselected))]}],
        'numPassedTests':int(selected=='passed'),'numFailedTests':int(selected=='failed'),
        'numPendingTests':len(deselected),'success':selected=='passed'}

def runtime_suite_observation(source,value,status,want,selection='synthetic-selection',runtime=False):
    # Compile the actual nested suite and its actual refusal helper, not a copy
    # of the counting rules. Only its external command boundary is a stub.
    tree=ast.parse(source)
    main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
    suite=next(node for node in main.body if isinstance(node,ast.FunctionDef) and node.name=='suite')
    require=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='require')
    with tempfile.TemporaryDirectory(prefix='mig01-suite-count-',dir='/private/tmp') as directory:
        root=Path(directory);(root/'synthetic.json').write_text(json.dumps(value))
        calls=[]
        def run(label,args,want=None):
            calls.append((label,args,want));return status
        namespace={'raw':root,'NODE':Path('/synthetic/node'),'run':run,'json':json,
                   'summary':{'suites':[]},'root':root,'TEST':'synthetic.test.ts' if runtime else 'other.test.ts',
                   'inventory':RUNTIME.runtime_inventory(),'selection_class':'ordinary',
                   'runtime_pattern':RUNTIME.runtime_pattern,'require_runtime_selection':RUNTIME.require_runtime_selection}
        exec(compile(ast.Module(body=[require,suite],type_ignores=[]),'actual-runtime-suite','exec'),namespace)
        accepted=True
        with contextlib.redirect_stdout(io.StringIO()):
            try:namespace['suite']('synthetic',['synthetic.test.ts'],selection,want)
            except RuntimeError as error:
                if str(error)!='mig01-runtime-control-refused':raise
                accepted=False
        return {'accepted':accepted,'suites':namespace['summary']['suites'],'runCalls':len(calls)}

class OrdinarySelection(unittest.TestCase):
    def test_exact_runtime_inventory_and_selection_adversaries(self):
        # Evaluate registration/table expansion only. Every test callback is
        # removed by TypeScript AST before evaluation; no runtime module imports.
        script=r"""
const fs=require('node:fs'),vm=require('node:vm'),ts=require('typescript');
const tree=ts.createSourceFile('runtime.ts',fs.readFileSync(process.argv[1],'utf8'),ts.ScriptTarget.Latest,true);
function isTest(call){return ts.isCallExpression(call)&&(call.expression.getText(tree)==='test'||call.expression.getText(tree).startsWith('test.each('));}
const statements=tree.statements.filter(s=>ts.isVariableStatement(s)&&s.declarationList.declarations.some(d=>d.name.getText(tree)==='refusalCases')||ts.isExpressionStatement(s)&&isTest(s.expression)||ts.isForOfStatement(s));
const transformed=ts.transform(ts.factory.updateSourceFile(tree,statements),[context=>{function visit(node){if(isTest(node))return ts.factory.updateCallExpression(node,node.expression,node.typeArguments,[node.arguments[0],ts.factory.createArrowFunction(undefined,undefined,[],undefined,undefined,ts.factory.createBlock([])),...node.arguments.slice(2)]);return ts.visitEachChild(node,visit,context);}return node=>ts.visitNode(node,visit);}]).transformed[0];
const titles=[],test=title=>titles.push(title);
test.each=values=>title=>values.forEach(value=>{const args=Array.isArray(value)?value:[value];let i=0;titles.push(title.replace(/%[si]/g,()=>String(args[i++])));});
vm.runInNewContext(ts.transpileModule(ts.createPrinter().printFile(transformed),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText,{test});
process.stdout.write(JSON.stringify(titles.sort()));
"""
        collected=json.loads(subprocess.check_output(['node','-e',script,str(ROOT/RUNTIME.TEST)],cwd=ROOT))
        self.assertEqual(collected,RUNTIME.runtime_titles('union'))
        self.assertEqual(len(set(collected)),119)
        ordinary=set(RUNTIME.runtime_titles('ordinary'));resource=set(RUNTIME.runtime_titles('resource'))
        self.assertEqual((len(ordinary),len(resource),ordinary&resource),(115,4,set()))
        self.assertEqual(ordinary|resource,set(collected))
        self.assertIn('P13 fixed committed public selector writes its public result then fails closed before the summary',ordinary)
        def result(selection):
            selected=set(RUNTIME.runtime_titles(selection))
            return {'testResults':[{'assertionResults':[{'fullName':title,'status':'passed' if title in selected else 'pending'} for title in collected]}],
                    'numPassedTests':len(selected),'numFailedTests':0,'numPendingTests':119-len(selected),'success':True}
        for selection in ('union','ordinary','resource'):
            valid=result(selection);account=RUNTIME.require_runtime_selection(valid,selection)
            self.assertEqual((account['total'],account['selected'],account['deselected']),(119,valid['numPassedTests'],valid['numPendingTests']))
            for index in range(119):
                for kind in ('missing','duplicate','unknown','skip','status'):
                    bad=copy.deepcopy(valid);rows=bad['testResults'][0]['assertionResults']
                    if kind=='missing':rows.pop(index)
                    elif kind=='duplicate':rows[index]['fullName']=rows[(index+1)%119]['fullName']
                    elif kind=='unknown':rows[index]['fullName']='unknown-row'
                    elif kind=='status':rows[index]['status']='todo'
                    elif rows[index]['status']=='passed':rows[index]['status']='skipped';bad['numPassedTests']-=1;bad['numPendingTests']+=1
                    else:rows[index]['status']='passed';bad['numPassedTests']+=1;bad['numPendingTests']-=1
                    with self.assertRaisesRegex(RuntimeError,'^mig01-runtime-control-refused$'):RUNTIME.require_runtime_selection(bad,selection)
            with self.assertRaisesRegex(RuntimeError,'^mig01-runtime-control-refused$'):RUNTIME.require_runtime_selection(valid,selection,'matches-no-title')
        value=json.loads(RUNTIME.SELECTION_FILE.read_bytes())
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            path=Path(tmp)/'selection.json'
            for index in range(119):
                for kind in ('delete','duplicate','class','unknown-key','missing-key'):
                    bad=copy.deepcopy(value)
                    if kind=='delete':bad['rows'].pop(index)
                    elif kind=='duplicate':bad['rows'][index]=bad['rows'][(index+1)%119]
                    elif kind=='class':bad['rows'][index]['selection']='ordinary' if bad['rows'][index]['selection']=='resource' else 'resource'
                    elif kind=='unknown-key':bad['rows'][index]['extra']=True
                    else:del bad['rows'][index]['selection']
                    path.write_text(json.dumps(bad))
                    with self.assertRaisesRegex(RuntimeError,'^mig01-runtime-control-refused$'):RUNTIME.runtime_inventory(path)
            path.write_text(json.dumps(value));self.assertEqual(RUNTIME.runtime_inventory(path),value['rows'])
        # Isolate each changed guard in a source-only module; no driver main.
        source=(SCRIPTS/'test-private-runner-runtime-no-proof.py').read_text()
        for before,after in (("require(executed==selected)",'require(True)'),
            ("require(len(actual)==len(set(actual))==119 and set(actual)==set(titles))",'require(True)'),
            ("require(resource==RESOURCE_TITLES and {title for title in titles if title.startswith('PH11-RESOURCE ')}==resource)",'require(True)')):
            self.assertEqual(source.count(before),1)
            namespace={'__file__':str(SCRIPTS/'test-private-runner-runtime-no-proof.py'),'__name__':'synthetic_runtime'}
            exec(compile(source.replace(before,after),'mutated-accounting','exec'),namespace)
            if before.startswith('require(executed'):
                bad=result('ordinary');rows=bad['testResults'][0]['assertionResults'];a=next(row for row in rows if row['status']=='passed');b=next(row for row in rows if row['status']=='pending');a['status'],b['status']=b['status'],a['status']
                with self.assertRaises(RuntimeError):RUNTIME.require_runtime_selection(bad,'ordinary')
                namespace['require_runtime_selection'](bad,'ordinary')
            elif before.startswith('require(len(actual)'):
                bad=result('ordinary');rows=bad['testResults'][0]['assertionResults'];a,b=[row for row in rows if row['status']=='pending'][:2];a['fullName']=b['fullName']
                with self.assertRaises(RuntimeError):RUNTIME.require_runtime_selection(bad,'ordinary')
                namespace['require_runtime_selection'](bad,'ordinary')
            else:
                bad=copy.deepcopy(value);a=next(row for row in bad['rows'] if row['selection']=='ordinary');b=next(row for row in bad['rows'] if row['selection']=='resource');a['selection'],b['selection']=b['selection'],a['selection']
                with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
                    path=Path(tmp)/'inventory.json';path.write_text(json.dumps(bad))
                    with self.assertRaises(RuntimeError):RUNTIME.runtime_inventory(path)
                    namespace['runtime_inventory'](path)
            RUNTIME.require_runtime_selection(result('union'),'union')

    def test_resource_entry_reuses_driver_and_exact_command_wiring(self):
        spec=importlib.util.spec_from_file_location('resource_entry',SCRIPTS/'test-private-runner-runtime-resource.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with patch.object(module.DRIVER,'main',return_value=17) as main:
            self.assertEqual(module.main(['synthetic']),17)
            main.assert_called_once_with(['synthetic'],selection_class='resource')
            main.reset_mock()
            with patch.dict(os.environ,{'BCH_CLOAK_TEST_SLOT_LOCK_PATH':'/private/tmp/bch-ordinary-gate.lock'}):
                with self.assertRaisesRegex(RuntimeError,'^mig01-runtime-control-refused$'):module.main([])
            main.assert_not_called()
        self.assertIsNone(module.DRIVER.STAGE_DRIVER)
        source=(SCRIPTS/'test-private-runner-runtime-resource.py').read_text()
        before="DRIVER.require('BCH_CLOAK_TEST_SLOT_LOCK_PATH' not in os.environ)"
        self.assertEqual(source.count(before),1)
        namespace={'__file__':str(SCRIPTS/'test-private-runner-runtime-resource.py'),'__name__':'resource_override_mutant'}
        exec(compile(source.replace(before,'DRIVER.require(True)'),'resource-override-mutant','exec'),namespace)
        with patch.dict(os.environ,{'BCH_CLOAK_TEST_SLOT_LOCK_PATH':'/private/tmp/bch-ordinary-gate.lock'}), \
             patch.object(namespace['DRIVER'],'main',return_value=17) as leaf:
            def regression(entry):
                with self.assertRaisesRegex(RuntimeError,'^mig01-runtime-control-refused$'):entry([])
            regression(module.main)
            with self.assertRaises(AssertionError):regression(namespace['main'])
            leaf.assert_called_once_with([],selection_class='resource')
            regression(module.main)
        scripts=json.loads((ROOT/'package.json').read_bytes())['scripts']
        self.assertEqual(scripts['validate:pool-action-modules:resource'],'node scripts/test-slot/test-slot.mjs run validate:pool-action-modules:resource -- python3 tools/apnt-pool-action-circuit/scripts/test-private-runner-runtime-resource.py')
        self.assertEqual(RUNTIME.main.__defaults__,('ordinary',))
        for selected in ('ordinary','resource'):
            pattern=RUNTIME.runtime_pattern(selected)
            self.assertEqual([title for title in RUNTIME.runtime_titles('union') if re.search(pattern,title)],RUNTIME.runtime_titles(selected))

    def test_ordinary_private_operation_guard_fires_before_launch(self):
        source=(ROOT/RUNTIME.TEST).read_text()
        start="if(process.env.MIG01_RUNTIME_SELECTION==='ordinary'"
        end="throw new Error('ordinary-private-operation-refused');"
        self.assertEqual((source.count(start),source.count(end)),(1,1))
        guard=source[source.index(start):source.index(end)+len(end)]
        def observe(unit,selection,command):
            script="const selected={command:"+json.dumps(command)+"};process.env.MIG01_RUNTIME_SELECTION="+json.dumps(selection)+";let effects=0,code='';try{"+unit+"effects++;}catch(e){code=e.message;}process.stdout.write(JSON.stringify({code,effects}));"
            return json.loads(subprocess.check_output(['node','-e',script]))
        for selection,command in (('ordinary','check-live'),('resource','prove')):
            self.assertEqual(observe(guard,selection,command),{'code':'','effects':1})
        expected={'code':'ordinary-private-operation-refused','effects':0}
        def regression(unit):self.assertEqual(observe(unit,'ordinary','prove'),expected,'ordinary-operation-effect-oracle')
        regression(guard)
        for mutant in ('',guard.replace("selected.command!=='check-live'","selected.command==='check-live'")):
            self.assertEqual(observe(mutant,'ordinary','prove'),{'code':'','effects':1})
            with self.assertRaisesRegex(AssertionError,'ordinary-operation-effect-oracle'):regression(mutant)
            regression(guard)

    def test_runtime_slot_override_and_mutation_oracles(self):
        # Actual selectors and main refusal, relocated together. Never execute a
        # valid driver main: it would build the runtime and touch prover guards.
        source=(SCRIPTS/'test-private-runner-runtime-no-proof.py').read_text()
        key='BCH_CLOAK_TEST_SLOT_LOCK_PATH';token='BCH_CLOAK_TEST_SLOT_TOKEN'
        admission=source[source.index("        if 'BCH_CLOAK_TEST_SLOT_LOCK_PATH' in os.environ:"):source.index('        prover_paths =')]
        self.assertIn('resolve(strict=True)',admission)
        counts={'refusals':0,'mutants':0,'restored':0}
        def world(text,control):
            with tempfile.TemporaryDirectory(prefix='eng1544-driver-',dir='/private/tmp') as directory:
                root=Path(directory);shared=root/'shared.lock';selected=root/'bch-ordinary-gate.lock'
                reserved=[root/name for name in (f'apnt-gnark-r2-proof-{os.getuid()}.lock','bch-cloak-sp1-prover-exclusive-v1','.prover.lock')]
                relocated=text.replace("'/private/tmp/bch-cloak-test-slot.lock'",repr(str(shared)))
                relocated=relocated.replace("!= '/private/tmp'",'!= '+repr(str(root)))
                for before,path in zip(("f'/private/tmp/apnt-gnark-r2-proof-{os.getuid()}.lock'",
                    "'/private/tmp/bch-cloak-sp1-prover-exclusive-v1'","os.path.expanduser('~/proof-scratch/.prover.lock')"),reserved):
                    relocated=relocated.replace(before,repr(str(path)))
                tree=ast.parse(relocated)
                units=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ('require','slot_available','main')]
                namespace={'os':os,'re':re,'Path':Path,'stat':stat,'json':json,'tempfile':tempfile,'runtime_inventory':RUNTIME.runtime_inventory,'runtime_titles':RUNTIME.runtime_titles}
                exec(compile(ast.Module(body=units,type_ignores=[]),'actual-driver-selector','exec'),namespace)
                shared.write_text(json.dumps({'token':'foreign-shared-synthetic'}))
                foreign=shared.read_bytes()
                def check(value,expected,holder=None,explicit=None):
                    env={} if value is None else {key:str(value)}
                    if holder is not None:env[token]=holder
                    with patch.object(os,'environ',env):self.assertIs(namespace['slot_available'](explicit),expected)
                def refuse(value,early=False):
                    before=sorted(str(path.relative_to(root)) for path in root.rglob('*'))
                    with patch.object(os,'environ',{key:str(value),token:'synthetic'}), contextlib.ExitStack() as stack:
                        stack.enter_context(patch.object(os,'open',side_effect=AssertionError('forbidden-lock-open')))
                        stack.enter_context(patch.object(json,'load',side_effect=AssertionError('forbidden-lock-read')))
                        stack.enter_context(patch.object(tempfile,'mkdtemp',side_effect=AssertionError('forbidden-driver-scratch')))
                        stack.enter_context(patch.object(subprocess,'Popen',side_effect=AssertionError('forbidden-child')))
                        stack.enter_context(patch.object(os,'umask',return_value=0o077))
                        if early:
                            stack.enter_context(patch.object(os,'lstat',side_effect=AssertionError('forbidden-lstat')))
                            stack.enter_context(patch.object(re,'fullmatch',side_effect=AssertionError('slash-must-refuse-before-name-check')))
                        with self.assertRaisesRegex(RuntimeError,'^mig01-runtime-control-refused$'):
                            namespace['main']([])
                    self.assertEqual(sorted(str(path.relative_to(root)) for path in root.rglob('*')),before)
                    self.assertEqual(shared.read_bytes(),foreign)
                    counts['refusals']+=1
                    print('eng1544-driver-refusal='+json.dumps({'input':str(value),'code':'mig01-runtime-control-refused',
                        'childStarted':False,'scratchCreated':False,'listingUnchanged':True,'foreignHolderUnchanged':True},sort_keys=True))
                control(root,shared,selected,reserved,check,refuse)
                self.assertEqual(shared.read_bytes(),foreign)
        def normal(root,shared,selected,reserved,check,refuse):
            # Default is screened, but must not acquire the explicit-name rule.
            check(None,False);check(None,True,'foreign-shared-synthetic')
            shared.unlink();check(None,True);shared.write_text(json.dumps({'token':'foreign-shared-synthetic'}))
            for name in ('bch-ordinary-gate.lock','bch-ordinary-gate-a1.lock'):
                target=root/name;check(target,True)
                target.write_text(json.dumps({'token':'synthetic'}))
                check(target,True,'synthetic');check(target,False,'foreign');check(target,False)
                target.unlink()
            check(selected,False,explicit=str(shared))
            link=root/'bch-ordinary-gate-link.lock';link.symlink_to(selected)
            check(None,False,'synthetic',explicit=str(link));link.unlink()
            fifo=root/'bch-ordinary-gate-fifo.lock';os.mkfifo(fifo)
            check(None,False,'synthetic',explicit=str(fifo));fifo.unlink()
            selected.write_text('invalid-json');check(selected,False,'synthetic');selected.unlink()
            for name in ('ordinary.lock','BCH-ordinary-gate.lock','bch-ordinary-gateXlock','bch-ordinary-gate.lock\n',
                         'bch-ordinary-gate'+chr(0x17f)+'.lock','bch-ordinary-gate.lock.extra'):
                refuse(root/name)
            for value in ('','relative.lock',str(root),str(root/'nul\0lock'),str(root/'absent/bch-ordinary-gate.lock')):
                refuse(value)
        world(source,normal)
        namespace_off=(admission,'')
        cases=(('firmlink',namespace_off),('volume-inode',namespace_off),('long-s',namespace_off),
            ('upper-basename',namespace_off),('physical-parent',namespace_off),
            ('dangling-symlink',('if candidate is not None and not stat.S_ISREG(candidate.st_mode): return False','if False: return False')),
            ('hard-link',('if candidate is not None and (candidate.st_dev, candidate.st_ino) == (reserved.st_dev, reserved.st_ino): return False','if False: return False')),
            ('fifo',('if candidate is not None and not stat.S_ISREG(candidate.st_mode): return False','if False: return False')),
            ('trailing-slash',None))
        for case,mutation in cases:
            for index in ([1] if case=='long-s' else range(3)):
                for present in ([True] if case=='hard-link' else [False,True]):
                    def control(root,shared,selected,reserved,check,refuse):
                        target=reserved[index]
                        if present:target.write_text('synthetic-reserved')
                        if case=='firmlink':candidate='/System/Volumes/Data'+str(target)
                        elif case=='volume-inode':
                            parent=root.stat();candidate=f'/.vol/{parent.st_dev}/{parent.st_ino}/{target.name}'
                        elif case=='long-s':candidate=root/('bch-cloak-'+chr(0x17f)+'p1-prover-exclusive-v1')
                        elif case=='upper-basename':candidate=target.with_name(target.name.upper())
                        elif case=='physical-parent':
                            (root/'local').mkdir();(root/'deep').mkdir();(root/'local/link').symlink_to(root/'deep')
                            candidate=str(root)+'/local/link/../'+target.name
                        elif case=='dangling-symlink':selected.symlink_to(target);candidate=selected
                        elif case=='hard-link':os.link(target,selected);candidate=selected
                        elif case=='fifo':os.mkfifo(selected);candidate=selected
                        elif case=='trailing-slash':candidate=str(target)+'/'
                        refuse(candidate)
                        if present:self.assertEqual(target.read_text(),'synthetic-reserved')
                        else:self.assertFalse(target.exists())
                    with self.subTest(case=case,index=index,present=present):
                        world(source,control)
                        if mutation and (not present or case=='hard-link'):
                            before,after=mutation;self.assertEqual(source.count(before),1,'unique mutation anchor')
                            with self.assertRaises(AssertionError):world(source.replace(before,after),control)
                            counts['mutants']+=1
                            world(source,control);counts['restored']+=1
        # Isolate the parent rule using an allowed basename, so name admission
        # cannot mask its mutant. Strict-resolution failures refuse too.
        parent="if str(Path(os.path.dirname(lock_path)).resolve(strict=True)) != '/private/tmp': return False"
        def forbidden_parent(root,shared,selected,reserved,check,refuse):
            (root/'other').mkdir();refuse(root/'other/bch-ordinary-gate.lock')
        self.assertEqual(source.count(parent),1)
        world(source,forbidden_parent)
        with self.assertRaises(AssertionError):world(source.replace(parent,'pass'),forbidden_parent)
        counts['mutants']+=1;world(source,forbidden_parent);counts['restored']+=1
        def slash(root,shared,selected,reserved,check,refuse):
            selected.write_text('synthetic');refuse(str(selected)+'/',early=True)
        world(source,slash)
        before=" or lock_path.endswith('/')";self.assertEqual(source.count(before),1)
        with self.assertRaises(AssertionError):world(source.replace(before,''),slash)
        counts['mutants']+=1;world(source,slash);counts['restored']+=1
        # Existing holder/open guards retain independent focused firing controls.
        for before,after in (("holder.get('token') == token",'True'),
            ('if lock_path is None:','if True:'),
            ('if not os.path.lexists(lock_path): return True','if not os.path.lexists(lock_path): return False'),
            ('except (OSError, ValueError):\n        return False','except (OSError, ValueError):\n        return True')):
            self.assertEqual(source.count(before),1)
            world(source,normal)
            with self.assertRaises(AssertionError):world(source.replace(before,after),normal)
            counts['mutants']+=1;world(source,normal);counts['restored']+=1
        print('eng1544-bounded-driver-oracle='+json.dumps(counts,sort_keys=True))

    def test_finite_inventory_and_host_partition_are_complete(self):
        selected=ORDINARY.inventory()
        self.assertEqual((len(selected),sum(len(ids) for _,ids in selected)),(16,209))
        self.assertEqual(len(ORDINARY.HOST_ONLY),4)
        self.assertFalse(set(item for _,ids in selected for item in ids)&ORDINARY.HOST_ONLY)
        self.assertFalse(any('reproduce-' in path or path in ('kernel-attribution.py','kernel-attribution-capture.py') for path,_ in selected))

    def test_missing_added_and_wrong_class_inventory_mutations_fire_then_restore(self):
        with tempfile.TemporaryDirectory(prefix='mig01-ordinary-inventory-',dir='/private/tmp') as directory:
            base=Path(directory)
            for filename,_ in ORDINARY.SELECTIONS:(base/filename).write_bytes((SCRIPTS/filename).read_bytes())
            path=base/'test-native-process-scan.py';original=path.read_text()
            with patch.object(ORDINARY,'SCRIPTS',base):
                for mutant in (original.replace('def test_global_unknown_selector_refuses(', 'def unused_global_unknown_selector_refuses('),
                    original.replace('class NativeScan(unittest.TestCase):','class NativeScan(unittest.TestCase):\n    def test_unreviewed_extra(self):pass'),
                    original+'\nclass Unreviewed(unittest.TestCase):\n    def test_extra(self):pass\n'):
                    path.write_text(mutant)
                    with self.assertRaisesRegex(RuntimeError,'^mig01-ordinary-control-refused$'):ORDINARY.inventory()
                    path.write_text(original);self.assertEqual(sum(len(ids) for _,ids in ORDINARY.inventory()),209)

    def test_actual_runtime_suite_accounts_for_selected_results_and_deselections(self):
        source=(SCRIPTS/'test-private-runner-runtime-no-proof.py').read_text()
        valid=0
        for deselected in (('skipped',),('pending',),('skipped','pending')):
            for selected in ('passed','failed'):
                status=int(selected=='failed');value=selected_result(selected,deselected)
                observed=runtime_suite_observation(source,value,status,status)
                self.assertTrue(observed['accepted'],'valid-selected-suite-refused')
                self.assertEqual(observed['runCalls'],1)
                self.assertEqual(observed['suites'],[{'label':'synthetic','tests':1,'passed':int(selected=='passed'),
                    'failed':int(selected=='failed'),'deselected':len(deselected),
                    'rows':[{'name':'selected-synthetic','status':selected}]}])
                valid+=1
        valid_pass=selected_result('passed',('skipped',));invalid=[]
        for key,bad in (('numPassedTests',0),('numFailedTests',1),('numPendingTests',0),
                        ('numPassedTests',True),('numFailedTests',-1),('numPendingTests','1'),('success',1)):
            value=copy.deepcopy(valid_pass);value[key]=bad;invalid.append(value)
        for unknown in ('todo','SYNTHETIC_UNKNOWN',None):
            value=copy.deepcopy(valid_pass);value['testResults'][0]['assertionResults'][1]['status']=unknown;invalid.append(value)
        value=copy.deepcopy(valid_pass);del value['numPendingTests'];invalid.append(value)
        value=copy.deepcopy(valid_pass);del value['testResults'][0]['assertionResults'][1]['status'];invalid.append(value)
        value=copy.deepcopy(valid_pass);value['testResults'][0]['assertionResults'][0]['status']='skipped'
        value.update(numPassedTests=0,numPendingTests=2);invalid.append(value)
        value=copy.deepcopy(valid_pass);value.update(numPassedTests=0,numFailedTests=1);invalid.append(value)
        for value in invalid:
            self.assertFalse(runtime_suite_observation(source,value,0,0)['accepted'],'invalid-suite-accepted')
        self.assertFalse(runtime_suite_observation(source,valid_pass,1,0)['accepted'])
        self.assertFalse(runtime_suite_observation(source,selected_result('failed',('skipped',)),0,1)['accepted'])
        self.assertFalse(runtime_suite_observation(source,{**valid_pass,'success':False},0,0)['accepted'])
        # Execute the canonical ordinary baseline with four exact deselections.
        for count,accepted in ((115,True),(114,False)):
            value={'testResults':[{'assertionResults':[{'fullName':title,'status':'passed' if title in RUNTIME.runtime_titles('ordinary')[:count] else 'pending'} for title in RUNTIME.runtime_titles('union')]}],
                'numPassedTests':count,'numFailedTests':0,'numPendingTests':119-count,'success':True}
            self.assertEqual(runtime_suite_observation(source,value,0,0,None,True)['accepted'],accepted)
        marker="rows = [row for row in all_rows if row['status'] in ('passed','failed')]"
        self.assertEqual(source.count(marker),1)
        mutant=source.replace(marker,"rows = [row for row in all_rows if row['status'] != 'pending']")
        regression=r'''
import importlib.util,pathlib,sys
spec=importlib.util.spec_from_file_location('count_controls',sys.argv[1]);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
value=module.selected_result('passed',('skipped',))
observed=module.runtime_suite_observation(pathlib.Path(sys.argv[2]).read_text(),value,0,0)
sys.exit(0 if observed['accepted'] and observed['suites'][0]['tests']==1 and observed['suites'][0]['deselected']==1 else 19)
'''
        with tempfile.TemporaryDirectory(prefix='mig01-counter-mutation-',dir='/private/tmp') as directory:
            path=Path(directory)/'runtime.py';statuses=[]
            for candidate in (source,mutant,source):
                path.write_text(candidate)
                result=subprocess.run(['/usr/bin/python3','-c',regression,str(Path(__file__)),str(path)],capture_output=True,timeout=10)
                self.assertEqual((len(result.stdout),len(result.stderr)),(0,0));statuses.append(result.returncode)
            self.assertEqual(statuses,[0,19,0])
        print('runtime-selection-oracle='+json.dumps({'validSelectedCases':valid,'invalidAccountingCases':len(invalid),
            'mutationStatuses':statuses,'runtimeMainCalled':False,'realRuntimeExecuted':False}))

    def test_entry_keeps_checkout_clean_without_caller_flags_and_mutations_fire(self):
        # Execute the actual router with one synthetic class and both an import
        # and a Python child import. The caller deliberately supplies no -B/env.
        original=(SCRIPTS/'test-private-runner-ordinary.py').read_text()
        bootstrap=r'''
import pathlib,sys
base=pathlib.Path(sys.argv[1]);path=base/'router.py'
namespace={'__file__':str(path),'__name__':'synthetic_router'}
exec(compile(path.read_text(),str(path),'exec'),namespace)
namespace.update(SCRIPTS=base,SELECTIONS=(('synthetic.py',(('Synthetic',1),)),),EXPECTED=1,HOST_ONLY=frozenset())
sys.argv=['router'];status=namespace['main']()
polluted=any(path.name.startswith(('synthetic.','own_helper.','child_helper.')) for path in base.rglob('*.pyc'))
sys.exit(19 if status==0 and polluted else status)
'''
        case='''import pathlib,subprocess,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import own_helper
class Synthetic(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(own_helper.value,1)
        self.assertEqual(subprocess.run([sys.executable,'-c','import child_helper'],cwd=pathlib.Path(__file__).parent,capture_output=True).returncode,0)
'''
        with tempfile.TemporaryDirectory(prefix='mig01-bytecode-',dir='/private/tmp') as directory:
            base=Path(directory);env=dict(os.environ);env.pop('PYTHONDONTWRITEBYTECODE',None)
            for mutation in ('sys.dont_write_bytecode = True',"os.environ['PYTHONDONTWRITEBYTECODE'] = '1'"):
                statuses=[]
                for index,mutated in enumerate((False,True,False)):
                    root=base/str(len(list(base.iterdir())));root.mkdir()
                    (root/'router.py').write_text(original.replace(mutation,'pass # synthetic mutation') if mutated else original)
                    (root/'synthetic.py').write_text(case)
                    for name in ('own_helper.py','child_helper.py'):(root/name).write_text('value=1\n')
                    env['PYTHONPYCACHEPREFIX']=str(root/'bytecode')
                    result=subprocess.run(['/usr/bin/python3','-c',bootstrap,str(root)],capture_output=True,env=env,timeout=10)
                    self.assertEqual(len(result.stderr),0);statuses.append(result.returncode)
                self.assertEqual(statuses,[0,19,0])

    def test_failure_error_skip_and_wrong_count_never_pass(self):
        class Valid(unittest.TestCase):
            def runTest(self):pass
        class Failed(unittest.TestCase):
            def runTest(self):self.fail('SYNTHETIC_PRIVATE_TEXT_CANARY')
        class Error(unittest.TestCase):
            def runTest(self):raise RuntimeError('SYNTHETIC_PRIVATE_TEXT_CANARY')
        class Skipped(unittest.TestCase):
            def runTest(self):self.skipTest('SYNTHETIC_PRIVATE_TEXT_CANARY')
        for case,fields in ((Valid,(0,0,0,True)),(Failed,(1,0,0,False)),(Error,(0,1,0,False)),(Skipped,(0,0,1,False))):
            value=ORDINARY.execute(unittest.TestSuite([case()]),1)
            self.assertEqual(tuple(value[key] for key in ('failures','errors','skipped','passed')),fields)
            self.assertNotIn('SYNTHETIC_PRIVATE_TEXT_CANARY',json.dumps(value))
        self.assertFalse(ORDINARY.execute(unittest.TestSuite([Valid()]),2)['passed'])

    def test_canonical_registration_and_single_runtime_supplement(self):
        scripts=json.loads((ROOT/'package.json').read_bytes())['scripts']
        entry='python3 tools/apnt-pool-action-circuit/scripts/test-private-runner-ordinary.py'
        circuit=scripts['validate:pool-action-circuit'].split(' && ')
        self.assertEqual((circuit[0],circuit.count(entry)),(entry,1));self.assertEqual(len(circuit),4)
        modules=scripts['validate:pool-action-modules'].split(' && ')
        self.assertIn('mig01-producers.test.ts',modules[-2])
        self.assertEqual(modules[-1],'python3 tools/apnt-pool-action-circuit/scripts/test-private-runner-runtime-no-proof.py')
        source=(SCRIPTS/'test-private-runner-runtime-no-proof.py').read_text();tree=ast.parse(source)
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name)]
        runtime=[node for node in calls if node.func.id=='suite' and node.args and isinstance(node.args[0],ast.Constant) and node.args[0].value=='runtime']
        host=[node for node in calls if node.func.id=='run' and node.args and isinstance(node.args[0],ast.Constant) and node.args[0].value=='native-inventory-guard-controls']
        readiness=[node for node in calls if node.func.id=='run' and node.args and isinstance(node.args[0],ast.Constant) and node.args[0].value=='eng1459-whole-host-readiness']
        self.assertEqual((len(runtime),len(host),len(readiness)),(1,1,1))
        helper=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='native_control_command')
        namespace={};exec(compile(ast.Module(body=[helper],type_ignores=[]),'actual-host-selection','exec'),namespace)
        ordinary=namespace['native_control_command']();temporary=namespace['native_control_command'](True)
        for args in (ordinary,temporary):self.assertEqual(args[:3],['/usr/bin/python3','tools/apnt-pool-action-circuit/scripts/test-native-process-scan.py','--host'])
        self.assertEqual((len(ordinary[3:]),len(temporary[3:])),(3,1))
        self.assertEqual(set(ordinary[3:]+temporary[3:]),ORDINARY.HOST_ONLY)
        self.assertLess(host[0].lineno,readiness[0].lineno);self.assertLess(readiness[0].lineno,runtime[0].lineno)
        main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
        guarded=next(node for node in main.body if isinstance(node,ast.If) and any(item is target for item in ast.walk(node) for target in readiness))
        self.assertEqual(ast.unparse(guarded.test),'readiness')
        self.assertIn("receipt['maxUnavailablePerMode']==0",source)
        self.assertIn("--candidate-readiness-eng1459",source)
        self.assertFalse(any(value in source for value in ('reproduce-kernel-stock-no-proof','kernel-attribution','instrument_attribution','ENG1436_DIAGNOSTIC_ROLE')))

if __name__=='__main__':unittest.main()
