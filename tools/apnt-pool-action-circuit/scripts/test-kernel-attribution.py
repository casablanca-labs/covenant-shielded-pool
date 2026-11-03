#!/usr/bin/python3
"""Focused disposable attribution controls; no genuine runner or private input."""
import ast
import hashlib
import importlib.util
import json
import os
import pwd
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode=True

ROOT=Path(__file__).resolve().parents[3]
SCRIPTS=ROOT/'tools/apnt-pool-action-circuit/scripts'
NODE=str(Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.nvm/versions/node/v22.22.3/bin/node')


def module(name):
    path=SCRIPTS/name;spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


ATTR=module('kernel-attribution.py')
REPRO=module('reproduce-kernel-stock-no-proof.py')


def row(producer,branch,status=0,error=0,aux=0):
    return {'producer':producer,'branch':branch,'status':status,'errno':error,'auxStatus':aux}


def lines(rows):return ''.join(json.dumps(value,separators=(',',':'))+'\n' for value in rows)

def observer_rows():return [{**row('number',branch),'value':0} for branch in ('observer-exit','observer-stderr-bytes','observer-elapsed-ms')]


def admission_stubs(source):
    # Execute the real operation selector; these attribution controls replace
    # only host inventory/memory access, which has separate firing controls.
    selector='requires_proving_admission() {'+source.split('requires_proving_admission() {',1)[1].split('names=()',1)[0]
    return selector+'\nrequire_quiet_machine(){ :; }\nrequire_runner_exclusivity(){ :; }\n'


class AttributionControls(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='other-provers-attribution-',dir='/private/tmp');self.addCleanup(self.temporary.cleanup)
        self.base=Path(self.temporary.name);self.trace=self.base/'trace.jsonl';self.trace.touch(mode=0o600)
        self.source=(ROOT/ATTR.RUNNER).read_text()

    def boundary(self,source):
        return source.split('# ---- private diagnostic boundary ----',1)[1].split('# ---- end private diagnostic boundary ----',1)[0]

    def collect(self,raw,annotated=True,status=1):
        source=ATTR.collector(self.source,self.trace,ATTR.BRANCHES) if annotated else self.source
        helper='eng1436_trace(){ :; }\n'
        script='set -euo pipefail\nPRIVATE_RUNNER_GENERATION=2\nhas_live=true\ncleanup(){ :; }\n'+helper+self.boundary(source)
        script+='\n/bin/cat >&2\nexit '+str(status)+'\n'
        result=subprocess.run(['/bin/bash','-c',script],input=raw,capture_output=True,timeout=5)
        records=[json.loads(line) for line in self.trace.read_bytes().splitlines()]
        return result,records

    def test_collector_preserves_original_exit_and_whole_stream_bytes(self):
        cases=[b'',b'live-request-process-list-unavailable\n',b'SYNTHETIC_PRIVATE_TEXT_CANARY\n',
               b'live-request-process-list-unavailable\nSYNTHETIC_PRIVATE_TEXT_CANARY\n',
               b'{"status":1,"reason":"arguments-query","errno":22,"confirmation":"query-error","confirmationErrno":1}\n',
               b'X'*100000,b'unterminated']
        for raw in cases:
            old,_=self.collect(raw,False);actual,records=self.collect(raw)
            self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(old.returncode,old.stdout,old.stderr))
            self.assertEqual(actual.returncode,1);self.assertTrue(records)
            for value in records:ATTR.validate(value)
            self.assertNotIn(b'SYNTHETIC_PRIVATE_TEXT_CANARY',self.trace.read_bytes())
        self.assertIn(row('native-scan','arguments-query-query-error',1,22,1),[json.loads(line) for line in self.trace.read_bytes().splitlines()])
        success,_=self.collect(b'',status=0);self.assertEqual((success.returncode,success.stdout,success.stderr),(0,b'',b''))

    def test_native_unknown_missing_types_and_extra_lines_never_project_private_fields(self):
        good=b'{"status":1,"reason":"arguments-query","errno":22}\n'
        bads=[good.replace(b'arguments-query',b'SYNTHETIC_PRIVATE_TEXT_CANARY'),good.replace(b'22',b'true'),
              good.replace(b'22',b'22.0'),good.replace(b'22',b'4096'),good.replace(b'{',b'{"private":"SYNTHETIC_PRIVATE_TEXT_CANARY",'),
              good.replace(b'{',b'{"status":1,'),good.rstrip(),b' '+good]
        for raw in bads:
            self.trace.write_bytes(b'');result,records=self.collect(raw)
            self.assertEqual((result.returncode,result.stderr),(1,b'measure-pk-load: live-plan-refused reason=unclassified\n'))
            self.assertFalse(any(value['producer']=='native-scan' for value in records))
            self.assertNotIn(b'SYNTHETIC_PRIVATE_TEXT_CANARY',self.trace.read_bytes())
        self.trace.write_bytes(b'');result,records=self.collect(good+b'SYNTHETIC_PRIVATE_TEXT_CANARY\n')
        self.assertIn(row('native-scan','arguments-query',1,22),records)
        self.assertIn(row('collector','unknown-line',1),records)
        self.assertEqual((result.returncode,result.stderr),(1,b'measure-pk-load: live-plan-refused reason=unclassified\n'))

    def fixture(self):
        fixture=self.base/'fixture';fixture.mkdir()
        paths=[ATTR.RUNNER,ATTR.MAIN,ATTR.GO_BRIDGE,ATTR.BOOTSTRAP,ATTR.BRIDGE,ATTR.INSTALLATION,ATTR.READER,ATTR.LIVE,REPRO.TEST]
        for relative in paths:
            path=fixture/relative;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((ROOT/relative).read_bytes())
        generated=ast.parse(REPRO.diagnostic_driver(ROOT));main=next(node for node in generated.body if isinstance(node,ast.FunctionDef) and node.name=='main')
        for node in main.body:
            if isinstance(node,ast.For) and isinstance(node.target,ast.Tuple) and isinstance(node.iter,ast.List):
                for relative,before,after in ast.literal_eval(node.iter):
                    if relative==REPRO.TEST:
                        source=(fixture/relative).read_text();self.assertEqual(source.count(before),1);(fixture/relative).write_text(source.replace(before,after))
        self.trace.unlink();branches=ATTR.instrument(fixture,self.trace)
        return fixture,branches

    def test_same_invocation_installation_refusal_is_captured_before_outer_drain(self):
        fixture,branches=self.fixture();source=(fixture/ATTR.RUNNER).read_text()
        helper=source.split('eng1436_trace() {',1)[1].split('eng1436_trace entry 0',1)[0]
        script='set -euo pipefail\nPRIVATE_RUNNER_GENERATION=2\nhas_live=true\ncleanup(){ :; }\neng1436_trace() {'+helper+self.boundary(source)
        script+='\neng1436_trace entry 0\n/usr/bin/python3 '+str(fixture/ATTR.INSTALLATION)+' --invalid\n'
        self.trace.write_text(lines([row('control','kernel-fixed-begin')]))
        actual=subprocess.run(['/bin/bash','-c',script],capture_output=True,timeout=5)
        self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(1,b'',b'measure-pk-load: live-plan-refused reason=unclassified\n'))
        with self.trace.open('a') as sink:sink.write(lines(observer_rows()+[row('control','kernel-fixed-end',1)]))
        result=ATTR.closed(self.trace,branches,{'kernel-fixed':{'status':1,'contacts':[0,0,0],'deliveries':[0,0,0]}})
        self.assertIn(row('installation','root',1),result['kernel-fixed']['records'])
        self.assertIn(row('collector','unknown-line',1),result['kernel-fixed']['records'])
        self.assertEqual(result['kernel-fixed']['runnerStatus'],1)
        print('same-invocation-refusal='+json.dumps({'originalStatus':1,'outerReason':'unclassified','producer':'installation','branch':'root','producerStatus':1,'rawStreamsRetained':False}))

    def test_transformed_sources_compile_and_preserve_assertions(self):
        fixture,_=self.fixture()
        for relative in (ATTR.RUNNER,):
            result=subprocess.run(['/bin/bash','-n',str(fixture/relative)],capture_output=True);self.assertEqual((result.returncode,len(result.stderr)),(0,0))
        for relative in (ATTR.BOOTSTRAP,ATTR.BRIDGE):
            result=subprocess.run([NODE,'--check',str(fixture/relative)],capture_output=True);self.assertEqual((result.returncode,len(result.stderr)),(0,0))
        compile((fixture/ATTR.INSTALLATION).read_text(),str(fixture/ATTR.INSTALLATION),'exec')
        syntax='const ts=require("typescript"),fs=require("node:fs");const r=ts.transpileModule(fs.readFileSync(process.argv[1],"utf8"),{reportDiagnostics:true,compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}});if(r.diagnostics?.length)process.exit(19);fs.writeFileSync(process.argv[2],r.outputText)'
        compiled=self.base/'runtime.mjs'
        actual=subprocess.run([NODE,'-e',syntax,str(fixture/REPRO.TEST),str(compiled)],cwd=ROOT,capture_output=True)
        self.assertEqual((actual.returncode,len(actual.stderr)),(0,0))
        actual=subprocess.run([NODE,'--check',str(compiled)],capture_output=True)
        self.assertEqual((actual.returncode,len(actual.stderr)),(0,0))
        for relative in (ATTR.MAIN,ATTR.GO_BRIDGE,ATTR.GO_TRACE):
            result=subprocess.run(['/opt/homebrew/bin/gofmt','-w',str(fixture/relative)],capture_output=True);self.assertEqual((result.returncode,len(result.stderr)),(0,0))
        donor=(ROOT/REPRO.TEST).read_text()
        assertions=lambda text:[line for line in text.splitlines() if 'expect(' in line]
        self.assertEqual(assertions((fixture/REPRO.TEST).read_text()),assertions(donor))
        self.assertNotIn('process.env.ENG1436',(fixture/ATTR.BOOTSTRAP).read_text())

    def test_real_owning_go_helpers_preserve_output_exit_and_refusal(self):
        fixture,branches=self.fixture();package=self.base/'go-unit';package.mkdir()
        (package/'go.mod').write_text('module eng1436/attribution\n\ngo 1.24\n')
        owner=ROOT/'tools/apnt-pool-action-circuit/internal/runneradmission'
        for name in ('bridge.go','harness.go','refusal.go','prerequisite.go'):
            source=fixture/ATTR.GO_BRIDGE if name=='bridge.go' else owner/name
            (package/name).write_bytes(source.read_bytes())
        (package/'eng1436_diagnostic.go').write_bytes((fixture/ATTR.GO_TRACE).read_bytes())
        (package/'attribution_test.go').write_text('''package runneradmission
import("os";"os/exec";"testing")
func TestAttributionStatuses(t *testing.T){
 for _,status:=range []string{"0","19"}{command:=exec.Command("/bin/sh","-c","exit "+status);err:=helperRun(command);if (status=="0")!=(err==nil){t.Fatal("status changed")}}
 command:=exec.Command("/bin/sh","-c","printf synthetic; exit 19");output,err:=helperOutput(command)
 if string(output)!="synthetic" || DiagnosticStatus(err)!=19{t.Fatal("output/status changed")}
}
func TestAttributionRefusal(t *testing.T){
 original:=os.Args;defer func(){os.Args=original}();os.Args=[]string{"unit","invalid"}
 snapshot,err:=AcquireSnapshot("/invalid","/synthetic")
 if snapshot!=nil || err==nil || err.Error()!="private-runner-refused"{t.Fatal("refusal changed")}
}
''')
        environment={**os.environ,'GOENV':'off','GOPROXY':'off','GOTOOLCHAIN':'local','GOFLAGS':''}
        binary=package/'helpers.test'
        built=subprocess.run(['/opt/homebrew/bin/go','test','-c','-o',str(binary),'.'],cwd=package,env=environment,capture_output=True,timeout=60)
        self.assertEqual((built.returncode,len(built.stderr)),(0,0))
        actual=subprocess.run([str(binary),'-test.count=1','-test.run=^TestAttribution(Statuses|Refusal)$'],cwd=package,env=environment,capture_output=True,timeout=60)
        self.assertEqual((actual.returncode,len(actual.stderr)),(0,0))
        records=[json.loads(line) for line in self.trace.read_bytes().splitlines()]
        for record in records:ATTR.validate(record,branches)
        self.assertIn(row('helper','other',19),records);self.assertIn(row('helper','other',0),records)
        self.assertIn(row('bridge','fixed-invocation',-1),records)
        print('attribution-go-helpers='+json.dumps({'tests':2,'exit':actual.returncode,'helperFailureStatus':19,'refusalPreserved':True,
                'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
                'sourceDigests':{path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in package.glob('*.go')}}))

    def test_shell_admission_status_preserves_refusal_and_forbidden_continuation(self):
        fixture,branches=self.fixture();source=(fixture/ATTR.RUNNER).read_text()
        for args in (['init','-b','main'],['add','.'],['-c','user.name=Fixture','-c','user.email=fixture@invalid','-c','commit.gpgsign=false','commit','-m','Synthetic source']):
            actual=subprocess.run(['/usr/bin/git',*args],cwd=fixture,capture_output=True);self.assertEqual(actual.returncode,0)
        helper='eng1436_trace() {'+source.split('eng1436_trace() {',1)[1].split('eng1436_trace entry 0',1)[0]
        die='die() {'+source.split('die() {',1)[1].split('\ncleanup() {',1)[0]
        prefix='run_case() {'+source.split('run_case() {',1)[1].split('\tlocal inputs=() f i=0',1)[0]+'\n}\n'
        for status in (0,19):
            binary=self.base/('admit-'+str(status));binary.write_text('#!/bin/bash\nexit '+str(status)+'\n');binary.chmod(0o700)
            continued=self.base/('continued-'+str(status));results=self.base/'results';results.mkdir(exist_ok=True)
            script='set -euo pipefail\nPRIVATE_RUNNER_GENERATION=2\nhas_live=true\nout=""\nrepo='+str(fixture)+'\nbin='+str(binary)+'\nresults='+str(results)+'\n'+admission_stubs(source)+helper+'\n'+die+'\n'+prefix
            script+='\nrun_case control 17 asis ok check-live --request /synthetic\n: >'+str(continued)+'\n'
            actual=subprocess.run(['/bin/bash','-c',script],capture_output=True,timeout=5)
            self.assertEqual((actual.returncode,continued.exists(),actual.stdout,actual.stderr),(0 if status==0 else 1,status==0,b'',b''))
            records=[ATTR.validate(json.loads(line),branches) for line in self.trace.read_bytes().splitlines()]
            self.assertIn(row('shell','admit',status),records)
        print('attribution-admission='+json.dumps({'validStatus':0,'invalidProducerStatus':19,'invalidRunnerStatus':1,'forbiddenContinuation':False}))

    def test_projection_binds_stage_original_status_and_phase_order(self):
        observation={'kernel-fixed':{'status':1,'contacts':[1,1,0],'deliveries':[1,1,0]}}
        values=[row('control','kernel-fixed-begin'),row('shell','entry'),row('phase','contact-P'),row('phase','delivery-P'),row('phase','contact-A'),row('phase','delivery-A'),
                row('helper','installation',1),row('native','work-refusal',1),*observer_rows(),row('control','kernel-fixed-end',1)]
        self.trace.write_text(lines(values));self.assertEqual(ATTR.closed(self.trace,ATTR.BRANCHES,observation)['kernel-fixed']['runnerStatus'],1)
        invalids=[values[:-1],values+[values[-1]],[*values[:-1],row('control','kernel-fixed-end',0)],
                  [*values[:-1],row('control','kernel-quiet-diagnostic-end',1)],values[:1]+values,
                  [value for value in values if value['branch']!='delivery-A'],[values[0],values[1],values[4],values[5],values[2],values[3],*values[6:]]]
        for invalid in invalids:
            self.trace.write_text(lines(invalid))
            with self.assertRaisesRegex(RuntimeError,'^kernel-attribution-refused$'):ATTR.closed(self.trace,ATTR.BRANCHES,observation)
        for invalid in (row('SYNTHETIC_PRIVATE_TEXT_CANARY','unknown'),row('native','SYNTHETIC_PRIVATE_TEXT_CANARY'),
                        {**row('native','work-refusal',1),'private':True},row('native','work-refusal',True),row('native','work-refusal',256),
                        row('native-scan','arguments-query',1,-1),row('native-scan','arguments-query',1,0,1)):
            with self.assertRaisesRegex(RuntimeError,'^kernel-attribution-refused$'):ATTR.validate(invalid)

    def test_partial_capture_retains_closed_failure_but_never_claims_binding(self):
        values=[row('control','kernel-fixed-begin'),row('native','work-refusal',1)]
        self.trace.write_text(lines(values))
        result=ATTR.project(self.trace,ATTR.BRANCHES,{'kernel-fixed':{'status':1,'contacts':[0,0,0],'deliveries':[0,0,0]}})
        self.assertEqual((result['captureStatus'],result['error'],result['frames'][0]['sameInvocation']),(1,'binding-refused',False))
        self.assertIn(row('native','work-refusal',1),result['frames'][0]['records'])
        self.trace.write_text(lines(values)+json.dumps({'private':'SYNTHETIC_PRIVATE_TEXT_CANARY'})+'\n')
        result=ATTR.project(self.trace,ATTR.BRANCHES,{})
        self.assertEqual((result['captureStatus'],result['error'],result['frames']),(1,'record-refused',[]))
        self.assertNotIn('SYNTHETIC_PRIVATE_TEXT_CANARY',json.dumps(result))

    def test_writer_rejects_names_and_symlinks_without_changing_producer_status(self):
        code='import json,os,stat\n'+ATTR.python_writer(self.trace,ATTR.BRANCHES)
        code+='\neng1436_trace("native","SYNTHETIC_PRIVATE_TEXT_CANARY",1)\nraise SystemExit(19)\n'
        actual=subprocess.run(['/usr/bin/python3','-c',code],capture_output=True)
        self.assertEqual((actual.returncode,len(actual.stdout),len(actual.stderr),self.trace.read_bytes()),(19,0,0,b''))
        target=self.base/'target';target.write_bytes(b'unchanged');self.trace.unlink();self.trace.symlink_to(target)
        actual=subprocess.run(['/usr/bin/python3','-c',code.replace('SYNTHETIC_PRIVATE_TEXT_CANARY','work-refusal')],capture_output=True)
        self.assertEqual((actual.returncode,len(actual.stdout),len(actual.stderr),target.read_bytes()),(19,0,0,b'unchanged'))

    def test_binding_mutations_fail_exact_regressions_and_restore(self):
        source=(SCRIPTS/'kernel-attribution.py').read_text()
        value=row('native','work-refusal',1)
        variants=[
            ("set(record)=={'producer','branch','status','errno','auxStatus'}|({'value'} if record.get('producer')=='number' else set())",'True',{**value,'private':0}),
            ("record['producer'] in branches",'True',row('SYNTHETIC_PRIVATE_TEXT_CANARY','work-refusal',1)),
            ("record['branch'] in branches[record['producer']]",'True',row('native','SYNTHETIC_PRIVATE_TEXT_CANARY',1)),
            ("type(record['status']) is int",'True',{**value,'status':True}),
            ("-1<=record['status']<=255",'True',{**value,'status':256}),
            ("record['producer']=='native-scan' or record['producer'].startswith('reader-') or record['errno']==record['auxStatus']==0",'True',{**value,'errno':1}),
            ("type(record['value']) is int",'True',{**row('number','collector-bytes'),'value':True}),
            ("-1<=record['value']<=2**53-1",'True',{**row('number','collector-bytes'),'value':2**53})]
        class LookupControl(dict):
            # Membership still rejects the unknown producer; only a disabled
            # membership guard can reach this independently controlled lookup.
            def __missing__(self,key):return ('work-refusal',)
        for before,after,invalid in variants:
            self.assertEqual(source.count(before),1)
            namespace={'__file__':str(SCRIPTS/'kernel-attribution.py'),'__name__':'attribution_mutation'}
            exec(compile(source.replace(before,after),'attribution-mutation','exec'),namespace)
            allowed=LookupControl(ATTR.BRANCHES)
            statuses=[]
            for function in (ATTR.validate,namespace['validate'],ATTR.validate):
                try:function(invalid,allowed);statuses.append(19)
                except RuntimeError as error:self.assertEqual(str(error),'kernel-attribution-refused');statuses.append(0)
            self.assertEqual(statuses,[0,19,0])
        print('attribution-binding-mutations='+json.dumps({'independentMutations':len(variants),'regressionStatuses':[0,19,0],'restored':True}))


if __name__=='__main__':unittest.main()
