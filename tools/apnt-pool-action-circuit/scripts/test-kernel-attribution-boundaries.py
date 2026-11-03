#!/usr/bin/python3
"""Source-extracted boundary controls; no global scan, pkill or genuine run."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def load(name):
    spec=importlib.util.spec_from_file_location(name,HERE/name)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
BASE=load('test-kernel-attribution.py')
ATTR=BASE.ATTR
row=BASE.row


class BoundaryControls(unittest.TestCase):
    setUp=BASE.AttributionControls.setUp
    fixture=BASE.AttributionControls.fixture
    boundary=BASE.AttributionControls.boundary

    def helpers(self,source):
        return 'eng1436_trace() {'+source.split('eng1436_trace() {',1)[1].split('eng1436_trace entry 0',1)[0]

    def records(self,branches=ATTR.BRANCHES):return ATTR.read_records(self.trace,branches)

    def test_each_reader_role_captures_original_success_and_first_failure_without_rescan(self):
        fixture,branches=self.fixture();native=load('test-native-process-scan.py')
        native.NativeScan.setUpClass();original_scratch=native.NativeScan.scratch;original_binary=native.NativeScan.binary
        self.addCleanup(original_scratch.cleanup)
        with patch.object(native,'READER',fixture/ATTR.READER):native.NativeScan.setUpClass()
        self.addCleanup(native.NativeScan.tearDownClass)
        # The existing independently constructed API doubles assert original
        # query/confirmation call counts internally. A rescan returns status 3.
        cases=[('einval-valid',0,'complete',0,0),('einval-live',1,'arguments-query-live',22,0),
               ('einval-confirmation-short',1,'arguments-query-unconfirmed',22,0),
               ('einval-confirmation-failed',1,'arguments-query-query-error',22,1),
               ('table-failed',1,'process-table-size',1,0)]
        counts=[]
        for role in ATTR.ROLES:
            for case,status,branch,error,aux in cases:
                self.trace.write_bytes(b'')
                actual=subprocess.run([str(native.NativeScan.binary),case,'pid=,comm='],
                    env={**os.environ,'ENG1436_DIAGNOSTIC_ROLE':role},capture_output=True,timeout=5)
                baseline=subprocess.run([str(original_binary),case,'pid=,comm='],capture_output=True,timeout=5)
                self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(baseline.returncode,baseline.stdout,baseline.stderr))
                self.assertEqual(actual.returncode,status)
                self.assertEqual(self.records(branches),[row('reader-'+role,branch,status,error,aux)])
                if status:self.assertEqual(json.loads(actual.stderr)['errno'],error)
                else:self.assertEqual(actual.stderr,b'')
            counts.append({'role':role,'cases':len(cases)})
        self.trace.write_bytes(b'')
        actual=subprocess.run([str(native.NativeScan.binary),'einval-live','pid=,comm='],
            env={**os.environ,'ENG1436_DIAGNOSTIC_ROLE':'SYNTHETIC_PRIVATE_TEXT_CANARY'},capture_output=True)
        self.assertEqual((actual.returncode,self.trace.read_bytes()),(1,b''))
        # The operator's selected extracted guard controls also run against
        # these instrumented source bytes; no host profile is invoked here.
        with patch.object(native,'RUNNER',fixture/ATTR.RUNNER):
            for method in ('test_einval_live_or_unconfirmed_identity_refuses_before_continuation','test_einval_on_independently_vanished_or_zombie_pid_is_skipped'):
                getattr(native.NativeScan(method),method)()
        print('attribution-reader-roles='+json.dumps({'roles':counts,'originalCallCountsChecked':True,'unknownRoleWrites':0,
              'sourceSha256':hashlib.sha256((fixture/ATTR.READER).read_bytes()).hexdigest()}))

    def test_real_instrumented_reader_own_ancestry_query_preserves_output_and_exit(self):
        fixture,branches=self.fixture();binary=self.base/'reader'
        actual=subprocess.run(['/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',str(fixture/ATTR.READER),'-lproc','-o',str(binary)],capture_output=True)
        self.assertEqual((actual.returncode,len(actual.stderr)),(0,0),actual.stderr.decode())
        actual=subprocess.run([str(binary),'-p',str(os.getpid()),'-o','ppid=','-o','comm='],
            env={**os.environ,'ENG1436_DIAGNOSTIC_ROLE':'ancestry'},capture_output=True)
        self.assertEqual((actual.returncode,len(actual.stderr)),(0,0));self.assertTrue(actual.stdout)
        self.assertEqual(self.records(branches),[row('reader-ancestry','complete')])

    def test_node_bootstrap_and_issuer_branches_preserve_refusals_and_no_private_projection(self):
        fixture,branches=self.fixture()
        writer=ATTR.js_writer(self.trace,branches)
        original=(BASE.ROOT/ATTR.BRIDGE).read_text();annotated=(fixture/ATTR.BRIDGE).read_text()
        extract=lambda source:source.split('async function privateRunnerBridge() {',1)[1].split('\nif (process.argv[1]',1)[0]
        for failing in ('entry','metadata','read-route','owner-slot','issuer-contact','complete'):
            self.trace.write_bytes(b'');outputs=[]
            for source in (original,annotated):
                program=writer+'''
import {EventEmitter} from 'node:events';
let activeContact=null,frames=0;
class PrivateRunnerRefusal extends Error{value={private:'SYNTHETIC_PRIVATE_TEXT_CANARY'}}
class Socket extends EventEmitter{
 constructor(){super();if(FAILING==='entry')throw new PrivateRunnerRefusal();queueMicrotask(()=>{this.emit('data',Buffer.alloc(0));this.emit('end')})}
 setTimeout(){} destroy(){this.destroyed=true} end(){frames++}
}
const RUNNER_LIMITS={metadata:4096},createLineFramer=({onLine})=>({push(){onLine('synthetic')},end(){return {oversize:FAILING==='metadata',partial:null}}});
const parseCanonicalLine=()=>({arguments:[],phase:'W',source:'/synthetic'}),keysOf=()=>"arguments,phase,source";
const randomBytes=()=>({toString:()=> 'synthetic'}),runnerAdmissionRequest=value=>value;
function readPrivateRunnerRoute(){if(FAILING==='read-route')throw new PrivateRunnerRefusal();return {identity:{paymentHome:{value:{policy:{mode:'host-provisioned'}}}},key:Buffer.alloc(32)}}
function readOwnerRunnerSlot(){if(FAILING==='owner-slot')throw new PrivateRunnerRefusal();return {epoch:null,input:null}}
async function contact(){if(FAILING==='issuer-contact')throw new PrivateRunnerRefusal();return Buffer.from('synthetic')}
const frame=()=>Buffer.alloc(0);
async function privateRunnerBridge() {BODY
await privateRunnerBridge();console.log(JSON.stringify({frames,status:process.exitCode??0}));
'''.replace('FAILING',json.dumps(failing)).replace('BODY',extract(source))
                actual=subprocess.run([BASE.NODE,'--input-type=module','-'],input=program.encode(),capture_output=True,timeout=5)
                outputs.append((actual.returncode,actual.stdout,actual.stderr))
            self.assertEqual(outputs[0],outputs[1]);self.assertEqual(outputs[1][2],b'')
            self.assertIn(row('issuer-bridge',failing,0 if failing=='complete' else 1),self.records(branches))
            self.assertNotIn(b'SYNTHETIC_PRIVATE_TEXT_CANARY',self.trace.read_bytes())
        original=(BASE.ROOT/ATTR.BOOTSTRAP).read_text();annotated=(fixture/ATTR.BOOTSTRAP).read_text()
        for failing in ('entry','installation','plan-acquire','continuation','complete'):
            self.trace.write_bytes(b'');outputs=[]
            for source in (original,annotated):
                body='async function bootstrap() {'+source.split('async function bootstrap() {',1)[1].split('// Remember only the checked',1)[0]
                outer='try {'+source.split('try {\n  process.exitCode = await bootstrap();',1)[1].split('\nfinally {',1)[0]
                outer=outer.replace('try {','try {\n process.exitCode=await bootstrap();',1)
                program=writer+'''
import {join} from 'node:path';
let attributionBranch='entry',scriptIdentity=null,continued=0;
process.argv=['node','bootstrap','/synthetic-script','/synthetic-output','/synthetic-plan','4'];
const PRIVATE_RUNNER_NODE=process.execPath,PRIVATE_RUNNER_NODE_VERSION=process.version;
function refuse(){throw new Error('SYNTHETIC_PRIVATE_TEXT_CANARY')}
function current(){if(FAILING==='entry')refuse()}
const realpathSync=()=>'/synthetic-root',canonicalRunnerPath=()=>{},lstatSync=()=>({dev:1,ino:2});
const git=(root,...args)=>args.includes('HEAD')?'synthetic-revision':root;
const spawnSync=()=>({status:FAILING==='installation'?19:0});
async function acquire(){if(FAILING==='plan-acquire')refuse();return Buffer.from('synthetic')}
function spawn(){if(FAILING==='continuation')refuse();continued++;return {stdio:Array.from({length:9},()=>({on(){},end(){}})),kill(){}}}
const childCompletion=()=>Promise.resolve(0),cleanEnvironment=()=>({}),fixedEnvironment=()=>({});
BODY
OUTER
console.log(JSON.stringify({continued,status:process.exitCode??0}));
'''.replace('FAILING',json.dumps(failing)).replace('BODY',body).replace('OUTER',outer)
                actual=subprocess.run([BASE.NODE,'--input-type=module','-'],input=program.encode(),capture_output=True,timeout=5)
                outputs.append((actual.returncode,actual.stdout,actual.stderr))
            self.assertEqual(outputs[0],outputs[1]);self.assertEqual(outputs[1][2],b'')
            self.assertIn(row('bootstrap',failing,0 if failing=='complete' else 1),self.records(branches))
            self.assertEqual(json.loads(outputs[1][1])['continued'],int(failing=='complete'))
            self.assertNotIn(b'SYNTHETIC_PRIVATE_TEXT_CANARY',self.trace.read_bytes())
        print('attribution-node-boundaries='+json.dumps({'issuerCases':6,'bootstrapCases':5,'originalStatusesAndFramesPreserved':True,'privateCanaryProjected':False}))

    def test_original_samples_keep_status_output_and_all_numeric_values(self):
        fixture,branches=self.fixture();source=(fixture/ATTR.RUNNER).read_text()
        unit=lambda text:'sample() {'+text.split('sample() {',1)[1].split('\ninputs_of()',1)[0]
        for role in ATTR.ROLES[2:5]:
            for invalid in (False,True):
                self.trace.write_bytes(b'');outputs=[]
                for text in (self.source,source):
                    script='set -euo pipefail\n'+self.helpers(source)+'''\n
swap_used_bytes(){ echo 1024; }
available_bytes(){ echo 21474836480; }
phase_rss_bytes(){ '''+('echo 4096;' if not invalid else 'return 19;')+' }\n'+unit(text)
                    script+='\neng1436_sample_role='+role+' sample '+str(self.base/'samples')+'\n'
                    actual=subprocess.run(['/bin/bash','-c',script],capture_output=True)
                    outputs.append((actual.returncode,actual.stdout,actual.stderr))
                self.assertEqual(outputs[0],outputs[1]);self.assertEqual(outputs[1],(0,('1024 21474836480 '+('-1' if invalid else '4096')+'\n').encode(),b''))
                self.assertIn(row('shell','sample-return',0),self.records(branches))
                metrics=[value for value in self.records(branches) if value['producer']=='number']
                self.assertEqual([(v['branch'],v['status'],v['value']) for v in metrics],
                    [(role+'-swap',0,1024),(role+'-available',0,21474836480),(role+'-rss',19 if invalid else 0,-1 if invalid else 4096)])
        print('attribution-samples='+json.dumps({'positions':3,'validInvalidPerPosition':2,'sampleFailureReturnPreserved':0,'failedRSSValue':-1}))

    def test_swap_available_sample_and_baseline_failures_keep_their_guard_status(self):
        fixture,branches=self.fixture();source=(fixture/ATTR.RUNNER).read_text()
        sample='sample() {'+source.split('sample() {',1)[1].split('\ninputs_of()',1)[0]
        for role in ATTR.ROLES[2:5]:
            for failed in ('swap','available'):
                self.trace.write_bytes(b'')
                script='set -euo pipefail\n'+self.helpers(source)+'\nswap_used_bytes(){ '+('return 19;' if failed=='swap' else 'echo 1024;')+' }\navailable_bytes(){ '+('return 23;' if failed=='available' else 'echo 21474836480;')+' }\nphase_rss_bytes(){ echo 4096; }\n'+sample
                actual=subprocess.run(['/bin/bash','-c',script+'\neng1436_sample_role='+role+' sample '+str(self.base/'sample')+'\n'],capture_output=True)
                self.assertEqual(actual.returncode,0)
                self.assertIn({**row('number',role+'-'+failed,19 if failed=='swap' else 23),'value':-1},self.records(branches))
        prefix='run_case() {'+source.split('run_case() {',1)[1].split('\teng1436_sample_role=rss-initial sample',1)[0]+'\n}\n'
        self.trace.write_bytes(b'')
        script='set -euo pipefail\nPRIVATE_RUNNER_GENERATION=2\nhas_live=false\nresults='+str(self.base)+'\n'+BASE.admission_stubs(source)+'inputs_of(){ :; }\nswap_used_bytes(){ return 19; }\ndie(){ exit 29; }\n'+self.helpers(source)+prefix+'\nrun_case synthetic 1 asis ok synthetic\n'
        actual=subprocess.run(['/bin/bash','-c',script],capture_output=True)
        self.assertEqual(actual.returncode,29);records=self.records(branches)
        self.assertIn(row('shell','baseline',19),records);self.assertIn({**row('number','swap-baseline',19),'value':-1},records)
        self.assertFalse(any(v['branch']=='launch' for v in records))

    def test_monitor_decisions_signal_result_wait_and_result_absence(self):
        fixture,branches=self.fixture();source=(fixture/ATTR.RUNNER).read_text()
        sample='sample() {'+source.split('sample() {',1)[1].split('\ninputs_of()',1)[0]
        run_case='run_case() {'+source.split('run_case() {',1)[1].split('\n\tlocal result_status=0',1)[0]+'\nreturn "$status"\n}\n'
        # Replace only the scratch launch and signal command. All decisions,
        # values, statuses and original ordering execute extracted source.
        run_case=run_case.replace('/usr/bin/caffeinate -i /usr/bin/time -l -o "$results/$name.time" \\\n   /usr/bin/nice -n 10','eng1436_launch')
        run_case=run_case.replace('/usr/bin/pkill -TERM -x pool-pk-load','eng1436_signal')
        self.assertNotIn('/usr/bin/pkill',run_case);self.assertNotIn('/usr/bin/caffeinate',run_case)
        cases=[('healthy',0,0),('unavailable',19,0),('swap',0,0),('rss',0,0),('unavailable',19,19)]
        for decision,rss_status,signal_status in cases:
            self.trace.write_bytes(b'')
            script='set -euo pipefail\nPRIVATE_RUNNER_GENERATION=2\nhas_live=false\nrepo=/synthetic\nbin=/synthetic\nprocs=1\nresults='+str(self.base)+'\nSAMPLE_SECONDS=0.01\nSWAP_GROWTH_TRIP_BYTES=10\nRSS_TRIP_BYTES=100\n'+self.helpers(source)+BASE.admission_stubs(source)+'''
die(){ exit 29; }
inputs_of(){ :; }
eng1436_launch(){ /bin/sleep 0.04; }
eng1436_signal(){ kill -TERM "$pid"; return SIGNAL_STATUS; }
swap_used_bytes(){ if [[ ${eng1436_sample_role:-} == rss-periodic && DECISION == swap ]]; then echo 100; else echo 0; fi; }
available_bytes(){ echo 21474836480; }
phase_rss_bytes(){ if [[ ${eng1436_sample_role:-} == rss-periodic ]]; then
 if [[ DECISION == unavailable ]]; then return RSS_STATUS; fi
 if [[ DECISION == rss ]]; then echo 200; return; fi
 fi; echo 0; }
'''.replace('SIGNAL_STATUS',str(signal_status)).replace('RSS_STATUS',str(rss_status)).replace('DECISION',decision)
            actual=subprocess.run(['/bin/bash','-c',script+sample+'\n'+run_case+'\nrun_case synthetic 1 asis ok synthetic\n'],capture_output=True,timeout=5)
            records=self.records(branches)
            self.assertIn(row('shell','baseline',0),records);self.assertIn(row('shell','launch'),records)
            self.assertIn(row('shell','monitor-'+decision,0 if decision=='healthy' else 1),records)
            self.assertIn(row('shell','result-absent',1),records)
            if decision=='healthy':self.assertEqual(actual.returncode,0);self.assertIn(row('shell','wait',0),records)
            else:self.assertEqual(actual.returncode,143);self.assertIn(row('shell','wait',143),records);self.assertIn(row('shell','signal',signal_status),records)
            self.assertEqual(len([r for r in records if r['producer']=='number' and r['branch']=='rss-final-rss']),1)
        print('attribution-monitor='+json.dumps({'cases':len(cases),'healthyStatus':0,'ownChildSignalStatus':143,'signalCommandFailuresRemainRecorded':True,'globalSignals':False}))

    def test_finish_boundary_statuses_total_bytes_overflow_and_classification(self):
        fixture,branches=self.fixture();source=(fixture/ATTR.RUNNER).read_text()
        for raw,known in [(b'',True),(b'live-request-process-list-unavailable\n',True),(b'X'*100000,False)]:
            for original_status in (0,19):
                self.trace.write_bytes(b'')
                script='set -euo pipefail\nPRIVATE_RUNNER_GENERATION=2\nhas_live=true\ncleanup(){ :; }\n'+self.helpers(source)+self.boundary(source)
                script+='\n/bin/cat >&2\nexit '+str(original_status)+'\n'
                actual=subprocess.run(['/bin/bash','-c',script],input=raw,capture_output=True,timeout=5)
                records=self.records(branches)
                for branch in ('cleanup','collector-wait','reason-read','reason-remove','stream-remove','directory-remove'):
                    self.assertIn(row('finish',branch,0),records)
                self.assertIn({**row('number','collector-bytes'),'value':len(raw)},records)
                self.assertIn({**row('number','collector-overflow'),'value':int(len(raw)>len(b'measure-pk-load: live-plan-prover-inventory-pipeline\n'))},records)
                self.assertIn(row('shell','private-exit',original_status),records)
                self.assertEqual(actual.returncode,0 if original_status==0 else 1)
                classification=next(v['branch'] for v in records if v['producer']=='classification')
                self.assertEqual(classification,('no-diagnostic' if not raw else 'live-request-process-list-unavailable') if known else 'unclassified')
        # An independently failed cleanup remains a failed outer result.
        self.trace.write_bytes(b'')
        script='set -euo pipefail\nPRIVATE_RUNNER_GENERATION=2\nhas_live=true\ncleanup(){ return 19; }\n'+self.helpers(source)+self.boundary(source)+'\nexit 0\n'
        actual=subprocess.run(['/bin/bash','-c',script],capture_output=True,timeout=5)
        self.assertEqual(actual.returncode,1);self.assertIn(row('finish','cleanup',19),self.records(branches))
        self.assertIn(row('finish','complete',1),self.records(branches))

    def test_each_finish_failure_remains_a_failed_result_and_captures_exact_status(self):
        fixture,branches=self.fixture();source=(fixture/ATTR.RUNNER).read_text()
        targets=[('collector-wait',None),('reason-read','IFS= read -r reason <"$private_runner_diagnostic_file"'),
                 ('reason-remove','/bin/rm -f "$private_runner_diagnostic_file"'),('stream-remove','/bin/rm -f "$private_runner_diagnostic_file.stream"'),
                 ('directory-remove','/bin/rmdir "${private_runner_diagnostic_file%/*}"')]
        for branch,target in targets:
            self.trace.write_bytes(b'');unit=self.boundary(source)
            if target:
                self.assertEqual(unit.count(target),1)
                unit=unit.replace(target,'{ '+target+'; (exit 19); }')
            else:
                position='if [[ $PRIVATE_RUNNER_GENERATION == 2 ]] && $has_live; then'
                self.assertEqual(unit.count(position),1)
                unit=unit.replace(position,'private_runner_diagnostics(){ printf "no-diagnostic\\n"; return 19; }\n'+position)
            script='set -euo pipefail\nPRIVATE_RUNNER_GENERATION=2\nhas_live=true\ncleanup(){ :; }\n'+self.helpers(source)+unit+'\nexit 0\n'
            actual=subprocess.run(['/bin/bash','-c',script],capture_output=True,timeout=5)
            self.assertEqual(actual.returncode,1)
            self.assertIn(row('finish',branch,19),self.records(branches));self.assertIn(row('finish','complete',1),self.records(branches))
        print('attribution-finish-failures='+json.dumps({'independentFailures':len(targets),'inputStatus':0,'failedOperationStatus':19,'outerStatus':1}))

    def test_native_bridge_boundaries_preserve_first_failure_and_original_call_order(self):
        fixture,branches=self.fixture();package=self.base/'go-boundaries';package.mkdir()
        (package/'go.mod').write_text('module eng1436/attribution\n\ngo 1.24\n')
        owner=BASE.ROOT/'tools/apnt-pool-action-circuit/internal/runneradmission'
        for name in ('harness.go','refusal.go','prerequisite.go'):(package/name).write_bytes((owner/name).read_bytes())
        source=(fixture/ATTR.GO_BRIDGE).read_text()
        replacements=[('invocation, err := fixedInvocation(source)','invocation, err := probeInvocation(source)'),
          ('if err = verifyBridgeInstallation(root);','if err = probeInstallation(root);'),('syscall.Socketpair(','probeSocketpair('),
          ('os.OpenFile(os.DevNull, os.O_RDWR, 0)','probeNull()'),('if closeBridgeInheritance() != nil {','if probeInheritance() != nil {'),
          ('command.Start()','probeStart(command)'),('parent.Write(append(request, \'\\n\'))','probeWrite(parent,append(request, \'\\n\'))'),
          ('syscall.Shutdown(','probeShutdown('),('command.Process.Kill()','probeKill(command)'),('command.Wait()','probeWait(command)'),
          ('io.ReadAll(io.LimitReader(parent, (1<<20)+(64<<10)+9))','probeRead()')]
        for before,after in replacements:
            self.assertIn(before,source);source=source.replace(before,after)
        (package/'bridge.go').write_text(source);(package/'eng1436_diagnostic.go').write_bytes((fixture/ATTR.GO_TRACE).read_bytes())
        (package/'boundary_test.go').write_text('''package runneradmission
import("errors";"os";"os/exec";"syscall";"testing";"reflect")
var failing string
var calls []string
func reached(name string)error{calls=append(calls,name);if failing==name{return errors.New("synthetic")};return nil}
func probeInvocation(source string)(map[string]any,error){if err:=reached("fixed-invocation");err!=nil{return nil,err};return fixedInvocation(source)}
func probeInstallation(string)error{return reached("installation")}
func probeSocketpair(domain,kind,protocol int)([2]int,error){if err:=reached("socketpair");err!=nil{return [2]int{-1,-1},err};return syscall.Socketpair(domain,kind,protocol)}
func probeNull()(*os.File,error){if err:=reached("null-open");err!=nil{return nil,err};return os.OpenFile(os.DevNull,os.O_RDWR,0)}
func probeInheritance()error{return reached("inheritance")}
func probeStart(*exec.Cmd)error{return reached("start")}
func probeWrite(_ *os.File,raw []byte)(int,error){return len(raw),reached("write")}
func probeShutdown(int,int)error{return reached("shutdown")}
func probeKill(*exec.Cmd)error{return reached("kill")}
func probeRead()([]byte,error){if err:=reached("read");err!=nil{return nil,err};if failing=="frame"{return make([]byte,8),nil};return []byte{0,0,0,24,0,0,0,9,'{','"','b','y','t','e','s','"',':','9',',','"','e','r','r','o','r','"',':','n','u','l','l','}', 's','y','n','t','h','e','t','i','c'},nil}
func probeWait(*exec.Cmd)error{return reached("wait")}
func TestCapturedBridgeBoundaries(t *testing.T){
 original:=os.Args;defer func(){os.Args=original}();os.Args=[]string{"unit","check-live","--request","/synthetic","/synthetic-out"}
 order:=[]string{"fixed-invocation","installation","socketpair","null-open","inheritance","start","write","shutdown","read","wait"}
 for _,name:=range append(append([]string{},order...),"frame","complete") {t.Run(name,func(t *testing.T){
 failing=name;calls=nil;snapshot,err:=AcquireSnapshot("/synthetic","/synthetic")
 if name=="complete" {if err!=nil || string(snapshot)!="synthetic"{t.Fatal("valid result changed")}} else if err==nil || snapshot!=nil {t.Fatal("refusal bypassed")}
 expected:=append([]string{},order...);for index,step:=range order{if step==name{expected=expected[:index+1];break}};if name=="write"||name=="shutdown"{expected=append(expected,"kill","wait")};if name=="read"{expected=append(expected,"wait")};if !reflect.DeepEqual(calls,expected){t.Fatal("operation order changed")}
 })}
}
''')
        environment={**os.environ,'GOENV':'off','GOPROXY':'off','GOTOOLCHAIN':'local','GOFLAGS':''}
        binary=package/'boundaries.test'
        built=subprocess.run(['/opt/homebrew/bin/go','test','-c','-o',str(binary),'.'],cwd=package,env=environment,capture_output=True,timeout=60)
        self.assertEqual((built.returncode,len(built.stderr)),(0,0))
        actual=subprocess.run([str(binary),'-test.count=1','-test.run=^TestCapturedBridgeBoundaries$'],cwd=package,env=environment,capture_output=True,timeout=60)
        self.assertEqual((actual.returncode,len(actual.stderr)),(0,0),actual.stderr.decode()+actual.stdout.decode())
        records=self.records(branches)
        for branch in ('fixed-invocation','installation','socketpair','null-open','inheritance','start','write','shutdown','read-wait','frame'):
            self.assertTrue(any(v['producer']=='bridge' and v['branch']==branch and v['status']==-1 for v in records),branch)
        self.assertIn(row('bridge','read',-1),records);self.assertIn(row('bridge','wait',-1),records);self.assertIn(row('bridge','frame',0),records)
        print('attribution-native-bridge='+json.dumps({'cases':12,'ownSocketpairs':True,'issuerOrPrivateInputsUsed':False,'originalOperationOrderChecked':True,'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))

    def test_missing_native_sample_and_finish_records_are_explicit_incomplete(self):
        values=[row('shell','entry'),row('reader-rss-initial','call-start'),row('reader-rss-initial','complete'),row('reader-rss-initial','call-end'),
                row('shell','sample-enter'),row('shell','sample-return'),row('shell','sample-valid'),*[{**row('number','rss-initial-'+metric),'value':0} for metric in ('swap','available','rss')],*BASE.observer_rows()]
        ATTR.complete_records(values,'kernel-fixed')
        for index in (1,2,3):
            with self.assertRaisesRegex(RuntimeError,'^kernel-attribution-refused$'):ATTR.complete_records(values[:index]+values[index+1:],'kernel-fixed')
        for values in ([row('shell','entry'),row('shell','sample-invalid',1)], [row('shell','entry'),row('shell','private-exit',1)]):
            with self.assertRaisesRegex(RuntimeError,'^kernel-attribution-refused$'):ATTR.complete_records(values,'kernel-fixed')
        for bad in ({**row('number','collector-bytes'),'value':True},{**row('number','collector-bytes'),'value':2**53},
                    {**row('number','collector-bytes'),'value':0,'private':0},row('number','collector-bytes')):
            with self.assertRaisesRegex(RuntimeError,'^kernel-attribution-refused$'):ATTR.validate(bad)

    def test_completeness_mutations_fire_their_focused_regression_then_restore(self):
        source=(HERE/'kernel-attribution.py').read_text()
        base=[row('shell','entry'),*BASE.observer_rows()]
        variants=[('require(diagnostic is not None and row[\'status\']==diagnostic[\'status\'])','require(True)',
                   base+[row('reader-ancestry','call-start'),row('reader-ancestry','call-end')]),
                  ("for branch in ('collector-bytes','collector-overflow'):require(count('number',branch)==1)","for branch in ('collector-bytes','collector-overflow'):require(True)",base+[row('shell','private-exit',1),row('finish','cleanup'),row('finish','complete',1),row('classification','unclassified')]),
                  ('require(len(metric_rows)==samples*3)','require(True)',base+[row('shell','sample-enter'),row('shell','sample-return'),row('shell','sample-invalid',1)]),
                  ("require(count('shell','sample-enter')==count('shell','sample-return')==samples)",'require(True)',
                   base+[row('shell','sample-enter'),row('shell','sample-valid'),row('reader-rss-initial','call-start'),row('reader-rss-initial','complete'),row('reader-rss-initial','call-end')]+[{**row('number','rss-initial-'+metric),'value':0} for metric in ('swap','available','rss')])]
        # Isolate collector-missing from the independently required finish
        # classification and observer events; no unrelated refusal is an oracle.
        for before,after,invalid in variants:
            self.assertEqual(source.count(before),1)
            namespace={'__file__':str(HERE/'kernel-attribution.py'),'__name__':'attribution_mutation'}
            exec(compile(source.replace(before,after),'attribution-completeness-mutation','exec'),namespace)
            statuses=[]
            for function in (ATTR.complete_records,namespace['complete_records'],ATTR.complete_records):
                try:function(invalid,'kernel-fixed');statuses.append(19)
                except RuntimeError as error:self.assertEqual(str(error),'kernel-attribution-refused');statuses.append(0)
            self.assertEqual(statuses,[0,19,0])
        print('attribution-completeness-mutations='+json.dumps({'independentMutations':len(variants),'regressionStatuses':[0,19,0],'restored':True}))


if __name__=='__main__':unittest.main()
