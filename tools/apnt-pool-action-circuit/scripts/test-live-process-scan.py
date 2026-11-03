#!/usr/bin/python3
"""Exact Go inventory/dispatch units, with synthetic prerequisites/resources.

No production hook is added. Fresh scratch binaries execute the source units;
fixed synthetic executables replace process queries only in those copies.
This does not exercise real installation admission, Seatbelt, memory or P/A/W.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'tools/apnt-pool-action-circuit/cmd/pool-pk-load/live_harness.go'
GO = '/opt/homebrew/bin/go'


class LiveProcessScan(unittest.TestCase):
    def dispatch_unit(self, label, edit=None):
        """Actual runV2 live branch + liveV2 guard + real synchronous monitor.

        Only this disposable source has synthetic admission/resource/inventory
        leaves and cache/key/prove sentinels. It is never an installed binary.
        Authentic P/A/W remains the separate runtime/resource suite's obligation.
        """
        main=(SOURCE.parent/'main.go').read_text()
        harness=SOURCE.read_text()
        def unit(source,start,end):
            self.assertEqual((source.count(start),source.count(end)),(1,1))
            a,b=source.index(start),source.index(end)
            self.assertLess(a,b)
            return source[a:b]
        branch=unit(main,'\t\t\t\tt := (liveV2{}).target(*request)', '\n\t\t\t\tbreak\n\t\t\t}\n\t\t\tvar t devprove.Target')
        dispatch=unit(main,'type liveV2 struct{}','func runV2(')
        self.assertIn('func (liveV2) guard(',dispatch)
        text=(unit(harness,'type liveResources struct','func readLiveResources()')+
              unit(harness,'func liveResourceFailure(','// Production live work')+
              harness[harness.index('func guardLiveWorkV2('):]+dispatch+
              '\nfunc dispatch(command string) error {\nargs:=[]string{"unit",command};var err error\nfor {\n'+branch+'\nbreak\n};return err\n}\n')
        # Package qualifiers are rebound only in the extracted scratch unit.
        for before,after in (('runneradmission.Require','requireW'),('devprove.SourceCheckout','sourceCheckout'),
            ('devprove.InactiveLiveActionTargetV2','syntheticTarget'),('devprove.Target','Target'),
            ('pkload.Format','Format'),('pkload.Pin','Pin'),('witness.Witness','any')):
            text=text.replace(before,after)
        text=text.replace('"/private/tmp/bch-cloak-sp1-prover-exclusive-v1"',json.dumps(str(self.base/'dispatch-sp1')))
        # Real inventory is covered above. This unit composes its call with
        # deterministic quiet inventory, without any host process query.
        stub=r'''
type Target struct{Name string}
type Format string
type Pin struct{Bytes int64;SHA256 string}
type Result struct{Target string;Admission *int}
func (*Result) timed(name string,f func()error)error{admissions++;return f()}
var r=&Result{}
var request,format,profile,liveCache,key,r1cs,vkPath=new(string),new(string),new(string),new(string),new(string),new(string),new(string)
var r1csBytes,vkBytes=new(int64),new(int64)
var r1csSHA,vkSHA=new(string),new(string)
var pin Pin
var admissions,prerequisites,scans,reads,cache,keyEffects,proveEffects int
var available int64
var failure string
func sourceCheckout()string{return "/synthetic"}
func syntheticTarget(path string)Target{return Target{path}}
func requireW(string)error{prerequisites++;if failure=="authority"{return errors.New("live-request-harness-required")};return nil}
func admitRequest(t Target,_ Format,_ Pin,_ Pin,_ Pin,_ string)(any,*int,error){
 // Successful synthetic W admission is required before the actual dispatch.
 // It carries no private witness or spend authority, and cannot touch keys.
 if t.Name!="synthetic-W"{return nil,nil,errors.New("synthetic-W-context-refused")};n:=1;return struct{}{},&n,nil
}
func prepareLiveCache(*Result,string,[]string)error{cache++;return nil}
func proveAssigned(*Result,Target,any,Format,string,Pin,string,Pin,string,Pin)error{
 keyEffects++;proveEffects++;return errors.New("synthetic-leaf-stop")
}
func liveQuietMachine(string)error{scans++;if failure=="inventory"{return errors.New("live-request-other-prover")};return nil}
func readLiveResources()(liveResources,error){
 reads++;if failure=="telemetry"{return liveResources{},errors.New("live-request-memory-unavailable")}
 s:=liveResources{available,0,0}
 if reads>1{switch failure{case "unreadable":s.available=-1;case "swap":s.swap=liveSwapTrip+1;case "rss":s.rss=liveRSSTrip+1}}
 return s,nil
}
func monitorOnly()error{
 ticks:=make(chan time.Time);fired:=make(chan error,1)
 stop,err:=startLiveMonitor("check-live",readLiveResources,ticks,func(e error){fired<-e})
 if err!=nil{return err};defer stop();ticks<-time.Now()
 // A second accepted tick is a deterministic missed-trip fence. A stalled
 // monitor is a separate invalid result, never a successful mutation oracle.
 select{case e:=<-fired:return e;case ticks<-time.Now():return errors.New("synthetic-monitor-missed-trip");case <-time.After(time.Second):return errors.New("synthetic-monitor-stalled")}
}
func main(){
 if len(os.Args)!=5{os.Exit(2)};*request="synthetic-W";*liveCache="asis"
 n,e:=strconv.ParseInt(os.Args[2],10,64);if e!=nil{os.Exit(3)};available=n;failure=os.Args[3]
 var err error
 if os.Args[4]=="dispatch"{err=dispatch(os.Args[1])}else if os.Args[4]=="monitor"{err=monitorOnly()}else{err=checkLiveV2(os.Args[1])}
 code:="";if err!=nil{code=err.Error()}
 json.NewEncoder(os.Stdout).Encode(map[string]any{"code":code,"admissions":admissions,"prerequisites":prerequisites,"scans":scans,"reads":reads,"cache":cache,"key":keyEffects,"prove":proveEffects})
}
'''
        if edit:
            before,after=edit
            self.assertEqual(text.count(before),1)
            text=text.replace(before,after)
        path=self.base/(label+'.go');binary=self.base/label
        path.write_text('package main\nimport("errors";"fmt";"os";"path/filepath";"time";"strconv";"encoding/json")\n'+text+stub)
        result=subprocess.run([GO,'build','-o',str(binary),str(path)],capture_output=True,timeout=60,
            env={'PATH':'/opt/homebrew/bin:/usr/bin:/bin','HOME':str(Path.home()),'GOENV':'off','GOFLAGS':'','GOPROXY':'off'})
        self.assertEqual(result.returncode,0,'dispatch-unit-build-refused')
        print('fresh-unit-build='+json.dumps({'sourceSha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'productionSha256':hashlib.sha256(main.encode()+harness.encode()).hexdigest(),'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
        return binary

    def dispatch_observe(self,binary,command='prove',available=16<<30,failure='',entry='dispatch'):
        result=subprocess.run([str(binary),command,str(available),failure,entry],capture_output=True,timeout=10)
        self.assertEqual((result.returncode,result.stderr),(0,b''))
        value=json.loads(result.stdout)
        self.assertEqual(set(value),{'code','admissions','prerequisites','scans','reads','cache','key','prove'})
        self.assertIs(type(value['code']),str)
        self.assertTrue(all(type(value[key]) is int for key in value if key!='code'))
        return value

    def test_actual_runv2_dispatch_guard_effects_and_mutants(self):
        valid=self.dispatch_unit('dispatch-valid')
        def regression(binary):
            self.assertEqual(self.dispatch_observe(binary),{'code':'live-request-memory-floor','admissions':1,
                'prerequisites':1,'scans':1,'reads':1,'cache':0,'key':0,'prove':0},'dispatch-floor-effect-oracle')
        regression(valid)
        self.assertEqual(self.dispatch_observe(valid,available=17<<30),{'code':'synthetic-leaf-stop','admissions':1,
            'prerequisites':1,'scans':1,'reads':1,'cache':1,'key':1,'prove':1})
        self.assertEqual(self.dispatch_observe(valid,command='check-live',available=1<<30),{'code':'','admissions':1,
            'prerequisites':1,'scans':1,'reads':1,'cache':0,'key':0,'prove':0})
        guard='err = (liveV2{}).guard(func() error {'
        mutants=(('misroute','if args[1] == "check-live" {','if args[1] == "prove" {'),
            ('direct-bypass',guard,'err = func(work func() error) error { return work() }(func() error {'),
            ('G4','beginLiveResources(reader, "prove")','beginLiveResources(reader, "check-live")'),
            ('initial-floor','initial && s.available < liveFloor','false && s.available < liveFloor'))
        for label,before,after in mutants:
            mutant=self.dispatch_unit('dispatch-'+label,(before,after))
            observed=self.dispatch_observe(mutant)
            if label=='misroute':
                self.assertEqual(observed,{'code':'live-request-options','admissions':1,'prerequisites':0,'scans':0,'reads':0,'cache':0,'key':0,'prove':0})
            elif label=='direct-bypass':
                self.assertEqual(observed,{'code':'synthetic-leaf-stop','admissions':1,'prerequisites':0,'scans':0,'reads':0,'cache':1,'key':1,'prove':1})
            else:
                self.assertEqual(observed,{'code':'synthetic-leaf-stop','admissions':1,'prerequisites':1,'scans':1,'reads':1,'cache':1,'key':1,'prove':1})
            with self.assertRaisesRegex(AssertionError,'dispatch-floor-effect-oracle'):regression(mutant)
            regression(valid)
        # Explicitly relabel prove as check-live at the call site, separately
        # from the unchanged-command misroute above.
        before='err = checkLiveV2(args[1])'
        # Use the builder's single-edit contract with one contiguous branch.
        original=(SOURCE.parent/'main.go').read_text()
        start=original.index('if args[1] == "check-live" {');end=original.index('\n\t\t\t\t\t\tbreak',start)
        branch=original[start:end]
        mutant=self.dispatch_unit('dispatch-relabel',(branch,branch.replace('== "check-live"','== "prove"').replace(before,'err = checkLiveV2("check-live")')))
        self.assertEqual(self.dispatch_observe(mutant),{'code':'','admissions':1,'prerequisites':1,'scans':1,'reads':1,'cache':0,'key':0,'prove':0})
        with self.assertRaisesRegex(AssertionError,'dispatch-floor-effect-oracle'):regression(mutant)
        regression(valid)

    def test_dispatch_prerequisites_inventory_and_callback_free_controls(self):
        valid=self.dispatch_unit('dispatch-boundaries')
        for failure,code,counts in (('authority','live-request-harness-required',(1,0,0)),
            ('inventory','live-request-other-prover',(1,1,0)),('telemetry','live-request-memory-unavailable',(1,1,1))):
            observed=self.dispatch_observe(valid,failure=failure)
            self.assertEqual(observed,{'code':code,'admissions':1,'prerequisites':counts[0],'scans':counts[1],
                'reads':counts[2],'cache':0,'key':0,'prove':0})
        for command in ('prove','unknown'):
            self.assertEqual(self.dispatch_observe(valid,command=command,entry='check'),{'code':'live-request-options',
                'admissions':0,'prerequisites':0,'scans':0,'reads':0,'cache':0,'key':0,'prove':0})
        mutants=(('Require','if err := requireW(sourceCheckout()); err != nil {','if err := error(nil); err != nil {'),)
        # The prerequisite has two actual sites: prove and callback-free check.
        source=(SOURCE.parent/'main.go').read_text();self.assertIn('(liveV2{}).guard(func() error {',source)
        for label,before,after in mutants:
            # Restrict the mutation to the prove guard; never waive a live guard.
            harness=SOURCE.read_text();start=harness.index('func guardLiveWorkV2(');end=harness.index('func guardLiveResources(')
            block=harness[start:end].replace('runneradmission.Require','requireW').replace('devprove.SourceCheckout','sourceCheckout')
            self.assertEqual(block.count(before),1)
            mutant=self.dispatch_unit('dispatch-drop-'+label,(block,block.replace(before,after)))
            observed=self.dispatch_observe(mutant,failure='authority')
            self.assertEqual(observed,{'code':'live-request-memory-floor','admissions':1,'prerequisites':0,'scans':1,'reads':1,'cache':0,'key':0,'prove':0})
            with self.assertRaises(AssertionError):self.assertEqual(observed,self.dispatch_observe(valid,failure='authority'))
            self.assertEqual(self.dispatch_observe(valid,failure='authority')['code'],'live-request-harness-required')

    def test_real_monitor_trip_mutants_fire_without_dangerous_effects(self):
        valid=self.dispatch_unit('monitor-valid')
        for failure,code,before in (
            ('unreadable','live-request-monitor-unavailable','case s.available < 0 || s.swap < 0 || s.rss < 0:'),
            ('swap','live-request-swap-trip','case s.swap > baseline && s.swap-baseline > liveSwapTrip:'),
            ('rss','live-request-rss-trip','case s.rss > liveRSSTrip:')):
            expected={'code':code,'admissions':0,'prerequisites':0,'scans':0,'reads':2,'cache':0,'key':0,'prove':0}
            def regression(binary):
                self.assertEqual(self.dispatch_observe(binary,available=1<<30,failure=failure,entry='monitor'),expected,'monitor-trip-effect-oracle')
            regression(valid)
            mutant=self.dispatch_unit('monitor-drop-'+failure,(before,'case false:'))
            self.assertEqual(self.dispatch_observe(mutant,available=1<<30,failure=failure,entry='monitor'),
                {**expected,'code':'synthetic-monitor-missed-trip','reads':3})
            with self.assertRaisesRegex(AssertionError,'monitor-trip-effect-oracle'):regression(mutant)
            regression(valid)

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='other-provers-live-', dir='/private/tmp')
        cls.base = Path(cls.scratch.name)
        cls.native = cls.base / 'tools/pool-action-modules/dist/private-runner-process'
        cls.native.parent.mkdir(parents=True)
        cls.legacy = cls.base / 'legacy-ps'
        cls.marker = cls.base / 'sp1-marker'
        cls.native_called = cls.base / 'native-called'
        cls.legacy_called = cls.base / 'legacy-called'
        cls.original = SOURCE.read_text()
        cls.binary = cls.build(cls.original, 'valid')

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    @classmethod
    def build(cls, text, label):
        start, end = 'var otherProverName =', 'func liveResourceFailure('
        if text.count(start) != 1 or text.count(end) != 1:
            raise RuntimeError('live-scan-unit-refused')
        inventory = start + text.split(start, 1)[1].split(end, 1)[0]
        guards = 'func guardLiveWorkV2(' + text.split('func guardLiveWorkV2(', 1)[1]
        guards = guards.replace('runneradmission.Require', 'requireV2').replace('devprove.SourceCheckout', 'sourceCheckout')
        units = inventory + guards
        units = units.replace('"/bin/ps"', json.dumps(str(cls.legacy)))
        units = units.replace('"/private/tmp/bch-cloak-sp1-prover-exclusive-v1"', json.dumps(str(cls.marker)))
        stub = r'''
type liveResources struct{}
var monitor, workRan, stopped bool
var monitoredCommand string
var prerequisiteCalls int
func sourceCheckout() string { return os.Args[1] }
func requireV2(string) error {
    prerequisiteCalls++
    if os.Args[3]=="prerequisite" { return errors.New("synthetic-prerequisite-refused") }
    return nil
}
func requireLiveHarness() error { return requireV2(sourceCheckout()) }
func readLiveResources() (liveResources,error) { return liveResources{},nil }
func startLiveMonitor(command string, read func()(liveResources,error), ticks <-chan time.Time, trip func(error))(func(),error) {
    monitor=true
    monitoredCommand=command
    if os.Args[3]=="monitor" { return nil,errors.New("live-request-monitor-unavailable") }
    return func(){stopped=true},nil
}
func main() {
    if len(os.Args)!=4 { os.Exit(2) }
    work:=func()error{workRan=true;return nil}
    var err error
    switch os.Args[2] {
    case "v2": err=guardLiveWorkV2(work)
    case "check-live": err=checkLiveV2("check-live")
    default: os.Exit(2)
    }
    if monitor && monitoredCommand != map[string]string{"v2":"prove","check-live":"check-live"}[os.Args[2]] { os.Exit(4) }
    code:="";if err!=nil { code=err.Error() }
    value:=struct{Code string `json:"code"`;Monitor bool `json:"monitor"`;Work bool `json:"work"`;Stopped bool `json:"stopped"`;Prerequisites int `json:"prerequisites"`}{code,monitor,workRan,stopped,prerequisiteCalls}
    if json.NewEncoder(os.Stdout).Encode(value)!=nil { os.Exit(3) }
}
'''
        source = cls.base / (label + '.go')
        source.write_text('package main\nimport("errors";"fmt";"os";"os/exec";"path/filepath";"regexp";"strconv";"strings";"time";"encoding/json")\n' + units + stub)
        binary = cls.base / label
        result = subprocess.run([GO, 'build', '-o', str(binary), str(source)], capture_output=True,
                                env={'PATH':'/opt/homebrew/bin:/usr/bin:/bin','HOME':str(Path.home()),
                                     'GOENV':'off','GOFLAGS':'','GOPROXY':'off'}, timeout=60)
        if result.returncode != 0:
            raise RuntimeError('live-scan-unit-build-failed')
        print('fresh-unit-build=' + json.dumps({'label':label,'sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                                               'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
        return binary

    def reader(self, path, called, rows='', status=0):
        # Fixed synthetic argv; rows and canaries are test material only.
        path.write_text('#!/bin/sh\n[ "$#" = 2 ] && [ "$1" = -axo ] && [ "$2" = pid=,comm= ] || exit 99\n'
                        '/usr/bin/touch ' + str(called) + '\n' + rows + '\nexit ' + str(status) + '\n')
        path.chmod(0o700)

    def observe(self, rows='', status=0, mode='v2', failure='', binary=None):
        for path in (self.native_called, self.legacy_called, self.marker):
            path.unlink(missing_ok=True)
        self.reader(self.native, self.native_called, rows, status)
        self.reader(self.legacy, self.legacy_called, '', 71)
        if failure == 'marker':
            self.marker.write_text('synthetic holder')
        result = subprocess.run([str(binary or self.binary),str(self.base),mode,failure],capture_output=True,timeout=10)
        self.assertEqual((result.returncode,len(result.stderr)),(0,0))
        value = json.loads(result.stdout)
        self.assertEqual(set(value),{'code','monitor','work','stopped','prerequisites'})
        self.assertEqual(value['prerequisites'],1)
        self.assertIs(type(value['code']),str)
        self.assertTrue(all(type(value[k]) is bool for k in ('monitor','work','stopped')))
        return value,self.native_called.exists(),self.legacy_called.exists()

    def assert_refusal(self, observed, code, native=True, legacy=False, monitor=False):
        value, n, l = observed
        self.assertEqual(value,{'code':code,'monitor':monitor,'work':False,'stopped':False,'prerequisites':1})
        self.assertEqual((n,l),(native,legacy))

    def test_v2_fresh_native_inventory_then_monitor_work_and_stop(self):
        value,n,l=self.observe('printf "  %s pool-pk-load\\n  499 /bin/bash\\n" "$PPID"')
        self.assertEqual(value,{'code':'','monitor':True,'work':True,'stopped':True,'prerequisites':1})
        self.assertEqual((n,l),(True,False))

    def test_failed_or_partial_inventory_refuses_before_monitor_and_work(self):
        for rows in ('','printf "  499 /bin/bash\\n"','printf "  499 /synthetic/pool-pk-load\\n"'):
            self.assert_refusal(self.observe(rows,71),'live-request-process-list-unavailable')

    def test_all_existing_prover_names_refuse_and_safe_lookalikes_pass(self):
        names=('pool-pk-load','pool-action-circuit','apnt-pool-action-circuit.test','apnt-pool-ceremony',
               'cargo-prove','sp1-prover','sp1_core-worker','apnt-action-runner-worker','synthetic-prover',
               'r2-run','r3-run','relation-r2-run','apnt-successor-child-circuits.test','apnt-child-circuits-cost.test')
        for name in names:
            self.assert_refusal(self.observe('printf "  499 /synthetic/'+name+'\\n"'),'live-request-other-prover')
        for name in ('pool-pk-load-safe','proveable','provider','cargo'):
            value,n,l=self.observe('printf "  499 /synthetic/'+name+'\\n"')
            self.assertEqual((value['code'],value['work'],n,l),('',True,True,False))

    def test_prerequisite_and_marker_refuse_before_inventory(self):
        self.assert_refusal(self.observe(failure='prerequisite'),'synthetic-prerequisite-refused',native=False)
        self.assert_refusal(self.observe(failure='marker'),'live-request-other-prover',native=False)

    def test_check_live_exclusivity_before_floor_free_monitor(self):
        value,n,l=self.observe(mode='check-live')
        self.assertEqual(value,{'code':'','monitor':True,'work':False,'stopped':True,'prerequisites':1})
        self.assertEqual((n,l),(True,False))
        self.assert_refusal(self.observe(mode='check-live',rows='printf "  499 /synthetic/sp1-prover\\n"'),
                            'live-request-other-prover')
        self.assert_refusal(self.observe(mode='check-live',failure='marker'),
                            'live-request-other-prover',native=False)
        before='if err := liveQuietMachine(reader); err != nil {'
        self.assertEqual(self.original.count(before),1)
        mutant=self.build(self.original.replace(before,'if err := error(nil); err != nil {'),'mutant-quiet')
        for failure in ('', 'marker'):
            observed=self.observe(mode='check-live',failure=failure,binary=mutant,
                rows='printf "  499 /synthetic/sp1-prover\\n"')
            self.assertEqual(observed,({'code':'','monitor':True,'work':False,'stopped':True,'prerequisites':1},False,False))
            with self.assertRaises(AssertionError):
                self.assert_refusal(observed,'live-request-other-prover',native=not failure)
        self.assert_refusal(self.observe(mode='check-live',failure='marker'),
                            'live-request-other-prover',native=False)

    def test_monitor_failure_refuses_work_after_successful_inventory(self):
        self.assert_refusal(self.observe(failure='monitor'),'live-request-monitor-unavailable',monitor=True)

    def test_retired_v1_guard_and_ps_dispatch_stay_absent(self):
        # C1 (GO) retired the v1 guard and its /bin/ps dispatch: only the v2 guard
        # remains, and a failing native reader refuses with no legacy fallback.
        self.assertEqual((self.original.count('func guardLiveWork('),self.original.count('func guardLiveWorkV2('),self.original.count('"/bin/ps"')),(0,1,0))
        self.assert_refusal(self.observe('',71),'live-request-process-list-unavailable',native=True,legacy=False)

    def test_dispatch_and_inventory_failure_mutations_fire_and_restore(self):
        mutations=[('filepath.Join(devprove.SourceCheckout(), "tools/pool-action-modules/dist/private-runner-process")\n\treturn guardLiveResources(work, reader)',
                    '"/bin/ps"\n\treturn guardLiveResources(work, reader)','dispatch'),
                   ('if err != nil {\n\t\treturn errors.New("live-request-process-list-unavailable")',
                    'if err != nil && false {\n\t\treturn errors.New("live-request-process-list-unavailable")','failure')]
        for before,after,label in mutations:
            self.assertEqual(self.original.count(before),1)
            mutant=self.build(self.original.replace(before,after),'mutant-'+label)
            if label=='dispatch':
                value,n,l=self.observe(binary=mutant)
                oracle=(value['code']=='' and value['work'] and n and not l)
            else:
                value,n,l=self.observe(status=71,binary=mutant)
                oracle=(value['code']=='live-request-process-list-unavailable' and not value['work'])
            self.assertFalse(oracle)
            # Independently execute the regression again in a child, using the
            # actual mutant's result and side effects rather than a passed flag.
            regression='''import json,subprocess,sys
from pathlib import Path
root=Path(sys.argv[2]);native=root/'native-called';legacy=root/'legacy-called'
native.unlink(missing_ok=True);legacy.unlink(missing_ok=True)
r=subprocess.run([sys.argv[1],str(root),'v2',''],capture_output=True)
v=json.loads(r.stdout)
ok=r.returncode==0 and not r.stderr and native.exists() and not legacy.exists()
if sys.argv[3]=='dispatch':ok=ok and v['code']=='' and v['work'] and v['monitor'] and v['stopped']
else:ok=ok and v['code']=='live-request-process-list-unavailable' and not any(v[k] for k in ('work','monitor','stopped'))
sys.exit(0 if ok else 19)
'''
            child=subprocess.run(['/usr/bin/python3','-c',regression,str(mutant),str(self.base),label],capture_output=True)
            self.assertEqual(child.returncode,19)
            child=subprocess.run(['/usr/bin/python3','-c',regression,str(self.binary),str(self.base),label],capture_output=True)
            self.assertEqual(child.returncode,0)
        self.test_v2_fresh_native_inventory_then_monitor_work_and_stop()
        self.test_failed_or_partial_inventory_refuses_before_monitor_and_work()


class QuietReturnDiagnostic(unittest.TestCase):
    def test_scratch_entry_emits_only_fixed_names_and_keeps_exit_status(self):
        spec=importlib.util.spec_from_file_location('reproduction',SOURCE.parents[2]/'scripts/reproduce-kernel-stock-no-proof.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        source=(SOURCE.parent/'main.go').read_text()
        # main() up to its closing brace; C1 dropped the marker that used to follow it.
        entry='func main() {'+source.split('func main() {',1)[1].split('\n}\n',1)[0]+'\n}\n'
        # Use the real entry and diagnostic substitution with synthetic return
        # values. No repository, harness, bridge or source-input read occurs.
        stub='''
type runDeps struct{stderr *os.File;resultWriter func()}
type runResult struct{status int;prerequisite error;refusal *struct{}}
func writeNew(){}
func runV2(_ []string,_ runDeps)runResult{
    code:=os.Args[1]
    switch code {
    case "success":return runResult{}
    case "ordinary":return runResult{status:1}
    case "bridge":return runResult{status:1,refusal:&struct{}{}}
    default:return runResult{status:1,prerequisite:errors.New(code)}
    }
}
'''
        with tempfile.TemporaryDirectory(prefix='other-provers-quiet-',dir='/private/tmp') as directory:
            root=Path(directory)
            for label,text in (('original',entry),('diagnostic',module.quiet_return_diagnostic(entry)),
                               ('mutant',module.quiet_return_diagnostic(entry).replace(
                                   'fmt.Fprintln(os.Stderr, "live-request-harness-required")',
                                   'fmt.Fprintln(os.Stderr, result.prerequisite.Error()+"SYNTHETIC_PRIVATE_TEXT_CANARY")'))):
                path=root/(label+'.go');binary=root/label
                imports='"os";"errors"'+(';"fmt"' if label!='original' else '')
                path.write_text('package main\nimport('+imports+')\n'+text+stub)
                build=subprocess.run([GO,'build','-o',str(binary),str(path)],capture_output=True,timeout=60,
                                     env={'PATH':'/opt/homebrew/bin:/usr/bin:/bin','HOME':str(Path.home()),'GOENV':'off','GOFLAGS':'','GOPROXY':'off'})
                self.assertEqual(build.returncode,0,'quiet-unit-build-refused')
                print('fresh-unit-build='+json.dumps({'label':'quiet-'+label,'sourceSha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                                                      'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
                cases=['success','ordinary','bridge','SYNTHETIC_PRIVATE_TEXT_CANARY',
                       'live-request-main-checkout-required','live-request-harness-required','live-request-prover-lock-required']
                for case in cases:
                    result=subprocess.run([str(binary),case],capture_output=True,timeout=10)
                    code='live-request-bridge-refused' if case=='bridge' else case if case.startswith('live-request-') else ''
                    expected=(code+'\n').encode() if label!='original' and code else b''
                    self.assertEqual((result.returncode,len(result.stdout)),(int(case!='success'),0))
                    matches=result.stderr==expected
                    self.assertEqual(matches,not(label=='mutant' and case=='live-request-harness-required'))
                    if label!='mutant':
                        self.assertFalse(b'SYNTHETIC_PRIVATE_TEXT_CANARY' in result.stderr)


if __name__=='__main__':
    unittest.main()
