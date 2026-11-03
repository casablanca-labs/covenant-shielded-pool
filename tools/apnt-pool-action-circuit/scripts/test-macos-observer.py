#!/usr/bin/python3
"""Focused observer controls; only own synthetic children or API doubles."""
import hashlib
import importlib.util
import ast
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import select
import os

ROOT=Path(__file__).resolve().parents[3]
OBSERVER=ROOT/'tools/apnt-pool-action-circuit/scripts/mig01-macos-observer.c'
REPRODUCER=OBSERVER.with_name('reproduce-kernel-stock-no-proof.py')
ENTRY='29e57d17cf5358e87e6c67bd66a3c47bf7853d8b'
COUNTS={'samples','observedProcesses','fd8PipeProcesses','fd8SocketProcesses',
        'fd8IdentitiesCompared','fd8IdentitiesDifferent','fd8SourceIdentityMatches',
        'sourceDescriptorMatches','nullStdioPrivateBridgeProcesses','inheritedProverLockBridges'}


def public_history_source(commit,path):
    spec=importlib.util.spec_from_file_location('public_history_source',OBSERVER.with_name('public-history-source.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.read_source(commit,path)



def reproduction():
    spec=importlib.util.spec_from_file_location('observer_reproduction',REPRODUCER)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class ObserverControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='other-provers-observer-',dir='/private/tmp')
        cls.base=Path(cls.temporary.name)
        cls.fixed=cls.build(OBSERVER,'fixed')
        previous=cls.base/'entry.c'
        previous.write_bytes(public_history_source(ENTRY,str(OBSERVER.relative_to(ROOT))))
        cls.previous=cls.build(previous,'entry')

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    @classmethod
    def build(cls, production, label):
        source=cls.base/(label+'-model.c');binary=cls.base/(label+'-model')
        source.write_text(r'''
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
static int model_stat(const char *,struct stat *);
static int model_info(int,int,uint64_t,void *,int);
static int model_fdinfo(int,int,int,void *,int);
static int model_children(int,void *,int);
static ssize_t model_read(int,void *,size_t);
static int model_clock(clockid_t,struct timespec *);
#define stat(...) model_stat(__VA_ARGS__)
#define proc_pidinfo model_info
#define proc_pidfdinfo model_fdinfo
#define proc_listchildpids model_children
#define read model_read
#define clock_gettime model_clock
#define main observer_main
#include '''+json.dumps(str(production))+r'''
#undef main
#undef clock_gettime
#undef read
#undef proc_listchildpids
#undef proc_pidfdinfo
#undef proc_pidinfo
#undef stat
static const char *scenario;
static int children_count,reads,clocks;
static int is_case(const char *name){return !strcmp(scenario,name);}
static int model_stat(const char *path,struct stat *value){
    memset(value,0,sizeof(*value));value->st_mode=S_IFREG|0600;
    if(!strcmp(path,"source")){value->st_dev=11;value->st_ino=101;}
    else if(!strcmp(path,"request")){value->st_dev=12;value->st_ino=102;}
    else if(!strcmp(path,"/dev/null")){value->st_dev=1;value->st_ino=2;value->st_mode=S_IFCHR|0600;}
    else if(is_case("lock")){value->st_dev=13;value->st_ino=103;}
    else return -1;
    return 0;
}
static int model_info(int pid,int flavor,uint64_t arg,void *out,int size){
    (void)arg;memset(out,0,size);
    if(flavor==PROC_PIDTBSDINFO){
        struct proc_bsdinfo *identity=out;identity->pbi_uid=getuid()+(is_case("uid")?1:0);
        strcpy(identity->pbi_comm,pid==500 || is_case("unrelated-node")?"node":"bash");return sizeof(*identity);
    }
    if(flavor!=PROC_PIDLISTFDS)return -1;
    if(is_case("fd-negative")){errno=EACCES;return -1;}
    if(is_case("fd-full"))return size;
    if(is_case("fd-shape"))return 1;
    struct proc_fdinfo *fds=out;int count=0;
    fds[count++]=(struct proc_fdinfo){pid==500?3:8,PROX_FDTYPE_PIPE};
    if(pid!=500 && is_case("unused-null"))for(int fd=3;fd<=7;fd++)fds[count++]=(struct proc_fdinfo){fd,PROX_FDTYPE_VNODE};
    if(pid!=500 && is_case("unused-pipe"))fds[count++]=(struct proc_fdinfo){3,PROX_FDTYPE_PIPE};
    if(pid==500 && is_case("lock"))fds[count++]=(struct proc_fdinfo){9,PROX_FDTYPE_VNODE};
    if(pid==600+children_count-1 && (is_case("source") || is_case("request")))
        fds[count++]=(struct proc_fdinfo){is_case("source")?12:13,PROX_FDTYPE_VNODE};
    return count*sizeof(*fds);
}
static int model_fdinfo(int pid,int fd,int flavor,void *out,int size){
    (void)pid;memset(out,0,size);
    if(flavor==PROC_PIDFDVNODEINFO){
        if(pid!=500 && fd>=3 && fd<=7 && !is_case("unused-null"))return 0;
        struct vnode_fdinfo *value=out;value->pvi.vi_stat.vst_dev=1;value->pvi.vi_stat.vst_ino=2;
        if(fd==12){value->pvi.vi_stat.vst_dev=11;value->pvi.vi_stat.vst_ino=101;}
        if(fd==13){value->pvi.vi_stat.vst_dev=12;value->pvi.vi_stat.vst_ino=102;}
        if(fd==9){value->pvi.vi_stat.vst_dev=13;value->pvi.vi_stat.vst_ino=103;}
        return sizeof(*value);
    }
    if(flavor==PROC_PIDFDPIPEINFO){
        struct pipe_fdinfo *value=out;value->pipeinfo.pipe_stat.vst_dev=21;
        value->pipeinfo.pipe_stat.vst_ino=201;value->pipeinfo.pipe_stat.vst_mode=S_IFIFO;
        return sizeof(*value);
    }
    return 0;
}
static int model_children(int pid,void *out,int size){
    pid_t *children=out;memset(out,0,size);
    if(is_case("child-negative")){errno=EPERM;return -1;}
    if(is_case("child-full"))return size/sizeof(pid_t);
    if(is_case("child-over"))return size/sizeof(pid_t)+1;
    if(is_case("depth")){children[0]=pid+1;return 1;}
    if(pid!=500)return 0;
    for(int i=0;i<children_count;i++)children[i]=600+i;
    return children_count;
}
static ssize_t model_read(int fd,void *out,size_t size){(void)fd;(void)out;(void)size;return reads++?1:0;}
static int model_clock(clockid_t clock,struct timespec *value){
    (void)clock;value->tv_nsec=0;value->tv_sec=is_case("timeout") && clocks++?181:0;return 0;
}
int main(int argc,char **argv){
    if(argc!=3)return 2;scenario=argv[1];children_count=atoi(argv[2]);
    if(children_count<0 || children_count>255)return 2;
    if(is_case("capacity"))np=sizeof(seen_process)/sizeof(seen_process[0]);
    if(is_case("ordinary-history")){
        np=4096;processes=np;
        for(unsigned i=0;i<np;i++)seen_process[i]=10000+(pid_t)i;
    }
    char *entry[]={"observer","500","source","request",NULL};return observer_main(4,entry);
}
''')
        command=['/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',str(source),'-lproc','-o',str(binary)]
        built=subprocess.run(command,capture_output=True,timeout=30)
        if (built.returncode,len(built.stdout),len(built.stderr))!=(0,0,0):
            raise AssertionError('observer-model-build-refused:'+str(built.returncode)+':'+str(len(built.stderr)))
        print('fresh-unit-build='+json.dumps({'label':label,'sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                'productionSha256':hashlib.sha256(production.read_bytes()).hexdigest(),'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
        return binary

    def observe(self,scenario='valid',children=4,binary=None):
        result=subprocess.run([str(binary or self.fixed),scenario,str(children)],capture_output=True,timeout=5)
        value=json.loads(result.stdout)
        self.assertEqual(set(value),COUNTS|{'observerRefused'})
        for name in COUNTS:self.assertTrue(type(value[name]) is int and value[name]>=0)
        self.assertIs(type(value['observerRefused']),bool)
        diagnostic=json.loads(result.stderr) if result.stderr else None
        if diagnostic is not None:self.assertEqual(set(diagnostic),{'reason','errno'})
        return result.returncode,value,diagnostic

    def test_entry_reproduces_count_refusal_and_four_child_blind_spot(self):
        for children in (1,2,3):
            code,value,diagnostic=self.observe(children=children,binary=self.previous)
            self.assertEqual((code,value['observerRefused'],diagnostic),(77,True,None))
        code,value,_=self.observe('source',4,self.previous)
        self.assertEqual((code,value['observedProcesses'],value['sourceDescriptorMatches']),(0,2,0))
        print('entry-observer='+json.dumps({'childCountsRefusing':[1,2,3],'status':77,'fourChildrenVisited':1,'lastChildSourceMissed':True}))

    def test_valid_counts_traverse_every_child_and_preserve_metadata_oracles(self):
        for children in (0,1,2,3,4,7,255):
            code,value,diagnostic=self.observe(children=children)
            self.assertEqual((code,value['observerRefused'],diagnostic),(0,False,None))
            self.assertEqual(value['observedProcesses'],children+1)
            self.assertEqual(value['fd8PipeProcesses'],children)
            self.assertEqual(value['fd8IdentitiesCompared'],children)
            self.assertEqual(value['fd8IdentitiesDifferent'],children)
            self.assertEqual((value['fd8SourceIdentityMatches'],value['sourceDescriptorMatches'],value['inheritedProverLockBridges']),(0,0,0))
            self.assertEqual(value['nullStdioPrivateBridgeProcesses'],1)
        # R-2442 measured 4,074 cumulative distinct PIDs in the normal runner.
        # Closed provenance: ENG-1671-R2442-EVIDENCE-20261019/
        # mig01-baseline-provenance.json (added in R-2450).
        # An otherwise valid history one root beyond 4,096 must stay observable.
        code,value,diagnostic=self.observe('ordinary-history',4)
        self.assertEqual((code,value['observerRefused'],diagnostic),(0,False,None))
        self.assertEqual(value['observedProcesses'],4101)

    def test_source_request_and_lock_canaries_still_fire(self):
        for scenario,field in (('source','sourceDescriptorMatches'),('request','sourceDescriptorMatches'),('lock','inheritedProverLockBridges')):
            code,value,diagnostic=self.observe(scenario,4)
            self.assertEqual((code,value['observerRefused'],diagnostic),(0,False,None))
            self.assertEqual(value[field],1)
            # The driver's unchanged zero-match assertion must reject this.
            self.assertNotEqual(value[field],0)

    def test_fd8_filter_requires_closed_unused_descriptors_and_bash(self):
        for scenario in ('unused-null','unused-pipe','unrelated-node'):
            code,value,diagnostic=self.observe(scenario,1)
            self.assertEqual((code,value['observerRefused'],diagnostic),(0,False,None))
            self.assertEqual((value['fd8PipeProcesses'],value['fd8SocketProcesses'],value['fd8IdentitiesCompared']),(0,0,0))
        original=OBSERVER.read_text();before='&& unused_closed)';self.assertEqual(original.count(before),1)
        source=self.base/'unused-mutant.c';source.write_text(original.replace(before,'&& (unused_closed || 1))'))
        mutant=self.build(source,'unused')
        statuses=[]
        for binary in (self.fixed,mutant,self.fixed):
            code,value,_=self.observe('unused-null',1,binary)
            statuses.append(0 if code==0 and value['fd8IdentitiesCompared']==0 else 19)
        self.assertEqual(statuses,[0,19,0])
        print('observer-unused-mutation='+json.dumps({'regressionStatuses':statuses,'nullDoesNotSubstituteForClosed':True}))

    def test_existing_refusals_stay_77_with_fixed_names_and_codes(self):
        for scenario,reason,error in (('child-negative','child-list',1),('child-full','child-list',0),
                ('child-over','child-list',0),('fd-negative','descriptor-list',13),('fd-full','descriptor-list',0),
                ('fd-shape','descriptor-list',0),('uid','uid',0),('depth','depth',0),
                ('capacity','process-capacity',0),('timeout','timeout',0)):
            code,value,diagnostic=self.observe(scenario)
            self.assertEqual((code,value['observerRefused'],diagnostic),(77,True,{'reason':reason,'errno':error}))

    def test_traversal_and_capacity_mutations_fail_then_restore(self):
        original=OBSERVER.read_text()
        for label,before,after,scenario,children in (
            ('traversal','i<childcount;i++','i<childcount/(int)sizeof(children[0]);i++','source',4),
            ('capacity','childcount>=(int)(sizeof(children)/sizeof(children[0]))','childcount>(int)(sizeof(children)/sizeof(children[0]))','child-full',4),
            ('pid-history','#define OBSERVED_PID_CAPACITY 16384','#define OBSERVED_PID_CAPACITY 4096','ordinary-history',4)):
            self.assertEqual(original.count(before),1)
            path=self.base/(label+'-mutant.c');path.write_text(original.replace(before,after))
            mutant=self.build(path,label)
            statuses=[]
            for binary in (self.fixed,mutant,self.fixed):
                code,value,_=self.observe(scenario,children,binary)
                valid=(code==0 and value['sourceDescriptorMatches']==1) if label=='traversal' else (code==0 and value['observedProcesses']==4101 and not value['observerRefused']) if label=='pid-history' else (code==77 and value['observerRefused'])
                statuses.append(0 if valid else 19)
            self.assertEqual(statuses,[0,19,0])
        print('observer-mutations='+json.dumps({'independentMutations':3,'regressionStatuses':[0,19,0],'restored':True}))

    def test_real_canary_build_and_own_descriptor_probe(self):
        binary=self.base/'observer';fixture=self.base/'synthetic-source';fixture.write_text('synthetic observer canary')
        command=['/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',str(OBSERVER),'-lproc','-o',str(binary)]
        built=subprocess.run(command,capture_output=True,timeout=30)
        self.assertEqual((built.returncode,len(built.stdout),len(built.stderr)),(0,0,0))
        actual=subprocess.run([str(binary),'--canary',str(fixture)],capture_output=True,timeout=5)
        self.assertEqual((actual.returncode,len(actual.stderr)),(0,0))
        self.assertEqual(json.loads(actual.stdout),{'sourceFstatDetectorFires':True,'transportFstatDiffers':True})
        self.assertEqual(abi_probe(),0)
        print('observer-real-canary='+json.dumps({'exit':0,'sourceFstatDetectorFires':True,'transportFstatDiffers':True,
                'sourceSha256':hashlib.sha256(OBSERVER.read_bytes()).hexdigest(),'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))

    def test_real_normal_observer_reproduces_refusal_on_own_child_subtree(self):
        fixture=self.base/'normal-source';fixture.write_text('synthetic normal observer control')
        child=subprocess.Popen(['/bin/bash','-c','trap \'kill "$child"; wait "$child"; exit\' TERM; /bin/sleep 30 & child=$!; printf R; wait'],
                               stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        try:
            self.assertTrue(select.select([child.stdout],[],[],5)[0]);self.assertEqual(child.stdout.read(1),b'R')
            measured=[]
            for label,source,wanted in (('normal-entry',self.base/'entry.c',77),('normal-fixed',OBSERVER,0)):
                binary=self.base/label
                wrapper=self.base/(label+'-ready.c')
                # Signal after inspect returns, rather than racing executable
                # startup with a timed stop. All process APIs remain real.
                wrapper.write_text('#include <unistd.h>\nstatic int ready_sleep(useconds_t);\n#define usleep ready_sleep\n#include '+json.dumps(str(source))+r'''
#undef usleep
static int ready_sleep(useconds_t delay){static int ready;if(!ready){ready=1;int fd=atoi(getenv("OBSERVER_TEST_READY_FD"));if(write(fd,"R",1)!=1)return -1;}return usleep(delay);}
''')
                built=subprocess.run(['/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',str(wrapper),'-lproc','-o',str(binary)],capture_output=True,timeout=30)
                self.assertEqual((built.returncode,len(built.stdout),len(built.stderr)),(0,0,0))
                ready_read,ready_write=os.pipe()
                observer=subprocess.Popen([str(binary),str(child.pid),str(fixture)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                          pass_fds=(ready_write,),env={**os.environ,'OBSERVER_TEST_READY_FD':str(ready_write)})
                os.close(ready_write)
                try:
                    self.assertTrue(select.select([ready_read],[],[],5)[0]);self.assertEqual(os.read(ready_read,1),b'R')
                    stdout,stderr=observer.communicate(b'stop',timeout=5)
                    counts=json.loads(stdout)
                    self.assertEqual((observer.returncode,counts['observerRefused'],len(stderr)),(wanted,wanted==77,0))
                    self.assertGreater(counts['samples'],0)
                    if wanted==0:self.assertGreaterEqual(counts['observedProcesses'],2)
                    measured.append({'label':label,'code':observer.returncode,'observerRefused':counts['observerRefused'],
                                     'observedProcesses':counts['observedProcesses'],'samplesPositive':counts['samples']>0,
                                     'sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()})
                finally:
                    os.close(ready_read)
                    if observer.poll() is None:observer.kill();observer.wait()
            print('observer-real-normal='+json.dumps({'ownSyntheticSubtreeOnly':True,'observerIsSibling':True,'observations':measured}))
        finally:
            child.terminate();child.wait(timeout=5);child.stdout.close()

    def test_closed_diagnostic_rejects_unknown_missing_types_and_extra_stream(self):
        module=reproduction()
        for reason in module.OBSERVER_REASONS:
            raw=(json.dumps({'reason':reason,'errno':0},separators=(',',':'))+'\n').encode()
            self.assertEqual(module.observer_diagnostic(raw),{'reason':reason,'errno':0})
        raw=b'{"reason":"child-list","errno":1}\n'
        bads=[raw+b'SYNTHETIC_PRIVATE_TEXT_CANARY',b' '+raw,raw.rstrip(),b'X'*257,
              raw.replace(b'child-list',b'SYNTHETIC_PRIVATE_TEXT_CANARY'),raw.replace(b'1',b'true'),
              raw.replace(b'1',b'1.0'),raw.replace(b'1',b'-1'),raw.replace(b'1',b'4096'),
              raw.replace(b'1',b'01'),raw.replace(b'{',b'{"extra":0,'),raw.replace(b'{',b'{"reason":"uid",'),
              raw.replace(b',"errno":1',b''),raw.replace(b'child-list',b'uid')]
        for bad in bads:
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):module.observer_diagnostic(bad)

    def test_closed_observation_keeps_refusal_and_complete_count_schema(self):
        module=reproduction();code,counts,diagnostic=self.observe('child-negative')
        value={'schema':'eng1436-descriptor-observer-v1','code':code,'observer':counts,
               'stderrBytes':len((json.dumps(diagnostic,separators=(',',':'))+'\n').encode()),'diagnostic':diagnostic}
        self.assertEqual(module.observer_observation(value),value)
        self.assertEqual(module.observer_observation({**value,'diagnostic':None})['code'],77)
        code,counts,_=self.observe(children=1)
        valid={**value,'code':code,'observer':counts,'stderrBytes':0,'diagnostic':None}
        self.assertEqual(module.observer_observation(valid),valid)
        invalids=[{k:v for k,v in value.items() if k!=key} for key in value]
        invalids.extend([{**value,'unknown':0},{**value,'code':0},{**value,'code':True},{**value,'code':2},
                        {**value,'stderrBytes':True},{**value,'stderrBytes':-1},{**value,'stderrBytes':2**53},
                        {**value,'stderrBytes':value['stderrBytes']+1},{**value,'schema':'SYNTHETIC_PRIVATE_TEXT_CANARY'},
                        {**valid,'stderrBytes':1},{**valid,'diagnostic':diagnostic}])
        invalids.extend({**value,'observer':{k:v for k,v in value['observer'].items() if k!=key}} for key in value['observer'])
        for key in COUNTS:
            for wrong in (True,-1,1.0,'1',None,2**53):
                invalids.append({**value,'observer':{**value['observer'],key:wrong}})
        invalids.extend([{**value,'observer':{**value['observer'],'extra':0}},
                        {**value,'observer':{**value['observer'],'observerRefused':1}},
                        {**value,'diagnostic':{'reason':'SYNTHETIC_PRIVATE_TEXT_CANARY','errno':0}},
                        {**value,'diagnostic':{**diagnostic,'extra':0}}])
        for invalid in invalids:
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):module.observer_observation(invalid)

    def test_host_composition_overlays_observer_and_preserves_every_assertion(self):
        module=reproduction();driver=module.diagnostic_driver(ROOT);tree=ast.parse(driver)
        self.assertIn(module.OBSERVER,module.OVERLAYS);self.assertIn(module.OBSERVER_TEST,module.OVERLAYS)
        self.assertIn("run('descriptor-observer-controls'",driver)
        self.assertIn("summary['descriptorObserverBuild']",driver)
        original=(ROOT/module.TEST).read_text()
        self.assertEqual(original.count("observation.request],{stdio:['pipe','pipe','pipe']});"),1)
        main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
        edits=[]
        for node in main.body:
            if isinstance(node,ast.For) and isinstance(node.target,ast.Tuple) and len(node.target.elts)==3 and isinstance(node.iter,ast.List):
                edits.extend(ast.literal_eval(node.iter))
        transformed=original
        for relative,before,after in edits:
            if relative==module.TEST:
                self.assertEqual(transformed.count(before),1);transformed=transformed.replace(before,after)
        assertions=lambda text:[line.strip() for line in text.splitlines() if 'expect(' in line]
        self.assertEqual(assertions(transformed),assertions(original))
        self.assertIn("[observed.code,observed.value.observerRefused],JSON.stringify(observed.diagnostic)).toEqual([0,false])",transformed)
        caller="runtimeStep('runner-complete');\n    requireFailClosed(f,status);"
        self.assertEqual(original.count(caller),1)
        self.assertLess(transformed.index("'-observer-closed.json'"),transformed.index('requireFailClosed(f,status);',transformed.index("runtimeStep('runner-complete')")))
        self.assertIn("stderrBytes:observed.stderrBytes,diagnostic:observed.diagnostic",transformed)

    def test_javascript_capture_uses_same_whole_stream_names_and_codes(self):
        module=reproduction();callback=module.observer_capture_edits()[-1][2].replace('(code:number)','(code)')
        script="""const observation={},runtimeStep=()=>{},observer={once:(_,fn)=>fn(77)};
const metadata=JSON.stringify({observerRefused:true}),observerError=Buffer.from(process.argv[1],'base64'),observerErrorBytes=observerError.length;
CALLBACK
observation.descriptorResult.then(value=>{process.exit(value.diagnostic===null?19:0)});
""".replace('CALLBACK',callback)
        import base64
        raw=b'{"reason":"child-list","errno":1}\n'
        bads=[raw+b'SYNTHETIC_PRIVATE_TEXT_CANARY',b' '+raw,raw.replace(b'child-list',b'SYNTHETIC_PRIVATE_TEXT_CANARY'),
              raw.replace(b'1',b'true'),raw.replace(b'1',b'1.0'),raw.replace(b'1',b'-1'),raw.replace(b'1',b'4096'),
              raw.replace(b'{',b'{"extra":0,'),raw.replace(b'{',b'{"reason":"uid",'),raw.replace(b'child-list',b'uid'),b'X'*257]
        for value,status in [(raw,0)]+[(bad,19) for bad in bads]:
            actual=subprocess.run([module.NODE,'-e',script,base64.b64encode(value).decode()],capture_output=True,timeout=5)
            self.assertEqual((actual.returncode,len(actual.stdout),len(actual.stderr)),(status,0,0))

    def test_failed_test_selection_is_retained_separately_from_runner_success(self):
        module=reproduction()
        self.assertEqual(module.NAME,'PH11-X-PROD/P0 genuine kernel stock runner reaches P/A/W and writes its check-live result then fails closed before the summary')
        titles=[row['title'] for row in json.loads(REPRODUCER.with_name('mig01-runtime-selection.json').read_bytes())['rows']]
        self.assertEqual((len(titles),len(set(titles)),titles.count(module.NAME)),(119,119,1))
        failed={'testResults':[{'assertionResults':[{'status':'failed','fullName':module.NAME}]+[{'status':'skipped','fullName':title} for title in titles if title!=module.NAME]}],
                'numPassedTests':0,'numFailedTests':1,'numPendingTests':118}
        self.assertEqual(module.selected_execution(failed,None),{'executed':1,'passed':0,'failed':1,'deselected':118})
        # The old 117/116 fixture must reach and fail the changed accounting.
        stale={'testResults':[{'assertionResults':failed['testResults'][0]['assertionResults'][:-2]}],
               'numPassedTests':0,'numFailedTests':1,'numPendingTests':116}
        with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):module.selected_execution(stale,None)
        with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):module.selected_execution(failed,'passed')
        fixed={'status':1,'contacts':[1,1,1],'deliveries':[1,1,1],'terminalBytes':1,'inventoryReason':None,
               'outerReason':'unclassified','runnerBinarySha256':'01'*32,'processListUnavailable':False,'outerRefusal':True,
               'memoryFloor':False,'workFailure':False,'openStage':False,'summaryCreated':False,
               **{key:True for key in ('outputCreated','runCreated','admissionCreated','resultCreated')}}
        old={**fixed,'status':1,'contacts':[1,0,0],'deliveries':[1,0,0],'inventoryReason':'ps',
             'outerReason':'live-plan-prover-inventory-ps','outerRefusal':True,'terminalBytes':72,
             **{key:False for key in ('runCreated','admissionCreated','resultCreated','summaryCreated')}}
        post={**fixed,'status':1,'outerReason':'live-request-process-list-unavailable','outerRefusal':True,'processListUnavailable':True,'summaryCreated':True,
              'terminalBytes':len(b'measure-pk-load: live-plan-refused reason=live-request-process-list-unavailable\n')}
        passed={'executed':1,'passed':1,'failed':0,'deselected':118};failed=module.selected_execution(failed,None)
        value={'observations':{'kernel-old':old,'kernel-post-w-old':post,'kernel-fixed':fixed},
               'selected':{'kernel-old':failed,'kernel-post-w-old':failed,'kernel-fixed':passed},
               'descriptorObservations':{'kernel-fixed':{'code':0}}}
        self.assertIsNone(module.require_kernel_expectations(value))
        invalids=[{**fixed,'status':0,'terminalBytes':0,'outerRefusal':False,'outerReason':None,'summaryCreated':True},
                  {**fixed,'status':0},{**fixed,'resultCreated':False},{**fixed,'summaryCreated':True}]
        invalids.extend({**fixed,key:[1 if index!=phase else 0 for index in range(3)]}
                        for key in ('contacts','deliveries') for phase in range(3))
        for invalid in invalids:
            value['observations']['kernel-fixed']=invalid
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):module.require_kernel_expectations(value)
        value['observations']['kernel-fixed']=fixed
        self.assertIsNone(module.require_kernel_expectations(value))
        for label in ('kernel-old','kernel-post-w-old','kernel-fixed'):
            valid=value['selected'][label]
            value['selected'][label]={**valid,'deselected':116}
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):module.require_kernel_expectations(value)
            value['selected'][label]=valid
            self.assertIsNone(module.require_kernel_expectations(value))
        value['selected']['kernel-fixed']=failed
        with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):module.require_kernel_expectations(value)
        before="    require(result['selected']['kernel-fixed']=={'executed':1,'passed':1,'failed':0,'deselected':118})\n"
        original=REPRODUCER.read_text();self.assertEqual(original.count(before),1)
        namespace={'__file__':str(REPRODUCER),'__name__':'observer_selection_mutant'}
        exec(compile(original.replace(before,''),'selection-mutation','exec'),namespace)
        self.assertIsNone(namespace['require_kernel_expectations'](value))
        with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):module.require_kernel_expectations(value)
        print('observer-selection-mutation='+json.dumps({'regressionStatuses':[0,19,0],'runnerRefusalDoesNotPassFailedTest':True}))

    def test_observer_build_binds_fresh_source_and_binary_identity(self):
        module=reproduction();source=hashlib.sha256(OBSERVER.read_bytes()).hexdigest()
        value={'sourceSha256':source,'binarySha256':'12'*32};composition={'kernel-fixed':[{'path':module.OBSERVER,'sha256':source}]}
        self.assertEqual(module.observer_build_observation(value,composition),value)
        invalids=[{k:v for k,v in value.items() if k!=key} for key in value]
        invalids.extend([{**value,'extra':False},{**value,'sourceSha256':True},{**value,'binarySha256':'SYNTHETIC_PRIVATE_TEXT_CANARY'},
                         {**value,'sourceSha256':'21'*32}])
        for invalid in invalids:
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):module.observer_build_observation(invalid,composition)
        for invalid in ({},{'kernel-fixed':[]},{'kernel-fixed':composition['kernel-fixed']*2}):
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):module.observer_build_observation(value,invalid)

    def test_diagnostic_binding_mutations_fire_then_restore(self):
        module=reproduction();code,counts,diagnostic=self.observe('child-negative')
        value={'schema':'eng1436-descriptor-observer-v1','code':code,'observer':counts,'stderrBytes':34,'diagnostic':diagnostic}
        value['stderrBytes']=len((json.dumps(diagnostic,separators=(',',':'))+'\n').encode())
        partial={**value,'diagnostic':None};success={**partial,'code':0,'stderrBytes':0,'observer':{**counts,'observerRefused':False}}
        cases=[
            ('diagnostic','int(match[2])<=4095','True',b'{"reason":"child-list","errno":4096}\n'),
            ('diagnostic',"value['reason'] in ('descriptor-list','child-list') or value['errno']==0",'True',b'{"reason":"uid","errno":1}\n'),
            ('observation',"set(observer)==set(OBSERVER_COUNTS)|{'observerRefused'}",'True',{**partial,'observer':{**counts,'extra':0}}),
            ('observation',"type(observer[k]) is int",'True',{**partial,'observer':{**counts,'samples':True}}),
            ('observation',"0<=observer[k]<=2**53-1",'True',{**partial,'observer':{**counts,'samples':-1}}),
            ('observation',"type(value['code']) is int",'True',{**success,'code':False}),
            ('observation',"observer['observerRefused']==(value['code']==77)",'True',{**partial,'observer':{**counts,'observerRefused':False}}),
            ('observation',"value['stderrBytes']==len(raw)",'True',{**value,'stderrBytes':value['stderrBytes']+1}),
            ('observation',"value['code']!=0 or value['stderrBytes']==0 and diagnostic is None",'True',{**success,'stderrBytes':1})]
        original=REPRODUCER.read_text()
        for function,before,after,invalid in cases:
            name='observer_'+function
            start=original.index('def '+name+'(');end=original.index('\ndef ',start)
            body=original[start:end];self.assertEqual(body.count(before),1)
            namespace={'__file__':str(REPRODUCER),'__name__':'observer_binding_mutant'}
            exec(compile(original[:start]+body.replace(before,after)+original[end:],'observer-binding-mutation','exec'),namespace)
            statuses=[]
            for call in (getattr(module,name),namespace[name],getattr(module,name)):
                try:call(invalid);statuses.append(19)
                except RuntimeError as error:
                    self.assertEqual(str(error),'kernel-reproduction-refused');statuses.append(0)
            self.assertEqual(statuses,[0,19,0])
        print('observer-binding-mutations='+json.dumps({'independentMutations':len(cases),'regressionStatuses':[0,19,0],'restored':True}))


def abi_probe():
    with tempfile.TemporaryDirectory(prefix='other-provers-observer-abi-',dir='/private/tmp') as directory:
        base=Path(directory);source=base/'probe.c';binary=base/'probe';fixture=base/'synthetic-source'
        fixture.write_text('synthetic observer metadata control')
        source.write_text(r'''
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc,char **argv){
    if(argc!=2)return 2;int ready[2],stop[2];if(pipe(ready)||pipe(stop))return 3;
    pid_t child=fork();if(child<0)return 4;
    if(!child){close(ready[0]);close(stop[1]);int fd=open(argv[1],O_RDONLY|O_NOFOLLOW);
        if(fd<0 || dup2(fd,12)<0)_exit(5);if(fd!=12)close(fd);
        if(write(ready[1],"R",1)!=1)_exit(6);close(ready[1]);char token;read(stop[0],&token,1);close(stop[0]);_exit(0);}
    close(ready[1]);close(stop[0]);char token;int prepared=read(ready[0],&token,1)==1;close(ready[0]);
    pid_t children[16]={0};errno=0;int count=proc_listchildpids(getpid(),children,sizeof(children)),child_error=errno;
    struct proc_fdinfo descriptors[128];errno=0;int bytes=proc_pidinfo(child,PROC_PIDLISTFDS,0,descriptors,sizeof(descriptors)),fd_error=errno;
    int listed=0;if(bytes>0 && bytes<(int)sizeof(descriptors) && bytes%(int)sizeof(descriptors[0])==0)
        for(int i=0;i<bytes/(int)sizeof(descriptors[0]);i++)if(descriptors[i].proc_fd==12 && descriptors[i].proc_fdtype==PROX_FDTYPE_VNODE)listed=1;
    struct vnode_fdinfo value;errno=0;int identity=proc_pidfdinfo(child,12,PROC_PIDFDVNODEINFO,&value,sizeof(value)),identity_error=errno;
    struct stat source;int matched=identity==(int)sizeof(value) && stat(argv[1],&source)==0 && value.pvi.vi_stat.vst_dev==(uint32_t)source.st_dev && value.pvi.vi_stat.vst_ino==(uint64_t)source.st_ino;
    close(stop[1]);int status;waitpid(child,&status,0);
    int known=prepared && count==1 && children[0]==child;
    printf("{\"heldSyntheticChildren\":1,\"childCountReturn\":%d,\"childQueryErrno\":%d,\"knownChildMatched\":%s,\"descriptorBytes\":%d,\"descriptorErrno\":%d,\"knownDescriptorListed\":%s,\"identityBytes\":%d,\"identityErrno\":%d,\"sourceIdentityMatched\":%s}\n",count,child_error,known?"true":"false",bytes,fd_error,listed?"true":"false",identity,identity_error,matched?"true":"false");
    return known && listed && matched && WIFEXITED(status) && WEXITSTATUS(status)==0?0:1;
}
''')
        command=['/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',str(source),'-lproc','-o',str(binary)]
        built=subprocess.run(command,capture_output=True,timeout=30)
        if built.returncode:
            print(json.dumps({'stage':'abi-build','exit':built.returncode,'stderrBytes':len(built.stderr)}));return 1
        print('fresh-unit-build='+json.dumps({'label':'observer-abi','sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
        result=subprocess.run([str(binary),str(fixture)],capture_output=True,timeout=10)
        value=json.loads(result.stdout)
        print('observer-abi='+json.dumps({'exit':result.returncode,'stderrBytes':len(result.stderr),'observation':value}))
        return result.returncode


if __name__=='__main__':
    if sys.argv[1:]==['--abi-probe']:sys.exit(abi_probe())
    unittest.main()
