#!/usr/bin/python3
"""Ordinary real-API comparisons restricted to our own synthetic subtree."""
import hashlib
import ast
import importlib.util
import json
import os
import pwd
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
SCRIPTS=ROOT/'tools/apnt-pool-action-circuit/scripts'
READER=ROOT/'tools/pool-action-modules/private-runner-process.c'
OBSERVER=SCRIPTS/'mig01-macos-observer.c'


def public_history_source(commit,path):
    spec=importlib.util.spec_from_file_location('public_history_source',OBSERVER.with_name('public-history-source.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.read_source(commit,path)



def worker(binary):
    child=subprocess.Popen(['/bin/sleep','60'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        print('{"ready":1}',flush=True)
        for line in sys.stdin:
            if line not in ('scan\n','churn\n'):break
            result=subprocess.run([binary,str(child.pid),'/bin/sleep']+(['churn'] if line=='churn\n' else []),capture_output=True,timeout=10)
            value=json.loads(result.stdout)
            print(json.dumps({'exit':result.returncode,'stderrBytes':len(result.stderr),'observation':value}),flush=True)
    finally:child.terminate();child.wait()


class ObserverInterference(unittest.TestCase):
    def test_real_pid_queries_while_observer_samples_same_subtree(self):
        with tempfile.TemporaryDirectory(prefix='other-provers-interference-',dir='/private/tmp') as directory:
            base=Path(directory);source=base/'query.c';binary=base/'inventory-probe';observer_binary=base/'macos-observer';fixture=base/'source'
            fixture.write_text('synthetic observer source')
            source.write_text('#include <sys/wait.h>\n#define main reader_main\n#include '+json.dumps(str(READER))+r'''
#undef main
int main(int argc,char **argv){
    if(argc!=3 && argc!=4)return 2;pid_t pid=atoi(argv[1]);int argmax=0;size_t size=sizeof(argmax);int mib[]={CTL_KERN,KERN_ARGMAX};
    if(sysctl(mib,2,&argmax,&size,NULL,0) || argmax<=0 || argmax>16*1024*1024)return 3;
    char *bytes=calloc(1,argmax);if(!bytes)return 4;
    int good=0,bad=0,error=0;const char *reason="none";
    if(argc==4){
        int skipped=0;const char *confirmation="none";
        for(int child_index=0;child_index<64;child_index++){
            int gate[2];if(pipe(gate))return 5;pid_t target=fork();if(target<0)return 6;
            if(!target){close(gate[1]);char byte;if(read(gate[0],&byte,1)!=1)_exit(7);close(gate[0]);execl("/bin/sleep","/bin/sleep","0.002",NULL);_exit(8);}
            close(gate[0]);struct kinfo_proc snapshot;
            int held=process(target,&snapshot);if(write(gate[1],"R",1)!=1)return 9;close(gate[1]);
            if(held!=1){waitpid(target,NULL,0);return 10;}
            for(int query=0;query<8;query++){
                struct recovery_budget recovery={0};
                const char *name=NULL;int found=command_of(&snapshot,bytes,argmax,&name,&recovery);
                if(found==1 && name && (!strcmp(name,argv[0]) || !strcmp(name,"/bin/sleep")))good++;
                else if(found==0)skipped++;
                else {if(!bad){error=closed_errno;reason=found<0?closed_reason:"name-mismatch";confirmation=closed_confirmation?closed_confirmation:"none";}bad++;}
                clear_name(&name);wipe(bytes,argmax);usleep(50);
            }
            int status;if(waitpid(target,&status,0)!=target || !WIFEXITED(status) || WEXITSTATUS(status))return 11;
        }
        free(bytes);printf("{\"queries\":512,\"matched\":%d,\"skipped\":%d,\"failed\":%d,\"reason\":\"%s\",\"errno\":%d,\"confirmation\":\"%s\"}\n",good,skipped,bad,reason,error,confirmation);return bad?1:0;
    }
    for(int i=0;i<256;i++){
        struct kinfo_proc value;int query_error=0;int status=process_query(pid,&value,&query_error);
        if(status!=1){bad++;if(!error){error=query_error;reason="process-query";}continue;}
        struct recovery_budget recovery={0};
        const char *name=NULL;int found=command_of(&value,bytes,argmax,&name,&recovery);
        if(found==1 && name && !strcmp(name,argv[2]))good++;
        else {bad++;if(!error){error=closed_errno;reason=found<0?closed_reason:"name-mismatch";}}
        clear_name(&name);wipe(bytes,argmax);usleep(100);
    }
    wipe(bytes,argmax);free(bytes);
    printf("{\"queries\":256,\"matched\":%d,\"failed\":%d,\"reason\":\"%s\",\"errno\":%d}\n",good,bad,reason,error);
    return bad?1:0;
}
''')
            old=base/'old.c';old.write_bytes(public_history_source('29e57d17cf5358e87e6c67bd66a3c47bf7853d8b',str(OBSERVER.relative_to(ROOT))))
            old_binary=base/'old/macos-observer';old_binary.parent.mkdir()
            for path,target in ((source,binary),(OBSERVER,observer_binary),(old,old_binary)):
                built=subprocess.run(['/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',str(path),'-lproc','-o',str(target)],capture_output=True,timeout=30)
                self.assertEqual((built.returncode,len(built.stdout),len(built.stderr)),(0,0,0))
            parent=subprocess.Popen(['/usr/bin/python3',str(Path(__file__).resolve()),'--worker',str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            observer=None;groups=[];observer_results=[]
            try:
                self.assertTrue(select.select([parent.stdout],[],[],5)[0]);self.assertEqual(json.loads(parent.stdout.readline()),{'ready':1})
                for mode in ('before','old-observer','fixed-observer','after'):
                    if mode.endswith('observer'):
                        selected=old_binary if mode=='old-observer' else observer_binary
                        observer=subprocess.Popen([str(selected),str(parent.pid),str(fixture)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    values=[]
                    for _ in range(8):
                        parent.stdin.write(b'scan\n');parent.stdin.flush()
                        self.assertTrue(select.select([parent.stdout],[],[],5)[0]);value=json.loads(parent.stdout.readline());values.append(value)
                        self.assertEqual(value,{'exit':0,'stderrBytes':0,'observation':{'queries':256,'matched':256,'failed':0,'reason':'none','errno':0}})
                    churn=[]
                    for _ in range(8):
                        parent.stdin.write(b'churn\n');parent.stdin.flush()
                        self.assertTrue(select.select([parent.stdout],[],[],10)[0]);value=json.loads(parent.stdout.readline());state=value['observation']
                        self.assertEqual((state['queries'],state['matched']+state['skipped']+state['failed'],value['stderrBytes']),(512,512,0))
                        self.assertEqual(value['exit'],1 if state['failed'] else 0)
                        self.assertIn(state['reason'],('none','arguments-query','name-mismatch','requery-identity','requery-budget','requery-limit','requery-wait','requery-clock'))
                        self.assertIn(state['confirmation'],('none','live','unconfirmed','query-error'))
                        churn.append(value)
                    groups.append({'mode':mode,'queries':sum(v['observation']['queries'] for v in values),'failed':sum(v['observation']['failed'] for v in values),
                                   'execChurnQueries':sum(v['observation']['queries'] for v in churn),'execChurnReaderRefusals':sum(v['exit']==1 for v in churn),
                                   'execChurnFailedQueries':sum(v['observation']['failed'] for v in churn),
                                   'execChurnFirstFailures':[v['observation'] for v in churn if v['exit']==1]})
                    if mode.endswith('observer'):
                        stdout,stderr=observer.communicate(b'stop',timeout=5);counts=json.loads(stdout)
                        wanted=77 if mode=='old-observer' else 0
                        self.assertEqual((observer.returncode,counts['observerRefused'],len(stderr)),(wanted,wanted==77,0))
                        self.assertGreater(counts['samples'],1);self.assertGreaterEqual(counts['observedProcesses'],1 if wanted else 3)
                        observer_results.append({'mode':mode,'code':observer.returncode,'samples':counts['samples'],'observedProcesses':counts['observedProcesses'],'observerRefused':counts['observerRefused']});observer=None
                print('observer-interference='+json.dumps({'ownSubtreeOnly':True,'globalInventoryExecuted':False,'groups':groups,'observers':observer_results,
                    'readerSourceSha256':hashlib.sha256(READER.read_bytes()).hexdigest(),'observerSourceSha256':hashlib.sha256(OBSERVER.read_bytes()).hexdigest(),
                    'probeSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'probeBinarySha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'observerBinarySha256':hashlib.sha256(observer_binary.read_bytes()).hexdigest()}))
            finally:
                if observer is not None:observer.communicate(b'stop',timeout=5)
                stdout,stderr=parent.communicate(b'stop\n',timeout=5);self.assertEqual((parent.returncode,len(stdout),len(stderr)),(0,0,0))

    def test_observer_basename_does_not_match_unchanged_other_prover_guard(self):
        path=SCRIPTS/'test-prove-memory-floors.py';spec=importlib.util.spec_from_file_location('guard_controls',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        for synthetic,expected in [('printf "123 /synthetic/macos-observer\\n"',(0,'',True,True)),
                ('printf "123 /synthetic/macos-observer\\n124 /synthetic/pool-pk-load\\n"',
                 (1,'measure-pk-load: live-plan-refused reason=live-plan-other-prover\n',False,False))]:
            control=module.ProverInventory();control.setUp()
            try:
                actual,memory,continued=control.inventory(synthetic,live=True)
                self.assertEqual((actual.returncode,actual.stderr,memory,continued),expected)
            finally:control.doCleanups()
        print('observer-name-guard='+json.dumps({'observerRefused':False,'independentProverRefused':True,'liveAliasLaunched':False}))

    def test_reproducer_change_keeps_observer_stderr_out_of_runner_stream(self):
        versions=('29e57d17cf5358e87e6c67bd66a3c47bf7853d8b','1957c58878dd5b1089654209e23054afc918da0a')
        for version in versions:
            relative='tools/apnt-pool-action-circuit/scripts/reproduce-kernel-stock-no-proof.py'
            code=subprocess.check_output(['/usr/bin/git','show',version+':'+relative],cwd=ROOT,stderr=subprocess.DEVNULL).decode()
            namespace={'__file__':str(ROOT/relative),'__name__':'routing_version'};exec(compile(code,'routing-version','exec'),namespace)
            generated=ast.parse(namespace['diagnostic_driver'](ROOT));main=next(node for node in generated.body if isinstance(node,ast.FunctionDef) and node.name=='main')
            donor=subprocess.check_output(['/usr/bin/git','show',namespace['RUNTIME_SOURCE']+':'+namespace['TEST']],cwd=ROOT,stderr=subprocess.DEVNULL).decode()
            for node in main.body:
                if isinstance(node,ast.For) and isinstance(node.target,ast.Tuple) and isinstance(node.iter,ast.List):
                    for path,before,after in ast.literal_eval(node.iter):
                        if path==namespace['TEST']:
                            self.assertEqual(donor.count(before),1);donor=donor.replace(before,after)
            start=donor.index("        runtimeStep('kernel-spawn');")
            end=donor.index('      } else child = actual.spawn(binary, args, observedOptions);',start)
            branch=donor[start:end]
            start=donor.index("      for(const stream of ['stdout','stderr']")
            end=donor.index('      observation.child =',start);capture=donor[start:end]
            unit=(branch+capture).replace(':Buffer','').replace(':number','').replace('ROOT!','ROOT').replace(' as const','')
            script=r'''
const {EventEmitter}=require('node:events'),{join}=require('node:path');
const processChild=()=>{const child=new EventEmitter();child.pid=123;child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.stdin={end(){}};child.kill=()=>{};return child};
const runner=processChild(),peer=processChild();let calls=0,child;
const actual={spawn:(file,args,options)=>{if(++calls===1){if(file!='/usr/bin/sandbox-exec'||JSON.stringify(options.stdio)!=='["ignore","pipe","pipe"]')process.exit(20);return runner};return peer}};
process.env.MIG01_TEST_OUTPUT_ROOT='/synthetic';
const observation={profile:'synthetic',plan:'synthetic',request:'synthetic',stdout:[],stderr:[],terminalBytes:0};
const args=[],observedOptions={stdio:['ignore','pipe','pipe']},runtimeStep=()=>{};
UNIT
const original=Buffer.from('live-request-process-list-unavailable\n');
peer.stderr.emit('data',Buffer.from('SYNTHETIC_PRIVATE_TEXT_CANARY'));
runner.stderr.emit('data',original);peer.stdout.emit('data',Buffer.from('{"observerRefused":true}'));peer.emit('close',77);
observation.descriptorResult.then(()=>process.exit(Buffer.concat(observation.stderr).equals(original)&&observation.terminalBytes===original.length?0:19));
'''.replace('UNIT',unit)
            actual=subprocess.run([str(Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.nvm/versions/node/v22.22.3/bin/node'),'-e',script],capture_output=True,timeout=5)
            self.assertEqual((actual.returncode,len(actual.stdout),len(actual.stderr)),(0,0,0))
        print('observer-stderr-routing='+json.dumps({'sourceVersions':list(versions),'observerBytesInRunnerStream':False,'originalRunnerBytesPreserved':True}))


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--worker':worker(sys.argv[2])
    else:unittest.main()
