#!/usr/bin/python3
"""Diagnostic-only source transformations for the disposable kernel fixture.

No production import, guard selector, wrapper process or retained FD.
A fixed diagnostic-only reader role never selects a query or guard behavior.
"""
import ast
import json
import os
from pathlib import Path
import re
import stat

RUNNER='tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh'
MAIN='tools/apnt-pool-action-circuit/cmd/pool-pk-load/main.go'
GO_BRIDGE='tools/apnt-pool-action-circuit/internal/runneradmission/bridge.go'
GO_TRACE='tools/apnt-pool-action-circuit/internal/runneradmission/eng1436_diagnostic.go'
BOOTSTRAP='tools/pool-action-modules/private-runner-bootstrap.mjs'
BRIDGE='tools/pool-action-modules/private-runner-bridge.mjs'
INSTALLATION='tools/pool-action-modules/private-runner-installation.py'
PATHS=[GO_BRIDGE,GO_TRACE,BOOTSTRAP,BRIDGE,INSTALLATION]
READER='tools/pool-action-modules/private-runner-process.c'
LIVE='tools/apnt-pool-action-circuit/cmd/pool-pk-load/live_harness.go'
ROLES=('quiet-start','quiet-case','rss-initial','rss-periodic','rss-final','ancestry','post-w-child')
STAGES=('kernel-old','kernel-post-w-old','kernel-fixed','kernel-quiet-diagnostic')
REASONS=('process-table-size','process-table-size-shape','process-table-allocation','process-table-fetch',
         'process-table-fetch-shape','argmax-query','argmax-shape','arguments-allocation','pid','foreign-path',
         'foreign-delimiter','arguments-query','arguments-size','arguments-count','executable-terminator',
         'argv0-terminator','argv0-delimiter','rss-query','stdout','identity-allocation','requery-clock',
         'requery-budget','requery-wait','requery-identity','requery-limit','ancestry-process','ancestry-path','ancestry-arguments')
BRANCHES={
 'control':tuple(stage+suffix for stage in STAGES for suffix in ('-begin','-end')),
 'phase':tuple(kind+'-'+phase for phase in ('P','A','W') for kind in ('contact','delivery')),
 'shell':('entry','early-exit','exit','private-exit','admit','inventory','sample-valid','sample-invalid','die-other','die-native-result'),
 'collector':('known-line','unknown-line','overlong-line','unterminated-line','empty','known-stream','unclassified-stream'),
 'native':('admit-complete','work-complete','other-complete','admit-refusal','work-refusal','other-refusal',
           'main-checkout','harness','prover-lock','result-write','failed','admit-entry','work-entry','other-entry'),
 'bridge':('fixed-invocation','installation','socketpair','null-open','inheritance','start','write','shutdown','read-wait','frame','complete'),
 'helper':('git-source','node-version','installation','reader-parent','reader-arguments','other'),
 'bootstrap':('entry','installation','plan-acquire','continuation','complete'),
 'issuer-bridge':('entry','metadata','read-route','owner-slot','issuer-contact','complete'),
 'installation':('complete','git','io','record','unclassified'),
 'native-scan':REASONS+tuple('arguments-query-'+name for name in ('live','unconfirmed','query-error'))}
BRANCHES.update({'reader-'+role:('call-start','call-end','complete','unclassified')+BRANCHES['native-scan'] for role in ROLES})
BRANCHES['number']=('swap-baseline','collector-bytes','collector-overflow','observer-exit','observer-stderr-bytes','observer-elapsed-ms')+tuple(role+'-'+metric for role in ROLES[2:5] for metric in ('swap','available','rss'))
BRANCHES['shell']+=('baseline','launch','monitor-healthy','monitor-unavailable','monitor-swap','monitor-rss','signal','wait','result-present','result-absent','sample-enter','sample-return')
BRANCHES['finish']=('cleanup','collector-wait','reason-read','reason-remove','stream-remove','directory-remove','complete')
BRANCHES['classification']=('unclassified',)
BRANCHES['bridge']+=('entry','read','wait','node-version','verify-source','verify-installation')
BRANCHES['bridge-enter']=BRANCHES['bridge']
MAX_BYTES=1<<20


def require(ok):
    if not ok:raise RuntimeError('kernel-attribution-refused')


def installation_branches(source):
    values={node.args[1].value for node in ast.walk(ast.parse(source)) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Name) and node.func.id=='require' and len(node.args)==2
            and isinstance(node.args[1],ast.Constant) and type(node.args[1].value) is str}
    packages=('protocol-runtime','chain-io','reference-aggregator','reference-wallet','wizardconnect-client','pool-wallet-host')
    for prefix in ('dist-directory-','dist-entry-','dependency-resolve-','dependency-realpath-','source-committed-'):
        values.update(prefix+name for name in packages)
    values.add('source-committed-runner-workspace')
    require(all(re.fullmatch('[a-z][a-z0-9-]{0,95}',name) for name in values))
    return tuple(sorted(set(BRANCHES['installation'])|values))


def validate(record,branches=BRANCHES):
    require(type(record) is dict)
    require(set(record)=={'producer','branch','status','errno','auxStatus'}|({'value'} if record.get('producer')=='number' else set()))
    require(type(record['producer']) is str and record['producer'] in branches
            and type(record['branch']) is str and record['branch'] in branches[record['producer']])
    require(type(record['status']) is int and -1<=record['status']<=255)
    require(all(type(record[key]) is int and 0<=record[key]<=4095 for key in ('errno','auxStatus')))
    if record['producer']=='number':require(type(record['value']) is int and -1<=record['value']<=2**53-1)
    if record['producer']=='number' and record['branch']=='collector-overflow':require(record['value'] in (0,1) and record['status']==0)
    require(record['producer']=='native-scan' or record['producer'].startswith('reader-') or record['errno']==record['auxStatus']==0)
    require(record['producer']!='native-scan' or record['status']==1)
    require(record['producer']!='phase' or record['status']==0)
    require(record['branch']=='arguments-query-query-error' or record['auxStatus']==0)
    if record['producer'].startswith('reader-'):
        if record['branch'] in ('call-start','complete'):require(record['status']==record['errno']==record['auxStatus']==0)
        elif record['branch']=='call-end':require(record['errno']==record['auxStatus']==0)
        else:require(record['status']==1)
    return record


def python_writer(path,branches):
    return '''
def eng1436_trace(producer,branch,status,error=0,aux=0,value=None):
    try:
        allowed=BRANCHES
        if producer not in allowed or branch not in allowed[producer] or type(status) is not int or not -1<=status<=255:return
        if type(error) is not int or not 0<=error<=4095 or type(aux) is not int or not 0<=aux<=4095:return
        row={'producer':producer,'branch':branch,'status':status,'errno':error,'auxStatus':aux}
        if producer=='number':
            if type(value) is not int or not -1<=value<=9007199254740991:return
            row['value']=value
        elif value is not None:return
        raw=(json.dumps(row,separators=(',',':'))+'\\n').encode()
        fd=os.open(TRACE_PATH,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info=os.fstat(fd)
            if stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600 and info.st_size+len(raw)<=1048576:os.write(fd,raw)
        finally:os.close(fd)
    except Exception:pass
'''.replace('BRANCHES',repr(branches)).replace('TRACE_PATH',repr(str(path)))


def collector(source,path,branches):
    """Keep original bounded whole-stream mapping and output exactly intact."""
    before='''raw = sys.stdin.buffer.read(limit + 1)
while sys.stdin.buffer.read(8192):
 pass
print(codes.get(raw, "unclassified"))'''
    after='''raw = sys.stdin.buffer.read(limit + 1)
pending=bytearray();overlong=False;total=len(raw)
def inspect_chunk(chunk):
 global pending,overlong
 for byte in chunk:
  if byte==10:
   if overlong:eng1436_trace("collector","overlong-line",1)
   else:inspect_line(bytes(pending)+b"\\n")
   pending.clear();overlong=False
  elif len(pending)<256 and not overlong:pending.append(byte)
  else:pending.clear();overlong=True
def inspect_line(line):
 if line in codes:
  eng1436_trace("collector","known-line",1);eng1436_trace("outer-code",codes[line],1);return
 try:
  value=json.loads(line)
  basic={"status","reason","errno"};extended=basic|{"confirmation","confirmationErrno"}
  assert type(value) is dict and set(value) in (basic,extended)
  assert type(value["status"]) is int and value["status"]==1 and value["reason"] in NATIVE_REASONS
  assert type(value["errno"]) is int and 0<=value["errno"]<=4095
  branch=value["reason"];aux=0
  if set(value)==extended:
   assert branch=="arguments-query" and value["confirmation"] in ("live","unconfirmed","query-error")
   aux=value["confirmationErrno"];assert type(aux) is int and 0<=aux<=4095
   assert value["confirmation"]=="query-error" or aux==0
   branch+="-"+value["confirmation"]
  assert line==(json.dumps(value,separators=(",",":"))+"\\n").encode()
  eng1436_trace("native-scan",branch,1,value["errno"],aux)
 except Exception:eng1436_trace("collector","unknown-line",1)
inspect_chunk(raw)
while True:
 chunk=sys.stdin.buffer.read(8192)
 if not chunk:break
 total+=len(chunk)
 inspect_chunk(chunk)
if pending or overlong:eng1436_trace("collector","unterminated-line",1)
eng1436_trace("collector","empty" if not raw else "known-stream" if raw in codes else "unclassified-stream",0 if not raw else 1)
eng1436_trace("number","collector-bytes",0,value=min(total,9007199254740991))
eng1436_trace("number","collector-overflow",0,value=int(total>limit))
print(codes.get(raw, "unclassified"))'''.replace('NATIVE_REASONS',repr(REASONS))
    require(source.count(before)==1)
    # This literal Python program lives inside a single-quoted Bash argument.
    writer=python_writer(path,branches)
    # Python repr single quotes would end that shell argument. Escape the
    # complete inserted text using the standard close/quoted-apostrophe form.
    insert='import json,os,stat\n'+writer+'\n'
    escape=lambda value:value.replace("'","'\"'\"'")
    source=source.replace('import sys\ncodes = {','import sys\n'+escape(insert)+'codes = {',1)
    return source.replace(before,escape(after))


def go_writer(path,branches):
    allowed=json.dumps({producer+':'+branch:True for producer,names in branches.items() for branch in names},separators=(',',':'))
    return '''package runneradmission
import("encoding/json";"os";"os/exec";"syscall")
func DiagnosticStatus(err error) int {if err==nil{return 0};if value,ok:=err.(*exec.ExitError);ok{if status,ok:=value.Sys().(syscall.WaitStatus);ok && status.Signaled(){return 128+int(status.Signal())};return value.ExitCode()};return -1}
func Diagnostic(producer,branch string,status int){
 allowed:=map[string]boolALLOWED
 if !allowed[producer+":"+branch] || status < -1 || status > 255{return}
 record:=struct{Producer string `json:"producer"`;Branch string `json:"branch"`;Status int `json:"status"`;Errno int `json:"errno"`;Aux int `json:"auxStatus"`}{producer,branch,status,0,0}
 raw,err:=json.Marshal(record);if err!=nil{return};raw=append(raw,10)
 file,err:=os.OpenFile(TRACE_PATH,os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0);if err!=nil{return};defer file.Close()
 info,err:=file.Stat();if err==nil {owner,ok:=info.Sys().(*syscall.Stat_t);if ok && owner.Uid==uint32(os.Geteuid()) && owner.Nlink==1 && info.Mode().IsRegular() && info.Mode().Perm()==0600 && info.Size()+int64(len(raw))<=1048576{file.Write(raw)}}
}
func diagnosticHelper(command *exec.Cmd) string {
 switch command.Path {case "/usr/bin/git":return "git-source";case "/usr/bin/python3":return "installation"}
 if len(command.Args)==2 && command.Args[1]=="--version" {return "node-version"}
 if len(command.Args)>1 {if command.Args[1]=="-ww"{return "reader-arguments"};if command.Args[1]=="-p"{return "reader-parent"}}
 return "other"
}
'''.replace('ALLOWED',allowed.replace(':true',':true')).replace('TRACE_PATH',json.dumps(str(path)))


def js_writer(path,branches):
    return '''
import {openSync as traceOpen,writeSync as traceWrite,closeSync as traceClose,fstatSync as traceStat,constants as traceFlags} from "node:fs";
function eng1436Trace(producer,branch,status){
 try{const allowed=BRANCHES;if(!allowed[producer]?.includes(branch)||!Number.isSafeInteger(status)||status < -1||status>255)return;
 const raw=Buffer.from(JSON.stringify({producer,branch,status,errno:0,auxStatus:0})+"\\n");
 const fd=traceOpen(TRACE_PATH,traceFlags.O_WRONLY|traceFlags.O_APPEND|traceFlags.O_NOFOLLOW);
 try{const st=traceStat(fd);if(st.isFile()&&st.uid===process.geteuid()&&st.nlink===1&&(st.mode&0o777)===0o600&&st.size+raw.length<=1048576)traceWrite(fd,raw);}finally{traceClose(fd);}
 }catch{}
}
'''.replace('BRANCHES',json.dumps(branches,separators=(',',':'))).replace('TRACE_PATH',json.dumps(str(path)))


def change(source,before,after):
    require(source.count(before)==1);return source.replace(before,after)


def instrument(fixture,path):
    """Only called on a private disposable export before its source commit."""
    branches={**BRANCHES,'installation':installation_branches((fixture/INSTALLATION).read_text())}
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
    shell=(fixture/RUNNER).read_text()
    helper='''
eng1436_trace() {
 case "$1" in entry|early-exit|exit|private-exit|admit|inventory|sample-valid|sample-invalid|die-other|die-native-result) ;; *) return 0;; esac
 [[ $2 =~ ^[0-9]+$ ]] || return 0
 [[ -f TRACE_PATH && ! -L TRACE_PATH ]] || return 0
 printf '{"producer":"shell","branch":"%s","status":%d,"errno":0,"auxStatus":0}\\n' "$1" "$2" >>TRACE_PATH 2>/dev/null || :
}
eng1436_trace entry 0
trap 'eng1436_trace early-exit "$?"' EXIT
'''.replace('TRACE_PATH',"'"+str(path).replace("'","'\"'\"'")+"'")
    shell=change(shell,'set -euo pipefail\n','set -euo pipefail\n'+helper)
    shell=change(shell,'trap cleanup EXIT','trap \'eng1436_trace exit "$?"; cleanup\' EXIT')
    shell=change(shell,' local status=$? reason=unclassified',' local status=$? reason=unclassified\n eng1436_trace private-exit "$status"')
    shell=change(shell,'die() {\n','die() {\n case "$*" in "native result refused") eng1436_trace die-native-result 1;; *) eng1436_trace die-other 1;; esac\n')
    shell=change(shell,'rss="$(phase_rss_bytes)" || rss=-1','rss="$(phase_rss_bytes)" || rss=-1\n if [[ $rss == "not measured" ]] || ((swap<0 || avail<0 || rss<0)); then eng1436_trace sample-invalid 1; else eng1436_trace sample-valid 0; fi')
    shell=change(shell,'others="$(other_provers 2>/dev/null)" || inventory_status=$?',
        'others="$(other_provers 2>/dev/null)" || inventory_status=$?\n if declare -F eng1436_trace >/dev/null; then eng1436_trace inventory "$inventory_status"; fi')
    invocation='POOL_PK_LOAD_HARNESS_PID=$$ "$bin" admit-request "${@:2}" "$results/$name.admission.json" || die "$name: live request admission failed"'
    shell=change(shell,invocation,'local eng1436_admit_status=0\n   '+invocation.split(' || die')[0]+' || eng1436_admit_status=$?\n   eng1436_trace admit "$eng1436_admit_status"\n   ((eng1436_admit_status==0)) || die "$name: live request admission failed"')
    shell=extended().shell_hooks(shell,path)
    (fixture/RUNNER).write_text(collector(shell,path,branches))
    (fixture/READER).write_text(extended().reader_hooks((fixture/READER).read_text(),path,branches))
    main=(fixture/MAIN).read_text()
    main=change(main,'func main() {','func main() {\n entry:="other-entry";if len(os.Args)>1 {switch os.Args[1]{case "admit-request":entry="admit-entry";case "check-live","prove":entry="work-entry"}}\n runneradmission.Diagnostic("native",entry,0)')
    call='''
 branch:="other-complete";if len(os.Args)>1 {switch os.Args[1]{case "admit-request":branch="admit-complete";case "check-live","prove":branch="work-complete"}}
 if result.refusal!=nil {switch branch{case "admit-complete":branch="admit-refusal";case "work-complete":branch="work-refusal";default:branch="other-refusal"}}
 if result.prerequisite!=nil {switch result.prerequisite.Error(){case "live-request-main-checkout-required":branch="main-checkout";case "live-request-harness-required":branch="harness";case "live-request-prover-lock-required":branch="prover-lock";default:branch="failed"}}
 runneradmission.Diagnostic("native",branch,result.status)
'''
    main=change(main,'\tif result.status != 0 {',call+'\tif result.status != 0 {');(fixture/MAIN).write_text(main)
    bridge=(fixture/GO_BRIDGE).read_text()
    bridge=change(bridge,'func helperOutput(command *exec.Cmd) ([]byte, error) {','func helperOutput(command *exec.Cmd) (output []byte, failure error) {\n defer func(){Diagnostic("helper",diagnosticHelper(command),DiagnosticStatus(failure))}()')
    bridge=change(bridge,'func helperRun(command *exec.Cmd) error {','func helperRun(command *exec.Cmd) (failure error) {\n defer func(){Diagnostic("helper",diagnosticHelper(command),DiagnosticStatus(failure))}()')
    bridge=change(bridge,'func AcquireSnapshot(root, source string) ([]byte, error) {','func AcquireSnapshot(root, source string) (snapshot []byte, failure error) {\n branch:="fixed-invocation"\n defer func(){Diagnostic("bridge",branch,DiagnosticStatus(failure))}()')
    bridge=extended().bridge_hooks(bridge)
    for before,branch in [('if err = verifyBridgeInstallation(root);','installation'),('pair, err := syscall.Socketpair(','socketpair'),
        ('null, err := os.OpenFile(','null-open'),('if closeBridgeInheritance() != nil {','inheritance'),('if command.Start() != nil {','start'),
        ("if _, err = parent.Write(",'write'),('if syscall.Shutdown(','shutdown'),('raw, err := io.ReadAll(','read-wait'),('return decodeBridgeFrame(raw)','frame')]:
        bridge=change(bridge,before,'branch="'+branch+'"\n Diagnostic("bridge-enter",branch,0)\n\t'+before)
    (fixture/GO_BRIDGE).write_text(bridge);(fixture/GO_TRACE).write_text(go_writer(path,branches)+extended().go_role_writer())
    (fixture/LIVE).write_text(extended().live_hooks((fixture/LIVE).read_text()))
    installation=(fixture/INSTALLATION).read_text();installation=change(installation,'if __name__ == "__main__":',python_writer(path,branches)+'\nif __name__ == "__main__":')
    installation=change(installation,'        main(sys.argv[1:])','        main(sys.argv[1:])\n        eng1436_trace("installation","complete",0)')
    installation=change(installation,'        print("private-runner-installation-refused:"','        eng1436_trace("installation",code if code in '+repr(branches['installation'])+' else "unclassified",1)\n        print("private-runner-installation-refused:"')
    (fixture/INSTALLATION).write_text(installation)
    bootstrap=(fixture/BOOTSTRAP).read_text();bootstrap=change(bootstrap,'let activeChild =',js_writer(path,branches)+'\nlet attributionBranch="entry";\nlet activeChild =')
    bootstrap=change(bootstrap,'  if (spawnSync("/usr/bin/python3",','  attributionBranch="installation";\n  if (spawnSync("/usr/bin/python3",')
    bootstrap=change(bootstrap,'  } else bytes = await acquire(root, output, plan);','  } else {attributionBranch="plan-acquire";bytes = await acquire(root, output, plan);}')
    bootstrap=change(bootstrap,'  const continuation = spawn(','  attributionBranch="continuation";\n  const continuation = spawn(')
    bootstrap=change(bootstrap,'  process.exitCode = await bootstrap();','  process.exitCode = await bootstrap();\n  eng1436Trace("bootstrap","complete",process.exitCode);')
    bootstrap=change(bootstrap,'} catch { process.exitCode = 1; }','} catch { eng1436Trace("bootstrap",attributionBranch,1);process.exitCode = 1; }');(fixture/BOOTSTRAP).write_text(bootstrap)
    node=(fixture/BRIDGE).read_text();node=change(node,'let activeContact =',js_writer(path,branches)+'\nlet activeContact =')
    node=change(node,'  let transport, acquired, terminated = false;','  let transport, acquired, terminated = false, attributionBranch="entry";')
    for before,branch in [('    const local = await new Promise','metadata'),('    acquired = readPrivateRunnerRoute','read-route'),
                         ('    const owner = mode ===','owner-slot'),('    const snapshot = await contact','issuer-contact')]:
        node=change(node,before,'    attributionBranch="'+branch+'";\n'+before)
    node=change(node,'    transport.end(frame(null, snapshot));','    eng1436Trace("issuer-bridge","complete",0);\n    transport.end(frame(null, snapshot));')
    node=change(node,'  } catch (error) {\n    if (transport','  } catch (error) {\n    eng1436Trace("issuer-bridge",attributionBranch,1);\n    if (transport');(fixture/BRIDGE).write_text(node)
    test_path=fixture/'tools/pool-action-modules/test/mig01-runtime-controls.test.ts';test=test_path.read_text()
    control='''
function eng1436Control(suffix:string,status:number){
 const stage=STAGES.find(value=>process.env.MIG01_CLOSED_LABEL===value+'-closed.json');
 if(!stage || !['begin','end'].includes(suffix) || !Number.isSafeInteger(status))throw new Error('attribution-control-refused');
 appendFileSync(TRACE_PATH,JSON.stringify({producer:'control',branch:stage+'-'+suffix,status,errno:0,auxStatus:0})+'\\n',{mode:0o600});
}
function eng1436Metric(branch:string,status:number,value:number){
 if(!['observer-exit','observer-stderr-bytes','observer-elapsed-ms'].includes(branch)||!Number.isSafeInteger(status)||status < -1||status>255||!Number.isSafeInteger(value)||value < -1)throw new Error('attribution-control-refused');
 appendFileSync(TRACE_PATH,JSON.stringify({producer:'number',branch,status,errno:0,auxStatus:0,value})+'\\n',{mode:0o600});
}
'''.replace('STAGES',repr(list(STAGES))).replace('TRACE_PATH',json.dumps(str(path)))
    test+=control
    test=change(test,"        runtimeStep('kernel-spawn');","        eng1436Control('begin',0);\n        runtimeStep('kernel-spawn');")
    test=change(test,"    runtimeStep('runner-complete');","    runtimeStep('runner-complete');\n    if(mode==='kernel'){await observation.descriptorResult!;eng1436Control('end',status);}")
    test=change(test,'        const observer = actual.spawn(', '        const eng1436ObserverStart=performance.now();\n        const observer = actual.spawn(')
    test=change(test,"observer.once('close',(code:number)=>{", "observer.once('close',(code:number,signal:string|null)=>{")
    test=change(test,"runtimeStep('observer-close');", "runtimeStep('observer-close');\n eng1436Metric('observer-exit',code??-1,signal===null?0:({SIGKILL:9,SIGTERM:15,SIGINT:2} as Record<string,number>)[signal]??-1);\n eng1436Metric('observer-stderr-bytes',0,observerErrorBytes);\n eng1436Metric('observer-elapsed-ms',0,Math.floor(performance.now()-eng1436ObserverStart));")
    test=change(test,'function runtimeStep(step:string) {',
        'function runtimeStep(step:string) {\n  if('+repr(list(BRANCHES['phase']))+".includes(step))appendFileSync("+json.dumps(str(path))+",JSON.stringify({producer:'phase',branch:step,status:0,errno:0,auxStatus:0})+'\\n',{mode:0o600});")
    test_path.write_text(test)
    return branches


def read_records(path,branches):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1
                and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=MAX_BYTES)
        with os.fdopen(fd,'rb',closefd=False) as source:raw=source.read(MAX_BYTES+1)
        require(len(raw)==info.st_size and len(raw)<=MAX_BYTES)
    finally:os.close(fd)
    rows=[]
    for line in raw.splitlines(keepends=True):
        require(len(line)<=512)
        row=validate(json.loads(line),branches)
        require(line==(json.dumps(row,separators=(',',':'))+'\n').encode());rows.append(row)
    require(len(rows)<=8192)
    return rows


def bind_records(rows,observations):
    result={};active=None;pending=[]
    for row in rows:
        if row['producer']=='control':
            branch=row['branch'];stage=branch.rsplit('-',1)[0]
            if branch.endswith('-begin'):
                require(active is None and stage not in result and row['status']==0);active=stage;pending=[]
            else:
                require(active==stage and row['status']==observations[stage]['status'])
                require(any(item['producer']!='phase' for item in pending))
                sequence=[item['branch'] for item in pending if item['producer']=='phase']
                require(sequence==list(BRANCHES['phase'])[:len(sequence)])
                for kind,key in (('contact','contacts'),('delivery','deliveries')):
                    require([sum(item['producer']=='phase' and item['branch']==kind+'-'+phase for item in pending) for phase in ('P','A','W')]==observations[stage][key])
                complete_records(pending,stage)
                if observations[stage].get('outerRefusal'):
                    require([item['branch'] for item in pending if item['producer']=='classification']==[observations[stage]['outerReason']])
                result[stage]={'schema':'eng1436-attribution-v1','sameInvocation':True,'records':pending,'runnerStatus':row['status']};active=None
        elif active is not None:pending.append(row)
    require(active is None and set(result)==set(observations))
    require(list(result)==[stage for stage in STAGES if stage in observations])
    return result


def complete_records(rows,stage):
    """Missing hooks are incomplete, including a lost native trace write.

    Explicit signal/start failures have no reader-return record; the caller's
    unchanged numeric status is still captured. Old stages deliberately use ps.
    """
    count=lambda producer,branch:sum(row['producer']==producer and row['branch']==branch for row in rows)
    require(count('shell','entry')>=1)
    for branch in ('observer-exit','observer-stderr-bytes','observer-elapsed-ms'):require(count('number',branch)==1)
    if count('shell','launch'):
        require(count('shell','wait')==count('native','work-entry')==1)
    if count('shell','admit'):require(count('shell','admit')==count('native','admit-entry')==1)
    if count('shell','private-exit'):
        for producer,branch in [('finish','cleanup'),('finish','complete'),('classification','unclassified')]:
            if producer!='classification':require(count(producer,branch)==1)
        require(sum(row['producer']=='classification' for row in rows)==1)
        for branch in ('collector-bytes','collector-overflow'):require(count('number',branch)==1)
    for role in ROLES:
        pending=False;diagnostic=None
        native=stage!='kernel-old' and (role!='post-w-child' or stage!='kernel-post-w-old')
        for row in rows:
            if row['producer']!='reader-'+role:continue
            if row['branch']=='call-start':require(not pending);pending=True;diagnostic=None
            elif row['branch']=='call-end':
                require(pending)
                if native and row['status'] not in (-1,) and row['status']<128:
                    require(diagnostic is not None and row['status']==diagnostic['status'])
                pending=False
            else:
                require(pending and diagnostic is None);diagnostic=row
                require((row['branch']=='complete')==(row['status']==0))
        require(not pending)
    samples=count('shell','sample-valid')+count('shell','sample-invalid')
    require(count('shell','sample-enter')==count('shell','sample-return')==samples)
    metric_rows=[row for row in rows if row['producer']=='number' and row['branch'].startswith('rss-')]
    require(len(metric_rows)==samples*3)
    for index in range(0,len(metric_rows),3):
        group=metric_rows[index:index+3];role=group[0]['branch'].rsplit('-',1)[0]
        require([row['branch'] for row in group]==[role+'-'+metric for metric in ('swap','available','rss')])
    periodic=count('number','rss-periodic-rss')
    require(sum(count('shell','monitor-'+kind) for kind in ('healthy','unavailable','swap','rss'))==periodic)
    for role in ROLES[2:5]:require(count('reader-'+role,'call-start')==count('number',role+'-rss'))


def closed(path,branches,observations):
    return bind_records(read_records(path,branches),observations)


def project(path,branches,observations):
    """Retain safe partial records even if a controller times out before end.

    Completeness/binding failure never licenses acceptance. Unknown record
    fields/names are not copied, and a privacy/schema failure yields no rows.
    """
    try:rows=read_records(path,branches)
    except Exception:return {'schema':'eng1436-attribution-v1','captureStatus':1,'error':'record-refused','frames':[],'unscopedRecords':[]}
    frames=[];outside=[];active=None
    for row in rows:
        if row['producer']=='control':
            stage=row['branch'].rsplit('-',1)[0]
            if row['branch'].endswith('-begin'):
                active={'stage':stage,'runnerStatus':None,'sameInvocation':False,'records':[]};frames.append(active)
            elif active is not None and active['stage']==stage:
                active['runnerStatus']=row['status'];active=None
            else:outside.append(row)
        elif active is not None:active['records'].append(row)
        else:outside.append(row)
    try:
        bound=bind_records(rows,observations)
        for frame in frames:frame['sameInvocation']=frame['stage'] in bound
        status=0;error=None
    except Exception:status=1;error='binding-refused'
    return {'schema':'eng1436-attribution-v1','captureStatus':status,'error':error,'frames':frames,'unscopedRecords':outside}


# Reuse the actual closed allowlist, rather than maintaining another copy of
# its names. This reads committed source code, never a process/private stream.
_source=(Path(__file__).resolve().parents[3]/RUNNER).read_text()
_mapping=ast.literal_eval(_source.split('codes = ',1)[1].split('\nlimit =',1)[0].strip())
require(type(_mapping) is dict and all(type(key) is bytes and type(value) is str and re.fullmatch('[a-z][a-z0-9-]{0,95}',value) for key,value in _mapping.items()))
BRANCHES['outer-code']=tuple(sorted(set(_mapping.values())))
BRANCHES['classification']+=BRANCHES['outer-code']

def extended():
    import importlib.util
    spec=importlib.util.spec_from_file_location('eng1436_capture',Path(__file__).with_name('kernel-attribution-capture.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
