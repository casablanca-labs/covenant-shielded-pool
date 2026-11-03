#!/usr/bin/python3
"""Temporary ENG-1459 readiness selection; ordinary harness controls are reusable.

The real helper is selected only by the explicit runtime readiness option. It
never narrows the reader's table or retains process rows, names or stream hashes.
"""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parent
ROOT=SCRIPTS.parents[2]
SOURCE=ROOT/'tools/pool-action-modules/private-runner-process.c'
COUNT=150
OVERALL_NS=300_000_000_000
SAMPLE_NS=2_000_000_000
WORKLOAD='permitted-build-exec'
spec=importlib.util.spec_from_file_location('availability_native',SCRIPTS/'test-native-process-scan.py')
NATIVE=importlib.util.module_from_spec(spec);spec.loader.exec_module(NATIVE)
OUTCOMES={'available','reader-refused','signal','diagnostic-invalid','inventory-invalid','timeout','launch-error','binding-changed'}
BINDING_KEYS={'candidateHead','fixtureHead','sourceSha256','binarySha256','profileSha256'}
SAMPLE_KEYS={'ordinal','mode','startedNs','elapsedNs','binding','bindingVerified','status','outcome',
             'reason','errno','confirmation','confirmationErrno','rows','stdoutBytes','stderrBytes'}

def require(ok):
    if not ok:raise RuntimeError('inventory-availability-refused')

def sha(data):return hashlib.sha256(data).hexdigest()

def valid_binding(value):
    return (type(value) is dict and set(value)==BINDING_KEYS and
            all(type(value[key]) is str and re.fullmatch('[0-9a-f]{40}' if key.endswith('Head') else '[0-9a-f]{64}',value[key]) for key in value))

class Rows:
    """Streaming validation; keep at most one bounded line, never emit identity."""
    def __init__(self,mode,required_pid):
        self.mode=mode;self.required=required_pid;self.seen=set();self.pending=b''
        self.rows=0;self.bytes=0;self.valid=True

    def feed(self,data):
        self.bytes+=len(data)
        if not self.valid:return
        self.pending+=data
        while b'\n' in self.pending:
            line,self.pending=self.pending.split(b'\n',1)
            fields=line.split(b' ',1)
            if (len(line)>16*1024*1024+32 or len(fields)!=2 or not re.fullmatch(b'(?:0|[1-9][0-9]{0,19})',fields[0]) or not fields[1]
                    or any(byte in fields[1] for byte in (b'\0',b'\r',b'\t'))):
                self.valid=False;self.pending=b'';return
            number=int(fields[0]);limit=2147483647 if self.mode=='pid' else 18446744073709551615
            if number>limit or self.mode=='pid' and (number==0 or number in self.seen):
                self.valid=False;self.pending=b'';return
            if self.mode=='pid':self.seen.add(number)
            self.rows+=1
        if len(self.pending)>16*1024*1024+32:self.valid=False;self.pending=b''

    def complete(self):
        return self.valid and not self.pending and (self.mode=='rss' or self.required in self.seen)

def projected(status,rows,stderr,timed_out=False,launch_errno=0):
    value={'status':status,'outcome':'available','reason':'none','errno':0,'confirmation':'none',
           'confirmationErrno':0,'rows':rows.rows,'stdoutBytes':rows.bytes,'stderrBytes':len(stderr)}
    if timed_out:value['outcome']='timeout'
    elif launch_errno:value.update(outcome='launch-error',errno=min(max(launch_errno,0),4095))
    elif status<0:value['outcome']='signal'
    else:
        try:diagnostic=NATIVE.reader_diagnostic(status,stderr)
        except RuntimeError:value['outcome']='diagnostic-invalid'
        else:
            value.update({key:diagnostic[key] for key in ('reason','errno','confirmation','confirmationErrno') if key in diagnostic})
            if status:value['outcome']='reader-refused'
            elif not rows.complete():value['outcome']='inventory-invalid'
    return value

def invoke(binary,profile,mode,timeout_ns):
    rows=Rows(mode,os.getpid());errors=bytearray();stderr_bytes=0;timed_out=False
    deadline=time.monotonic_ns()+timeout_ns
    try:child=subprocess.Popen(['/usr/bin/sandbox-exec','-p',profile,str(binary),'-axo',mode+'=,comm='],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    except OSError as error:return projected(127,rows,b'',launch_errno=error.errno or 1)
    io_errno=0
    try:
        with selectors.DefaultSelector() as selector:
            for stream,kind in ((child.stdout,'rows'),(child.stderr,'errors')):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,kind)
            while selector.get_map():
                remaining=deadline-time.monotonic_ns()
                if remaining<=0:timed_out=True;break
                for key,_ in selector.select(remaining/1e9):
                    data=os.read(key.fd,65536)
                    if not data:selector.unregister(key.fileobj);continue
                    if key.data=='rows':rows.feed(data)
                    else:
                        stderr_bytes+=len(data)
                        errors.extend(data[:max(0,257-len(errors))])
        if not timed_out:
            try:child.wait(timeout=max(0,(deadline-time.monotonic_ns())/1e9))
            except subprocess.TimeoutExpired:timed_out=True
    except OSError as error:io_errno=error.errno or 1
    finally:
        if child.poll() is None:child.kill()
        child.wait();child.stdout.close();child.stderr.close()
    value=projected(child.returncode,rows,bytes(errors),timed_out,io_errno)
    value['stderrBytes']=stderr_bytes
    return value

def collect(binding,current_binding,call,clock,started_ns,workload,max_unavailable=0,retain=None):
    """Exactly one issuance per ordinal; failures are retained, never replaced."""
    require(valid_binding(binding) and type(max_unavailable) is int and 0<=max_unavailable<=COUNT and workload==WORKLOAD)
    record={'schema':'eng1459-inventory-availability-v1','binding':binding,'workloadClass':workload,
            'workloadBasis':'supervisor-declared-window','maxUnavailablePerMode':max_unavailable,
            'samplesPerMode':COUNT,'overallLimitNs':OVERALL_NS,'sampleLimitNs':SAMPLE_NS,
            'startedNs':started_ns,'finishedNs':started_ns,'issued':[],'samples':[],'overallTimeout':False}
    for ordinal in range(COUNT*2):
        mode='pid' if ordinal%2==0 else 'rss';started=clock()
        if started-started_ns>=OVERALL_NS:record['overallTimeout']=True;break
        if current_binding()!=binding:break
        issued={'ordinal':ordinal,'mode':mode,'startedNs':started}
        record['issued'].append(issued)
        remaining=min(SAMPLE_NS-(clock()-started),OVERALL_NS-(clock()-started_ns))
        if remaining<=0:
            value=projected(124,Rows(mode,0),b'',True)
        else:value=call(mode,remaining)
        verified=current_binding()==binding
        ended=clock();elapsed=ended-started
        require(type(value) is dict and set(value)==SAMPLE_KEYS-{'ordinal','mode','startedNs','elapsedNs','binding','bindingVerified'})
        sample={**value,**issued,'elapsedNs':elapsed,'binding':dict(binding),'bindingVerified':verified}
        if not sample['bindingVerified']:sample['outcome']='binding-changed'
        elif elapsed>=SAMPLE_NS:sample['outcome']='timeout'
        record['samples'].append(sample)
        record['finishedNs']=ended
        if retain:retain(record)
        if ended-started_ns>=OVERALL_NS:record['overallTimeout']=True;break
        # Zero is the required readiness policy: retain this failed attempt and
        # stop. A denied native permission is never repeatedly probed either.
        if sample['outcome']!='available' and (max_unavailable==0 or sample['errno'] in (1,13)):break
    record['finishedNs']=clock()
    record['overallTimeout']=record['overallTimeout'] or record['finishedNs']-started_ns>=OVERALL_NS
    if retain:retain(record)
    return record

def evaluate(record,binding,max_unavailable):
    keys={'schema','binding','workloadClass','workloadBasis','maxUnavailablePerMode','samplesPerMode','overallLimitNs','sampleLimitNs',
          'startedNs','finishedNs','issued','samples','overallTimeout'}
    require(type(record) is dict and set(record)==keys and valid_binding(binding) and record['binding']==binding)
    require(type(max_unavailable) is int and 0<=max_unavailable<=COUNT and type(record['maxUnavailablePerMode']) is int and record['maxUnavailablePerMode']==max_unavailable)
    require(record['schema']=='eng1459-inventory-availability-v1' and record['workloadClass']==WORKLOAD and record['workloadBasis']=='supervisor-declared-window')
    require(all(type(record[key]) is int and record[key]==value for key,value in (('samplesPerMode',COUNT),('overallLimitNs',OVERALL_NS),('sampleLimitNs',SAMPLE_NS))))
    require(type(record['startedNs']) is int and type(record['finishedNs']) is int and 0<=record['startedNs']<=record['finishedNs'])
    require(record['finishedNs']-record['startedNs']<OVERALL_NS and record['overallTimeout'] is False)
    require(type(record['issued']) is list and type(record['samples']) is list and len(record['issued'])==len(record['samples'])==COUNT*2)
    unavailable={'pid':0,'rss':0};previous=record['startedNs']
    for ordinal,(issued,sample) in enumerate(zip(record['issued'],record['samples'])):
        mode='pid' if ordinal%2==0 else 'rss'
        require(type(issued) is dict and set(issued)=={'ordinal','mode','startedNs'} and type(issued['ordinal']) is int and issued['ordinal']==ordinal and issued['mode']==mode)
        require(type(sample) is dict and set(sample)==SAMPLE_KEYS and all(sample[key]==issued[key] and type(sample[key]) is type(issued[key]) for key in issued))
        require(type(sample['startedNs']) is int and type(sample['elapsedNs']) is int and previous<=sample['startedNs'] and 0<=sample['elapsedNs']<SAMPLE_NS)
        previous=sample['startedNs']+sample['elapsedNs'];require(previous<=record['finishedNs'])
        require(all(type(sample[key]) is str for key in ('outcome','reason','confirmation')))
        require(sample['binding']==binding and sample['bindingVerified'] is True and sample['outcome'] in OUTCOMES-{'timeout','binding-changed'})
        require(all(type(sample[key]) is int for key in ('status','errno','confirmationErrno','rows','stdoutBytes','stderrBytes')))
        require(-127<=sample['status']<=255 and 0<=sample['errno']<=4095 and 0<=sample['confirmationErrno']<=4095 and min(sample['rows'],sample['stdoutBytes'],sample['stderrBytes'])>=0)
        require(sample['reason'] in NATIVE.DIAGNOSTIC_REASONS and sample['confirmation'] in ('none','live','unconfirmed','query-error'))
        available=(sample['outcome']=='available' and sample['status']==0 and sample['reason']=='none' and sample['errno']==sample['confirmationErrno']==sample['stderrBytes']==0
                   and sample['confirmation']=='none' and (mode=='rss' or sample['rows']>0))
        require(sample['outcome']!='available' or available)
        unavailable[mode]+=int(not available)
    require(all(value<=max_unavailable for value in unavailable.values()))
    return {'schema':'eng1459-readiness-v1','scope':'eng1436-repair-only','passed':True,'binding':binding,'workloadClass':record['workloadClass'],
            'workloadBasis':record['workloadBasis'],'maxUnavailablePerMode':max_unavailable,'completed':{'pid':COUNT,'rss':COUNT},
            'unavailable':unavailable,'elapsedNs':record['finishedNs']-record['startedNs']}

def _real_host_series(base,max_unavailable,started,retain):
    require(type(max_unavailable) is int and max_unavailable==0 and os.environ.get('MIG01_READINESS_WORKLOAD')==WORKLOAD)
    source=SOURCE.read_bytes()
    require(source==subprocess.check_output(['/usr/bin/git','show','HEAD:tools/pool-action-modules/private-runner-process.c'],cwd=ROOT,stderr=subprocess.DEVNULL,timeout=2))
    binary=base/'availability-reader'
    built=subprocess.run(['/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',str(SOURCE),'-lproc','-o',str(binary)],capture_output=True,timeout=30)
    require(built.returncode==0 and SOURCE.read_bytes()==source)
    denied=base/'availability-denied';denied.write_text('synthetic read control')
    profile='(version 1) (allow default) (deny file-read* (literal '+json.dumps(str(denied))+'))'
    fixture=subprocess.check_output(['/usr/bin/git','rev-parse','HEAD'],cwd=ROOT,stderr=subprocess.DEVNULL,timeout=2).decode().strip()
    candidate=os.environ.get('MIG01_READINESS_CANDIDATE',fixture)
    def current():
        return {'candidateHead':candidate,'fixtureHead':subprocess.check_output(['/usr/bin/git','rev-parse','HEAD'],cwd=ROOT,stderr=subprocess.DEVNULL,timeout=2).decode().strip(),
                'sourceSha256':sha(SOURCE.read_bytes()),'binarySha256':sha(binary.read_bytes()),'profileSha256':sha(profile.encode())}
    binding=current();require(valid_binding(binding))
    allowed=subprocess.run(['/usr/bin/sandbox-exec','-p','(version 1) (allow default)','/bin/cat',str(denied)],capture_output=True,timeout=2)
    blocked=subprocess.run(['/usr/bin/sandbox-exec','-p',profile,'/bin/cat',str(denied)],capture_output=True,timeout=2)
    require(allowed.returncode==0 and allowed.stdout==b'synthetic read control' and not allowed.stderr and blocked.returncode==1 and not blocked.stdout)
    record=collect(binding,current,lambda mode,limit:invoke(binary,profile,mode,limit),time.monotonic_ns,started,WORKLOAD,max_unavailable,retain)
    return record,binding

def real_host_control(test,base,max_unavailable=0):
    started=time.monotonic_ns()
    destination=os.environ.get('MIG01_TEST_OUTPUT_ROOT');require(destination is not None)
    latest={'schema':'eng1459-preparation-v1','samples':[],'issued':[]}
    def retain(record):
        nonlocal latest
        latest=record
        temporary=Path(destination)/'inventory-availability-samples.next'
        temporary.write_text(json.dumps(record,sort_keys=True)+'\n')
        temporary.replace(Path(destination)/'inventory-availability-samples.json')
    retain(latest)
    receipt_path=Path(destination)/'inventory-availability-closed.json'
    receipt={'schema':'eng1459-readiness-v1','scope':'eng1436-repair-only','passed':False,'maxUnavailablePerMode':0,
             'outcome':'preparation-incomplete','workloadClass':WORKLOAD}
    receipt_path.write_text(json.dumps(receipt,sort_keys=True)+'\n')
    try:
        record,binding=_real_host_series(base,max_unavailable,started,retain)
        record['finishedNs']=time.monotonic_ns();retain(record)
        receipt=evaluate(record,binding,0)
        require(time.monotonic_ns()-started<OVERALL_NS)
    except Exception:
        receipt.update(outcome='readiness-refused',recordedSamples=len(latest['samples']),elapsedNs=time.monotonic_ns()-started)
        receipt_path.write_text(json.dumps(receipt,sort_keys=True)+'\n')
        test.fail('inventory-availability-refused')
    receipt_path.write_text(json.dumps(receipt,sort_keys=True)+'\n')
    print('inventory-availability='+json.dumps(receipt,sort_keys=True))

class AvailabilityHarness(unittest.TestCase):
    def setUp(self):
        self.binding={key:('0123456789abcdef'*2+'12345678' if key.endswith('Head') else '0123456789abcdef'*4) for key in BINDING_KEYS}
        self.now=100;self.calls=[]

    def clock(self):return self.now

    def call(self,mode,limit):
        self.calls.append((mode,limit));self.now+=1000
        return {'status':0,'outcome':'available','reason':'none','errno':0,'confirmation':'none','confirmationErrno':0,'rows':2 if mode=='pid' else 0,'stdoutBytes':20 if mode=='pid' else 0,'stderrBytes':0}

    def valid(self):return collect(self.binding,lambda:self.binding,self.call,self.clock,self.now,WORKLOAD)

    def rejects(self,record):
        with self.assertRaisesRegex(RuntimeError,'^inventory-availability-refused$'):evaluate(record,self.binding,0)

    def test_complete_interleaved_serial_series_and_zero_receipt(self):
        record=self.valid();receipt=evaluate(record,self.binding,0)
        self.assertEqual(self.calls,[('pid',SAMPLE_NS),('rss',SAMPLE_NS)]*150)
        self.assertEqual((receipt['maxUnavailablePerMode'],receipt['unavailable'],receipt['completed']),(0,{'pid':0,'rss':0},{'pid':150,'rss':150}))
        self.assertEqual(receipt['elapsedNs'],300000)
        path=SCRIPTS/'test-private-runner-runtime-no-proof.py'
        spec=importlib.util.spec_from_file_location('actual_runtime_receipt',path)
        runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
        context=(self.binding['candidateHead'],self.binding['fixtureHead'],self.binding['sourceSha256'])
        runtime.require_readiness_receipt(receipt,*context)
        invalid=[{**receipt,'maxUnavailablePerMode':1},{**receipt,'maxUnavailablePerMode':False},
                 {**receipt,'unavailable':{'pid':False,'rss':False}},{**receipt,'completed':{'pid':149,'rss':150}},
                 {**receipt,'passed':False},{**receipt,'private':'SYNTHETIC_ARG_CANARY'},
                 {**receipt,'binding':{**self.binding,'candidateHead':'f'*40}},{**receipt,'elapsedNs':OVERALL_NS}]
        invalid.extend({k:v for k,v in receipt.items() if k!=key} for key in receipt)
        for candidate in invalid:
            with self.assertRaisesRegex(RuntimeError,'^mig01-runtime-control-refused$'):runtime.require_readiness_receipt(candidate,*context)

    def test_refused_sample_never_disappears_or_becomes_named_prover_pass(self):
        record=self.valid();sample=record['samples'][22]
        sample.update(status=1,outcome='reader-refused',reason='requery-budget',rows=100)
        self.rejects(record);self.assertEqual(len(record['samples']),300)
        record['maxUnavailablePerMode']=1
        self.assertEqual(evaluate(record,self.binding,1)['unavailable'],{'pid':1,'rss':0})
        self.rejects(record)  # Required caller binds zero, independently of receipt.
        self.now=100;self.calls=[];retained=[]
        def refused(mode,limit):
            value=self.call(mode,limit)
            if len(self.calls)==3:value.update(status=1,outcome='reader-refused',reason='requery-budget')
            return value
        record=collect(self.binding,lambda:self.binding,refused,self.clock,self.now,WORKLOAD,retain=lambda value:retained.append(copy.deepcopy(value)))
        self.rejects(record);self.assertEqual(len(self.calls),3)
        self.assertEqual(retained[-1],record);self.assertEqual(record['samples'][-1]['reason'],'requery-budget')

    def test_missing_duplicate_and_replaced_samples_are_fatal(self):
        original=self.valid()
        for kind in ('missing','duplicate','replaced','issued-missing','issued-duplicate'):
            record=copy.deepcopy(original)
            if kind=='missing':record['samples'].pop(17)
            elif kind=='duplicate':record['samples'][17]=copy.deepcopy(record['samples'][15])
            elif kind=='replaced':
                record['samples'][17]=copy.deepcopy(record['samples'][15]);record['samples'][17]['ordinal']=17
            elif kind=='issued-missing':record['issued'].pop()
            else:record['issued'][17]=copy.deepcopy(record['issued'][15])
            self.rejects(record)

    def test_wrong_mode_binding_and_midseries_replacement_are_fatal(self):
        original=self.valid()
        for place in ('mode','sample-binding','receipt-binding','verified','issued-mode'):
            record=copy.deepcopy(original)
            if place=='mode':record['samples'][1]['mode']='pid'
            elif place=='sample-binding':record['samples'][1]['binding']['binarySha256']='f'*64
            elif place=='receipt-binding':record['binding']={**self.binding,'profileSha256':'f'*64}
            elif place=='verified':record['samples'][1]['bindingVerified']=False
            else:record['issued'][1]['mode']='pid'
            self.rejects(record)
        self.now=100;self.calls=[];checks=0
        def changed():
            nonlocal checks
            checks+=1
            return self.binding if checks<4 else {**self.binding,'binarySha256':'f'*64}
        record=collect(self.binding,changed,self.call,self.clock,self.now,WORKLOAD)
        self.rejects(record);self.assertEqual(len(self.calls),2)

    def test_sample_and_overall_timeouts_never_pass_or_reset(self):
        for kind in ('timeout','elapsed','overall','clock-backwards'):
            record=self.valid()
            if kind=='timeout':record['samples'][2]['outcome']='timeout'
            elif kind=='elapsed':record['samples'][2]['elapsedNs']=SAMPLE_NS
            elif kind=='overall':record['finishedNs']=record['startedNs']+OVERALL_NS
            else:record['samples'][2]['startedNs']=0
            self.rejects(record)
        self.now=100;self.calls=[]
        def slow(mode,limit):
            value=self.call(mode,limit);self.now+=SAMPLE_NS;return value
        record=collect(self.binding,lambda:self.binding,slow,self.clock,self.now,WORKLOAD)
        self.rejects(record);self.assertEqual(len(self.calls),1)
        self.assertEqual(record['samples'][0]['outcome'],'timeout');self.assertEqual(len(record['issued']),len(self.calls))
        self.now=100;self.calls=[]
        record=collect(self.binding,lambda:self.binding,slow,self.clock,self.now,WORKLOAD,1)
        with self.assertRaisesRegex(RuntimeError,'^inventory-availability-refused$'):evaluate(record,self.binding,1)
        self.assertLess(len(self.calls),300);self.assertTrue(record['overallTimeout'])

    def test_stream_and_diagnostic_projection_rejects_partial_and_private_data(self):
        rows=Rows('pid',731);rows.feed(b'731 neutral\n')
        self.assertEqual(projected(0,rows,b'')['outcome'],'available')
        rows=Rows('rss',731);self.assertEqual(projected(0,rows,b'')['outcome'],'available')
        for data in (b'',b'731 neutral',b'731 neutral\n731 duplicate\n',b'731 private\tname\n',b'0 name\n',b'999 other\n'):
            rows=Rows('pid',731);rows.feed(data)
            self.assertEqual(projected(0,rows,b'')['outcome'],'inventory-invalid')
        rows=Rows('pid',731);rows.feed(b'731 SYNTHETIC_ARG_CANARY\n')
        for status,raw,outcome in ((1,b'{"status":1,"reason":"requery-budget","errno":0}\n','reader-refused'),
                                   (0,b'SYNTHETIC_ENV_CANARY','diagnostic-invalid'),(1,b'not-json','diagnostic-invalid'),(-9,b'','signal')):
            value=projected(status,rows,raw);self.assertEqual(value['outcome'],outcome)
            self.assertNotIn('SYNTHETIC_',json.dumps(value));self.assertNotIn('731',json.dumps(value))
        # Exercise actual streaming/timeout/owned-child cleanup, substituting only
        # the launch command with our own synthetic Python writer: no Seatbelt.
        original=subprocess.Popen;children=[];profile='synthetic-unchanged-profile'
        for mode,stall in (('pid',False),('rss',False),('pid',True)):
            def launch(command,**options):
                self.assertEqual(command,['/usr/bin/sandbox-exec','-p',profile,'synthetic-reader','-axo',mode+'=,comm='])
                code='import time;time.sleep(5)' if stall else 'import os;os.write(1,'+repr((str(os.getpid())+' neutral\n').encode() if mode=='pid' else b'12 neutral\n')+')'
                child=original([sys.executable,'-c',code],**options);children.append(child);return child
            with patch.object(subprocess,'Popen',launch):value=invoke('synthetic-reader',profile,mode,100_000_000 if stall else SAMPLE_NS)
            self.assertEqual(value['outcome'],'timeout' if stall else 'available')
            self.assertIsNotNone(children[-1].poll())

    def test_complete_schema_types_and_unknown_fields_are_closed(self):
        original=self.valid()
        for key in original:
            record=copy.deepcopy(original);del record[key];self.rejects(record)
        for key in SAMPLE_KEYS:
            record=copy.deepcopy(original);del record['samples'][0][key];self.rejects(record)
        for key,value in (('status',True),('rows',-1),('outcome','SYNTHETIC_ARG_CANARY'),('errno',4096),('confirmation','unknown')):
            record=copy.deepcopy(original);record['samples'][0][key]=value;self.rejects(record)
        record=copy.deepcopy(original);record['private']='SYNTHETIC_ENV_CANARY';self.rejects(record)

    def test_actual_evaluator_mutations_fire_then_restore(self):
        source=Path(__file__).read_text();tree=ast.parse(source)
        function=ast.get_source_segment(source,next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='evaluate'))
        bad=self.valid();bad['samples'][0].update(status=1,outcome='reader-refused',reason='requery-budget')
        cases=[('threshold','require(all(value<=max_unavailable for value in unavailable.values()))','pass',bad)]
        bad=self.valid();bad['samples'][-1]['binding']={**self.binding,'binarySha256':'f'*64}
        cases.append(('binding',"sample['binding']==binding",'True',bad))
        bad=self.valid();bad['samples'][-1]['mode']=bad['issued'][-1]['mode']='pid'
        cases.append(('mode',"issued['mode']==mode",'True',bad))
        bad=self.valid();bad['samples'][-1]['startedNs']+=10;bad['finishedNs']+=10
        cases.append(('replacement',"all(sample[key]==issued[key] and type(sample[key]) is type(issued[key]) for key in issued)",'True',bad))
        bad=self.valid();bad['samples'][-1]['elapsedNs']=SAMPLE_NS;bad['finishedNs']+=SAMPLE_NS
        cases.append(('sample-ceiling',"0<=sample['elapsedNs']<SAMPLE_NS","0<=sample['elapsedNs']",bad))
        bad=self.valid();bad['samples'].pop();bad['issued'].pop()
        cases.append(('missing',"len(record['issued'])==len(record['samples'])==COUNT*2","len(record['issued'])==len(record['samples'])",bad))
        bad=self.valid();bad['finishedNs']=bad['startedNs']+OVERALL_NS
        cases.append(('overall-ceiling',"record['finishedNs']-record['startedNs']<OVERALL_NS",'True',bad))
        for label,marker,replacement,bad in cases:
            self.assertEqual(function.count(marker),1);statuses=[]
            for candidate in (function,function.replace(marker,replacement),function):
                namespace=dict(globals());exec(compile(candidate,'actual-availability-evaluator','exec'),namespace)
                try:namespace['evaluate'](bad,self.binding,0)
                except RuntimeError as error:self.assertEqual(str(error),'inventory-availability-refused');statuses.append(0)
                else:statuses.append(19)
            self.assertEqual(statuses,[0,19,0],label)
            print('availability-oracle='+json.dumps({'guard':label,'statuses':statuses,'hostExecuted':False}))

if __name__=='__main__':unittest.main()
