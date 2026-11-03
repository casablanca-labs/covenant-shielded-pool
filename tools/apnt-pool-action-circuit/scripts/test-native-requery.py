#!/usr/bin/python3
"""Finite API-sequence, identity, budget, redaction and mutation controls.

Only the separately selected host helper exercises real exec transitions.
Ordinary controls never query the host process table or run a prover.
"""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
SCRIPTS=Path(__file__).resolve().parent
READER=ROOT/'tools/pool-action-modules/private-runner-process.c'
CONTROL=SCRIPTS/'mig01-native-requery-controls.c'
KEYS={'readerStatus','reason','errno','confirmation','confirmationErrno','arguments','additional',
      'confirmations','paths','tasks','waits','elapsedNs','firstWaitNs','secondWaitNs','resetViolations',
      'argumentWipes','identityWipes','rows','namedRows','canaryOutput','fallbackControls',
      'chargedAdditional','recoveryNs','episodeActive'}


def load(name):
    spec=importlib.util.spec_from_file_location(name,SCRIPTS/name)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def host_firing_record(value,guard,denied,reader,stderr_bytes,stdout_bytes,allowed_read):
    keys={'outcome','readerStatus','attempts','realEinval','liveEinval','queries','confirmations',
          'matchingConfirmations','paths','recovered','childReaped'}
    valid=(type(value) is dict and set(value)==keys and value['outcome']=='recovered'
           and all(type(value[key]) is int and value[key]>=0 for key in keys-{'outcome'})
           and all(type(item) is int for item in (guard,denied,reader,stderr_bytes,stdout_bytes,allowed_read)))
    if not valid:raise RuntimeError('native-live-requery-control-refused')
    valid=(guard==19 and allowed_read==0 and denied==1 and reader==value['readerStatus']==0 and stderr_bytes==stdout_bytes==0
           and 1<=value['attempts']<=50000 and 1<=value['realEinval']<=2 and value['liveEinval']==1
           and 2<=value['queries']<=3 and 3<=value['confirmations']<=5
           and value['matchingConfirmations']==value['confirmations']
           and value['paths']==0 and value['recovered']==value['childReaped']==1)
    if not valid:raise RuntimeError('native-live-requery-control-refused')
    return {'schema':'eng1457-real-requery-v1',**value,'guardStatus':guard,'deniedReadStatus':denied,'allowedReadStatus':allowed_read,
            'profileChanged':False,'ownChildOnly':True,'realCallsForwarded':True}


def build_host(base):
    binary=base/'exec-row'
    source=SCRIPTS/'mig01-native-requery-host.c'
    command=['/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',str(source),'-lproc','-o',str(binary)]
    result=subprocess.run(command,capture_output=True,timeout=30)
    if result.returncode:raise RuntimeError('native-live-requery-build-refused')
    print('fresh-unit-build='+json.dumps({'sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),
          'productionSha256':hashlib.sha256(READER.read_bytes()).hexdigest(),'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
    return binary


def real_host_control(test,base):
    # Same profile bytes as the existing real inventory and vanished controls.
    native=load('test-native-process-scan.py');binary=build_host(base)
    denied=base/'live-requery-denied';denied.write_text('synthetic denied-read control')
    profile='(version 1) (allow default) (deny file-read* (literal '+json.dumps(str(denied))+'))'
    allowed=subprocess.run(['/usr/bin/sandbox-exec','-p','(version 1) (allow default)','/bin/cat',str(denied)],capture_output=True,timeout=5)
    test.assertEqual((allowed.returncode,allowed.stdout==b'synthetic denied-read control',len(allowed.stderr)),(0,True,0))
    probe=subprocess.run(['/usr/bin/sandbox-exec','-p',profile,'/bin/cat',str(denied)],capture_output=True,timeout=5)
    test.assertEqual((probe.returncode,len(probe.stdout)),(1,0),'native-live-requery-denied-read-did-not-fire')
    meta=base/'live-requery.json';errors=base/'live-requery-stderr';status=base/'live-requery-status'
    launch=base/'live-requery-reader'
    launch.write_text('#!/bin/sh\nexec '+shlex.quote(str(binary))+' '+shlex.quote(str(meta))+' "$@"\n');launch.chmod(0o700)
    script=base/'live-requery-guard.sh'
    script.write_text(native.guard_script(launch,errors,status,base/'absent-sp1',base/'absent-marker'))
    try:actual=subprocess.run(['/usr/bin/sandbox-exec','-p',profile,'/bin/bash',str(script)],capture_output=True,timeout=35)
    except subprocess.TimeoutExpired:test.fail('native-live-requery-fixture-timeout')
    try:
        value=json.loads(meta.read_bytes());reader=int(status.read_bytes())
        record=host_firing_record(value,actual.returncode,probe.returncode,reader,
                                  len(errors.read_bytes())+len(actual.stderr),len(actual.stdout),allowed.returncode)
    except Exception:
        # No raw stderr, identity, argv, PID or birth value enters a failure.
        record={'schema':'eng1457-real-requery-refusal-v1','guardStatus':actual.returncode,
                'metadataPresent':meta.is_file(),'stderrBytes':len(actual.stderr),'profileChanged':False}
        if meta.is_file():
            try:
                candidate=json.loads(meta.read_bytes())
                count=candidate.get('realEinval')
                record['realEinval']=count if type(count) is int and 0<=count<=2 else None
                record['outcome']=candidate['outcome'] if candidate.get('outcome') in ('recovered','unresolved','event-missing') else 'unclassified'
            except Exception:pass
        destination=os.environ.get('MIG01_TEST_OUTPUT_ROOT')
        if destination:(Path(destination)/'native-live-requery-closed.json').write_text(json.dumps(record,sort_keys=True)+'\n')
        test.fail('native-live-requery-closed='+json.dumps(record,sort_keys=True))
    destination=os.environ.get('MIG01_TEST_OUTPUT_ROOT')
    if destination:(Path(destination)/'native-live-requery-closed.json').write_text(json.dumps(record,sort_keys=True)+'\n')
    print('real-live-requery='+json.dumps(record,sort_keys=True))


class RequeryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch=tempfile.TemporaryDirectory(prefix='native-requery-',dir='/private/tmp')
        cls.base=Path(cls.scratch.name);cls.original=READER.read_text()
        cls.native=load('test-native-process-scan.py')
        cls.binary=cls.build(cls.original,'original')

    @classmethod
    def tearDownClass(cls):cls.scratch.cleanup()

    @classmethod
    def build(cls,source,label):
        path=cls.base/(label+'.c');path.write_text(source);binary=cls.base/label
        command=['/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',
                 '-DREQUERY_READER='+json.dumps(str(path)),str(CONTROL),'-lproc','-o',str(binary)]
        result=subprocess.run(command,capture_output=True,timeout=30)
        if result.returncode:raise RuntimeError('requery-control-build-refused')
        print('fresh-unit-build='+json.dumps({'sourceSha256':hashlib.sha256(CONTROL.read_bytes()).hexdigest(),
              'productionSha256':hashlib.sha256(source.encode()).hexdigest(),'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
        return binary

    def observe(self,case,rss=False,binary=None):
        result=subprocess.run([str(binary or self.binary),case,'rss=,comm=' if rss else 'pid=,comm='],capture_output=True,timeout=5)
        self.assertEqual((result.returncode,len(result.stderr)),(0,0),'requery-control-process-refused')
        value=json.loads(result.stdout)
        self.assertEqual(set(value),KEYS)
        self.assertTrue(all(type(value[key]) is int and value[key]>=0 for key in KEYS-{'reason','confirmation'}))
        self.assertIn(value['readerStatus'],(0,1));self.assertIn(value['reason'],self.native.DIAGNOSTIC_REASONS)
        self.assertIn(value['confirmation'],('none','live','unconfirmed','query-error'))
        self.assertEqual((value['resetViolations'],value['argumentWipes'],value['canaryOutput']),(0,1,0),'requery-storage-or-redaction-violation')
        self.assertEqual(value['chargedAdditional'],value['additional'],'recovery-issued-count-mismatch')
        return value

    def guard(self,case,binary=None,rss=False):
        script=self.base/'guard-native';errors=self.base/'guard-errors';status=self.base/'guard-status'
        continued=self.base/'downstream';continued.unlink(missing_ok=True)
        script.write_text('#!/bin/sh\nexec '+shlex.quote(str(binary or self.binary))+' '+shlex.quote(case)+' "$2" scan\n');script.chmod(0o700)
        source=self.native.guard_script(script,errors,status,self.base/'absent-sp1',self.base/'absent-prover')
        if rss:
            shell=(ROOT/'tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh').read_text()
            phase='phase_rss_bytes() {'+shell.split('phase_rss_bytes() {',1)[1].split('other_provers() {',1)[0]
            source=('set -euo pipefail\nrunner_process_scan(){ '+shlex.quote(str(script))+' "$@"; }\n'+phase+
                    '\nstatus=0\nrss="$(phase_rss_bytes 2>'+shlex.quote(str(errors))+')" || status=$?\n'+
                    'printf "%s\\n" "$status" >'+shlex.quote(str(status))+'\n((status == 0)) || exit 20\n')
        source+='printf reached >'+shlex.quote(str(continued))+'\n'
        result=subprocess.run(['/bin/bash','-c',source],capture_output=True,timeout=5)
        self.assertEqual((len(result.stdout),len(result.stderr)),(0,0))
        diagnostic=self.native.reader_diagnostic(int(status.read_bytes()),errors.read_bytes())
        return result.returncode,diagnostic,continued.exists()

    def refused(self,case,reason,error=0,arguments=None,additional=None,confirmation='none',confirmation_errno=0,rss=False,binary=None):
        value=self.observe(case,rss,binary)
        self.assertEqual((value['readerStatus'],value['reason'],value['errno'],value['confirmation'],value['confirmationErrno']),
                         (1,reason,error,confirmation,confirmation_errno),'requery-wrong-refusal')
        if arguments is not None:self.assertEqual(value['arguments'],arguments)
        if additional is not None:self.assertEqual(value['additional'],additional)
        guarded,diagnostic,continued=self.guard(case,binary,rss)
        self.assertEqual((guarded,continued),(20,False),'requery-inventory-oracle-not-20')
        self.assertEqual((diagnostic['reason'],diagnostic['errno']),(reason,error))
        return value

    def test_einval_eio_recover_full_benign_and_alias_identity(self):
        for error in ('einval','eio'):
            for kind,oracle in (('benign',0),('alias',19)):
                case=error+'-'+kind;value=self.observe(case)
                self.assertEqual((value['readerStatus'],value['arguments'],value['additional'],value['confirmations'],value['paths'],value['waits'],value['elapsedNs']),
                                 (0,2,1,3,0,1,10000000))
                self.assertEqual(value['namedRows'],int(oracle==19))
                self.assertEqual(self.guard(case),(oracle,{'status':0,'reason':'none','errno':0},oracle==0))
        value=self.observe('executable-only');self.assertEqual((value['readerStatus'],value['namedRows']),(0,0))
        self.assertEqual(self.guard('executable-only')[0],0)
        value=self.observe('foreign-alias');self.assertEqual((value['readerStatus'],value['arguments'],value['paths']),(0,0,1))
        self.assertEqual(self.guard('foreign-alias')[0],0)

    def test_last_row_retry_is_exactly_second_additional_query(self):
        for case in ('einval-second','eio-second-alias'):
            value=self.observe(case)
            self.assertEqual((value['readerStatus'],value['arguments'],value['additional'],value['confirmations'],value['waits'],value['firstWaitNs'],value['secondWaitNs'],value['elapsedNs']),
                             (0,3,2,5,2,10000000,40000000,50000000))

    def test_persistent_live_and_permission_failures_never_fall_back(self):
        for case,error in (('persistent-einval',22),('persistent-eio',5)):
            value=self.refused(case,'arguments-query',error,3,2,'live')
            self.assertEqual((value['paths'],value['waits'],value['elapsedNs']),(0,2,50000000))
            self.assertEqual(value['fallbackControls'],2)
        for case,error in (('eperm',1),('eintr',4),('enomem',12),('esrch',3),('efault',14)):
            value=self.refused(case,'arguments-query',error,1,0,'live')
            self.assertEqual((value['paths'],value['waits']),(0,0))

    def test_failed_short_and_mismatched_confirmation_refuse(self):
        for case,confirmation,error in (('confirm-error','query-error',1),('confirm-short','unconfirmed',0),('confirm-pid','unconfirmed',0)):
            self.refused(case,'arguments-query',22,1,0,confirmation,error)
        self.refused('confirm-error-after','arguments-query',0,2,1,'query-error',1)

    def test_birth_uid_and_missing_incarnation_refuse_at_each_boundary(self):
        for case,count,additional in ((kind+'-'+stage,2 if stage=='after' else 1,1 if stage=='after' else 0)
                for kind in ('birth','uid') for stage in ('first','before','after')):
            self.refused(case,'requery-identity',arguments=count,additional=additional)
        for case in ('snapshot-no-birth','snapshot-bad-usec','snapshot-negative-usec','confirm-no-birth','confirm-state-zero','confirm-state-unknown'):
            self.refused(case,'requery-identity',arguments=1,additional=0)

    def test_confirmed_absence_zombie_and_prior_positive_are_preserved(self):
        for case,count,additional in (('exit',1,0),('zombie',1,0),('exit-before',1,0),('exit-after',2,1)):
            value=self.observe(case)
            self.assertEqual((value['readerStatus'],value['rows'],value['arguments'],value['additional']),(0,0,count,additional))
            self.assertEqual(self.guard(case)[0],0)
        value=self.observe('positive-before-exit')
        self.assertEqual((value['readerStatus'],value['namedRows']),(0,1));self.assertEqual(self.guard('positive-before-exit')[0],19)
        for case in ('state-sleep-alias','state-stop-alias'):self.assertEqual(self.guard(case)[0],19)

    def test_malformed_success_never_retries_or_uses_fallback(self):
        reasons={'size':'arguments-size','large':'arguments-size','count':'arguments-count','executable':'executable-terminator',
                 'argv':'argv0-terminator','empty':'argv0-terminator','delimiter':'argv0-delimiter','cr':'argv0-delimiter','tab':'argv0-delimiter'}
        for prefix,queries,extra in (('initial',1,0),('recovered',2,1)):
            for shape,reason in reasons.items():
                value=self.refused(prefix+'-bad-'+shape,reason,arguments=queries,additional=extra)
                self.assertEqual(value['paths'],0)
        self.refused('identity-allocation','identity-allocation',12,1,0)
        self.refused('foreign-allocation','identity-allocation',12,0,0)

    def test_inventory_query_and_monotonic_budgets_never_reset_per_row(self):
        value=self.observe('quota-edge')
        self.assertEqual((value['readerStatus'],value['arguments'],value['additional'],value['rows']),(0,32,16,16))
        value=self.refused('quota','requery-limit',arguments=33,additional=16)
        self.assertEqual((value['rows'],value['elapsedNs']),(16,160000000))
        value=self.refused('many-time','requery-budget',arguments=14,additional=9)
        self.assertEqual((value['rows'],value['elapsedNs']),(4,250000000))

    def test_interrupted_wait_preserves_deadlines_and_errors_refuse(self):
        value=self.observe('wait-interrupted')
        self.assertEqual((value['readerStatus'],value['arguments'],value['waits'],value['firstWaitNs'],value['secondWaitNs'],value['elapsedNs']),
                         (0,2,2,10000000,6000000,10000000))
        self.refused('wait-interrupted-budget','requery-budget',arguments=1,additional=0)
        self.refused('wait-error','requery-wait',5,1,0)
        self.refused('wait-no-errno','requery-wait',0,1,0)
        self.refused('clock-error','requery-clock',5,1,0)
        self.refused('clock-backwards','requery-clock',arguments=1,additional=0)
        for case in ('clock-negative','clock-bad-nsec','clock-negative-nsec','clock-overflow','wait-overflow'):
            self.refused(case,'requery-clock',arguments=1,additional=0)
        self.refused('clock-after-confirm','requery-budget',arguments=1,additional=0)
        self.refused('clock-after-query','requery-budget',arguments=2,additional=1)

    def test_both_consumers_reject_partial_output_and_preserve_rss_matcher(self):
        for rss in (False,True):
            value=self.refused('partial-rss-eio','arguments-query',5,4,2,'live',rss=rss)
            self.assertEqual((value['rows'],value['namedRows']),(1,1))
        value=self.observe('eio-rss-alias',True)
        self.assertEqual((value['readerStatus'],value['rows'],value['namedRows'],value['tasks']),(0,1,1,1))
        self.refused('rss-failure','rss-query',5,1,0,rss=True)
        shell=(ROOT/'tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh').read_text()
        unit='phase_rss_bytes() {'+shell.split('phase_rss_bytes() {',1)[1].split('other_provers() {',1)[0]
        for case,wanted in (('partial-rss-eio',1),('eio-rss-alias',0)):
            program='set -euo pipefail\nrunner_process_scan(){ '+shlex.quote(str(self.binary))+' '+shlex.quote(case)+' "$2" scan; }\n'+unit+'\nphase_rss_bytes\n'
            actual=subprocess.run(['/bin/bash','-c',program],capture_output=True,timeout=5)
            self.assertEqual(actual.returncode,wanted)
            if wanted:self.assertEqual(self.native.reader_diagnostic(1,actual.stderr)['reason'],'arguments-query')
            else:self.assertEqual(actual.stdout,b'125952\n')

    def test_each_new_closed_reason_schema_and_private_canary_controls(self):
        extra={'identity-allocation','requery-clock','requery-budget','requery-wait','requery-identity','requery-limit'}
        attr=load('kernel-attribution.py')
        for reason in extra:
            value={'status':1,'reason':reason,'errno':0};raw=(json.dumps(value,separators=(',',':'))+'\n').encode()
            self.assertEqual(self.native.reader_diagnostic(1,raw),value)
            self.assertIn(reason,attr.REASONS)
            invalid=[{**value,'reason':'SYNTHETIC_ARG_CANARY'},{**value,'errno':True},{**value,'errno':-1},
                     {**value,'errno':'1'},{**value,'status':True},{**value,'status':0},
                     {**value,'private':'SYNTHETIC_ENV_CANARY'},{**value,'confirmation':'live','confirmationErrno':0}]
            invalid.extend({k:v for k,v in value.items() if k!=key} for key in value)
            for item in invalid:
                with self.assertRaisesRegex(RuntimeError,'^native-diagnostic-result-refused$'):
                    self.native.reader_diagnostic(1,(json.dumps(item,separators=(',',':'))+'\n').encode())
            for malformed in (b' '+raw,raw+b'X',raw.replace(b'{',b'{"status":1,',1),raw+b'\0',b'X'*257):
                with self.assertRaisesRegex(RuntimeError,'^native-diagnostic-result-refused$'):self.native.reader_diagnostic(1,malformed)

    def test_host_build_and_closed_oracle_never_accept_missing_event(self):
        build_host(self.base)
        valid={'outcome':'recovered','readerStatus':0,'attempts':123,'realEinval':1,'liveEinval':1,'queries':2,
               'confirmations':3,'matchingConfirmations':3,'paths':0,'recovered':1,'childReaped':1}
        self.assertEqual(host_firing_record(valid,19,1,0,0,0,0)['guardStatus'],19)
        invalid=[{**valid,'realEinval':0},{**valid,'outcome':'event-missing'},{**valid,'outcome':'unresolved'},
                 {**valid,'liveEinval':0},{**valid,'queries':4},{**valid,'paths':1},{**valid,'recovered':0},
                 {**valid,'childReaped':0},{**valid,'matchingConfirmations':2},
                 {**valid,'private':'SYNTHETIC_ARG_CANARY'}]
        invalid.extend({k:v for k,v in valid.items() if k!=key} for key in valid)
        invalid.extend({**valid,key:True} for key in valid if key!='outcome')
        for value in invalid:
            with self.assertRaisesRegex(RuntimeError,'^native-live-requery-control-refused$'):host_firing_record(value,19,1,0,0,0,0)
        for guard,denied,reader,err,out in ((20,1,0,0,0),(0,1,0,0,0),(19,0,0,0,0),(19,1,1,0,0),(19,1,0,1,0),(19,1,0,0,1)):
            with self.assertRaisesRegex(RuntimeError,'^native-live-requery-control-refused$'):host_firing_record(valid,guard,denied,reader,err,out,0)
        with self.assertRaisesRegex(RuntimeError,'^native-live-requery-control-refused$'):host_firing_record(valid,19,1,0,0,0,1)
        source=Path(__file__).read_text();tree=ast.parse(source)
        function=ast.get_source_segment(source,next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='host_firing_record'))
        marker="1<=value['realEinval']<=2";self.assertEqual(function.count(marker),1)
        statuses=[]
        for candidate in (function,function.replace(marker,"0<=value['realEinval']<=2"),function):
            namespace={};exec(compile(candidate,'host-event-oracle','exec'),namespace)
            try:namespace['host_firing_record']({**valid,'realEinval':0},19,1,0,0,0,0)
            except RuntimeError as error:self.assertEqual(str(error),'native-live-requery-control-refused');statuses.append(0)
            else:statuses.append(19)
        self.assertEqual(statuses,[0,19,0])
        print('host-event-oracle='+json.dumps({'statuses':statuses,'realHostExecuted':False}))

    def test_independent_guard_mutations_fire_and_restore(self):
        cases=[('return-empty','if (retries == 2) { arguments_refusal(query_errno, 1, 0); goto done; }',
                'if (retries == 2) { result = 0; goto done; }','test_persistent_live_and_permission_failures_never_fall_back'),
               ('path-fallback','if (retries == 2) { arguments_refusal(query_errno, 1, 0); goto done; }',
                'if (retries == 2) { if (path_of(pid,bytes,capacity)) { *name=strdup(bytes);result=1; } goto done; }','test_persistent_live_and_permission_failures_never_fall_back'),
               ('incarnation','if (!same_incarnation(snapshot, &current))','if (!same_incarnation(snapshot, &current) && 0)','test_birth_uid_and_missing_incarnation_refuse_at_each_boundary'),
               ('shape','if (strpbrk(at, "\\r\\n\\t"))','if (strpbrk(at, "\\r\\n\\t") && 0)','test_malformed_success_never_retries_or_uses_fallback'),
               ('quota','if (budget->additional >= 16)','if (budget->additional >= 16 && 0)','test_inventory_query_and_monotonic_budgets_never_reset_per_row'),
               ('deadline','if (budget->spent >= 250000000 || now - budget->started >= 250000000 - budget->spent)',
                'if ((budget->spent >= 250000000 || now - budget->started >= 250000000 - budget->spent) && 0)','test_inventory_query_and_monotonic_budgets_never_reset_per_row'),
               ('interrupted','int status = nanosleep(&remaining, NULL), wait_errno = errno;',
                'int status = nanosleep(&remaining, NULL), wait_errno = errno; if (status && wait_errno == EINTR && !monotonic_ns(&budget->started)) return 0;','test_interrupted_wait_preserves_deadlines_and_errors_refuse'),
               ('per-row-reset','for (size_t i = 0; i < size / sizeof(*table); i++) {',
                'for (size_t i = 0; i < size / sizeof(*table); i++) { memset(recovery,0,sizeof(*recovery));','test_inventory_query_and_monotonic_budgets_never_reset_per_row'),
               ('wipe','while (size--) *at++ = 0;','while (size--) (void)*at++;','test_einval_eio_recover_full_benign_and_alias_identity'),
               ('redaction','*name = strdup(at);','*name = strdup(at + strlen(at) + 1);','test_einval_eio_recover_full_benign_and_alias_identity')]
        for label,before,after,method in cases:
            self.assertEqual(self.original.count(before),2 if label=='quota' else 1)
            mutant=self.build(self.original.replace(before,after),label)
            statuses=[]
            for binary in (self.binary,mutant,self.binary):
                control=RequeryControls(method);control.binary=binary
                result=unittest.TestResult();control.run(result)
                self.assertEqual(len(result.errors),0,'requery-mutation-unrelated-error')
                if result.failures:
                    expected='requery-storage-or-redaction-violation' if label in ('wipe','redaction') else 'recovery-issued-count-mismatch' if label=='per-row-reset' else 'requery-wrong-refusal'
                    self.assertIn(expected,result.failures[0][1],'requery-mutation-unrelated-assertion')
                statuses.append(19 if result.failures else 0)
            self.assertEqual(statuses,[0,19,0],'requery-mutation-did-not-fire')
            print('requery-mutation='+json.dumps({'guard':label,'statuses':statuses,'privateOutput':False}))

    def test_resolved_exit_and_recovered_tail_are_not_recovery_work(self):
        for rss in (False,True):
            for case,recovery,arguments,additional,confirmations in (('exit-tail',60000000,2,0,1),('recovered-tail',10000000,3,1,3),('slow-before',10000000,3,1,3),('slow-initial-error',10000000,2,1,3)):
                value=self.observe(case,rss)
                self.assertEqual((value['readerStatus'],value['recoveryNs'],value['arguments'],value['additional'],value['confirmations'],value['episodeActive']),
                                 (0,recovery,arguments,additional,confirmations,0),'recovery-accounting-valid-control-refused')
                self.assertEqual(value['elapsedNs'],recovery+(3000000000 if case=='slow-initial-error' else 2000000000))
                self.assertEqual(self.guard(case,rss=rss)[0],0)

    def test_cumulative_episodes_preserve_elapsed_time_across_ordinary_gaps(self):
        for rss in (False,True):
            value=self.observe('alternating-episodes',rss)
            self.assertEqual((value['readerStatus'],value['elapsedNs'],value['recoveryNs'],value['arguments'],value['additional'],value['confirmations']),(0,6180000000,180000000,9,3,9),'recovery-cumulative-accounting-mismatch')
            value=self.refused('cumulative-episodes','requery-budget',arguments=13,additional=4,rss=rss)
            self.assertEqual((value['elapsedNs'],value['recoveryNs'],value['confirmations']),(8250000000,250000000,13))
            value=self.refused('exit-cumulative','requery-budget',arguments=9,additional=0,rss=rss)
            self.assertEqual((value['elapsedNs'],value['recoveryNs'],value['confirmations']),(8300000000,300000000,5))

    def test_strict_completion_boundary_and_issued_query_accounting(self):
        for rss in (False,True):
            value=self.observe('recovery-below',rss)
            self.assertEqual((value['readerStatus'],value['recoveryNs'],value['arguments'],value['additional'],value['confirmations']),(0,249999999,2,1,3))
            value=self.refused('recovery-at','requery-budget',arguments=2,additional=1,rss=rss)
            self.assertEqual(value['recoveryNs'],250000000)
            value=self.refused('issue-boundary','requery-budget',arguments=1,additional=0,rss=rss)
            self.assertEqual(value['chargedAdditional'],0)

    def test_episode_accounting_mutations_fire_then_restore(self):
        cases=[('absolute-tail',self.original.replace('budget->active = 0;','budget->active = 1;'),
                'test_resolved_exit_and_recovered_tail_are_not_recovery_work','recovery-accounting-valid-control-refused'),
               ('episode-reset',self.original.replace('if (!budget->active) {','if (!budget->active) { budget->spent = 0;'),
                'test_cumulative_episodes_preserve_elapsed_time_across_ordinary_gaps','recovery-cumulative-accounting-mismatch'),
               ('free-exit',self.original.replace('done:\n    wipe(bytes, capacity);','done:\n    if (result == 0) budget->active = 0;\n    wipe(bytes, capacity);'),
                'test_cumulative_episodes_preserve_elapsed_time_across_ordinary_gaps','requery-wrong-refusal'),
               ('reservation',self.original.replace('budget->additional++;','/* moved reservation */').replace('retries++;','budget->additional++; retries++;'),
                'test_strict_completion_boundary_and_issued_query_accounting','recovery-issued-count-mismatch')]
        for label,source,method,message in cases:
            self.assertNotEqual(source,self.original)
            mutant=self.build(source,label);statuses=[]
            for binary in (self.binary,mutant,self.binary):
                case=RequeryControls(method);case.binary=binary;result=unittest.TestResult();case.run(result)
                self.assertFalse(result.errors,'recovery-mutation-unrelated-error')
                if result.failures:self.assertIn(message,result.failures[0][1],'recovery-mutation-unrelated-assertion')
                statuses.append(19 if result.failures else 0)
            self.assertEqual(statuses,[0,19,0],label)
            print('recovery-mutation='+json.dumps({'guard':label,'statuses':statuses,'privateOutput':False}))


if __name__=='__main__':unittest.main()
