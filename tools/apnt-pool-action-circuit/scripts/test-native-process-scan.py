#!/usr/bin/python3
"""One-file native inventory controls; --host adds real Seatbelt firing controls.

API doubles compile the unchanged reader, with no production injection hook.
Captured process rows/arguments never appear in assertion errors or reports.
No wallet, proof, key work or external service is used.
"""
import ast
import hashlib
import json
import importlib.util
import os
from pathlib import Path
import pwd
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
READER = ROOT / 'tools/pool-action-modules/private-runner-process.c'
RUNNER = ROOT / 'tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh'
HOST = '--host' in sys.argv
if HOST:
    sys.argv.remove('--host')


def run(*args, **options):
    return subprocess.run(args, capture_output=True, **options)


DIAGNOSTIC_REASONS = {'none', 'unclassified', 'process-table', 'argmax', 'allocation',
                      'process-table-size', 'process-table-size-shape', 'process-table-allocation',
                      'process-table-fetch', 'process-table-fetch-shape', 'argmax-query',
                      'argmax-shape', 'arguments-allocation',
                      'pid', 'foreign-path', 'foreign-delimiter', 'arguments-query',
                      'arguments-size', 'arguments-count', 'executable-terminator',
                      'argv0-terminator', 'argv0-delimiter', 'rss-query', 'stdout',
                      'identity-allocation', 'requery-clock', 'requery-budget', 'requery-wait',
                      'requery-identity', 'requery-limit'}


def reader_diagnostic(status, raw):
    if type(status) is not int or type(raw) is not bytes or len(raw)>256:
        raise RuntimeError('native-diagnostic-result-refused')
    if status == 0 and type(status) is int and raw == b'':
        return {'status':0,'reason':'none','errno':0}
    try:
        value = json.loads(raw)
    except (ValueError,TypeError):
        raise RuntimeError('native-diagnostic-result-refused') from None
    basic={'status','reason','errno'}
    extended=basic|{'confirmation','confirmationErrno'}
    if (type(value) is not dict or set(value) not in (basic,extended) or type(value['status']) is not int
            or type(status) is not int or value['status'] != status or status != 1 or type(value['reason']) is not str
            or value['reason'] not in DIAGNOSTIC_REASONS-{'none','unclassified'} or type(value['errno']) is not int
            or not 0 <= value['errno'] <= 4095):
        raise RuntimeError('native-diagnostic-result-refused')
    suffix=''
    if set(value)==extended:
        if (value['reason']!='arguments-query' or type(value['confirmation']) is not str
                or value['confirmation'] not in ('live','unconfirmed','query-error')
                or type(value['confirmationErrno']) is not int or not 0<=value['confirmationErrno']<=4095
                or value['confirmation']!='query-error' and value['confirmationErrno']!=0):
            raise RuntimeError('native-diagnostic-result-refused')
        suffix=',"confirmation":"'+value['confirmation']+'","confirmationErrno":'+str(value['confirmationErrno'])
    canonical=('{"status":1,"reason":"'+value['reason']+'","errno":'+str(value['errno'])+suffix+'}\n').encode()
    if (len(raw)>256
            or raw != canonical):
        raise RuntimeError('native-diagnostic-result-refused')
    return value


def closed_diagnostic(result, allow_stdout=False):
    if result.stdout and not allow_stdout:
        raise RuntimeError('native-diagnostic-result-refused')
    return reader_diagnostic(result.returncode,result.stderr)


def host_failure_metadata(point, expected, control, reader_status=None, reader_stderr=None):
    diagnostic = None
    if reader_status is not None:
        try: diagnostic = reader_diagnostic(reader_status,reader_stderr)
        except (RuntimeError,ValueError,TypeError): pass
    return {'schema':'eng1436-native-scan-v2','failurePoint':point,'expectedStatus':expected,
            'originalStatus':control.returncode,'originalStdoutBytes':len(control.stdout),
            'originalStderrBytes':len(control.stderr),'readerStatus':reader_status,
            'readerStderrBytes':len(reader_stderr) if reader_stderr is not None else None,
            'diagnostic':diagnostic,'sameScanClaimed':reader_status is not None,'profileChanged':False}


def guard_script(native, error_file, status_file, sp1_marker, prover_marker):
    shell=RUNNER.read_text()
    units='other_provers() {'+shell.split('other_provers() {',1)[1].split('# ---- locks:',1)[0]
    scan='runner_process_scan() {'+shell.split('runner_process_scan() {',1)[1].split('phase_rss_bytes() {',1)[0]
    binding='"$repo/tools/pool-action-modules/dist/private-runner-process" "$@"'
    if scan.count(binding)!=1:raise RuntimeError('native-guard-fixture-refused')
    scan=scan.replace(binding,'local queried_status=0\n  '+shlex.quote(str(native))+' "$@" 2>'+shlex.quote(str(error_file))+
                      ' || queried_status=$?\n  printf "%s\\n" "$queried_status" >'+shlex.quote(str(status_file))+'\n  return "$queried_status"')
    # Every production global read by the extracted unit is declared here.
    # Only a genuine name match may produce the named-prover oracle status.
    setup='set -euo pipefail\numask 077\nPRIVATE_RUNNER_GENERATION=2\nhas_live=true\ndie(){ [[ "$1" == live-plan-other-prover ]] && exit 19; exit 20; }\navailable_bytes(){ echo 999999999999; }\nSP1_EXCLUSIVE_MARKER='+shlex.quote(str(sp1_marker))+'\nPROVER_MARKER='+shlex.quote(str(prover_marker))+'\n'
    return setup+scan+units+'\nrequire_quiet_machine start 1\n'


class NativeScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='other-provers-native-', dir='/private/tmp')
        cls.base = Path(cls.scratch.name)
        cls.binary = cls.base / 'reader'
        cls.source = cls.base / 'api-double.c'
        cls.source.write_text(r'''
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <stdlib.h>
static int scan_sysctl(int *, unsigned, void *, size_t *, void *, size_t);
static int scan_pidinfo(int, int, uint64_t, void *, int);
static int scan_pidpath(int, void *, uint32_t);
static void *scan_calloc(size_t, size_t);
#define sysctl scan_sysctl
#define proc_pidinfo scan_pidinfo
#define proc_pidpath scan_pidpath
#define calloc scan_calloc
#define main scan_main
#include ''' + json.dumps(str(READER)) + r'''
#undef main
#undef calloc
static const char *scenario;
static int calls, path_calls, allocations, confirmation_calls;
static int einval_case(void) { return !strncmp(scenario,"einval-",7); }
static void *scan_calloc(size_t count,size_t size) {
    allocations++;
    if((!strcmp(scenario,"table-allocation") && allocations==1) ||
       (!strcmp(scenario,"arguments-allocation") && allocations==2)){errno=ENOMEM;return NULL;}
    return calloc(count,size);
}
static int boundary(void) {
    return !strcmp(scenario,"same-uid-alias") || !strcmp(scenario,"same-uid-executable-only") ||
        !strcmp(scenario,"foreign-alias") || !strcmp(scenario,"foreign-executable");
}
static void identity(struct kinfo_proc *p, int pid) {
    memset(p, 0, sizeof(*p)); p->kp_proc.p_pid=pid; p->kp_proc.p_stat=SRUN;
    p->kp_proc.p_starttime.tv_sec=123; p->kp_proc.p_starttime.tv_usec=456;
    p->kp_eproc.e_ucred.cr_uid=geteuid(); strcpy(p->kp_proc.p_comm,"foreign-prover");
}
static int scan_sysctl(int *mib, unsigned n, void *out, size_t *size, void *in, size_t insize) {
    (void)n; (void)in; (void)insize;
    if(mib[1]==KERN_ARGMAX) {
        if(!strcmp(scenario,"argmax-query")){errno=EPERM;return -1;}
        *(int *)out=!strcmp(scenario,"argmax-shape")?0:4096;*size=sizeof(int);return 0;
    }
    if(mib[1]==KERN_PROC) {
        if(mib[2]==KERN_PROC_PID) {
            confirmation_calls++;
            if(einval_case()) {
                if(!strcmp(scenario,"einval-exited")){*size=0;return 0;}
                if(!strcmp(scenario,"einval-confirmation-failed")){errno=EPERM;return -1;}
                if(!strcmp(scenario,"einval-confirmation-no-errno")){errno=0;return -1;}
                identity(out,mib[3]);*size=sizeof(struct kinfo_proc);errno=ENOTTY;
                if(!strcmp(scenario,"einval-zombie"))((struct kinfo_proc *)out)->kp_proc.p_stat=SZOMB;
                if(!strcmp(scenario,"einval-system"))((struct kinfo_proc *)out)->kp_proc.p_flag=P_SYSTEM;
                if(!strcmp(scenario,"einval-confirmation-short"))*size-=1;
                if(!strcmp(scenario,"einval-confirmation-mismatch"))((struct kinfo_proc *)out)->kp_proc.p_pid++;
                return 0;
            }
            if(!strcmp(scenario,"exited") || !strcmp(scenario,"rss-exited")) { *size=0; return 0; }
            identity(out,mib[3]); *size=sizeof(struct kinfo_proc); errno=ENOTTY; return 0;
        }
        if(!strcmp(scenario,"table-failed")) {errno=EPERM;return -1;}
        if(!strcmp(scenario,"einval-table-size")){errno=EINVAL;return -1;}
        if(!out) { *size=!strcmp(scenario,"table-size-shape")?0:2*sizeof(struct kinfo_proc); return 0; }
        if(!strcmp(scenario,"table-churn")) {errno=ENOMEM;return -1;}
        struct kinfo_proc *p=out;identity(p,499);identity(p+1,500);
        if(!strcmp(scenario,"einval-table-fetch")){errno=EINVAL;return -1;}
        if(!strcmp(scenario,"pid-invalid"))p[1].kp_proc.p_pid=-1;
        if(!strncmp(scenario,"foreign",7)) p[1].kp_eproc.e_ucred.cr_uid=geteuid()+1;
        *size=2*sizeof(*p)-(!strcmp(scenario,"table-short")?1:0);return 0;
    }
    if(mib[1]==KERN_PROCARGS2) {
        calls++;
        if(einval_case() && mib[2]==500 && strcmp(scenario,"einval-valid")){errno=EINVAL;return -1;}
        if(boundary() && mib[2]==500 && !strncmp(scenario,"foreign",7)) {errno=EPERM;return -1;}
        if(mib[2]==500 && (!strcmp(scenario,"args-failed") || !strcmp(scenario,"exited"))) {errno=EIO;return -1;}
        int count=2; memcpy(out,&count,sizeof(count));
        const char data[]="/synthetic/executable\0\0/synthetic/apnt-test-prover-long\0SYNTHETIC_ARG_CANARY\0SYNTHETIC_ENV_CANARY\0";
        memcpy((char *)out+sizeof(count),data,sizeof(data)); *size=sizeof(count)+sizeof(data);
        if(einval_case()) {
            const char quiet[]="/synthetic/executable\0\0neutral\0SYNTHETIC_ARG_CANARY\0SYNTHETIC_ENV_CANARY\0";
            const char prover[]="/synthetic/executable\0\0/synthetic/pool-pk-load\0SYNTHETIC_ARG_CANARY\0SYNTHETIC_ENV_CANARY\0";
            const char *args=mib[2]==500?prover:quiet;
            size_t length=mib[2]==500?sizeof(prover):sizeof(quiet);
            memcpy((char *)out+sizeof(count),args,length);*size=sizeof(count)+length;
        }
        if(boundary()) {
            const char neutral[]="/synthetic/executable\0\0neutral\0SYNTHETIC_ARG_CANARY\0SYNTHETIC_ENV_CANARY\0";
            const char alias[]="/synthetic/executable\0\0pool-pk-load\0SYNTHETIC_ARG_CANARY\0SYNTHETIC_ENV_CANARY\0";
            const char executable_only[]="/synthetic/pool-pk-load\0\0neutral\0SYNTHETIC_ARG_CANARY\0SYNTHETIC_ENV_CANARY\0";
            int matching=mib[2]==500 && (!strcmp(scenario,"same-uid-alias") || !strcmp(scenario,"foreign-alias"));
            int executable=mib[2]==500 && !strcmp(scenario,"same-uid-executable-only");
            const char *data=matching?alias:executable?executable_only:neutral;
            size_t length=matching?sizeof(alias):executable?sizeof(executable_only):sizeof(neutral);
            memcpy((char *)out+sizeof(count),data,length); *size=sizeof(count)+length;
        }
        if(!strncmp(scenario,"rss",3)) {
            const char rss[]="/synthetic/executable\0\0pool-pk-load\0SYNTHETIC_ARG_CANARY\0";
            memcpy((char *)out+sizeof(count),rss,sizeof(rss)); *size=sizeof(count)+sizeof(rss);
        }
        if(!strcmp(scenario,"args-short")) *size=sizeof(count);
        if(!strcmp(scenario,"args-newline")) ((char *)out)[sizeof(count)+26]='\n';
        if(mib[2]==500 && !strcmp(scenario,"arguments-count")){count=0;memcpy(out,&count,sizeof(count));}
        if(mib[2]==500 && !strcmp(scenario,"executable-terminator")){memset((char *)out+sizeof(count),'X',20);*size=sizeof(count)+20;}
        if(mib[2]==500 && !strcmp(scenario,"argv0-terminator")){
            const char data[]="/worker\0\0unterminated";memcpy((char *)out+sizeof(count),data,sizeof(data)-1);*size=sizeof(count)+sizeof(data)-1;
        }
        return 0;
    }
    return -1;
}
static int scan_pidinfo(int pid,int flavor,uint64_t arg,void *out,int size) {
    (void)flavor;(void)arg;
    if(pid==500 && (!strcmp(scenario,"rss-failed") || !strcmp(scenario,"rss-exited"))) {errno=EIO;return 0;}
    memset(out,0,(size_t)size);((struct proc_taskinfo *)out)->pti_resident_size=123*1024;return size;
}
static int scan_pidpath(int pid,void *out,uint32_t size) {
    (void)pid;
    path_calls++;
    if(!strcmp(scenario,"foreign-path-failed")) {errno=EPERM;return 0;}
    if(!strcmp(scenario,"foreign-delimiter"))return snprintf(out,size,"/worker\tprivate");
    if(boundary()) return snprintf(out,size,"/synthetic/%s",!strcmp(scenario,"foreign-executable") ||
        !strcmp(scenario,"same-uid-executable-only") ? "pool-pk-load":"neutral");
    int length=snprintf(out,size,"/synthetic/apnt-foreign-prover-long");return length;
}
int main(int argc,char **argv) {
    if(argc!=3)return 2; scenario=argv[1];
    if(!strcmp(argv[2],"process-status")){
        struct kinfo_proc value;int status=process(500,&value);
        if(confirmation_calls!=1 || calls || path_calls)return 3;
        printf("{\"status\":%d}\n",status);return 0;
    }
    if(!strcmp(scenario,"stdout-failed")){setvbuf(stdout,NULL,_IONBF,0);close(STDOUT_FILENO);}
    char *args[]={"reader","-axo",argv[2]}; int status=scan_main(3,args);
    if(!strcmp(scenario,"foreign") && calls!=1)return 3;
    if(boundary() && (calls!=(!strncmp(scenario,"foreign",7)?1:2) ||
        path_calls!=(!strncmp(scenario,"foreign",7)?1:0)))return 3;
    if(einval_case()) {
        int table=!strncmp(scenario,"einval-table-",13);
        int live=!strcmp(scenario,"einval-live") || !strcmp(scenario,"einval-system");
        if(calls!=(table?0:live?4:2) || confirmation_calls!=(table || !strcmp(scenario,"einval-valid")?0:live?5:1) || path_calls)return 3;
    }
    return status;
}
''')
        built = run('/usr/bin/clang', '-O2', '-Wall', '-Wextra', '-Werror', str(cls.source), '-lproc', '-o', str(cls.binary))
        if built.returncode:
            raise RuntimeError('native-control-build-failed')
        print('fresh-unit-build='+json.dumps({'label':'native-api-double','sourceSha256':hashlib.sha256(cls.source.read_bytes()).hexdigest(),
                                            'productionSha256':hashlib.sha256(READER.read_bytes()).hexdigest(),'binarySha256':hashlib.sha256(cls.binary.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def test_global_table_and_argv0_preserve_long_names_without_arguments(self):
        actual = run(str(self.binary), 'valid', 'pid=,comm=')
        self.assertEqual(actual.returncode, 0)
        self.assertTrue(actual.stdout == b'499 /synthetic/apnt-test-prover-long\n500 /synthetic/apnt-test-prover-long\n')
        self.assertEqual(len(actual.stderr), 0)

    def test_foreign_uid_uses_full_kernel_path_and_refuses_unavailable_identity(self):
        actual = run(str(self.binary), 'foreign', 'pid=,comm=')
        self.assertEqual(actual.returncode, 0)
        self.assertTrue(actual.stdout == b'499 /synthetic/apnt-test-prover-long\n500 /synthetic/apnt-foreign-prover-long\n')
        self.assertEqual(run(str(self.binary),'foreign-path-failed','pid=,comm=').returncode,1)

    def test_standalone_source_builds_with_exact_installer_recipe(self):
        # Doubles rename native APIs. Compile the real translation unit too,
        # using the installer's flags/environment, without scanning this host.
        installer = ast.parse((READER.with_name('private-runner-installation.py')).read_text())
        commands = [call.args[1] for call in ast.walk(installer) if isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name) and call.func.id == 'build_log'
                    and isinstance(call.args[1], ast.List)]
        self.assertEqual(len(commands), 1)
        recipe = commands[0].elts
        self.assertEqual([ast.literal_eval(value) for value in recipe[:5]],
                         ['/usr/bin/clang', '-O2', '-Wall', '-Wextra', '-Werror'])
        self.assertEqual([ast.literal_eval(value) for value in recipe[6:8]], ['-lproc', '-o'])
        binary = self.base / 'installer-reader'
        home = pwd.getpwuid(os.geteuid()).pw_dir
        environment = {'PATH': home + '/.nvm/versions/node/v22.22.3/bin:' + home +
                       '/.cargo/bin:/opt/homebrew/bin:/usr/bin:/bin',
                       'HOME': home, 'LANG': 'C', 'TMPDIR': '/private/tmp'}
        command = ['/usr/bin/clang', '-O2', '-Wall', '-Wextra', '-Werror', str(READER), '-lproc', '-o', str(binary)]
        built = run(*command, cwd=ROOT, env=environment)
        self.assertEqual((built.returncode, len(built.stdout), len(built.stderr)), (0, 0, 0))
        self.assertTrue(binary.is_file() and os.access(binary, os.X_OK))
        print('fresh-unit-build='+json.dumps({'label':'native-installer-recipe','sourceSha256':hashlib.sha256(READER.read_bytes()).hexdigest(),
                                            'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))

    def test_observe_accepted_foreign_alias_miss_and_uid_matching_contract(self):
        shell = RUNNER.read_text()
        units = 'other_provers() {' + shell.split('other_provers() {', 1)[1].split('# ---- locks:', 1)[0]
        # Feed only synthetic rows to the unchanged shell matcher. This observes
        # detection, not a require_quiet_machine guard pass or a real foreign UID.
        command = 'set -euo pipefail\nrunner_process_scan(){ /bin/cat; }\n' + units + '\nother_provers\n'
        def detected(rows):
            result = run('/bin/bash', '-c', command, input=rows)
            self.assertEqual((result.returncode, len(result.stderr)), (0, 0))
            return bool(result.stdout)
        observed = {}
        for case, wanted in [('same-uid-alias', True), ('same-uid-executable-only', False),
                             ('foreign-executable', True), ('foreign-alias', False)]:
            actual = run(str(self.binary), case, 'pid=,comm=')
            self.assertEqual((actual.returncode, len(actual.stderr)), (0, 0))
            observed[case] = detected(actual.stdout)
            self.assertEqual(observed[case], wanted)
        legacy_alias = detected(b'500 pool-pk-load\n')
        self.assertTrue(legacy_alias)
        print('accepted-boundary-observation=' + json.dumps({
            'schema': 'eng1436-uid-boundary-v1', 'apiDoubles': True,
            'nativeDetected': observed, 'syntheticLegacyForeignAliasDetected': legacy_alias,
            'foreignAliasMissObserved': legacy_alias and not observed['foreign-alias'],
            'guardPassClaimed': False}, sort_keys=True))

    def test_failed_and_partial_inventory_never_succeeds(self):
        for case,reason,error in (('table-failed','process-table-size',1),('table-churn','process-table-fetch',12),
                                  ('table-short','process-table-fetch-shape',0),('args-failed','arguments-query',5),
                                  ('args-short','arguments-size',0),('args-newline','argv0-delimiter',0)):
            with self.subTest(case=case):
                actual = run(str(self.binary), case, 'pid=,comm=')
                self.assertEqual(actual.returncode, 1)
                expected={'status':1,'reason':reason,'errno':error}
                if reason=='arguments-query':expected.update(confirmation='live',confirmationErrno=0)
                self.assertEqual(closed_diagnostic(actual,allow_stdout=True),expected)
                if case == 'args-failed':
                    self.assertTrue(actual.stdout == b'499 /synthetic/apnt-test-prover-long\n')

    def test_independently_confirmed_exit_is_skipped(self):
        actual = run(str(self.binary), 'exited', 'pid=,comm=')
        self.assertEqual(actual.returncode, 0)
        self.assertTrue(actual.stdout == b'499 /synthetic/apnt-test-prover-long\n')

    def einval_guard(self, scenario):
        native=self.base/'einval-reader';error_file=self.base/'einval-error';status_file=self.base/'einval-status'
        continued=self.base/'einval-continued';continued.unlink(missing_ok=True)
        native.write_text('#!/bin/sh\nexec '+shlex.quote(str(self.binary))+' '+shlex.quote(scenario)+' "$2"\n')
        native.chmod(0o700)
        source=guard_script(native,error_file,status_file,self.base/'absent-sp1',self.base/'absent-marker')
        source+='printf continued >'+shlex.quote(str(continued))+'\n'
        actual=run('/bin/bash','-c',source)
        status=int(status_file.read_bytes())
        return actual,reader_diagnostic(status,error_file.read_bytes()),continued.exists()

    def test_einval_on_independently_vanished_or_zombie_pid_is_skipped(self):
        for scenario in ('einval-exited','einval-zombie'):
            actual=run(str(self.binary),scenario,'pid=,comm=')
            self.assertEqual((actual.returncode,len(actual.stderr)),(0,0))
            self.assertTrue(actual.stdout==b'499 neutral\n')
            guarded,diagnostic,continued=self.einval_guard(scenario)
            self.assertEqual((guarded.returncode,len(guarded.stdout),len(guarded.stderr)),(0,0,0))
            self.assertEqual(diagnostic,{'status':0,'reason':'none','errno':0})
            self.assertTrue(continued)
            print('einval-case='+json.dumps({'scenario':scenario,'readerStatus':actual.returncode,
                                            'guardStatus':guarded.returncode,'continued':continued,'diagnostic':diagnostic}))

    def test_einval_live_or_unconfirmed_identity_refuses_before_continuation(self):
        valid=run(str(self.binary),'einval-valid','pid=,comm=')
        self.assertEqual((valid.returncode,len(valid.stderr)),(0,0))
        self.assertTrue(valid.stdout==b'499 neutral\n500 /synthetic/pool-pk-load\n')
        guarded,diagnostic,continued=self.einval_guard('einval-valid')
        self.assertEqual((guarded.returncode,len(guarded.stdout),len(guarded.stderr)),(19,0,0))
        self.assertEqual(diagnostic,{'status':0,'reason':'none','errno':0})
        self.assertFalse(continued)
        print('einval-case='+json.dumps({'scenario':'einval-valid','readerStatus':valid.returncode,
                                        'guardStatus':guarded.returncode,'continued':continued,'diagnostic':diagnostic}))
        for scenario,confirmation,confirmation_errno in (
                ('einval-live','live',0),('einval-system','live',0),
                ('einval-confirmation-failed','query-error',1),('einval-confirmation-no-errno','query-error',0),
                ('einval-confirmation-short','unconfirmed',0),('einval-confirmation-mismatch','unconfirmed',0)):
            actual=run(str(self.binary),scenario,'pid=,comm=')
            self.assertEqual(actual.returncode,1)
            self.assertTrue(actual.stdout==b'499 neutral\n')
            expected={'status':1,'reason':'arguments-query','errno':22,
                      'confirmation':confirmation,'confirmationErrno':confirmation_errno}
            self.assertEqual(closed_diagnostic(actual,allow_stdout=True),expected)
            guarded,diagnostic,continued=self.einval_guard(scenario)
            self.assertEqual((guarded.returncode,len(guarded.stdout),len(guarded.stderr)),(20,0,0))
            self.assertEqual(diagnostic,expected)
            self.assertFalse(continued)
            print('einval-case='+json.dumps({'scenario':scenario,'readerStatus':actual.returncode,
                                            'guardStatus':guarded.returncode,'continued':continued,'diagnostic':diagnostic}))

    def test_einval_table_failure_never_reaches_identity(self):
        for scenario,reason in (('einval-table-size','process-table-size'),('einval-table-fetch','process-table-fetch')):
            actual=run(str(self.binary),scenario,'pid=,comm=')
            self.assertEqual((actual.returncode,len(actual.stdout)),(1,0))
            self.assertEqual(closed_diagnostic(actual),{'status':1,'reason':reason,'errno':22})
            guarded,diagnostic,continued=self.einval_guard(scenario)
            self.assertEqual((guarded.returncode,len(guarded.stdout),len(guarded.stderr)),(20,0,0))
            self.assertEqual(diagnostic,{'status':1,'reason':reason,'errno':22})
            self.assertFalse(continued)
            print('einval-case='+json.dumps({'scenario':scenario,'readerStatus':actual.returncode,
                                            'guardStatus':guarded.returncode,'continued':continued,'diagnostic':diagnostic}))

    def test_process_wrapper_preserves_its_existing_tri_state(self):
        for scenario,status in (('einval-exited',0),('einval-live',1),('einval-zombie',1),
                                ('einval-confirmation-failed',-1),('einval-confirmation-no-errno',-1),
                                ('einval-confirmation-short',-1),('einval-confirmation-mismatch',-1)):
            actual=run(str(self.binary),scenario,'process-status')
            self.assertEqual((actual.returncode,len(actual.stderr)),(0,0))
            self.assertTrue(actual.stdout==('{"status":'+str(status)+'}\n').encode())

    def test_einval_blanket_skip_mutation_hides_live_prover_then_restores(self):
        original=READER.read_text()
        before='if (retries == 2) { arguments_refusal(query_errno, 1, 0); goto done; }'
        self.assertEqual(original.count(before),1)
        mutant=self.base/'einval-mutant.c'
        mutant.write_text(original.replace(before,'if (retries == 2) { if (query_errno == EINVAL) { result=0;goto done; } arguments_refusal(query_errno, 1, 0); goto done; }'))
        wrapper=self.base/'einval-wrapper.c'
        wrapper.write_text(self.source.read_text().replace(json.dumps(str(READER)),json.dumps(str(mutant))))
        binary=self.base/'einval-mutant'
        built=run('/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',str(wrapper),'-lproc','-o',str(binary))
        self.assertEqual(built.returncode,0)
        guarded,diagnostic,continued=self.einval_guard('einval-live')
        self.assertEqual((guarded.returncode,diagnostic['status'],continued),(20,1,False))
        original_binary=self.binary
        try:
            self.binary=binary
            guarded,diagnostic,continued=self.einval_guard('einval-live')
            self.assertEqual((guarded.returncode,diagnostic['status'],continued),(0,0,True))
        finally:
            self.binary=original_binary
        # Execute the exact focused regression in a child; only its assertion
        # failure, with zero errors, counts as the mutation oracle.
        regression='''import contextlib,importlib.util,io,json,sys,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('einval_regression',sys.argv[1]);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
case=module.NativeScan('test_einval_live_or_unconfirmed_identity_refuses_before_continuation');case.base=Path(sys.argv[2]);case.binary=Path(sys.argv[3])
result=unittest.TestResult()
with contextlib.redirect_stdout(io.StringIO()): case.run(result)
print(json.dumps({'testsRun':result.testsRun,'failures':len(result.failures),'errors':len(result.errors)}))
sys.exit(19 if result.failures and not result.errors else 0 if result.wasSuccessful() else 20)
'''
        for tested,status,failures in ((original_binary,0,0),(binary,19,1),(original_binary,0,0)):
            result=run('/usr/bin/python3','-c',regression,__file__,str(self.base),str(tested))
            self.assertEqual((result.returncode,len(result.stderr)),(status,0))
            self.assertEqual(json.loads(result.stdout),{'testsRun':1,'failures':failures,'errors':0})
        print('einval-mutation='+json.dumps({'mutation':'blanket-EINVAL-skip','mutantReaderStatus':0,
            'mutantGuardStatus':0,'mutantContinued':True,'originalGuardStatus':20,'originalContinued':False,
            'focusedRegressionStatuses':[0,19,0],'mutantAssertionFailures':1,'mutantErrors':0}))

    def test_global_unknown_selector_refuses(self):
        actual = run(str(self.binary), 'valid', 'args=')
        self.assertEqual((actual.returncode, len(actual.stdout), len(actual.stderr)), (1, 0, 0))

    def test_rss_query_failure_refuses_and_confirmed_exit_is_skipped(self):
        for case,status,wanted in [('rss',0,b'123 pool-pk-load\n123 pool-pk-load\n'),
                                   ('rss-failed',1,b'123 pool-pk-load\n'),
                                   ('rss-exited',0,b'123 pool-pk-load\n')]:
            actual=run(str(self.binary),case,'rss=,comm=')
            self.assertEqual(actual.returncode,status)
            self.assertTrue(actual.stdout==wanted)
            if status:self.assertEqual(closed_diagnostic(actual,allow_stdout=True),{'status':1,'reason':'rss-query','errno':5})
            else:self.assertEqual(len(actual.stderr),0)

    def test_failure_guards_have_firing_mutation_oracles(self):
        original = READER.read_text()
        cases = [('if (!ready) { free(table); return 1; }', 'if (!ready && 0) { free(table); return 1; }', 'table-failed'),
                 ('if (found < 0) goto done;', 'if (found < 0) continue;', 'args-failed')]
        for index,(before,after,case) in enumerate(cases):
            self.assertEqual(original.count(before),1)
            mutant=self.base/('mutant-'+str(index)+'.c')
            mutant.write_text(original.replace(before,after))
            wrapper=self.base/('wrapper-'+str(index)+'.c')
            wrapper.write_text(self.source.read_text().replace(json.dumps(str(READER)),json.dumps(str(mutant))))
            binary=self.base/('mutant-'+str(index))
            built=run('/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',str(wrapper),'-lproc','-o',str(binary))
            self.assertEqual(built.returncode,0)
            # Same exact-status regression runs in a child, so its failure is
            # measured independently; no crash/timeout is a firing oracle.
            regression='import subprocess,sys; r=subprocess.run(sys.argv[1:],capture_output=True); sys.exit(0 if r.returncode==1 else 19)'
            self.assertEqual(run('/usr/bin/python3','-c',regression,str(binary),case,'pid=,comm=').returncode,19)
            self.assertEqual(run('/usr/bin/python3','-c',regression,str(self.binary),case,'pid=,comm=').returncode,0)

    def test_closed_diagnostic_labels_query_shape_and_delimiter_failures(self):
        for case, reason, error in [('valid','none',0), ('table-failed','process-table-size',1),
                                     ('args-failed','arguments-query',5), ('args-short','arguments-size',0),
                                     ('args-newline','argv0-delimiter',0), ('foreign-path-failed','foreign-path',1),
                                     ('rss-failed','rss-query',5)]:
            with self.subTest(case=case):
                actual = run(str(self.binary),case,'rss=,comm=' if case=='rss-failed' else 'pid=,comm=')
                expected={'status':int(case!='valid'),'reason':reason,'errno':error}
                if reason=='arguments-query':expected.update(confirmation='live',confirmationErrno=0)
                self.assertEqual(closed_diagnostic(actual,allow_stdout=True),expected)
                # The error stream contains no row/argument/environment bytes,
                # even when unusable partial stdout preceded the refusal.
                self.assertFalse(any(canary in actual.stderr for canary in
                                     (b'SYNTHETIC_ARG_CANARY',b'SYNTHETIC_ENV_CANARY',b'/synthetic',b'499',b'500')))

    def test_host_guard_fixture_names_prover_refusal_and_cannot_pass_on_inventory_failure(self):
        native=self.base/'synthetic-reader';error_file=self.base/'fixture-error';status_file=self.base/'fixture-status'
        source=guard_script(native,error_file,status_file,self.base/'absent-sp1',self.base/'absent-marker')
        for mode,expected,reader_status in (('quiet',0,0),('match',19,0),('failed',20,1)):
            native.write_text('#!/bin/sh\n[ "$*" = "-axo pid=,comm=" ] || exit 99\n'+
                ("printf '499 pool-pk-load\\n'\n" if mode!='quiet' else ':\n')+
                ("printf '%s\\n' '{\"status\":1,\"reason\":\"process-table-fetch\",\"errno\":12}' >&2\nexit 1\n" if mode=='failed' else 'exit 0\n'))
            native.chmod(0o700)
            actual=run('/bin/bash','-c',source)
            self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(expected,b'',b''))
            self.assertEqual(int(status_file.read_bytes()),reader_status)
            if mode=='match':
                mutant=run('/bin/bash','-c',source.replace('has_live=true\n',''))
                self.assertEqual(mutant.returncode,1)
                self.assertTrue(b'has_live: unbound variable' in mutant.stderr)
                self.assertEqual(run('/bin/bash','-c',source).returncode,19)
            if mode=='failed':
                # A generic die status would make the named-prover control
                # pass vacuously on this independently failed inventory.
                old='die(){ [[ "$1" == live-plan-other-prover ]] && exit 19; exit 20; }'
                self.assertEqual(source.count(old),1)
                self.assertEqual(run('/bin/bash','-c',source.replace(old,'die(){ exit 19; }')).returncode,19)
                restored=run('/bin/bash','-c',source)
                self.assertEqual(restored.returncode,20)
                record=host_failure_metadata('named-prover-guard',19,restored,int(status_file.read_bytes()),error_file.read_bytes())
                self.assertEqual(record['diagnostic'],{'status':1,'reason':'process-table-fetch','errno':12})
                self.assertTrue(record['sameScanClaimed'])

    def test_remaining_closed_failure_branches_report_only_call_and_errno(self):
        for case,reason,error in (('table-allocation','process-table-allocation',12),('arguments-allocation','arguments-allocation',12),
            ('argmax-query','argmax-query',1),('argmax-shape','argmax-shape',0),('table-size-shape','process-table-size-shape',0),
            ('pid-invalid','pid',0),('arguments-count','arguments-count',0),('executable-terminator','executable-terminator',0),
            ('argv0-terminator','argv0-terminator',0),('foreign-delimiter','foreign-delimiter',0),('stdout-failed','stdout',9)):
            actual=run(str(self.binary),case,'pid=,comm=')
            self.assertEqual(actual.returncode,1)
            self.assertEqual(closed_diagnostic(actual,allow_stdout=True),{'status':1,'reason':reason,'errno':error})
            self.assertFalse(any(canary in actual.stderr for canary in (b'/synthetic',b'SYNTHETIC_ARG_CANARY',b'SYNTHETIC_ENV_CANARY')))

    def test_reader_diagnostic_whole_stream_schema_and_mutation(self):
        raw=b'{"status":1,"reason":"arguments-query","errno":5}\n'
        self.assertEqual(reader_diagnostic(1,raw),{'status':1,'reason':'arguments-query','errno':5})
        self.assertEqual(reader_diagnostic(0,b''),{'status':0,'reason':'none','errno':0})
        bads=[raw+b'SYNTHETIC_PRIVATE_TEXT_CANARY',b' '+raw,raw.replace(b'5',b'true'),
              raw.replace(b'arguments-query',b'SYNTHETIC_PRIVATE_TEXT_CANARY'),raw.replace(b',"errno":5',b''),
              raw.replace(b'{',b'{"extra":0,'),raw.replace(b'{',b'{"status":1,'),b'null',b'X'*257]
        for bad in bads:
            with self.assertRaisesRegex(RuntimeError,'^native-diagnostic-result-refused$'):reader_diagnostic(1,bad)
        with self.assertRaisesRegex(RuntimeError,'^native-diagnostic-result-refused$'):reader_diagnostic(True,raw)
        original=Path(__file__).read_text()
        line=next(line for line in original.splitlines() if line.strip().startswith('or raw !='))
        namespace={'__file__':__file__,'__name__':'diagnostic_mutation'}
        exec(compile(original.replace(line,'            or False):'),'diagnostic-mutation','exec'),namespace)
        self.assertEqual(namespace['reader_diagnostic'](1,b' '+raw),reader_diagnostic(1,raw))
        with self.assertRaisesRegex(RuntimeError,'^native-diagnostic-result-refused$'):reader_diagnostic(1,b' '+raw)
        self.assertEqual(reader_diagnostic(1,raw)['errno'],5)

    def test_confirmation_diagnostic_schema_and_name_guard_mutation(self):
        original=Path(__file__).read_text()
        for confirmation,error in (('live',0),('unconfirmed',0),('query-error',1),('query-error',0)):
            value={'status':1,'reason':'arguments-query','errno':22,'confirmation':confirmation,'confirmationErrno':error}
            raw=(json.dumps(value,separators=(',',':'))+'\n').encode()
            self.assertEqual(reader_diagnostic(1,raw),value)
        base={'status':1,'reason':'arguments-query','errno':22,'confirmation':'live','confirmationErrno':0}
        invalids=[{k:v for k,v in base.items() if k!=name} for name in ('confirmation','confirmationErrno')]
        invalids.extend([{**base,'confirmation':'SYNTHETIC_PRIVATE_TEXT_CANARY'},
                        {**base,'confirmation':True},{**base,'confirmationErrno':True},
                        {**base,'confirmationErrno':-1},{**base,'confirmationErrno':4096},
                        {**base,'confirmationErrno':1},{**base,'reason':'rss-query'},
                        {**base,'unknown':'SYNTHETIC_PRIVATE_TEXT_CANARY'},{**base,'status':0}])
        for value in invalids:
            raw=(json.dumps(value,separators=(',',':'))+'\n').encode()
            with self.assertRaisesRegex(RuntimeError,'^native-diagnostic-result-refused$'):reader_diagnostic(1,raw)
        raw=(json.dumps(base,separators=(',',':'))+'\n').encode()
        for bad in (raw+b'X',b' '+raw,raw.replace(b'{',b'{"confirmation":"live",',1)):
            with self.assertRaisesRegex(RuntimeError,'^native-diagnostic-result-refused$'):reader_diagnostic(1,bad)
        before=next(line for line in original.splitlines() if line.strip().startswith("or value['confirmation'] not in "))
        self.assertEqual(original.count(before),1)
        mutant=self.base/'confirmation-mutant.py';mutant.write_text(original.replace(before,'                or False'))
        regression='''import importlib.util,sys
spec=importlib.util.spec_from_file_location('confirmation_regression',sys.argv[1]);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
raw=b'{"status":1,"reason":"arguments-query","errno":22,"confirmation":"SYNTHETIC_PRIVATE_TEXT_CANARY","confirmationErrno":0}\\n'
try: module.reader_diagnostic(1,raw)
except RuntimeError as error: sys.exit(0 if str(error)=='native-diagnostic-result-refused' else 20)
sys.exit(19)
'''
        for path,status in ((Path(__file__),0),(mutant,19),(Path(__file__),0)):
            actual=run('/usr/bin/python3','-c',regression,str(path))
            self.assertEqual((actual.returncode,len(actual.stdout),len(actual.stderr)),(status,0,0))
        print('confirmation-name-mutation='+json.dumps({'regressionStatuses':[0,19,0],'privateNameRejectedAfterRestore':True}))

    def vanished_probe(self):
        # A real stale snapshot, not a fabricated errno: retain a live child
        # snapshot, reap that child, then execute the production name query.
        # Only call outcomes leave the probe; no PID or identity is emitted.
        source=self.base/'vanished-probe.c';binary=self.base/'vanished-probe'
        source.write_text(r'''
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <signal.h>
static int trace_sysctl(int *, unsigned, void *, size_t *, void *, size_t);
#define sysctl trace_sysctl
#define main reader_main
#include '''+json.dumps(str(READER))+r'''
#undef main
#undef sysctl
static int armed, arguments_calls, arguments_status, arguments_errno, confirmation_calls, confirmation_status, confirmation_empty;
static int trace_sysctl(int *mib,unsigned n,void *out,size_t *size,void *in,size_t insize) {
    int result=sysctl(mib,n,out,size,in,insize),error=errno;
    if(armed && mib[1]==KERN_PROCARGS2){arguments_calls++;arguments_status=result;arguments_errno=error;}
    if(armed && mib[1]==KERN_PROC && mib[2]==KERN_PROC_PID){confirmation_calls++;confirmation_status=result;confirmation_empty=*size==0;}
    errno=error;return result;
}
int main(void) {
    int channel[2];if(pipe(channel))return 2;
    pid_t child=fork();if(child<0)return 3;
    if(child==0){close(channel[1]);char byte;int received=read(channel[0],&byte,1);close(channel[0]);_exit(received==1?0:4);}
    close(channel[0]);struct kinfo_proc snapshot;
    if(process(child,&snapshot)!=1 || snapshot.kp_eproc.e_ucred.cr_uid!=geteuid() || snapshot.kp_proc.p_stat==SZOMB){
        close(channel[1]);kill(child,SIGKILL);waitpid(child,NULL,0);return 5;
    }
    if(write(channel[1],"X",1)!=1){close(channel[1]);kill(child,SIGKILL);waitpid(child,NULL,0);return 6;}
    close(channel[1]);int status;
    if(waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status))return 7;
    char bytes[4096]={0};const char *name=NULL;armed=1;
    struct recovery_budget recovery={0};
    int found=command_of(&snapshot,bytes,sizeof(bytes),&name,&recovery);wipe(bytes,sizeof(bytes));
    printf("{\"commandStatus\":%d,\"nameAbsent\":%d,\"argumentsCalls\":%d,\"argumentsStatus\":%d,\"argumentsErrno\":%d,\"confirmationCalls\":%d,\"confirmationStatus\":%d,\"confirmationEmpty\":%d}\n",
        found,name==NULL,arguments_calls,arguments_status,arguments_errno,confirmation_calls,confirmation_status,confirmation_empty);
    return 0;
}
''')
        built=run('/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',str(source),'-lproc','-o',str(binary))
        self.assertEqual((built.returncode,len(built.stdout),len(built.stderr)),(0,0,0))
        print('fresh-unit-build='+json.dumps({'label':'real-vanished-probe','sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                                            'productionSha256':hashlib.sha256(READER.read_bytes()).hexdigest(),'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
        return binary

    def test_vanished_pid_probe_builds_without_running_host_queries(self):
        binary=self.vanished_probe()
        self.assertTrue(binary.is_file() and os.access(binary,os.X_OK))

    @unittest.skipUnless(HOST, 'real Seatbelt requires outside host')
    def test_kernel_vanished_pid_einval_has_independent_exit_confirmation(self):
        binary=self.vanished_probe()
        denied=self.base/'vanished-denied';denied.write_text('synthetic denied read')
        profile='(version 1) (allow default) (deny file-read* (literal '+json.dumps(str(denied))+'))'
        actual=run('/usr/bin/sandbox-exec','-p',profile,str(binary),timeout=30)
        self.assertEqual((actual.returncode,len(actual.stderr)),(0,0))
        expected={'commandStatus':0,'nameAbsent':1,'argumentsCalls':1,'argumentsStatus':-1,'argumentsErrno':22,
                  'confirmationCalls':1,'confirmationStatus':0,'confirmationEmpty':1}
        self.assertEqual(json.loads(actual.stdout),expected)
        print('real-vanished-observation='+json.dumps(expected,sort_keys=True))

    @unittest.skipUnless(HOST, 'real Seatbelt requires outside host')
    def test_kernel_scan_and_guard_fire_without_profile_loosening(self):
        binary = self.base / 'native-reader'
        built = run('/usr/bin/clang', '-O2', '-Wall', '-Wextra', '-Werror', str(READER), '-lproc', '-o', str(binary))
        self.assertEqual(built.returncode, 0)
        source = self.base / 'denied-plan'; source.write_text('synthetic read control')
        profile = '(version 1) (allow default) (deny file-read* (literal '+json.dumps(str(source))+'))'
        def sandbox(*args, policy=profile):
            return run('/usr/bin/sandbox-exec', '-p', policy, *args)
        def check(point, actual, expected, reader_status=None, reader_stderr=None):
            if actual.returncode == expected:return
            record=host_failure_metadata(point,expected,actual,reader_status,reader_stderr)
            destination=os.environ.get('MIG01_TEST_OUTPUT_ROOT')
            if destination:
                descriptor=os.open(Path(destination)/'native-scan-closed.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(descriptor,'w') as sink:sink.write(json.dumps(record,sort_keys=True)+'\n')
            self.fail('native-scan-closed='+json.dumps(record,sort_keys=True))
        # Absolute ps fails at exec even with allow-default; no PATH or
        # process-info deny rule participates. Captured errors never print.
        for policy in ('(version 1) (allow default)', profile):
            actual = sandbox('/bin/ps', '-axo', 'pid=,comm=', policy=policy)
            self.assertEqual((actual.returncode, len(actual.stdout)), (71, 0))
            self.assertTrue(b'Operation not permitted' in actual.stderr)
        self.assertEqual(sandbox('/bin/cat', str(source)).returncode, 1)
        actual = sandbox(str(binary), '-axo', 'pid=,comm=')
        check('initial-inventory',actual,0,actual.returncode,actual.stderr)
        # Fixed synthetic scan binding in extracted units only; installed entry
        # binding and real checkout/resource guards remain in the kernel suite.
        error_file=self.base/'reader-error';status_file=self.base/'reader-status'
        script = self.base/'guard.sh';script.write_text(guard_script(binary,error_file,status_file,self.base/'absent-sp1',self.base/'absent-marker'))
        def guard(point, expected):
            error_file.unlink(missing_ok=True);status_file.unlink(missing_ok=True)
            actual=sandbox('/bin/bash',str(script))
            reader_status=int(status_file.read_bytes()) if status_file.is_file() else None
            reader_stderr=error_file.read_bytes() if error_file.is_file() else None
            check(point,actual,expected,reader_status,reader_stderr)
        guard('quiet-guard',0)
        # exec argv[0] through Python, avoiding a real prover or lock marker.
        child = subprocess.Popen(['pool-pk-load','30'],executable='/bin/sleep',stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            inventory = sandbox(str(binary),'-axo','pid=,comm=')
            check('named-prover-inventory',inventory,0,inventory.returncode,inventory.stderr)
            self.assertTrue((str(child.pid)+' pool-pk-load\n').encode() in inventory.stdout)
            guard('named-prover-guard',19)
            sample = sandbox(str(binary),'-axo','rss=,comm=')
            check('rss-inventory',sample,0,sample.returncode,sample.stderr)
            self.assertTrue(any(row.endswith(b' pool-pk-load') and int(row.split()[0])>0 for row in sample.stdout.splitlines()))
        finally:
            child.terminate(); child.wait()

    @unittest.skipUnless(HOST, 'real Seatbelt requires outside host')
    def test_kernel_live_einval_recovery_preserves_named_prover_guard(self):
        spec=importlib.util.spec_from_file_location('live_requery',READER.parents[1]/'apnt-pool-action-circuit/scripts/test-native-requery.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        module.real_host_control(self,self.base)

    @unittest.skipUnless(HOST, 'real Seatbelt requires outside host')
    def test_kernel_whole_host_inventory_availability_eng1459(self):
        spec=importlib.util.spec_from_file_location('inventory_availability',READER.parents[1]/'apnt-pool-action-circuit/scripts/test-native-inventory-availability.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        module.real_host_control(self,self.base,max_unavailable=0)


class ReproductionSelection(unittest.TestCase):
    def runtime_titles(self,module):
        spec=importlib.util.spec_from_file_location('runtime_selection',RUNNER.with_name('test-private-runner-runtime-no-proof.py'))
        selection=importlib.util.module_from_spec(spec);spec.loader.exec_module(selection)
        return selection.runtime_titles('union')

    def test_confirmation_binding_guard_mutations_fire_then_restore(self):
        base={'status':1,'reason':'arguments-query','errno':22,'confirmation':'live','confirmationErrno':0}
        code_float={**base,'confirmation':'query-error','confirmationErrno':0.0}
        code_high={**base,'confirmation':'query-error','confirmationErrno':4096}
        code_mismatch={**base,'confirmationErrno':1}
        wrong_query={**base,'reason':'rss-query'}
        private_name={**base,'confirmation':'SYNTHETIC_PRIVATE_TEXT_CANARY'}
        partial={k:v for k,v in base.items() if k!='confirmationErrno'}
        mutations=[
            ('reader',"value['reason']!='arguments-query'",'False',wrong_query),
            ('reader',"type(value['confirmationErrno']) is not int",'False',code_float),
            ('reader',"not 0<=value['confirmationErrno']<=4095",'False',code_high),
            ('reader',"value['confirmation']!='query-error' and value['confirmationErrno']!=0",'False',code_mismatch),
            ('projection','set(diagnostic) in (basic,extended)','True',partial),
            ('projection',"diagnostic['reason']=='arguments-query'",'True',wrong_query),
            ('projection',"diagnostic['confirmation'] in ('live','unconfirmed','query-error')",'True',private_name),
            ('projection',"type(diagnostic['confirmationErrno']) is int",'True',code_float),
            ('projection',"0<=diagnostic['confirmationErrno']<=4095",'True',code_high),
            ('projection',"(diagnostic['confirmation']=='query-error' or diagnostic['confirmationErrno']==0)",'True',code_mismatch)]
        regression='''import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('binding_regression',sys.argv[1]);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
diagnostic=json.loads(sys.argv[3])
try:
 if sys.argv[2]=='reader': module.reader_diagnostic(1,(json.dumps(diagnostic,separators=(',',':'))+'\\n').encode())
 else:
  value={'schema':'eng1436-native-scan-v2','failurePoint':'named-prover-guard','expectedStatus':19,'originalStatus':20,'originalStdoutBytes':0,'originalStderrBytes':0,'readerStatus':1,'readerStderrBytes':100,'diagnostic':diagnostic,'sameScanClaimed':True,'profileChanged':False}
  module.native_scan_original_observation(value)
except RuntimeError as error: sys.exit(0 if str(error) in ('native-diagnostic-result-refused','kernel-reproduction-refused') else 20)
sys.exit(19)
'''
        with tempfile.TemporaryDirectory(prefix='other-provers-binding-',dir='/private/tmp') as directory:
            for index,(kind,before,after,invalid) in enumerate(mutations):
                path=Path(__file__) if kind=='reader' else RUNNER.with_name('reproduce-kernel-stock-no-proof.py')
                original=path.read_text();function='reader_diagnostic' if kind=='reader' else 'native_scan_original_observation'
                start=original.index('def '+function+'(');end=original.index('\ndef ',start)
                body=original[start:end];self.assertEqual(body.count(before),1)
                mutant=Path(directory)/(str(index)+'.py')
                mutant.write_text(original[:start]+body.replace(before,after)+original[end:])
                for tested,status in ((path,0),(mutant,19),(path,0)):
                    actual=run('/usr/bin/python3','-c',regression,str(tested),kind,json.dumps(invalid,separators=(',',':')))
                    self.assertEqual((actual.returncode,len(actual.stdout),len(actual.stderr)),(status,0,0))
        print('confirmation-binding-mutations='+json.dumps({'independentMutations':len(mutations),'statusesPerMutation':[0,19,0],'restored':True}))

    def test_confirmation_projection_binds_class_code_and_original_query(self):
        spec=importlib.util.spec_from_file_location('reproduction',RUNNER.with_name('reproduce-kernel-stock-no-proof.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        control=subprocess.CompletedProcess([],20,b'',b'')
        for confirmation,error in (('live',0),('unconfirmed',0),('query-error',1),('query-error',0)):
            diagnostic={'status':1,'reason':'arguments-query','errno':22,'confirmation':confirmation,'confirmationErrno':error}
            raw=(json.dumps(diagnostic,separators=(',',':'))+'\n').encode()
            value=host_failure_metadata('named-prover-guard',19,control,1,raw)
            self.assertEqual(module.native_scan_original_observation(value)['diagnostic'],diagnostic)
        base={'status':1,'reason':'arguments-query','errno':22,'confirmation':'live','confirmationErrno':0}
        invalids=[{k:v for k,v in base.items() if k!=name} for name in ('confirmation','confirmationErrno')]
        invalids.extend([{**base,'confirmation':True},{**base,'confirmation':'SYNTHETIC_PRIVATE_TEXT_CANARY'},
                        {**base,'confirmationErrno':True},{**base,'confirmationErrno':-1},
                        {**base,'confirmationErrno':4096},{**base,'confirmationErrno':1},
                        {**base,'unknown':False},{**base,'reason':'rss-query'},{**base,'status':0}])
        value=host_failure_metadata('named-prover-guard',19,control,1,b'{"status":1,"reason":"arguments-query","errno":22}\n')
        for diagnostic in invalids:
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
                module.native_scan_original_observation({**value,'diagnostic':diagnostic})

    def test_original_scan_metadata_keeps_reader_and_control_status_distinct(self):
        spec=importlib.util.spec_from_file_location('reproduction',RUNNER.with_name('reproduce-kernel-stock-no-proof.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        control=subprocess.CompletedProcess([],20,b'',b'')
        raw=b'{"status":1,"reason":"process-table-fetch","errno":12}\n'
        value=host_failure_metadata('named-prover-guard',19,control,1,raw)
        self.assertEqual(module.native_scan_original_observation(value),value)
        self.assertEqual((value['originalStatus'],value['readerStatus'],value['diagnostic']['errno']),(20,1,12))
        valid=host_failure_metadata('named-prover-guard',19,control,0,b'')
        self.assertEqual(module.native_scan_original_observation(valid)['diagnostic'],{'status':0,'reason':'none','errno':0})
        absent=host_failure_metadata('named-prover-guard',19,control)
        self.assertEqual(module.native_scan_original_observation(absent)['diagnostic'],None)
        invalids=[{**value,'unknown':0},{k:v for k,v in value.items() if k!='readerStatus'},
                  {**value,'originalStatus':True},{**value,'failurePoint':'SYNTHETIC_PRIVATE_TEXT_CANARY'},
                  {**value,'sameScanClaimed':False},{**value,'expectedStatus':0},{**value,'profileChanged':0},
                  {**value,'readerStderrBytes':True},{**value,'originalStdoutBytes':-1}]
        for diag in ({**value['diagnostic'],'status':20},{**value['diagnostic'],'errno':True},
                     {**value['diagnostic'],'reason':'SYNTHETIC_PRIVATE_TEXT_CANARY'},
                     {**value['diagnostic'],'extra':False}):invalids.append({**value,'diagnostic':diag})
        for invalid in invalids:
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
                module.native_scan_original_observation(invalid)
        with tempfile.TemporaryDirectory(prefix='other-provers-original-',dir='/private/tmp') as directory:
            path=Path(directory)/'closed.json';path.write_text(json.dumps(value))
            self.assertEqual(module.native_scan_observation(path),value)

    def test_native_diagnostic_projection_refuses_unknown_missing_and_wrong_types(self):
        spec=importlib.util.spec_from_file_location('reproduction',RUNNER.with_name('reproduce-kernel-stock-no-proof.py'))
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix='other-provers-diagnostic-',dir='/private/tmp') as directory:
            path=Path(directory)/'closed.json'
            value={'schema':'eng1436-native-scan-v1','originalStatus':1,'originalStdoutBytes':42,'originalStderrBytes':0,
                   'diagnostic':{'status':1,'reason':'arguments-query','errno':5},
                   'sameScanClaimed':False,'profileChanged':False}
            path.write_text(json.dumps(value));self.assertEqual(module.native_scan_observation(path),value)
            invalids=[{**value,'unknown':True},{k:v for k,v in value.items() if k!='diagnostic'},
                      {**value,'originalStatus':True},{**value,'originalStdoutBytes':-1},
                      {**value,'profileChanged':0},{**value,'sameScanClaimed':True}]
            for diagnostic in ({'status':1,'reason':'private text','errno':5},
                               {'status':1,'reason':'arguments-query','errno':True},
                               {'status':0,'reason':'arguments-query','errno':5},
                               {'status':1,'reason':'arguments-query'},
                               {'status':1,'reason':'arguments-query','errno':5,'unknown':False}):
                invalids.append({**value,'diagnostic':diagnostic})
            for invalid in invalids:
                path.write_text(json.dumps(invalid))
                with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
                    module.native_scan_observation(path)

    def test_closed_post_w_error_projection_requires_exact_boolean_schema(self):
        spec=importlib.util.spec_from_file_location('reproduction',RUNNER.with_name('reproduce-kernel-stock-no-proof.py'))
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix='other-provers-closed-',dir='/private/tmp') as directory:
            path=Path(directory)/'closed.json'
            value={'status':1,'contacts':[1,1,1],'deliveries':[1,1,1],'terminalBytes':55,'inventoryReason':None,
                   'outerReason':'unclassified',
                   'runnerBinarySha256':'01'*32,
                   'processListUnavailable':True,'outerRefusal':True,'memoryFloor':False,'outputCreated':True,
                   'runCreated':True,'admissionCreated':True,'resultCreated':True,'summaryCreated':True,
                   'workFailure':False,'openStage':False}
            path.write_text(json.dumps(value));self.assertEqual(module.closed_observation(path),value)
            for kind in ('missing','unknown','int','string','null','reason-private','reason-bool','reason-missing','reason-inconsistent',
                         'binary-missing','binary-private','binary-bool','binary-null'):
                invalid=dict(value)
                if kind=='missing':del invalid['processListUnavailable']
                elif kind=='unknown':invalid['foreign']=True
                elif kind=='reason-private':invalid['outerReason']='SYNTHETIC_PRIVATE_TEXT_CANARY'
                elif kind=='reason-bool':invalid['outerReason']=True
                elif kind=='reason-missing':del invalid['outerReason']
                elif kind=='reason-inconsistent':invalid['outerReason']=None
                elif kind=='binary-missing':del invalid['runnerBinarySha256']
                elif kind=='binary-private':invalid['runnerBinarySha256']='SYNTHETIC_PRIVATE_TEXT_CANARY'
                elif kind=='binary-bool':invalid['runnerBinarySha256']=True
                elif kind=='binary-null':invalid['runnerBinarySha256']=None
                else:invalid['processListUnavailable']={'int':1,'string':'true','null':None}[kind]
                path.write_text(json.dumps(invalid))
                with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
                    module.closed_observation(path)

    def test_installed_fixture_commit_excludes_generated_files_with_firing_oracle(self):
        spec = importlib.util.spec_from_file_location('reproduction', RUNNER.with_name('reproduce-kernel-stock-no-proof.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        source = module.diagnostic_driver(ROOT)
        tree = ast.parse(source)
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        commit = next(node for node in main.body if isinstance(node, ast.FunctionDef) and node.name == 'commit')
        for mutate in (False, True, False):
            with tempfile.TemporaryDirectory(prefix='other-provers-commit-', dir='/private/tmp') as directory:
                fixture = Path(directory)
                def step(label, args):
                    result = run(*args, cwd=fixture)
                    self.assertEqual(result.returncode, 0)
                step('init', ['/usr/bin/git', 'init', '-b', 'main'])
                (fixture / '.gitignore').write_text('node_modules/\ndist/\n')
                path = fixture / module.RUNNER; path.parent.mkdir(parents=True); path.write_text('old scanner\n')
                guard = fixture / module.LIVE_GUARD; guard.parent.mkdir(parents=True,exist_ok=True); guard.write_text('synthetic child guard\n')
                namespace = {'run': step}
                code = ast.unparse(commit)
                if mutate:
                    exact = "['/usr/bin/git', 'add', '--', " + repr(module.RUNNER) + ", " + repr(module.LIVE_GUARD) + "] if label in ('fixed-scan', 'fixed-live-scan') else "
                    self.assertEqual(code.count(exact), 1)
                    code = code.replace(exact, '')
                exec(compile(code, 'generated-commit-control', 'exec'), namespace)
                namespace['commit']('source')
                artifacts = [fixture / 'tools/pool-action-modules/dist/private-runner-process',
                             fixture / 'tools/pool-action-modules/dist/private-runner-build.log']
                for artifact in artifacts:
                    artifact.parent.mkdir(parents=True, exist_ok=True); artifact.write_text('synthetic build output\n')
                target = fixture / 'node_modules/synthetic-dependency'; target.mkdir(parents=True)
                (target / 'package.json').write_text('{}\n')
                link = fixture / 'packages/chain-io/node_modules/synthetic-dependency'
                link.parent.mkdir(parents=True); link.symlink_to(target, target_is_directory=True)
                path.write_text('fixed scanner\n'); namespace['commit']('fixed-scan')
                tracked = run('/usr/bin/git', 'ls-files', '-z', cwd=fixture).stdout.decode().split('\0')
                changed = run('/usr/bin/git', 'diff-tree', '--no-commit-id', '--name-only', '-r', 'HEAD', cwd=fixture).stdout.decode().splitlines()
                regression = ('import subprocess,sys; r=subprocess.run(["/usr/bin/git","diff-tree",'
                              '"--no-commit-id","--name-only","-r","HEAD"],capture_output=True); '
                              'sys.exit(0 if r.returncode==0 and r.stdout.decode().splitlines()==[sys.argv[1]] else 19)')
                self.assertEqual(run('/usr/bin/python3', '-c', regression, module.RUNNER, cwd=fixture).returncode,
                                 19 if mutate else 0)
                if mutate:
                    self.assertIn(str(link.relative_to(fixture)), tracked)
                    # The same file-read primitive used by runtimeSourceDigest
                    # reaches EISDIR. A timeout or earlier refusal is no oracle.
                    with self.assertRaises(IsADirectoryError) as refused:
                        link.read_bytes()
                    self.assertEqual(refused.exception.errno, 21)
                    self.assertNotEqual(changed, [module.RUNNER])
                else:
                    self.assertEqual(changed, [module.RUNNER])
                    self.assertEqual(set(tracked) - {''}, {'.gitignore', module.RUNNER, module.LIVE_GUARD})
                    self.assertEqual(run('/usr/bin/git', 'status', '--porcelain', cwd=fixture).stdout, b'')

    def replay_composition(self, mutate=False, fixed_failure=False, instrumented=True, missing_inventory_input=None):
        spec=importlib.util.spec_from_file_location('reproduction',RUNNER.with_name('reproduce-kernel-stock-no-proof.py'))
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        source=module.diagnostic_driver(ROOT) if instrumented else module.acceptance_driver(ROOT)
        overlays=module.OVERLAYS if instrumented else module.ACCEPTANCE_OVERLAYS
        if mutate:
            marker="    run('inventory-controls',"
            self.assertEqual(source.count(marker),1)
            source=source.replace(marker,
                f"    path=fixture/{module.RUNNER!r}; text=path.read_text()\n"
                f"    path.write_text(text.replace({module.NATIVE!r},{module.OLD!r}))\n"+marker)
        tree=ast.parse(source)
        body=next(node.body for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
        # Replay the actual generated composition and both scanner transitions.
        # Builds and kernel suites are observed, never executed by this control.
        start=next(i for i,node in enumerate(body) if isinstance(node,ast.For)
                   and isinstance(node.iter,ast.List) and ast.literal_eval(node.iter)==overlays)
        with tempfile.TemporaryDirectory(prefix='other-provers-composition-',dir='/private/tmp') as directory:
            root=Path(directory); fixture=root/'fixture'; fixture.mkdir()
            attribution=module.attribution_module()
            for relative in overlays+[module.LIVE_GUARD,module.TEST,'tools/apnt-pool-action-circuit/cmd/pool-pk-load/main.go']+module.ACCEPTANCE_PATHS+[path for path in attribution.PATHS if path!=attribution.GO_TRACE]:
                path=fixture/relative; path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(subprocess.check_output(['/usr/bin/git','show',module.RUNTIME_SOURCE+':'+relative],
                                 cwd=ROOT,stderr=subprocess.DEVNULL) if relative not in overlays
                                 else (ROOT/relative).read_bytes())
            summary={'composition':[], 'commands':[{'exit':0}]}; calls=[]; inventories=[]; phases={}
            self.composition_sources={};self.composition_test_sources={}
            self.composition_inventories=inventories
            self.composition_inventory_stderr=b'';self.composition_calls=calls
            def run_step(label,args,cwd=fixture):
                calls.append(label)
                if label=='observer-build':
                    # Composition replay does not execute a compiler. Supply
                    # only its synthetic artifact for the new digest hop.
                    artifact=root/'artifacts/macos-observer';artifact.parent.mkdir(exist_ok=True)
                    artifact.write_bytes(b'synthetic observer build artifact')
                if label=='descriptor-observer-controls':
                    self.assertEqual((args,cwd),(['/usr/bin/python3',module.OBSERVER_TEST],ROOT))
                if label=='continuation-observer-controls':
                    self.assertEqual((args,cwd),(['/usr/bin/python3',module.CONTINUATION_TEST],ROOT))
                if label=='reproduction-controls':
                    self.assertEqual(cwd,ROOT)
                    self.assertEqual(args,['/usr/bin/python3',str(RUNNER.relative_to(ROOT)).replace('measure-pk-load.sh','test-native-process-scan.py'),'ReproductionSelection'])
                if label=='native-scan-controls':
                    self.assertEqual(args[-2:],['--host','NativeScan'])
                if label=='live-scan-controls':
                    self.assertEqual((args,cwd),(['/usr/bin/python3',module.LIVE_TEST],ROOT))
                if label=='inventory-controls':
                    self.assertEqual(args,['/usr/bin/python3',module.RUNNER.replace('measure-pk-load.sh','test-prove-memory-floors.py'),'ProverInventory'])
                    self.assertEqual(cwd,root/'inventory-controls')
                    inputs=module.INVENTORY_FIXTURE_INPUTS+module.INVENTORY_CONTROL_INPUTS
                    self.assertEqual([row['path'] for row in summary['inventoryControlInputs']],inputs)
                    self.assertEqual({str(path.relative_to(cwd)) for path in cwd.rglob('*') if path.is_file()},set(inputs))
                    for row in summary['inventoryControlInputs']:
                        origin=fixture if row['path'] in module.INVENTORY_FIXTURE_INPUTS else ROOT
                        raw=(cwd/row['path']).read_bytes()
                        self.assertEqual(raw,(origin/row['path']).read_bytes())
                        self.assertEqual(row['sha256'],hashlib.sha256(raw).hexdigest())
                    removed=None
                    if missing_inventory_input is not None:
                        self.assertIn(missing_inventory_input,module.INVENTORY_CONTROL_INPUTS)
                        removed=(cwd/missing_inventory_input).read_bytes()
                        (cwd/missing_inventory_input).unlink()
                    try:
                        result=subprocess.run(args,cwd=cwd,capture_output=True,timeout=30)
                    finally:
                        if removed is not None:(cwd/missing_inventory_input).write_bytes(removed)
                    self.composition_inventory_stderr=result.stderr
                    text=(cwd/module.RUNNER).read_text()
                    inventories.append({'exit':result.returncode,'native':text.count(module.NATIVE),'old':text.count(module.OLD),
                                        'elevenTests':b'Ran 11 tests' in result.stderr})
                    module.require(result.returncode==0)
            def suite(label,files,selection,want=0):
                calls.append(label)
                self.assertEqual((files,selection,want),([module.TEST],'^'+module.NAME+'$',None if label in ('kernel-fixed','kernel-quiet-diagnostic') else 1))
                summary['commands'].append({'exit':int(fixed_failure and label=='kernel-fixed')})
                phases[label]=(fixture/module.RUNNER).read_bytes()
                self.composition_sources[label]={path:(fixture/path).read_bytes() for path in module.ACCEPTANCE_PATHS+[
                    module.RUNNER,module.LIVE_GUARD,'tools/apnt-pool-action-circuit/cmd/pool-pk-load/main.go',
                    'tools/pool-action-modules/private-runner-process.c',module.OBSERVER]}
                self.composition_test_sources[label]=(fixture/module.TEST).read_text()
                for row in summary['composition'][label]:
                    self.assertEqual(row['sha256'],hashlib.sha256((fixture/row['path']).read_bytes()).hexdigest())
            namespace={'__file__':str(ROOT/module.DRIVER),'__name__':'composition_control',
                       'quiet_return_diagnostic':module.quiet_return_diagnostic,'instrument_attribution':attribution.instrument,
                       'instrument_live':attribution.extended().live_hooks}
            exec(compile(tree,'generated-driver','exec'),namespace)
            (root/'artifacts').mkdir()
            namespace.update(fixture=fixture,root=root,summary=summary,env={},artifacts=root/'artifacts',
                             run=run_step,suite=suite,commit=lambda label:calls.append('commit-'+label))
            def fixture_head(args,*,cwd,env):
                self.assertEqual((args,cwd),(['/usr/bin/git','rev-parse','HEAD'],fixture))
                return b'synthetic-fixture-head\n'
            with patch.object(subprocess,'check_output',side_effect=fixture_head) as checkout:
                exec(compile(ast.Module(body=body[start:],type_ignores=[]),'composition-replay','exec'),namespace)
                self.assertEqual(checkout.call_count,1)
            return module,summary,calls,inventories,phases

    def check_each_missing_rss_control_input_refuses_both_compositions(self):
        pin='tools/pool-action-modules/test/private-runner-result.test.ts'
        attribution='tools/apnt-pool-action-circuit/scripts/kernel-attribution.py'
        capture='tools/apnt-pool-action-circuit/scripts/kernel-attribution-capture.py'
        for instrumented in (True,False):
            self.replay_composition(instrumented=instrumented)
            for path,check in ((pin,'check_summary_refuses_missing_and_receipt_tail_pin_is_unchanged'),
                               (attribution,'check_attribution_refuses_missing_validity_and_mutation'),
                               (capture,'check_attribution_refuses_missing_validity_and_mutation')):
                with self.subTest(instrumented=instrumented,missing=path):
                    with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
                        self.replay_composition(instrumented=instrumented,missing_inventory_input=path)
                    self.assertEqual(self.composition_inventories,[{'exit':1,'native':1,'old':0,'elevenTests':True}])
                    error=self.composition_inventory_stderr.decode()
                    self.assertIn("(rss_consumer='"+check+"')",error)
                    self.assertIn('FileNotFoundError: [Errno 2]',error)
                    self.assertIn('/inventory-controls/'+path,error)
                    self.assertIn('FAILED (errors=1)',error)
                    self.assertNotIn('commit-composition',self.composition_calls)
                    self.assertFalse(self.composition_sources)
                    self.replay_composition(instrumented=instrumented)
                    print('inventory-missing-input-oracle='+json.dumps({'instrumented':instrumented,'input':path,
                        'control':'MissingRSSControls.'+check,'statuses':[0,1,0],'productionStagesDuringRefusal':0}))

    def test_deselected_statuses_and_count_negatives_fire(self):
        spec=importlib.util.spec_from_file_location('reproduction',RUNNER.with_name('reproduce-kernel-stock-no-proof.py'))
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.assertEqual(module.NAME,'PH11-X-PROD/P0 genuine kernel stock runner reaches P/A/W and writes its check-live result then fails closed before the summary')
        inventory=json.loads(RUNNER.with_name('mig01-runtime-selection.json').read_bytes())['rows']
        self.assertEqual([row['selection'] for row in inventory if row['title']==module.NAME],['ordinary'])
        for status in ('passed','failed'):
            for deselected in ('skipped','pending'):
                value={'testResults':[{'assertionResults':[{'status':status,'fullName':module.NAME}]+[{'status':deselected,'fullName':title} for title in self.runtime_titles(module) if title!=module.NAME]}],
                       'numPassedTests':int(status=='passed'),'numFailedTests':int(status=='failed'),'numPendingTests':118}
                self.assertEqual(module.selected_execution(value,status),{'executed':1,'passed':int(status=='passed'),'failed':int(status=='failed'),'deselected':118})
                # Negative controls reach the changed total/name guard: stale
                # 117/116, duplicate and unknown deselections all refuse.
                import copy
                for kind in ('old-total','duplicate','unknown'):
                    bad=copy.deepcopy(value);rows=bad['testResults'][0]['assertionResults']
                    if kind=='old-total': del rows[-2:];bad['numPendingTests']=116
                    elif kind=='duplicate': rows[-1]['fullName']=rows[-2]['fullName']
                    else: rows[-1]['fullName']='unreviewed-row'
                    with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):module.selected_execution(bad,status)
                self.assertEqual(module.selected_execution(value,status)['deselected'],118)
                value['testResults'][0]['assertionResults'][-1]['status']='passed'
                with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
                    module.selected_execution(value,status)

    def test_generated_host_driver_keeps_composition_and_one_test_selection(self):
        spec=importlib.util.spec_from_file_location('reproduction',RUNNER.with_name('reproduce-kernel-stock-no-proof.py'))
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        source=module.diagnostic_driver(ROOT)
        compile(source,'closed-host-driver','exec')
        self.assertLess(source.index('for relative in '+repr(module.OVERLAYS)),source.index("edits = [(PREFIX+"))
        self.assertEqual(source.count("suite('kernel-old',[TEST]"),1)
        self.assertEqual(source.count("suite('kernel-fixed',[TEST]"),1)
        self.assertEqual(source.count("suite('kernel-post-w-old',[TEST]"),1)
        self.assertIn("if row['status'] in ('passed','failed')",source)

    def test_composed_fixture_controls_and_final_phase_receipts(self):
        module,summary,calls,inventories,phases=self.replay_composition()
        self.assertEqual(inventories,[{'exit':0,'native':1,'old':0,'elevenTests':True}])
        self.assertLess(calls.index('inventory-controls'),calls.index('commit-composition'))
        self.assertLess(calls.index('continuation-observer-controls'),calls.index('commit-composition'))
        self.assertLess(calls.index('commit-composition'),calls.index('installation-build'))
        self.assertLess(calls.index('installation-build'),calls.index('kernel-old'))
        self.assertLess(calls.index('commit-fixed-scan'),calls.index('installation-fixed-build'))
        self.assertLess(calls.index('installation-fixed-build'),calls.index('kernel-fixed'))
        self.assertLess(calls.index('installation-fixed-build'),calls.index('kernel-post-w-old'))
        self.assertLess(calls.index('kernel-post-w-old'),calls.index('commit-fixed-live-scan'))
        self.assertLess(calls.index('commit-fixed-live-scan'),calls.index('installation-fixed-live-build'))
        self.assertLess(calls.index('installation-fixed-live-build'),calls.index('kernel-fixed'))
        manifests=summary['composition']
        self.assertEqual(set(manifests),{'inventory-controls','kernel-old','kernel-post-w-old','kernel-fixed'})
        for phase,rows in manifests.items():
            extra=module.attribution_module().PATHS if phase!='inventory-controls' else []
            self.assertEqual(len(rows),len(module.OVERLAYS)+3+len(extra))
            self.assertEqual({r['path'] for r in rows},set(module.OVERLAYS+[module.LIVE_GUARD,module.TEST,'tools/apnt-pool-action-circuit/cmd/pool-pk-load/main.go']+extra))
        self.assertEqual(summary['descriptorObserverBuild'],{'sourceSha256':hashlib.sha256((ROOT/module.OBSERVER).read_bytes()).hexdigest(),
                         'binarySha256':hashlib.sha256(b'synthetic observer build artifact').hexdigest()})
        self.assertEqual(phases['kernel-fixed'],phases['kernel-post-w-old'])
        self.assertEqual(phases['kernel-old'],phases['kernel-fixed'].replace(module.NATIVE.encode(),module.OLD.encode()))
        self.assertIn(b'readonly PRIVATE_RUNNER_GENERATION=2',phases['kernel-fixed'])
        # Attribution is added only after the inventory controls ran on their
        # original fixture bytes. Do not relabel those controls as instrumented.
        initial={row['path']:row['sha256'] for row in manifests['inventory-controls']}
        post={row['path']:row['sha256'] for row in manifests['kernel-post-w-old']}
        self.assertEqual({path for path in initial if initial[path]!=post[path]},
                         {module.RUNNER,module.TEST,module.LIVE_GUARD,'tools/pool-action-modules/private-runner-process.c','tools/apnt-pool-action-circuit/cmd/pool-pk-load/main.go'})
        self.assertEqual([a['path'] for a,b in zip(manifests['kernel-old'],manifests['kernel-post-w-old']) if a!=b],[module.RUNNER])
        self.assertEqual([a['path'] for a,b in zip(manifests['kernel-post-w-old'],manifests['kernel-fixed']) if a!=b],[module.LIVE_GUARD])
        self.check_each_missing_rss_control_input_refuses_both_compositions()

    def test_mutating_dispatch_before_inventory_fires_regression(self):
        with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
            self.replay_composition(mutate=True)
        self.assertEqual(self.composition_inventories,[{'exit':1,'native':0,'old':1,'elevenTests':True}])

    def test_failed_candidate_is_preserved_before_distinct_quiet_diagnostic(self):
        module,summary,calls,_,phases=self.replay_composition(fixed_failure=True)
        self.assertLess(calls.index('kernel-fixed'),calls.index('commit-quiet-diagnostic'))
        self.assertLess(calls.index('commit-quiet-diagnostic'),calls.index('installation-quiet-diagnostic-build'))
        self.assertLess(calls.index('installation-quiet-diagnostic-build'),calls.index('kernel-quiet-diagnostic'))
        original=summary['composition']['kernel-fixed']; diagnostic=summary['composition']['kernel-quiet-diagnostic']
        self.assertEqual([a['path'] for a,b in zip(original,diagnostic) if a!=b],
                         ['tools/apnt-pool-action-circuit/cmd/pool-pk-load/main.go'])
        self.assertEqual(phases['kernel-fixed'],phases['kernel-quiet-diagnostic'])

    def test_each_composed_stage_executes_the_intended_scan_dispatch(self):
        module,_,_,_,phases=self.replay_composition(fixed_failure=True)
        for label,source in phases.items():
            self.assertEqual(module.scan_dispatch(source.decode()),'ps' if label=='kernel-old' else 'native')
        with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
            module.scan_dispatch(phases['kernel-fixed'].decode().replace('readonly PRIVATE_RUNNER_GENERATION=2',
                                                                       'readonly PRIVATE_RUNNER_GENERATION=1'))

    def test_runtime_snapshot_binds_committed_sources_installed_bytes_and_stage(self):
        spec=importlib.util.spec_from_file_location('reproduction',RUNNER.with_name('reproduce-kernel-stock-no-proof.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix='other-provers-stage-',dir='/private/tmp') as directory:
            root=Path(directory)
            texts={module.RUNNER:RUNNER.read_text().replace('readonly PRIVATE_RUNNER_GENERATION=1','readonly PRIVATE_RUNNER_GENERATION=2'),
                   module.LIVE_GUARD:(ROOT/module.LIVE_GUARD).read_text(),
                   'tools/apnt-pool-action-circuit/cmd/pool-pk-load/main.go':(ROOT/'tools/apnt-pool-action-circuit/cmd/pool-pk-load/main.go').read_text().replace('result := run(os.Args, runDeps{','result := runV2(os.Args, runDeps{'),
                   'tools/pool-action-modules/synthetic.mjs':'// synthetic installation source\n',
                   '.gitignore':'dist/\n'}
            for path,text in texts.items():
                target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
            for args in (['init','-b','main'],['add','.'],['-c','user.name=Fixture','-c','user.email=fixture@invalid','-c','commit.gpgsign=false','commit','-m','Synthetic source']):
                self.assertEqual(run('/usr/bin/git',*args,cwd=root).returncode,0)
            revision=run('/usr/bin/git','rev-parse','HEAD',cwd=root).stdout.decode().strip()
            reader=root/'tools/pool-action-modules/dist/private-runner-process';reader.parent.mkdir();reader.write_bytes(b'synthetic installed executable');reader.chmod(0o700)
            entries=[{'path':path,'sha256':hashlib.sha256((root/path).read_bytes()).hexdigest()} for path in
                     ('tools/pool-action-modules/synthetic.mjs','tools/pool-action-modules/dist/private-runner-process')]
            record={'schema':'private-runner-installation-record-v1','revision':revision,'entries':entries}
            receipt=reader.parent/'private-runner-installation.json';receipt.write_text(json.dumps(record))
            composition=[{'path':path,'sha256':hashlib.sha256((root/path).read_bytes()).hexdigest()} for path in texts if path!='.gitignore']
            observed=module.stage_runtime(root,'kernel-fixed',composition)
            self.assertEqual(set(observed),{'revision','shellDispatch','childDispatch','goSources','installedClosure'})
            self.assertEqual((observed['revision'],observed['shellDispatch'],observed['childDispatch'],observed['installedClosure']),
                             (revision,'native','native',entries))
            self.assertEqual(len(observed['goSources']),2)
            for bad in ({**record,'revision':'00'*20},{**record,'entries':entries+entries},
                        {**record,'entries':[dict(entries[0],extra=True),entries[1]]},
                        {**record,'entries':[dict(entries[0],path='../outside'),entries[1]]},
                        {**record,'entries':[dict(entries[0],sha256='SYNTHETIC_PRIVATE_TEXT_CANARY'),entries[1]]}):
                receipt.write_text(json.dumps(bad))
                with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
                    module.stage_runtime(root,'kernel-fixed',composition)
            receipt.write_text(json.dumps(record))
            reader.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
                module.stage_runtime(root,'kernel-fixed',composition)
            reader.chmod(0o700)
            corrupted=[dict(row,sha256='00'*32) if row['path']==module.RUNNER else row for row in composition]
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
                module.stage_runtime(root,'kernel-fixed',corrupted)
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
                module.stage_runtime(root,'kernel-old',composition)
            original=Path(module.__file__).read_text()
            # Independent scratch function mutations must make the same exact
            # refusal predicates fail, then the untouched function must refuse.
            for before,argument,stage in (
                ("require(hashlib.sha256((fixture/row['path']).read_bytes()).hexdigest() == row['sha256'])",corrupted,'kernel-fixed'),
                ("require(shell == ('ps' if stage == 'kernel-old' else 'native'))",composition,'kernel-fixed')):
                namespace={'__name__':'scratch_snapshot','__file__':module.__file__}
                exec(compile(original.replace(before,'require(True)',1),'scratch-snapshot','exec'),namespace)
                if argument is composition:
                    namespace['scan_dispatch']=lambda source:'ps'
                    self.assertEqual(namespace['stage_runtime'](root,stage,argument)['shellDispatch'],'ps')
                    with patch.object(module,'scan_dispatch',return_value='ps'):
                        with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
                            module.stage_runtime(root,stage,argument)
                else:
                    self.assertEqual(namespace['stage_runtime'](root,stage,argument)['shellDispatch'],'native')
                    with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
                        module.stage_runtime(root,stage,argument)
            self.assertEqual(module.stage_runtime(root,'kernel-fixed',composition),observed)
            # Execute the actual generated suite, including its snapshot hop;
            # only the host Vitest subprocess is replaced by a count-controlled
            # JSON result. This is routing evidence, not a kernel measurement.
            tree=ast.parse(module.diagnostic_driver(ROOT))
            body=next(node.body for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
            suite_node=next(node for node in body if isinstance(node,ast.FunctionDef) and node.name=='suite')
            suite_source=ast.unparse(suite_node)
            hook=next(line for line in suite_source.splitlines() if ' = stage_runtime(' in line)
            raw=reader.parent/'raw';raw.mkdir()
            for mutate in (False,True,False):
                calls=[];summary={'composition':{'kernel-fixed':composition},'stageRuntime':{},'suites':[]}
                def snapshot(*args):
                    calls.append('snapshot')
                    self.assertEqual(args,(root,'kernel-fixed',composition))
                    return module.stage_runtime(*args)
                def execute(label,args,want=None):
                    calls.append('suite')
                    self.assertEqual((label,want),('kernel-fixed',None))
                    self.assertEqual(args[-2:],['-t','^'+module.NAME+'$'])
                    rows=[{'fullName':module.NAME,'status':'failed'}]+[{'fullName':title,'status':'skipped'} for title in self.runtime_titles(module) if title!=module.NAME]
                    (raw/(label+'.json')).write_text(json.dumps({'testResults':[{'assertionResults':rows}],
                        'numPassedTests':0,'numFailedTests':1,'numPendingTests':118,'success':False}))
                    return 1
                namespace={'root':reader.parent,'raw':raw,'fixture':root,'NODE':Path(module.NODE),'TEST':module.TEST,
                           'summary':summary,'stage_runtime':snapshot,'run':execute,'require':module.require,'json':json}
                code=suite_source.replace(hook,'') if mutate else suite_source
                exec(compile(code,'generated-suite-unit','exec'),namespace)
                namespace['suite']('kernel-fixed',[module.TEST],'^'+module.NAME+'$',want=None)
                self.assertEqual(calls,['suite'] if mutate else ['snapshot','suite'])
                self.assertEqual(bool(summary['stageRuntime']),not mutate)
                if not mutate:self.assertEqual(summary['stageRuntime']['kernel-fixed'],observed)


if __name__ == '__main__':
    if HOST:
        # One capability check; a denied nested Seatbelt stops this supplement
        # without repeatedly probing the denied operation in each method.
        capability=run('/usr/bin/sandbox-exec','-p','(version 1) (allow default)','/usr/bin/true',timeout=5)
        if capability.returncode:
            print('native-host-unavailable='+json.dumps({'status':capability.returncode,
                  'stdoutBytes':len(capability.stdout),'stderrBytes':len(capability.stderr)}))
            sys.exit(77)
    unittest.main()
