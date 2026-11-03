#!/usr/bin/python3
"""Source-only hooks for the disposable, explicitly instrumented composition.

No hook changes a production guard, query, diagnostic stream or assertion.
Caller context selects only a finite trace label, never reader behavior.
"""
import json


def change(source,before,after):
    if source.count(before)!=1:raise RuntimeError('kernel-attribution-refused')
    return source.replace(before,after)


def shell_hooks(source,path):
    quoted="'"+str(path).replace("'","'\"'\"'")+"'"
    branches='baseline|launch|monitor-healthy|monitor-unavailable|monitor-swap|monitor-rss|signal|wait|result-present|result-absent|sample-enter|sample-return'
    source=change(source,'|die-native-result) ;;', '|die-native-result|'+branches+') ;;')
    helper='''
eng1436_event() {
 case "$1:$2" in
  reader-quiet-start:call-*|reader-quiet-case:call-*|reader-rss-initial:call-*|reader-rss-periodic:call-*|reader-rss-final:call-*) ;;
  finish:cleanup|finish:collector-wait|finish:reason-read|finish:reason-remove|finish:stream-remove|finish:directory-remove|finish:complete) ;;
  classification:*) case "$2" in CLASSIFICATIONS) ;; *) return 0;; esac ;;
  *) return 0;;
 esac
 [[ $3 =~ ^-?[0-9]+$ ]] || return 0
 [[ -f TRACE && ! -L TRACE ]] || return 0
 printf '{"producer":"%s","branch":"%s","status":%d,"errno":0,"auxStatus":0}\\n' "$1" "$2" "$3" >>TRACE 2>/dev/null || :
}
eng1436_number() {
 case "$1" in swap-baseline|rss-initial-*|rss-periodic-*|rss-final-*) ;; *) return 0;; esac
 [[ $2 =~ ^[0-9]+$ && $3 =~ ^-?[0-9]+$ ]] || return 0
 [[ -f TRACE && ! -L TRACE ]] || return 0
 printf '{"producer":"number","branch":"%s","status":%d,"errno":0,"auxStatus":0,"value":%d}\\n' "$1" "$2" "$3" >>TRACE 2>/dev/null || :
}
'''
    # Fixed source allowlist, never labels derived from private bytes.
    import ast
    mapping=ast.literal_eval(source.split('codes = ',1)[1].split('\nlimit =',1)[0])
    helper=helper.replace('CLASSIFICATIONS','|'.join(sorted(set(mapping.values())|{'unclassified'}))).replace('TRACE',quoted)
    source=change(source,'eng1436_trace entry 0',helper+'\neng1436_trace entry 0')
    # The inventory lives in the operation-independent exclusivity guard;
    # the proving-only wrapper adds memory admission without another scan.
    source=change(source,'local phase=$1 others inventory_status=0',
                  'local phase=$1 others inventory_status=0\n local eng1436_scan_role=quiet-case\n [[ $phase != start ]] || eng1436_scan_role=quiet-start')
    # C1 (GO) removed the generation branch around this call, leaving it one space deep.
    source=change(source,' "$repo/tools/pool-action-modules/dist/private-runner-process" "$@"',
        '''  local eng1436_reader_status=0
  if declare -F eng1436_event >/dev/null; then eng1436_event "reader-${eng1436_scan_role:-unknown}" call-start 0; fi
  ENG1436_DIAGNOSTIC_ROLE="${eng1436_scan_role:-unknown}" "$repo/tools/pool-action-modules/dist/private-runner-process" "$@" || eng1436_reader_status=$?
  if declare -F eng1436_event >/dev/null; then eng1436_event "reader-${eng1436_scan_role:-unknown}" call-end "$eng1436_reader_status"; fi
  return "$eng1436_reader_status"''')
    source=change(source,'\tlocal swap avail rss\n','\tlocal swap avail rss eng1436_swap_status=0 eng1436_available_status=0 eng1436_rss_status=0\n local eng1436_scan_role=${eng1436_sample_role:-unknown}\n eng1436_trace sample-enter 0\n')
    source=change(source,'echo "$swap $avail $rss"','echo "$swap $avail $rss"\n eng1436_trace sample-return 0')
    for variable,call,status in [('swap','swap_used_bytes','swap'),('avail','available_bytes','available'),('rss','phase_rss_bytes','rss')]:
        source=change(source,f'{variable}="$({call})" || {variable}=-1',
                      f'{variable}="$({call})" || {{ eng1436_{status}_status=$?; {variable}=-1; }}')
    before='\tprintf \'%s\\t%s\\t%s\\t%s\\n\' "$(/bin/date +%s)" "$swap" "$avail" "$rss"'
    source=change(source,before,''' eng1436_number "${eng1436_sample_role:-unknown}-swap" "$eng1436_swap_status" "$swap"
 eng1436_number "${eng1436_sample_role:-unknown}-available" "$eng1436_available_status" "$avail"
 eng1436_number "${eng1436_sample_role:-unknown}-rss" "$eng1436_rss_status" "$rss"
'''+before)
    source=change(source,'swap0="$(swap_used_bytes)" || die "$name: vm.swapusage unreadable"',
        '''local eng1436_baseline_status=0
 swap0="$(swap_used_bytes)" || eng1436_baseline_status=$?
 eng1436_trace baseline "$eng1436_baseline_status"
 if ((eng1436_baseline_status==0)); then eng1436_number swap-baseline 0 "$swap0"; else eng1436_number swap-baseline "$eng1436_baseline_status" -1; fi
 ((eng1436_baseline_status==0)) || die "$name: vm.swapusage unreadable"''')
    # Position labels do not change which samples execute, their order or output.
    if source.count('sample "$samples" >/dev/null')!=2:raise RuntimeError('kernel-attribution-refused')
    source=source.replace('sample "$samples" >/dev/null','eng1436_sample_role=rss-initial sample "$samples" >/dev/null',1)
    source=source.replace('\n\tsample "$samples" >/dev/null','\n\teng1436_sample_role=rss-final sample "$samples" >/dev/null',1)
    source=change(source,'$(sample "$samples")','$(eng1436_sample_role=rss-periodic sample "$samples")')
    source=change(source,'\tpid=$!\n','\tpid=$!\n eng1436_trace launch 0\n')
    source=change(source,'tripped="resource monitor unavailable"','eng1436_trace monitor-unavailable 1\n   tripped="resource monitor unavailable"')
    source=change(source,'tripped="swap grew ', 'eng1436_trace monitor-swap 1\n   tripped="swap grew ')
    source=change(source,'tripped="case RSS ', 'eng1436_trace monitor-rss 1\n   tripped="case RSS ')
    source=change(source,'\t\tif [[ -n $tripped ]]; then','\t\t[[ -n $tripped ]] || eng1436_trace monitor-healthy 0\n\t\tif [[ -n $tripped ]]; then')
    source=change(source,'/usr/bin/pkill -TERM -x pool-pk-load || true',
                  'local eng1436_signal_status=0\n   /usr/bin/pkill -TERM -x pool-pk-load || eng1436_signal_status=$?\n   eng1436_trace signal "$eng1436_signal_status"')
    source=change(source,'\twait "$pid" || status=$?', '\twait "$pid" || status=$?\n eng1436_trace wait "$status"\n if [[ -f "$results/$name.json" ]]; then eng1436_trace result-present 0; else eng1436_trace result-absent 1; fi')
    source=change(source,' cleanup || status=1',
                  ' local eng1436_finish_status=0\n cleanup || eng1436_finish_status=$?\n eng1436_event finish cleanup "$eng1436_finish_status"\n ((eng1436_finish_status==0)) || status=1')
    for original,branch in [('wait "$private_runner_diagnostic_pid"','collector-wait'),
        ('IFS= read -r reason <"$private_runner_diagnostic_file"','reason-read'),
        ('/bin/rm -f "$private_runner_diagnostic_file"','reason-remove'),
        ('/bin/rm -f "$private_runner_diagnostic_file.stream"','stream-remove'),
        ('/bin/rmdir "${private_runner_diagnostic_file%/*}"','directory-remove')]:
        source=change(source,original+' || status=1',
            'eng1436_finish_status=0\n  '+original+' || eng1436_finish_status=$?\n  eng1436_event finish '+branch+' "$eng1436_finish_status"\n  ((eng1436_finish_status==0)) || status=1')
    source=change(source,' if ((status != 0)); then',
        ' eng1436_event classification "$reason" 0\n eng1436_event finish complete "$status"\n if ((status != 0)); then')
    return source


def reader_hooks(source,path,branches):
    source=change(source,'if (sysctl(mib, 2, &capacity, &size, NULL, 0) != 0 || size != sizeof(capacity) ||\n        capacity < (int)sizeof(int) || capacity > 16 * 1024 * 1024) return 1;',
        'int capacity_status=sysctl(mib,2,&capacity,&size,NULL,0);int capacity_error=errno;\n    if(capacity_status!=0 || size!=sizeof(capacity) || capacity<(int)sizeof(int) || capacity>16*1024*1024)return closed_fail(capacity_status?"argmax-query":"argmax-shape",capacity_status?capacity_error:0,1);')
    source=change(source,'if (!bytes) return 1;','if (!bytes) return closed_fail("arguments-allocation",errno,1);')
    source=change(source,'if (process(pid, &value) != 1) return 1;',
                  'int query_errno=0;\n    if (process_query(pid, &value,&query_errno) != 1) return closed_fail("ancestry-process",query_errno,1);')
    source=change(source,'if ((!strcmp(field, "comm=") || both) && !path_of(pid, path, sizeof(path))) return 1;',
                  'if ((!strcmp(field, "comm=") || both) && !path_of(pid, path, sizeof(path))) return closed_fail("ancestry-path",errno,1);')
    # Existing ancestry query already returns failure quietly. Attribute that
    # query without issuing a confirmation/retry that its contract lacks.
    before='if (sysctl(query, 3, bytes, &size, NULL, 0) != 0 || size <= sizeof(argc) || size > (size_t)capacity) goto done;'
    after='int query_status=sysctl(query,3,bytes,&size,NULL,0);int query_error=errno;\n    if(query_status!=0 || size<=sizeof(argc) || size>(size_t)capacity){closed_fail(query_status?"arguments-query":"arguments-size",query_status?query_error:0,1);goto done;}'
    source=change(source,before,after)
    source=change(source,'    return result;\n}\n\nstatic int single(',
                  '    if(result && !strcmp(closed_reason,"unclassified"))closed_fail("ancestry-arguments",0,1);\n    return result;\n}\n\nstatic int single(')
    source=change(source,'int main(int argc, char **argv) {','static int eng1436_recorded;\nstatic void eng1436_record(int status);\nstatic int eng1436_original_main(int argc, char **argv) {')
    source=change(source,'int status = global_scan(rss);','int status = global_scan(rss);\n        eng1436_record(status);')
    # No second process query, stdout/stderr redirection, or PID capture.
    prefix='\n#include <fcntl.h>\n#include <sys/stat.h>\n'
    allowed=' || '.join('!strcmp(role,'+json.dumps(name)+')' for name in ('quiet-start','quiet-case','rss-initial','rss-periodic','rss-final','ancestry','post-w-child'))
    reasons=' || '.join('!strcmp(reason,'+json.dumps(name)+')' for name in branches['native-scan'] if not name.startswith('arguments-query-'))
    return source+prefix+'''
static void eng1436_record(int status) {
 if(eng1436_recorded)return;
 eng1436_recorded=1;
 int saved_errno=errno;
 const char *role=getenv("ENG1436_DIAGNOSTIC_ROLE");
 if (!role || !(ROLES)) {errno=saved_errno;return;}
 const char *reason=status ? closed_reason : "complete";
 if(status && !(REASONS))reason="unclassified";
 char branch[96];int error=status?closed_errno:0,aux=0;
 if(status && !strcmp(reason,"arguments-query") && closed_confirmation) {
  if(strcmp(closed_confirmation,"live") && strcmp(closed_confirmation,"unconfirmed") && strcmp(closed_confirmation,"query-error")){errno=saved_errno;return;}
  snprintf(branch,sizeof(branch),"arguments-query-%s",closed_confirmation);
  reason=branch;aux=closed_confirmation_errno;
 }
 if(error<0 || error>4095 || aux<0 || aux>4095 || status<0 || status>255){errno=saved_errno;return;}
 char row[384];int size=snprintf(row,sizeof(row),"{\\"producer\\":\\"reader-%s\\",\\"branch\\":\\"%s\\",\\"status\\":%d,\\"errno\\":%d,\\"auxStatus\\":%d}\\n",role,reason,status,error,aux);
 if(size>0 && size<(int)sizeof(row)) {
  int fd=open(TRACE,O_WRONLY|O_APPEND|O_NOFOLLOW|O_CLOEXEC);
  if(fd>=0){struct stat st;if(!fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_uid==geteuid() && st.st_nlink==1 && (st.st_mode&0777)==0600 && st.st_size+size<=1048576){ssize_t written=write(fd,row,(size_t)size);(void)written;}close(fd);}
 }
 errno=saved_errno;
}
int main(int argc,char **argv){int status=eng1436_original_main(argc,argv);eng1436_record(status);return status;}
'''.replace('ROLES',allowed).replace('REASONS',reasons).replace('TRACE',json.dumps(str(path)))


def go_role_writer():
    return '''
func diagnosticReader(command *exec.Cmd){
 branch:=diagnosticHelper(command)
 if branch=="reader-parent" || branch=="reader-arguments" {
  environment:=command.Env;if environment==nil{environment=os.Environ()}
  command.Env=append(environment,"ENG1436_DIAGNOSTIC_ROLE=ancestry")
  Diagnostic("reader-ancestry","call-start",0)
 }
}
func diagnosticReaderEnd(command *exec.Cmd,err error){branch:=diagnosticHelper(command);if branch=="reader-parent" || branch=="reader-arguments"{Diagnostic("reader-ancestry","call-end",DiagnosticStatus(err))}}
'''


def live_hooks(source):
    reader='reader' if 'func liveQuietMachine(reader string)' in source else '"/bin/ps"'
    return change(source,'b, err := exec.Command('+reader+', "-axo", "pid=,comm=").Output()',
        'command := exec.Command('+reader+', "-axo", "pid=,comm=")\n command.Env=append(os.Environ(),"ENG1436_DIAGNOSTIC_ROLE=post-w-child")\n runneradmission.Diagnostic("reader-post-w-child","call-start",0)\n b, err := command.Output()\n runneradmission.Diagnostic("reader-post-w-child","call-end",runneradmission.DiagnosticStatus(err))')


def bridge_hooks(source):
    before='defer func(){Diagnostic("helper",diagnosticHelper(command),DiagnosticStatus(failure))}()'
    if source.count(before)!=2:raise RuntimeError('kernel-attribution-refused')
    source=source.replace(before,'diagnosticReader(command)\n defer func(){diagnosticReaderEnd(command,failure);Diagnostic("helper",diagnosticHelper(command),DiagnosticStatus(failure))}()',1)
    source=change(source,'branch:="fixed-invocation"','Diagnostic("bridge","entry",0)\n branch:="fixed-invocation"')
    source=change(source,'if err != nil || readErr != nil || !bytes.Equal(actual, committed) {',
                  'if err != nil || readErr != nil || !bytes.Equal(actual, committed) {\n Diagnostic("bridge","verify-source",1)')
    source=change(source,'check := exec.Command("/usr/bin/python3",',
                  'Diagnostic("bridge","verify-source",0)\n check := exec.Command("/usr/bin/python3",')
    source=change(source,'if err != nil || string(output) != nodeVersion+"\\n" {',
                  'if err != nil || string(output) != nodeVersion+"\\n" {\n Diagnostic("bridge","node-version",1)')
    # Record actual operation exits as well as deferred first failure class.
    source=change(source,'raw, err := io.ReadAll(io.LimitReader(parent, (1<<20)+(64<<10)+9))',
        'raw, err := io.ReadAll(io.LimitReader(parent, (1<<20)+(64<<10)+9))\n Diagnostic("bridge","read",DiagnosticStatus(err))')
    source=change(source,'waitErr := command.Wait()', 'waitErr := command.Wait()\n Diagnostic("bridge","wait",DiagnosticStatus(waitErr))')
    source=change(source,'output, err := helperOutput(version)', 'output, err := helperOutput(version)\n Diagnostic("bridge","node-version",DiagnosticStatus(err))')
    source=change(source,'if helperRun(check) != nil {', 'if failure:=helperRun(check);failure != nil {\n Diagnostic("bridge","verify-installation",DiagnosticStatus(failure))')
    source=change(source,'version := exec.Command(nodePath, "--version")', 'Diagnostic("bridge","verify-installation",0)\n version := exec.Command(nodePath, "--version")')
    return source
