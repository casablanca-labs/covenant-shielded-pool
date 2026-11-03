#!/usr/bin/python3
"""Supervisor-only: FIX-SHA ABSOLUTE-JSON on an outside validate desk.

Exports pinned VR composition, overlays only this lane's scoped source, then
isolates the old shell scan, the old child scan after W, and both fixed scans.
The CLI runs the uninstrumented acceptance composition. Diagnostic generators
are separate tooling functions. No proof, keys or retained wallet.
"""
import contextlib
import hashlib
import importlib.util
import json
import os
import re
import stat
import pwd
from pathlib import Path
import subprocess
import sys
import tempfile

RUNTIME_SOURCE = 'a9475e0908c00fa17a5ed71b3bffa0c4e901141c'
DRIVER = 'tools/apnt-pool-action-circuit/scripts/test-private-runner-runtime-no-proof.py'
RUNNER = 'tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh'
LIVE_GUARD = 'tools/apnt-pool-action-circuit/cmd/pool-pk-load/live_harness.go'
LIVE_TEST = 'tools/apnt-pool-action-circuit/scripts/test-live-process-scan.py'
RACE_TEST = 'tools/apnt-pool-action-circuit/scripts/test-native-scan-race.py'
OBSERVER = 'tools/apnt-pool-action-circuit/scripts/mig01-macos-observer.c'
OBSERVER_TEST = 'tools/apnt-pool-action-circuit/scripts/test-macos-observer.py'
CONTINUATION_TEST = 'tools/apnt-pool-action-circuit/scripts/test-observer-continuation.py'
ATTRIBUTION = 'tools/apnt-pool-action-circuit/scripts/kernel-attribution.py'
ATTRIBUTION_TEST = 'tools/apnt-pool-action-circuit/scripts/test-kernel-attribution.py'
ATTRIBUTION_BOUNDARIES = 'tools/apnt-pool-action-circuit/scripts/test-kernel-attribution-boundaries.py'
INTERFERENCE_TEST = 'tools/apnt-pool-action-circuit/scripts/test-observer-interference.py'
ACCEPTANCE_TEST = 'tools/apnt-pool-action-circuit/scripts/test-kernel-acceptance.py'
TEST = 'tools/pool-action-modules/test/mig01-runtime-controls.test.ts'
NAME = 'PH11-X-PROD/P0 genuine kernel stock runner reaches P/A/W and writes its check-live result then fails closed before the summary'
NODE = str(Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.nvm/versions/node/v22.22.3/bin/node')
OVERLAYS = [RUNNER, 'tools/pool-action-modules/private-runner-process.c',
            'tools/apnt-pool-action-circuit/scripts/kernel-attribution-capture.py',
            'tools/apnt-pool-action-circuit/scripts/test-prove-memory-floors.py',
            'tools/apnt-pool-action-circuit/scripts/test-native-process-scan.py', LIVE_TEST, RACE_TEST, OBSERVER, OBSERVER_TEST, CONTINUATION_TEST,
            ATTRIBUTION,ATTRIBUTION_TEST,ATTRIBUTION_BOUNDARIES,INTERFERENCE_TEST,ACCEPTANCE_TEST]
ACCEPTANCE_OVERLAYS=[path for path in OVERLAYS if path not in
    (ATTRIBUTION,ATTRIBUTION_TEST,ATTRIBUTION_BOUNDARIES,INTERFERENCE_TEST,
     'tools/apnt-pool-action-circuit/scripts/kernel-attribution-capture.py',ACCEPTANCE_TEST)]
ACCEPTANCE_PATHS=['tools/apnt-pool-action-circuit/internal/runneradmission/bridge.go',
    'tools/apnt-pool-action-circuit/internal/runneradmission/harness.go',
    'tools/pool-action-modules/private-runner-bootstrap.mjs',
    'tools/pool-action-modules/private-runner-bridge.mjs',
    'tools/pool-action-modules/private-runner-installation.py']
INVENTORY_FIXTURE_INPUTS=[RUNNER,
    'tools/apnt-pool-action-circuit/scripts/test-prove-memory-floors.py']
INVENTORY_CONTROL_INPUTS=['tools/pool-action-modules/test/private-runner-result.test.ts',
    ATTRIBUTION,'tools/apnt-pool-action-circuit/scripts/kernel-attribution-capture.py']
NATIVE = '"$repo/tools/pool-action-modules/dist/private-runner-process" "$@"'
OLD = '"/bin/ps" "$@"'
OUTER_REASONS = ('no-diagnostic', 'unclassified', 'live-request-result-write',
                 'live-request-main-checkout-required', 'live-request-harness-required',
                 'live-request-prover-lock-required', 'live-request-bridge-refused',
                 'live-request-process-list-unavailable', 'live-request-other-prover',
                 'live-request-memory-unavailable', 'live-request-monitor-unavailable',
                 'live-request-memory-floor', 'live-request-swap-trip', 'live-request-rss-trip',
                 'live-plan-memory-floor', 'live-plan-main-checkout',
                 'live-plan-memory-unavailable', 'live-plan-other-prover',
                 'live-plan-sp1-marker', 'live-plan-prover-marker',
                 'live-plan-prover-inventory-ps', 'live-plan-prover-inventory-awk',
                 'live-plan-prover-inventory-pipeline', 'live-plan-prover-inventory-sigpipe')
OBSERVER_REASONS = ('process-capacity','depth','uid','descriptor-list','child-list','timeout')
OBSERVER_COUNTS = ('samples','observedProcesses','fd8PipeProcesses','fd8SocketProcesses',
                   'fd8IdentitiesCompared','fd8IdentitiesDifferent','fd8SourceIdentityMatches',
                   'sourceDescriptorMatches','nullStdioPrivateBridgeProcesses','inheritedProverLockBridges')


def attribution_module():
    spec=importlib.util.spec_from_file_location('eng1436_attribution',Path(__file__).with_name('kernel-attribution.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def observer_diagnostic(raw):
    """Whole-stream, fixed names/codes only; never project an unknown string."""
    require(type(raw) is bytes and len(raw)<=256)
    match=re.fullmatch(rb'\{"reason":"('+b'|'.join(reason.encode() for reason in OBSERVER_REASONS)+rb')","errno":(0|[1-9][0-9]{0,3})\}\n',raw)
    require(match is not None and int(match[2])<=4095)
    value={'reason':match[1].decode('ascii'),'errno':int(match[2])}
    require(value['reason'] in ('descriptor-list','child-list') or value['errno']==0)
    return value


def observer_observation(value):
    require(type(value) is dict and set(value)=={'schema','code','observer','stderrBytes','diagnostic'}
            and value['schema']=='eng1436-descriptor-observer-v1')
    observer=value['observer']
    require(type(observer) is dict and set(observer)==set(OBSERVER_COUNTS)|{'observerRefused'})
    require(all(type(observer[k]) is int and 0<=observer[k]<=2**53-1 for k in OBSERVER_COUNTS))
    require(type(observer['observerRefused']) is bool and type(value['code']) is int
            and value['code'] in (0,77) and observer['observerRefused']==(value['code']==77))
    require(type(value['stderrBytes']) is int and 0<=value['stderrBytes']<=2**53-1)
    diagnostic=value['diagnostic']
    if diagnostic is not None:
        require(type(diagnostic) is dict and set(diagnostic)=={'reason','errno'})
        raw=(json.dumps(diagnostic,separators=(',',':'))+'\n').encode()
        require(observer_diagnostic(raw)==diagnostic and value['code']==77 and value['stderrBytes']==len(raw))
    require(value['code']!=0 or value['stderrBytes']==0 and diagnostic is None)
    return value


def observer_build_observation(value,compositions):
    require(type(value) is dict and set(value)=={'sourceSha256','binarySha256'}
            and all(type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest) is not None for digest in value.values()))
    require(bool(compositions) and all([row['sha256'] for row in rows if row['path']==OBSERVER]==[value['sourceSha256']]
                                      for rows in compositions.values()))
    return value


def observer_capture_edits():
    """Preserve stdout and every original assertion; carry closed stderr only."""
    callback="""        observation.descriptorResult=new Promise(resolveMetadata=>observer.once('close',(code:number)=>{
          runtimeStep('observer-close');
          // Only the observer's fixed reason/errno record can enter diagnostics.
          const diagnostic=observerDiagnostic(diagnosticBytes);
          resolveMetadata({code,value:JSON.parse(metadata),diagnostic});
        }));"""
    replacement="""        observation.descriptorResult=new Promise(resolveMetadata=>observer.once('close',(code:number)=>{
          runtimeStep('observer-close');
          let diagnostic=null;
          try { const value=JSON.parse(observerError.toString('utf8'));
            if(observerErrorBytes<=256 && Object.keys(value).join(',')==='reason,errno'
              && OBSERVER_REASONS.includes(value.reason) && Number.isSafeInteger(value.errno) && value.errno>=0 && value.errno<=4095
              && (['descriptor-list','child-list'].includes(value.reason) || value.errno===0)
              && observerError.equals(Buffer.from(JSON.stringify(value)+'\\n'))) diagnostic=value;
          } catch {}
          resolveMetadata({code,value:JSON.parse(metadata),stderrBytes:observerErrorBytes,diagnostic});
        }));""".replace('OBSERVER_REASONS',repr(list(OBSERVER_REASONS)))
    return [
        # TEST is the current overlay, which already pipes observer stderr.
        # Replace its bounded capture, retaining exact whole-stream accounting.
        (TEST,"        let diagnosticBytes=Buffer.alloc(0);\n"
         "        observer.stderr.on('data',(bytes:Buffer)=>{if(diagnosticBytes.length<=256)diagnosticBytes=Buffer.concat([diagnosticBytes,bytes]);});",
         "        let observerError=Buffer.alloc(0),observerErrorBytes=0;\n"
         "        observer.stderr.on('data',(bytes:Buffer)=>{observerErrorBytes+=bytes.length;if(observerErrorBytes<=256)observerError=Buffer.concat([observerError,bytes]);});"),
        (TEST,callback,replacement)]


def quiet_return_diagnostic(source):
    """Separate scratch run only; do not change the exact candidate's entry.

    V2 deliberately returns prerequisites/refusals without stderr or a result.
    Emit only fixed branch names, never a refusal's fields or error text. The
    new run has its own source digest and is not the original observation.
    """
    before = '\tif result.status != 0 {\n\t\tos.Exit(result.status)'
    after = '''\tif result.status != 0 {
        if result.prerequisite != nil {
            switch result.prerequisite.Error() {
            case "live-request-main-checkout-required":
                fmt.Fprintln(os.Stderr, "live-request-main-checkout-required")
            case "live-request-harness-required":
                fmt.Fprintln(os.Stderr, "live-request-harness-required")
            case "live-request-prover-lock-required":
                fmt.Fprintln(os.Stderr, "live-request-prover-lock-required")
            }
        } else if result.refusal != nil {
            fmt.Fprintln(os.Stderr, "live-request-bridge-refused")
        }
\t\tos.Exit(result.status)'''
    require(source.count(before) == 1)
    return source.replace(before, after)


def require(ok):
    if not ok:
        raise RuntimeError('kernel-reproduction-refused')


def scan_dispatch(source):
    """Execute only the composed dispatch with fixed synthetic executables."""
    generation = re.findall(r'^readonly PRIVATE_RUNNER_GENERATION=([12])\b', source, re.M)
    require(generation == ['2'])
    start, end = 'runner_process_scan() {', 'phase_rss_bytes() {'
    require(source.count(start) == source.count(end) == 1)
    unit = start + source.split(start, 1)[1].split(end, 1)[0]
    unit = unit.replace('"$repo/tools/pool-action-modules/dist/private-runner-process"', 'stub_native')
    unit = unit.replace('/bin/ps', 'stub_ps')
    prefix = '''set -euo pipefail
readonly PRIVATE_RUNNER_GENERATION=2
stub_native() { [[ "$*" == '-axo pid=,comm=' ]] || return 99; echo native; }
stub_ps() { [[ "$*" == '-axo pid=,comm=' ]] || return 99; echo ps; }
'''
    result = subprocess.run(['/bin/bash','-c',prefix+unit+'\nrunner_process_scan -axo pid=,comm='],
                            capture_output=True,timeout=10)
    require(result.returncode == 0 and not result.stderr and result.stdout in (b'native\n',b'ps\n'))
    # A successful stub alone cannot detect a commented-out status capture.
    # Quiet inventory calls this function inside a conditional pipeline, where
    # errexit cannot rescue a swallowed reader failure.
    failed=prefix.replace('echo native;', 'return 23;').replace('echo ps;', 'return 23;')
    result_failure=subprocess.run(['/bin/bash','-c',failed+unit+
        '\nif runner_process_scan -axo pid=,comm=; then exit 0; else exit "$?"; fi'],capture_output=True,timeout=10)
    require((result_failure.returncode,result_failure.stdout,result_failure.stderr)==(23,b'',b''))
    return result.stdout.decode().strip()


def stage_runtime(fixture, stage, composition):
    """Bind committed source, installed closure and executable dispatch."""
    require(stage in ('kernel-old','kernel-post-w-old','kernel-fixed','kernel-quiet-diagnostic'))
    for row in composition:
        require(hashlib.sha256((fixture/row['path']).read_bytes()).hexdigest() == row['sha256'])
    shell = scan_dispatch((fixture/RUNNER).read_text())
    require(shell == ('ps' if stage == 'kernel-old' else 'native'))
    main = (fixture/'tools/apnt-pool-action-circuit/cmd/pool-pk-load/main.go').read_text()
    require(main.count('result := runV2(os.Args, runDeps{') == 1)
    require(('if result.prerequisite != nil {' in main) == (stage == 'kernel-quiet-diagnostic'))
    guard = (fixture/LIVE_GUARD).read_text()
    require(('return guardLiveResources(work, reader)' in guard) == (stage in ('kernel-fixed','kernel-quiet-diagnostic')))
    environment = {'PATH':'/usr/bin:/bin','LANG':'C','TMPDIR':'/private/tmp'}
    revision = subprocess.check_output(['/usr/bin/git','rev-parse','HEAD'],cwd=fixture,env=environment,stderr=subprocess.DEVNULL).decode().strip()
    require(subprocess.check_output(['/usr/bin/git','status','--porcelain'],cwd=fixture,env=environment,stderr=subprocess.DEVNULL) == b'')
    record = json.loads((fixture/'tools/pool-action-modules/dist/private-runner-installation.json').read_bytes())
    require(set(record) == {'schema','revision','entries'} and record['schema'] == 'private-runner-installation-record-v1'
            and record['revision'] == revision and type(record['entries']) is list and bool(record['entries']))
    entries = record['entries']
    for row in entries:
        require(type(row) is dict and set(row) == {'path','sha256'} and type(row['path']) is str)
        require(not Path(row['path']).is_absolute() and '..' not in Path(row['path']).parts
                and (row['path'].startswith(('tools/pool-action-modules/','packages/','node_modules/'))
                or row['path'] in ('pnpm-lock.yaml','pnpm-workspace.yaml','package.json','tsconfig.base.json','.npmrc','.nvmrc')))
        require((fixture/row['path']).resolve() == fixture/row['path'])
        require(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None)
        require(hashlib.sha256((fixture/row['path']).read_bytes()).hexdigest() == row['sha256'])
    require(len({row['path'] for row in entries}) == len(entries))
    reader = fixture/'tools/pool-action-modules/dist/private-runner-process'
    require(sum(row['path'] == str(reader.relative_to(fixture)) for row in entries) == 1)
    info = reader.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_mode & 0o111 and not info.st_mode & 0o6022)
    tracked = subprocess.check_output(['/usr/bin/git','ls-files','-z','tools/apnt-pool-action-circuit'],cwd=fixture,env=environment).decode().split('\0')
    go_sources = [path for path in tracked if path.endswith('.go') or path.endswith(('/go.mod','/go.sum'))]
    sources = []
    for path in sorted(go_sources):
        raw = (fixture/path).read_bytes()
        require(raw == subprocess.check_output(['/usr/bin/git','show','HEAD:'+path],cwd=fixture,env=environment,stderr=subprocess.DEVNULL))
        sources.append({'path':path,'sha256':hashlib.sha256(raw).hexdigest()})
    return {'revision':revision,'shellDispatch':shell,'childDispatch':'native' if stage in ('kernel-fixed','kernel-quiet-diagnostic') else 'ps',
            'goSources':sources,'installedClosure':entries}


def diagnostic_driver(root):
    return comparison_driver(root,instrumented=True)


def acceptance_driver(root):
    return comparison_driver(root,instrumented=False)


def acceptance_sources(fixture,stage,source_root):
    """Exact uninstrumented owning bytes, not absence of an enabled flag."""
    require(stage in ('kernel-old','kernel-post-w-old','kernel-fixed'))
    def donor(path):
        return subprocess.check_output(['/usr/bin/git','show',RUNTIME_SOURCE+':'+path],cwd=source_root,stderr=subprocess.DEVNULL)
    paths=ACCEPTANCE_PATHS+['tools/pool-action-modules/private-runner-process.c',OBSERVER]
    expected={path:(source_root/path).read_bytes() for path in paths}
    shell=(source_root/RUNNER).read_text()
    # Since C1 (GO) the candidate's committed generation is 2, so the
    # composition leaves its shell byte-identical; a generation-1 marker refuses.
    require(shell.count('readonly PRIVATE_RUNNER_GENERATION=2')==1 and 'readonly PRIVATE_RUNNER_GENERATION=1' not in shell)
    if stage=='kernel-old':
        require(shell.count(NATIVE)==1);shell=shell.replace(NATIVE,OLD)
    expected[RUNNER]=shell.encode()
    expected[LIVE_GUARD]=(source_root/LIVE_GUARD).read_bytes() if stage=='kernel-fixed' else donor(LIVE_GUARD)
    main='tools/apnt-pool-action-circuit/cmd/pool-pk-load/main.go'
    original=donor(main);require(original.count(b'result := run(os.Args, runDeps{')==1)
    expected[main]=original.replace(b'result := run(os.Args, runDeps{',b'result := runV2(os.Args, runDeps{')
    for path in ACCEPTANCE_PATHS:require(donor(path)==expected[path])
    for path in set(OVERLAYS)-set(ACCEPTANCE_OVERLAYS)|{'tools/apnt-pool-action-circuit/internal/runneradmission/eng1436_diagnostic.go'}:
        target=fixture/path;require(not target.exists() and not target.is_symlink())
    result=[]
    for path,raw in expected.items():
        require((fixture/path).read_bytes()==raw)
        result.append({'path':path,'sha256':hashlib.sha256(raw).hexdigest()})
    return {'schema':'eng1436-uninstrumented-sources-v1','diagnosticHooksAbsent':True,'sources':result}


def acceptance_runtime(fixture,stage,composition,source_root):
    snapshot=stage_runtime(fixture,stage,composition)
    snapshot['acceptanceSourceBinding']=acceptance_sources(fixture,stage,source_root)
    return snapshot


def comparison_driver(root,*,instrumented):
    # The driver/production donor stays immutable. Overlay only the current
    # runtime TEST source so collection follows B's 119-row accounting.
    overlays=OVERLAYS if instrumented else ACCEPTANCE_OVERLAYS
    extra_paths=attribution_module().PATHS if instrumented else ACCEPTANCE_PATHS
    restored_child='instrument_live((REPO/'+repr(LIVE_GUARD)+').read_text())' if instrumented else '(REPO/'+repr(LIVE_GUARD)+').read_text()'
    spec=importlib.util.spec_from_file_location('public_history_source',Path(__file__).with_name('public-history-source.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    source = module.read_source(RUNTIME_SOURCE,DRIVER).decode()
    cut = "    run('ordinary-build',"
    require(source.count(cut) == 1)
    source = source.split(cut)[0] + f'''
    env['MIG01_TEST_OUTPUT_ROOT']=str(artifacts)
    env['MIG01_CLOSED_LABEL']='kernel-old-closed.json'
    suite('kernel-old',[TEST],{('^' + NAME + '$')!r},want=1)
    path=fixture/{RUNNER!r}; text=path.read_text()
    require(text.count({OLD!r})==1)
    path.write_text(text.replace({OLD!r},{NATIVE!r}))
    composition('kernel-post-w-old')
    commit('fixed-scan')
    run('installation-fixed-build',['/usr/bin/python3','tools/pool-action-modules/private-runner-installation.py','--build'])
    run('native-scan-controls',['/usr/bin/python3','tools/apnt-pool-action-circuit/scripts/test-native-process-scan.py','--host','NativeScan'])
    env['MIG01_CLOSED_LABEL']='kernel-post-w-old-closed.json'
    suite('kernel-post-w-old',[TEST],{('^' + NAME + '$')!r},want=1)
    path=fixture/{LIVE_GUARD!r}; path.write_text({restored_child})
    composition('kernel-fixed')
    commit('fixed-live-scan')
    run('installation-fixed-live-build',['/usr/bin/python3','tools/pool-action-modules/private-runner-installation.py','--build'])
    env['MIG01_CLOSED_LABEL']='kernel-fixed-closed.json'
    suite('kernel-fixed',[TEST],{('^' + NAME + '$')!r},want=None)
    if {instrumented!r} and summary['commands'][-1]['exit'] != 0:
        # Preserve the exact candidate failure, then diagnose silent native
        # returns in an explicitly distinct composition. No production hook.
        path=fixture/'tools/apnt-pool-action-circuit/cmd/pool-pk-load/main.go'
        path.write_text(quiet_return_diagnostic(path.read_text()))
        composition('kernel-quiet-diagnostic')
        commit('quiet-diagnostic')
        run('installation-quiet-diagnostic-build',['/usr/bin/python3','tools/pool-action-modules/private-runner-installation.py','--build'])
        env['MIG01_CLOSED_LABEL']='kernel-quiet-diagnostic-closed.json'
        suite('kernel-quiet-diagnostic',[TEST],{('^' + NAME + '$')!r},want=None)
'''
    if not instrumented:
        marker="    if False and summary['commands'][-1]['exit'] != 0:\n"
        require(source.count(marker)==1);source=source.split(marker,1)[0]
    replacements = [
        # The second commit happens after installation. Force-adding the whole
        # fixture would track ignored dist and dependency-directory symlinks,
        # which the source inventory correctly refuses to read as files.
        ("run(label+'-add',['/usr/bin/git','add','--force','.'])",
         f"run(label+'-add',['/usr/bin/git','add','--',{RUNNER!r},{LIVE_GUARD!r}] if label in ('fixed-scan','fixed-live-scan') else ['/usr/bin/git','add','--','tools/apnt-pool-action-circuit/cmd/pool-pk-load/main.go'] if label=='quiet-diagnostic' else ['/usr/bin/git','add','--force','.'])"),
        ("summary['sourceHead'] = git('rev-parse','HEAD').decode().strip()", f"summary['sourceHead'] = {RUNTIME_SOURCE!r}"),
        ("git('rev-parse','HEAD^{tree}') ==", f"git('rev-parse',{(RUNTIME_SOURCE+'^{tree}')!r}) =="),
        ("if row['status'] != 'pending'", "if row['status'] in ('passed','failed')"),
        # C1: the candidate shell (an overlay) already carries the composition;
        # the donor's main.go still takes its edit. Exact bytes are bound later.
        ("path=fixture/relative; text=path.read_text(); require(text.count(old)==1); path.write_text(text.replace(old,new))",
         f"path=fixture/relative; text=path.read_text(); require(text.count(old)==1 or (relative=={RUNNER!r} and text.count(new)==1 and old not in text)); path.write_text(text.replace(old,new))"),
        ("status = run(label,args,want=None)",
         "summary['stageRuntime'][label] = stage_runtime(fixture,label,summary['composition'][label])\n        status = run(label,args,want=None)"),
        ("require(status == want and (result['numFailedTests'] > 0 if want else result['success'] and result['numPassedTests'] == len(rows)))",
         "require(want is None or (status == want and (result['numFailedTests'] > 0 if want else result['success'] and result['numPassedTests'] == len(rows))))"),
    ]
    for old,new in replacements:
        require(source.count(old)==1); source=source.replace(old,new)
    observer_build=next(line for line in source.splitlines() if line.startswith("    run('observer-build',"))
    source=source.replace(observer_build,observer_build+f"\n    summary['descriptorObserverBuild']={{'sourceSha256':hashlib.sha256((fixture/{OBSERVER!r}).read_bytes()).hexdigest(),'binarySha256':hashlib.sha256((artifacts/'macos-observer').read_bytes()).hexdigest()}}\n    (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\\n')")
    overlay_marker='    # Explicit disposable composition; no lane selector or guard edits.\n'
    require(source.count(overlay_marker)==1)
    source=source.replace(overlay_marker,f'''
    for relative in {overlays!r}:
        path=fixture/relative; path.write_bytes((REPO/relative).read_bytes())
    path=fixture/{TEST!r}; path.write_bytes((REPO/{TEST!r}).read_bytes())
    require(path.read_text().count("observation.request],{{stdio:['pipe','pipe','pipe']}});")==1)
''' + overlay_marker)
    edits = [
        (TEST, '    outerRefusal: stderr.includes(',
         "    inventoryReason: ['ps','awk','pipeline','sigpipe'].find(code => stderr.equals(Buffer.from('measure-pk-load: live-plan-refused reason=live-plan-prover-inventory-'+code+'\\n'))) ?? null,\n"
         "    processListUnavailable: receipt?.error === 'live-request-process-list-unavailable',\n"
         "    runnerBinarySha256: existsSync(join(f.output,'bin/pool-pk-load')) ? createHash('sha256').update(readFileSync(join(f.output,'bin/pool-pk-load'))).digest('hex') : null,\n"
         f"    outerReason: {list(OUTER_REASONS)!r}.find(code => stderr.equals(Buffer.from('measure-pk-load: live-plan-refused reason='+code+'\\n'))) ?? null,\n"
         '    outerRefusal: stderr.includes('),
        (TEST, "    runtimeStep('runner-complete');\n",
         "    runtimeStep('runner-complete');\n"
         "    writeFileSync(join(OUTPUT!,process.env.MIG01_CLOSED_LABEL!),JSON.stringify({status,...JSON.parse(runnerDiagnostic(f))})+'\\n',{mode:0o600,flag:'wx'});\n"
         "    if(mode==='kernel'){const observed=await observation.descriptorResult!;writeFileSync(join(OUTPUT!,process.env.MIG01_CLOSED_LABEL!.replace('-closed.json','-observer-closed.json')),JSON.stringify({schema:'eng1436-descriptor-observer-v1',code:observed.code,observer:observed.value,stderrBytes:observed.stderrBytes,diagnostic:observed.diagnostic})+'\\n',{mode:0o600,flag:'wx'});}\n"),
    ] + observer_capture_edits()
    marker = "    commit('composition')\n"
    require(source.count(marker)==1)
    return source.replace(marker,f'''
    for relative,old,new in {edits!r}:
        path=fixture/relative; text=path.read_text(); require(text.count(old)==1)
        path.write_text(text.replace(old,new))
    # Record the final bytes of each phase, rather than intermediate overlays.
    summary['composition']={{}}
    summary['stageRuntime']={{}}
    def composition(phase):
        summary['composition'][phase]=[{{'path':relative,'sha256':hashlib.sha256((fixture/relative).read_bytes()).hexdigest()}}
            for relative in {overlays + [LIVE_GUARD, TEST, 'tools/apnt-pool-action-circuit/cmd/pool-pk-load/main.go']!r} + ({extra_paths!r} if phase!='inventory-controls' else {[] if instrumented else ACCEPTANCE_PATHS!r})]
        (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\\n')
    composition('inventory-controls')
    def inventory_fixture():
        # RSS controls inspect attribution source, but acceptance production
        # explicitly forbids it. Bind a separate finite control fixture to the
        # composed runner/test bytes and current control-only source inputs.
        control=root/'inventory-controls'
        rows=[]
        for relative in {INVENTORY_FIXTURE_INPUTS + INVENTORY_CONTROL_INPUTS!r}:
            origin=fixture if relative in {INVENTORY_FIXTURE_INPUTS!r} else REPO
            path=control/relative; path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((origin/relative).read_bytes())
            rows.append({{'path':relative,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}})
        summary['inventoryControlInputs']=rows
        (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\\n')
        return control
    run('diagnostic-controls',['/usr/bin/python3','tools/apnt-pool-action-circuit/scripts/test-prove-memory-floors.py','PrivateDiagnostics'],cwd=REPO)
    run('case-guard-controls',['/usr/bin/python3','tools/apnt-pool-action-circuit/scripts/test-prove-memory-floors.py','MemoryFloors.test_child_case_guard'],cwd=REPO)
    # Reproduction controls need this lane's script and the donor Git object,
    # which are intentionally absent from the exported runtime fixture.
    run('reproduction-controls',['/usr/bin/python3','tools/apnt-pool-action-circuit/scripts/test-native-process-scan.py','ReproductionSelection'],cwd=REPO)
    run('live-scan-controls',['/usr/bin/python3',{LIVE_TEST!r}],cwd=REPO)
    run('table-race-controls',['/usr/bin/python3',{RACE_TEST!r}],cwd=REPO)
    run('descriptor-observer-controls',['/usr/bin/python3',{OBSERVER_TEST!r}],cwd=REPO)
    run('continuation-observer-controls',['/usr/bin/python3',{CONTINUATION_TEST!r}],cwd=REPO)
    run('attribution-controls',['/usr/bin/python3',{ATTRIBUTION_TEST!r}],cwd=REPO)
    run('attribution-boundary-controls',['/usr/bin/python3',{ATTRIBUTION_BOUNDARIES!r}],cwd=REPO)
    run('observer-interference-controls',['/usr/bin/python3',{INTERFERENCE_TEST!r}],cwd=REPO)
    run('acceptance-controls',['/usr/bin/python3',{ACCEPTANCE_TEST!r}],cwd=REPO)
    # These controls require the intact native dispatch. Mutate only afterwards,
    # before committing/building the old scanner's installation receipt.
    run('inventory-controls',['/usr/bin/python3','tools/apnt-pool-action-circuit/scripts/test-prove-memory-floors.py','ProverInventory'],cwd=inventory_fixture())
    {"summary['attributionBranches']=instrument_attribution(fixture,artifacts/'pre-w-attribution.jsonl')" if instrumented else "summary['acceptanceComposition']=True"}
    summary['diagnosticInstrumentation']={instrumented!r}
    path=fixture/{RUNNER!r}; text=path.read_text(); require(text.count({NATIVE!r})==1)
    path.write_text(text.replace({NATIVE!r},{OLD!r}))
    composition('kernel-old')
''' + marker)


def closed_observation(path):
    value=json.loads(path.read_bytes())
    keys={'status','contacts','deliveries','terminalBytes','inventoryReason','processListUnavailable','runnerBinarySha256','outerRefusal','outerReason','memoryFloor',
          'outputCreated','runCreated','admissionCreated','resultCreated','summaryCreated','workFailure','openStage'}
    require(set(value)==keys and value['inventoryReason'] in ('ps','awk','pipeline','sigpipe',None))
    require(value['outerReason'] is None or type(value['outerReason']) is str and value['outerReason'] in OUTER_REASONS)
    require(value['runnerBinarySha256'] is None or type(value['runnerBinarySha256']) is str and re.fullmatch('[0-9a-f]{64}',value['runnerBinarySha256']) is not None)
    require(not value['runCreated'] or value['runnerBinarySha256'] is not None)
    require(all(type(value[k]) is bool for k in keys-{'status','contacts','deliveries','terminalBytes','inventoryReason','outerReason','runnerBinarySha256'}))
    require(value['outerRefusal'] == (value['outerReason'] is not None))
    require(type(value['status']) is int and type(value['terminalBytes']) is int and value['terminalBytes']>=0)
    require(all(type(value[k]) is list and len(value[k])==3 and all(type(n) is int and n>=0 for n in value[k]) for k in ('contacts','deliveries')))
    return value


def native_scan_observation(path):
    value=json.loads(path.read_bytes())
    require(type(value) is dict)
    if value.get('schema')=='eng1436-native-scan-v2':
        return native_scan_original_observation(value)
    require(set(value)=={'schema','originalStatus','originalStdoutBytes','originalStderrBytes',
                         'diagnostic','sameScanClaimed','profileChanged'})
    require(value['schema']=='eng1436-native-scan-v1' and type(value['originalStatus']) is int
            and value['originalStatus']==1)
    require(all(type(value[k]) is int and value[k]>=0 for k in ('originalStdoutBytes','originalStderrBytes')))
    require(value['sameScanClaimed'] is False and value['profileChanged'] is False)
    diagnostic=value['diagnostic']
    require(type(diagnostic) is dict and set(diagnostic)=={'status','reason','errno'})
    require(type(diagnostic['status']) is int and diagnostic['status'] in (0,1)
            and type(diagnostic['errno']) is int and diagnostic['errno']>=0)
    require(type(diagnostic['reason']) is str and diagnostic['reason'] in
            {'none','unclassified','process-table','argmax','allocation','pid','foreign-path','foreign-delimiter',
             'arguments-query','arguments-size','arguments-count','executable-terminator',
             'argv0-terminator','argv0-delimiter','rss-query','stdout'})
    require(diagnostic['status']!=0 or diagnostic=={'status':0,'reason':'none','errno':0})
    return value


def native_scan_original_observation(value):
    keys={'schema','failurePoint','expectedStatus','originalStatus','originalStdoutBytes','originalStderrBytes',
          'readerStatus','readerStderrBytes','diagnostic','sameScanClaimed','profileChanged'}
    require(type(value) is dict and set(value)==keys and value['schema']=='eng1436-native-scan-v2')
    points={'initial-inventory':0,'quiet-guard':0,'named-prover-inventory':0,'named-prover-guard':19,'rss-inventory':0}
    require(type(value['failurePoint']) is str and value['failurePoint'] in points
            and type(value['expectedStatus']) is int and value['expectedStatus']==points[value['failurePoint']])
    require(type(value['originalStatus']) is int and -128<=value['originalStatus']<=255
            and value['originalStatus']!=value['expectedStatus'])
    require(all(type(value[k]) is int and value[k]>=0 for k in ('originalStdoutBytes','originalStderrBytes')))
    require(type(value['sameScanClaimed']) is bool and value['profileChanged'] is False)
    status=value['readerStatus'];error_bytes=value['readerStderrBytes'];diagnostic=value['diagnostic']
    require(status is None or type(status) is int and -128<=status<=255)
    require(error_bytes is None or type(error_bytes) is int and error_bytes>=0)
    require(value['sameScanClaimed']==(status is not None))
    if status is None:
        require(diagnostic is None and error_bytes is None)
    if diagnostic is not None:
        basic={'status','reason','errno'}
        extended=basic|{'confirmation','confirmationErrno'}
        require(type(diagnostic) is dict and set(diagnostic) in (basic,extended)
                and type(diagnostic['status']) is int and diagnostic['status']==status and status in (0,1))
        reasons={'none','process-table-size','process-table-size-shape','process-table-allocation','process-table-fetch',
                 'process-table-fetch-shape','argmax-query','argmax-shape','arguments-allocation',
                 'pid','foreign-path','foreign-delimiter','arguments-query','arguments-size','arguments-count',
                 'executable-terminator','argv0-terminator','argv0-delimiter','rss-query','stdout'}
        require(type(diagnostic['reason']) is str and diagnostic['reason'] in reasons
                and type(diagnostic['errno']) is int and 0<=diagnostic['errno']<=4095 and error_bytes is not None)
        require(status!=0 or diagnostic=={'status':0,'reason':'none','errno':0} and error_bytes==0)
        require(status!=1 or diagnostic['reason']!='none' and error_bytes>0)
        if set(diagnostic)==extended:
            require(status==1 and diagnostic['reason']=='arguments-query'
                    and type(diagnostic['confirmation']) is str and diagnostic['confirmation'] in ('live','unconfirmed','query-error')
                    and type(diagnostic['confirmationErrno']) is int and 0<=diagnostic['confirmationErrno']<=4095
                    and (diagnostic['confirmation']=='query-error' or diagnostic['confirmationErrno']==0))
    return value


def selected_execution(vitest,wanted):
    all_rows=[r for f in vitest['testResults'] for r in f['assertionResults']]
    require(len(all_rows)==119 and all(r['status'] in ('passed','failed','pending','skipped') for r in all_rows))
    spec=importlib.util.spec_from_file_location('runtime_selection',Path(__file__).with_name('test-private-runner-runtime-no-proof.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    titles=module.runtime_titles('union')
    require(len({r.get('fullName') for r in all_rows})==119 and {r.get('fullName') for r in all_rows}==set(titles))
    rows=[r for r in all_rows if r['status'] in ('passed','failed')]
    deselected=[r for r in all_rows if r['status'] in ('pending','skipped')]
    require(len(rows)==1 and len(deselected)==118 and rows[0]['fullName']==NAME
            and (wanted is None or rows[0]['status']==wanted))
    require(len(rows)==vitest['numPassedTests']+vitest['numFailedTests'] and len(deselected)==vitest['numPendingTests'])
    return {'executed':len(rows),'passed':vitest['numPassedTests'],'failed':vitest['numFailedTests'],'deselected':len(deselected)}


def require_kernel_expectations(result):
    old=result['observations']['kernel-old']; fixed=result['observations']['kernel-fixed']
    require(old['status']==1 and old['contacts']==old['deliveries']==[1,0,0] and old['inventoryReason']=='ps' and old['outerRefusal'] and old['terminalBytes']==72)
    require(not any(old[k] for k in ('processListUnavailable','memoryFloor','runCreated','admissionCreated','resultCreated','summaryCreated','workFailure','openStage')))
    post=result['observations']['kernel-post-w-old']
    require(post['status']==1 and post['contacts']==post['deliveries']==[1,1,1] and post['inventoryReason'] is None)
    require(post['outerReason']=='live-request-process-list-unavailable' and post['outerRefusal'] and post['processListUnavailable'])
    require(post['terminalBytes']==len(b'measure-pk-load: live-plan-refused reason=live-request-process-list-unavailable\n'))
    require(all(post[k] for k in ('outputCreated','runCreated','admissionCreated','resultCreated','summaryCreated')))
    require(not any(post[k] for k in ('memoryFloor','workFailure','openStage')))
    require(fixed['status']==1 and fixed['contacts']==fixed['deliveries']==[1,1,1] and fixed['inventoryReason'] is None and fixed['terminalBytes']>0)
    require(all(fixed[k] for k in ('outputCreated','runCreated','admissionCreated','resultCreated','outerRefusal')))
    require(not any(fixed[k] for k in ('summaryCreated','processListUnavailable','memoryFloor','workFailure','openStage')))
    require(fixed['outerReason'] in OUTER_REASONS)
    require(result['selected']['kernel-fixed']=={'executed':1,'passed':1,'failed':0,'deselected':118})
    require(all(result['selected'][label]=={'executed':1,'passed':0,'failed':1,'deselected':118}
                for label in ('kernel-old','kernel-post-w-old')))
    require(result['descriptorObservations']['kernel-fixed']['code']==0)


def main(expected_sha,destination):
    os.umask(0o077)
    output=Path(destination)
    require(output.is_absolute() and output.parent.resolve()==output.parent)
    descriptor=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    result={'schema':'eng1436-kernel-acceptance-v1','sourceHead':expected_sha,'runtimeSource':RUNTIME_SOURCE,
            'scriptSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'nodeVersion':None,
            'preparationFinished':False,'expectationMet':False,'observations':{},'descriptorObservations':{},'selected':{},'commands':[]}
    run=None
    try:
        root=Path.cwd().resolve()
        def git(*args):
            return subprocess.check_output(['/usr/bin/git',*args],cwd=root,stderr=subprocess.DEVNULL).strip()
        require(git('rev-parse','HEAD').decode()==expected_sha and git('status','--porcelain')==b'')
        result['nodeVersion']=subprocess.check_output([NODE,'--version'],stderr=subprocess.DEVNULL).decode().strip()
        require(result['nodeVersion']=='v22.22.3')
        namespace={'__file__':str(root/DRIVER),'__name__':'eng1436_acceptance_driver',
                   'stage_runtime':lambda fixture,stage,composition:acceptance_runtime(fixture,stage,composition,root)}
        exec(compile(acceptance_driver(root),str(root/DRIVER),'exec'),namespace)
        run=Path(tempfile.mkdtemp(prefix='other-provers-eng1436-',dir='/private/tmp'))/'run'
        with open(os.devnull,'w') as sink,contextlib.redirect_stdout(sink),contextlib.redirect_stderr(sink):
            namespace['main']([str(run)])
        result['preparationFinished']=True
    except Exception:
        pass  # Never emit private paths, captured streams or exception text.
    try:
        if run and (run/'summary.json').is_file():
            summary=json.loads((run/'summary.json').read_bytes())
            result['commands']=[{'label':r['label'],'exit':r['exit']} for r in summary['commands']]
            result['composition']=summary['composition']
            result['stageRuntime']=summary.get('stageRuntime',{})
            result['diagnosticInstrumentation']=summary.get('diagnosticInstrumentation',False)
            require(result['diagnosticInstrumentation'] is False and summary.get('acceptanceComposition') is True)
            trace=run/'observation-artifacts/pre-w-attribution.jsonl'
            require(not trace.exists() and not trace.is_symlink())
            if 'descriptorObserverBuild' in summary:
                result['descriptorObserverBuild']=observer_build_observation(summary['descriptorObserverBuild'],summary['composition'])
        diagnostic=run/'observation-artifacts/native-scan-closed.json' if run else None
        if diagnostic and diagnostic.is_file():
            result['nativeScanDiagnostic']=native_scan_observation(diagnostic)
        require(not (run/'raw/kernel-quiet-diagnostic.json').exists())
        for label in ('kernel-old','kernel-post-w-old','kernel-fixed'):
            vitest=json.loads((run/('raw/'+label+'.json')).read_bytes())
            result['observations'][label]=closed_observation(run/('observation-artifacts/'+label+'-closed.json'))
            # An expected runner refusal can coexist with a failed descriptor test.
            # Retain both original observations; acceptance still requires PASS.
            result['selected'][label]=selected_execution(vitest,None)
            observer=run/('observation-artifacts/'+label+'-observer-closed.json')
            result['descriptorObservations'][label]=observer_observation(json.loads(observer.read_bytes()))
        require_kernel_expectations(result)
        result['expectationMet']=result['preparationFinished']
    except Exception:
        result['expectationMet']=False
    with os.fdopen(descriptor,'w') as sink:
        json.dump(result,sink,sort_keys=True); sink.write('\n')
    return 0 if result['expectationMet'] else 1


if __name__=='__main__':
    try:
        require(len(sys.argv)==3)
        sys.exit(main(sys.argv[1],sys.argv[2]))
    except Exception:
        sys.exit(1)
