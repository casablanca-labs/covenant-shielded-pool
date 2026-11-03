#!/usr/bin/python3
"""Outside-sandbox ordinary runtime; no proving memory admission; slot checks remain.

Only closed summaries may be archived. Resource dispatch has a separate entry.
"""
import hashlib, json, os, re, signal, stat, subprocess, sys, tempfile, time
import pwd
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
NODE = Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.nvm/versions/node/v22.22.3/bin/node'
GO = '/opt/homebrew/bin/go'
PREFIX = 'tools/apnt-pool-action-circuit/'
TEST = 'tools/pool-action-modules/test/mig01-runtime-controls.test.ts'
OBSERVERS = ['TestMIG01R3RegisteredLibraryObservation', 'TestMIG01R3RegisteredDispatchObservation']
STEPS = tuple('control-start eligibility-start eligibility-complete eligibility-refused kernel-spawn observer-close runner-exit runner-close contact-P contact-A contact-W delivery-P delivery-A delivery-W kernel-canary-start kernel-canary-complete kernel-allow-start kernel-deny-start kernel-alias-allow-start kernel-alias-deny-start kernel-probes-complete classification-start classification-ready cleanup-start classification-closed cleanup-complete runner-wait runner-complete'.split())
STAGE_DRIVER = None # Resource certification reuses the reviewed stage lifecycle.

def require(ok):
    if not ok: raise RuntimeError('mig01-runtime-control-refused')

SELECTION_FILE = Path(__file__).with_name('mig01-runtime-selection.json')
RESOURCE_TITLES = frozenset(
    'PH11-RESOURCE '+suffix+' '+expected
    for suffix in ('valid prove failure receipt preserves EXPECT', 'missing prove result after A refuses even for EXPECT')
    for expected in ('fail','refuse-open'))

def runtime_inventory(path=None):
    value=json.loads((path or SELECTION_FILE).read_bytes())
    require(type(value) is dict and set(value)=={'schema','rows'} and value['schema']=='mig01-runtime-selection-v1')
    rows=value['rows']
    require(type(rows) is list and len(rows)==119)
    require(all(type(row) is dict and set(row)=={'title','selection'} and type(row['title']) is str
                and row['title'] and row['selection'] in ('ordinary','resource') for row in rows))
    titles=[row['title'] for row in rows]
    require(len(set(titles))==119 and titles==sorted(titles))
    resource={row['title'] for row in rows if row['selection']=='resource'}
    require(resource==RESOURCE_TITLES and {title for title in titles if title.startswith('PH11-RESOURCE ')}==resource)
    require(sum(row['selection']=='ordinary' for row in rows)==115)
    return rows

def runtime_titles(selection_class, inventory=None, pattern=None):
    require(selection_class in ('union','ordinary','resource'))
    rows=runtime_inventory() if inventory is None else inventory
    titles=[row['title'] for row in rows if selection_class=='union' or row['selection']==selection_class]
    if pattern is not None: titles=[title for title in titles if re.search(pattern,title)]
    require(titles)
    return titles

def runtime_pattern(selection_class):
    return '^(?:'+'|'.join(re.escape(title) for title in runtime_titles(selection_class))+')$'

def require_runtime_selection(result, selection_class, pattern=None, inventory=None):
    inventory=runtime_inventory() if inventory is None else inventory
    titles=runtime_titles('union',inventory)
    selected=set(runtime_titles(selection_class,inventory,pattern))
    rows=[row for entry in result['testResults'] for row in entry['assertionResults']]
    require(all(type(row) is dict and type(row.get('fullName')) is str and row.get('status') in ('passed','failed','skipped','pending') for row in rows))
    actual=[row['fullName'] for row in rows]
    require(len(actual)==len(set(actual))==119 and set(actual)==set(titles))
    executed={row['fullName'] for row in rows if row['status'] in ('passed','failed')}
    require(executed==selected)
    require(all(type(result.get(key)) is int and result[key]>=0 for key in ('numPassedTests','numFailedTests','numPendingTests'))
            and type(result.get('success')) is bool)
    require(sum(row['status']=='passed' for row in rows)==result['numPassedTests']
            and sum(row['status']=='failed' for row in rows)==result['numFailedTests']
            and len(rows)-len(selected)==result['numPendingTests'])
    return {'class':selection_class,'total':119,'selected':len(selected),'deselected':119-len(selected),
            'inventorySha256':hashlib.sha256(SELECTION_FILE.read_bytes()).hexdigest(),
            'sourceSha256':hashlib.sha256((REPO/TEST).read_bytes()).hexdigest(),
            'selectedSha256':hashlib.sha256(('\n'.join(sorted(selected))+'\n').encode()).hexdigest(),
            'deselectedSha256':hashlib.sha256(('\n'.join(sorted(set(titles)-selected))+'\n').encode()).hexdigest()}

def require_resource_receipt(value, head=None):
    """Closed certification receipt, never a projection of private test payloads."""
    require(type(value) is dict and set(value)=={'schema','sourceHead','sourceTree','fixtureHead','selection','buildIdentities','cases'})
    require(value['schema']=='mig01-resource-controls-v1')
    for key in ('sourceHead','sourceTree','fixtureHead'):
        require(type(value[key]) is str and re.fullmatch('[0-9a-f]{40}',value[key]) is not None)
    require(head is None or value['sourceHead']==head)
    selected=set(runtime_titles('resource'));deselected=set(runtime_titles('ordinary'))
    expected={'class':'resource','total':119,'selected':4,'deselected':115,
        'inventorySha256':hashlib.sha256(SELECTION_FILE.read_bytes()).hexdigest(),
        'sourceSha256':hashlib.sha256((REPO/TEST).read_bytes()).hexdigest(),
        'selectedSha256':hashlib.sha256(('\n'.join(sorted(selected))+'\n').encode()).hexdigest(),
        'deselectedSha256':hashlib.sha256(('\n'.join(sorted(deselected))+'\n').encode()).hexdigest()}
    require(type(value['selection']) is dict and set(value['selection'])==set(expected)
            and all(type(value['selection'][key]) is type(item) and value['selection'][key]==item for key,item in expected.items()))
    builds=value['buildIdentities']
    require(type(builds) is dict and set(builds)=={'process','installation','native'})
    require(all(type(item) is str and re.fullmatch('[0-9a-f]{64}',item) is not None for item in builds.values()))
    cases=value['cases']
    require(type(cases) is list and len(cases)==4)
    require(all(type(row) is dict and set(row)=={'title','stop','stockNativeSha256'} and type(row['title']) is str
                and row['title'] in RESOURCE_TITLES and row['stop']==('open' if 'valid prove failure' in row['title'] else 'W-expiry')
                and type(row['stockNativeSha256']) is str and re.fullmatch('[0-9a-f]{64}',row['stockNativeSha256']) is not None for row in cases))
    require([row['title'] for row in cases]==sorted(RESOURCE_TITLES))

def resource_receipt(summary):
    suites=[row for row in summary['suites'] if row['label']=='runtime']
    require(len(suites)==1)
    suite=suites[0]
    require((suite['tests'],suite['passed'],suite['failed'],suite['deselected'])==(4,4,0,115)
            and len(suite['rows'])==4 and {row['name'] for row in suite['rows']}==RESOURCE_TITLES
            and all(row['status']=='passed' for row in suite['rows']))
    require([row['exit'] for row in summary['commands'] if row['label']=='runtime']==[0])
    builds=summary['buildIdentities']
    value={'schema':'mig01-resource-controls-v1',**{key:summary[key] for key in ('sourceHead','sourceTree','fixtureHead')},
        'selection':suite['selection'],'buildIdentities':{
            'process':builds['tools/pool-action-modules/dist/private-runner-process'],
            'installation':builds['tools/pool-action-modules/dist/private-runner-installation.json'],
            'native':summary['preRuntimeArtifactSha256']['ordinary-pool-pk-load']},'cases':summary['resourceCases']}
    require_resource_receipt(value)
    return value

def native_control_command(readiness=False):
    command=['/usr/bin/python3','tools/apnt-pool-action-circuit/scripts/test-native-process-scan.py','--host',
        'NativeScan.test_kernel_scan_and_guard_fire_without_profile_loosening',
        'NativeScan.test_kernel_vanished_pid_einval_has_independent_exit_confirmation',
        'NativeScan.test_kernel_live_einval_recovery_preserves_named_prover_guard']
    if readiness:return command[:3]+['NativeScan.test_kernel_whole_host_inventory_availability_eng1459']
    return command

def require_readiness_receipt(receipt,candidate,fixture,source_sha):
    require(type(receipt) is dict and set(receipt)=={'schema','scope','passed','binding','workloadClass','workloadBasis',
            'maxUnavailablePerMode','completed','unavailable','elapsedNs'})
    require(receipt['schema']=='eng1459-readiness-v1' and receipt['scope']=='eng1436-repair-only' and receipt['passed'] is True
            and type(receipt['maxUnavailablePerMode']) is int and receipt['maxUnavailablePerMode']==0
            and receipt['workloadClass']=='permitted-build-exec' and receipt['workloadBasis']=='supervisor-declared-window'
            and type(receipt['elapsedNs']) is int and 0<=receipt['elapsedNs']<300_000_000_000)
    for key,expected in (('completed',150),('unavailable',0)):
        value=receipt[key]
        require(type(value) is dict and set(value)=={'pid','rss'} and all(type(number) is int and number==expected for number in value.values()))
    binding=receipt['binding']
    require(type(binding) is dict and set(binding)=={'candidateHead','fixtureHead','sourceSha256','binarySha256','profileSha256'}
            and all(type(value) is str and len(value)==(40 if key.endswith('Head') else 64)
                    and all(c in '0123456789abcdef' for c in value) for key,value in binding.items())
            and binding['candidateHead']==candidate and binding['fixtureHead']==fixture and binding['sourceSha256']==source_sha)

def slot_available(lock_path=None):
    """Allow a free slot or the inherited holder; never follow a lock symlink."""
    # ENG-1544 ordinary no-proof interim only; superseded by ENG-1526.
    if lock_path is None:
        lock_path = os.environ.get('BCH_CLOAK_TEST_SLOT_LOCK_PATH', '/private/tmp/bch-cloak-test-slot.lock')
        if not os.path.isabs(lock_path) or '\0' in lock_path or lock_path.endswith('/'): return False
        # Only explicit overrides use the bounded ASCII ordinary-gate namespace.
        # Strict resolution requires an existing physical parent; this is not a
        # general APFS alias detector. The absent-env shared default stays valid.
        if 'BCH_CLOAK_TEST_SLOT_LOCK_PATH' in os.environ:
            if re.fullmatch(r'bch-ordinary-gate[a-z0-9-]*\.lock', os.path.basename(lock_path)) is None: return False
            try:
                if str(Path(os.path.dirname(lock_path)).resolve(strict=True)) != '/private/tmp': return False
            except (OSError, RuntimeError): return False
        prover_paths = (f'/private/tmp/apnt-gnark-r2-proof-{os.getuid()}.lock',
                        '/private/tmp/bch-cloak-sp1-prover-exclusive-v1',
                        os.path.expanduser('~/proof-scratch/.prover.lock'))
        try:
            candidate = os.lstat(lock_path)
        except FileNotFoundError:
            candidate = None
        except OSError:
            return False
        if candidate is not None and not stat.S_ISREG(candidate.st_mode): return False
        for file in prover_paths:
            try: reserved = os.stat(file)
            except FileNotFoundError: continue
            except OSError: return False
            if candidate is not None and (candidate.st_dev, candidate.st_ino) == (reserved.st_dev, reserved.st_ino): return False
    if not os.path.lexists(lock_path): return True
    token = os.environ.get('BCH_CLOAK_TEST_SLOT_TOKEN')
    if not token: return False
    try:
        with os.fdopen(os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)) as lock:
            if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode): return False
            holder = json.load(lock)
        return isinstance(holder, dict) and holder.get('token') == token
    except (OSError, ValueError):
        return False

def main(argv, selection_class='ordinary'):
    os.umask(0o077)
    # Temporary repair-readiness selection; not a new permanent per-merge gate.
    readiness='--candidate-readiness-eng1459' in argv
    require(argv.count('--candidate-readiness-eng1459')<=1)
    argv=[value for value in argv if value!='--candidate-readiness-eng1459']
    if readiness:require(os.environ.get('MIG01_READINESS_WORKLOAD')=='permitted-build-exec')
    require(len(argv) <= 1 and slot_available())
    inventory=runtime_inventory()
    runtime_titles(selection_class,inventory)
    root = Path(argv[0]) if argv else Path(tempfile.mkdtemp(prefix='mig01-vr-runtime-', dir='/private/tmp'))
    require(root.is_absolute() and root.resolve() == root and root.parent.is_dir())
    require(subprocess.run(['/usr/bin/git','-C',str(root.parent),'rev-parse','--git-dir'], stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode != 0)
    if argv:
        require(not os.path.lexists(root)); root.mkdir(mode=0o700)
    fixture, raw, artifacts = [root / name for name in ('fixture-main', 'raw', 'observation-artifacts')]
    for path in (fixture, raw, artifacts): path.mkdir(mode=0o700)
    env = {k:os.environ[k] for k in ('HOME', 'USER', 'LOGNAME') if k in os.environ}
    env.update(PATH=str(NODE.parent)+':/opt/homebrew/bin:/usr/bin:/bin', LANG='C', TMPDIR='/private/tmp', GOENV='off', GOFLAGS='', GOPROXY='off', GOCACHE=str(root/'go-cache'))
    env['MIG01_RUNTIME_SELECTION']=selection_class
    summary = {'schema':'mig01-runtime-no-proof-v1', 'commands':[], 'suites':[], 'composition':[]}
    summary['toolchain']={'node':subprocess.check_output([str(NODE),'--version'],env=env).decode().strip(),
        'go':subprocess.check_output([GO,'version'],env=env).decode().strip(),
        'clang':subprocess.check_output(['/usr/bin/clang','--version'],env=env).decode().splitlines()[0]}
    def run(label, args, cwd=fixture, want=0):
        require(slot_available())
        if STAGE_DRIVER is not None:
            started=time.time()
            result=STAGE_DRIVER.logged_stage(label,args,cwd,env,raw/(label+'.log'),1800)
            summary['commands'].append({'label':label,'exit':result.returncode,'startedAt':started,'finishedAt':time.time()})
            (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
            if want is not None: require(result.returncode==want)
            return result.returncode
        tracked = label in {'runtime','poison-0','poison-1','restore-0','restore-1'}
        started = time.time(); last_change = time.monotonic(); size = -1; deadline = None if tracked else last_change + 1800; step = label
        control_limit = len(runtime_titles(selection_class)) if tracked else 0
        accepted = None; advances = 0
        (root/'active-step.json').write_text(json.dumps({'step':label,'at':started})+'\n')
        with (raw/(label+'.log')).open('xb') as sink:
            child = subprocess.Popen(args, cwd=cwd, env=env, stdout=sink, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while True:
                    try: status = child.wait(timeout=30); break
                    except subprocess.TimeoutExpired:
                        status = child.poll()
                        if status is not None: break
                        progress = artifacts/'runtime-steps.jsonl'
                        if tracked and progress.exists() and progress.stat().st_size != size:
                            size = progress.stat().st_size; require(size <= 1048576)
                            row = json.loads(progress.read_bytes().splitlines()[-1]); require(set(row) == {'at','control','step'} and row['step'] in STEPS and type(row['at']) is int and type(row['control']) is int)
                            # runtimeStep in mig01-runtime-controls.test.ts:159-163
                            # emits asynchronous/repeated labels, not STEPS order.
                            # Its global 8192-row guard bounds credit, including
                            # recurring P/A/W eligibility labels within a control.
                            position = (row['control'], row['step'])
                            if (1 <= row['control'] <= control_limit
                                    and advances < 8192
                                    and (accepted is None or (position != accepted[0] and position[0] >= accepted[0][0] and row['at'] > accepted[1]))
                                    and child.poll() is None):
                                accepted = (position, row['at']); advances += 1
                                step = row['step']; last_change = time.monotonic()
                        if (deadline is not None and time.monotonic() >= deadline) or (tracked and time.monotonic()-last_change >= 120):
                            os.killpg(child.pid, signal.SIGKILL); child.wait(); status = 124; summary['timeoutStep'] = step; break
            finally:
                if child.poll() is None: os.killpg(child.pid, signal.SIGKILL); child.wait()
        summary['commands'].append({'label':label, 'exit':status, 'startedAt':started, 'finishedAt':time.time()})
        (root/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
        print(label+' exit='+str(status)+(' step='+step if status == 124 else ''), flush=True)
        if want is not None: require(status == want)
        return status
    def git(*args):
        return subprocess.check_output(['/usr/bin/git','-C',str(REPO),*args], env=env, stderr=subprocess.DEVNULL)
    def suite(label, files, selection=None, want=0):
        output = raw/(label+'.json')
        args = [str(NODE.with_name('pnpm')),'exec','vitest','run',*files,'--maxWorkers=1','--minWorkers=1','--testTimeout=30000','--reporter=json','--outputFile='+str(output)]
        pattern=selection if selection is not None else (runtime_pattern(selection_class) if files==[TEST] else None)
        if pattern is not None: args += ['-t',pattern]
        status = run(label,args,want=None)
        result = json.loads(output.read_bytes())
        all_rows = [row for entry in result['testResults'] for row in entry['assertionResults']]
        require(all(type(row) is dict and row.get('status') in ('passed','failed','skipped','pending') for row in all_rows))
        require(all(type(result.get(key)) is int and result[key]>=0 for key in ('numPassedTests','numFailedTests','numPendingTests'))
                and type(result.get('success')) is bool)
        rows = [row for row in all_rows if row['status'] in ('passed','failed')]
        deselected = [row for row in all_rows if row['status'] in ('skipped','pending')]
        require(rows and len(rows) == result['numPassedTests']+result['numFailedTests']
                and sum(row['status']=='passed' for row in rows)==result['numPassedTests']
                and sum(row['status']=='failed' for row in rows)==result['numFailedTests']
                and len(deselected)==result['numPendingTests'])
        summary['suites'].append({'label':label,'tests':len(rows),'passed':result['numPassedTests'],'failed':result['numFailedTests'],
            'deselected':len(deselected),'rows':[{'name':r['fullName'],'status':r['status']} for r in rows]})
        (root/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
        print(label+' tests='+str(len(rows)), flush=True)
        require(status == want and (result['numFailedTests'] > 0 if want else result['success'] and result['numPassedTests'] == len(rows)))
        if files==[TEST]:
            accounting=require_runtime_selection(result,selection_class,selection,inventory)
            summary['suites'][-1]['selection']=accounting
        elif selection is None: require(len(rows) == 11)
    require(git('status','--porcelain') == b'' and subprocess.check_output([str(NODE),'--version'],env=env).strip() == b'v22.22.3')
    summary['sourceHead'] = git('rev-parse','HEAD').decode().strip()
    summary['sourceTree'] = git('rev-parse','HEAD^{tree}').decode().strip()
    archive = git('archive','--format=tar',summary['sourceHead'])
    summary['archiveSha256'] = hashlib.sha256(archive).hexdigest()
    subprocess.run(['/usr/bin/tar','-xf','-','-C',str(fixture)],input=archive,check=True,stderr=subprocess.DEVNULL)
    run('init',['/usr/bin/git','init','-b','main'])
    def commit(label, allow_empty=False):
        run(label+'-add',['/usr/bin/git','add','--force','.'])
        run(label+'-commit',['/usr/bin/git','-c','user.name=MIG01 Fixture','-c','user.email=fixture@invalid','-c','commit.gpgsign=false','commit',*(['--allow-empty'] if allow_empty else []),'-m','Disposable runtime test composition'])
    commit('source')
    require(git('rev-parse','HEAD^{tree}') == subprocess.check_output(['/usr/bin/git','rev-parse','HEAD^{tree}'],cwd=fixture,env=env))
    # The private test composition. Since C1 (GO) production carries it, so it is
    # verified in place: nothing is edited and the composition commit is empty.
    edits = [(PREFIX+'scripts/measure-pk-load.sh','readonly PRIVATE_RUNNER_GENERATION=1','readonly PRIVATE_RUNNER_GENERATION=2'),
             (PREFIX+'cmd/pool-pk-load/main.go','result := run(os.Args, runDeps{','result := runV2(os.Args, runDeps{')]
    for relative, old, new in edits:
        path=fixture/relative; text=path.read_text(); require(text.count(new)==1 and old not in text)
        summary['composition'].append({'path':relative,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    commit('composition', allow_empty=True)
    summary['fixtureHead']=subprocess.check_output(['/usr/bin/git','rev-parse','HEAD'],cwd=fixture,env=env).decode().strip()
    run('offline-install',[str(NODE.with_name('pnpm')),'install','--offline','--frozen-lockfile','--ignore-scripts','--store-dir',str(REPO/'.pnpm-store')])
    run('installation-build',['/usr/bin/python3','tools/pool-action-modules/private-runner-installation.py','--build'])
    run('ink-build',[str(NODE.with_name('pnpm')),'--filter','@bch-cloak/pool-wallet-ink','build'])
    circuit=fixture/PREFIX
    run('observer-build',['/usr/bin/clang','-O2','-Wall','-Wextra','-Werror','scripts/mig01-macos-observer.c','-lproc','-o',str(artifacts/'macos-observer')],circuit)
    run('ordinary-build',[GO,'build','-tags=','-o',str(artifacts/'ordinary-pool-pk-load'),'./cmd/pool-pk-load'],circuit)
    run('library-build',[GO,'build','-tags=','-o',str(artifacts/'ordinary-library-probe'),'scripts/mig01-library-probe.go'],circuit)
    def tagged(label): run(label,[GO,'test','-c','-tags=private_runner_admission_test','-o',str(artifacts/'tagged-dispatch.test'),'./cmd/pool-pk-load'],circuit)
    tagged('tagged-build')
    run('bridge-exec-controls',[GO,'test','-tags=','./internal/runneradmission','-run','TestMIG01(ActualExec|R3Private)','-count=1'],circuit)
    suite('lock-process',['tools/pool-action-modules/test/private-runner-lock-process.test.ts'])
    env['MIG01_TEST_OUTPUT_ROOT']=str(artifacts)
    if readiness:
        env['MIG01_READINESS_WORKLOAD']='permitted-build-exec'
        env['MIG01_READINESS_CANDIDATE']=summary['sourceHead']
    # Bounded real inventory/confirmed-exit supplement, not another P/A/W run.
    # Four are registered; the temporary fourth requires an explicit selection.
    run('native-inventory-guard-controls',native_control_command())
    if readiness:run('eng1459-whole-host-readiness',native_control_command(True))
    summary['nativeInventoryControls']={'selected':4 if readiness else 3,'exit':0}
    if readiness:
        receipt=json.loads((artifacts/'inventory-availability-closed.json').read_bytes())
        require_readiness_receipt(receipt,summary['sourceHead'],summary['fixtureHead'],hashlib.sha256((fixture/'tools/pool-action-modules/private-runner-process.c').read_bytes()).hexdigest())
        summary['eng1459Readiness']=receipt
    identity_paths=['tools/pool-action-modules/private-runner-process.c',PREFIX+'scripts/measure-pk-load.sh',
        PREFIX+'cmd/pool-pk-load/main.go',PREFIX+'cmd/pool-pk-load/live_harness.go',PREFIX+'scripts/mig01-macos-observer.c',
        PREFIX+'internal/runneradmission/bridge.go',PREFIX+'internal/runneradmission/harness.go',
        'tools/pool-action-modules/private-runner-bootstrap.mjs','tools/pool-action-modules/private-runner-bridge.mjs',
        'tools/pool-action-modules/private-runner-installation.py',TEST,
        PREFIX+'scripts/test-native-process-scan.py',PREFIX+'scripts/test-native-requery.py',
        PREFIX+'scripts/mig01-native-requery-host.c',PREFIX+'scripts/mig01-native-requery-controls.c',
        PREFIX+'scripts/test-native-inventory-availability.py',PREFIX+'scripts/mig01-runtime-selection.json']
    summary['fixtureSources']={path:hashlib.sha256((fixture/path).read_bytes()).hexdigest() for path in identity_paths}
    summary['buildIdentities']={path:hashlib.sha256((fixture/path).read_bytes()).hexdigest() for path in
        ('tools/pool-action-modules/dist/private-runner-process','tools/pool-action-modules/dist/private-runner-installation.json')}
    summary['preRuntimeArtifactSha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts.iterdir() if p.is_file()}
    print('runtime selection='+selection_class+'; ordinary operations take no startup/per-case memory admission; proving-key load/prove floors and legacy slot checks retained',flush=True)
    suite('runtime',[TEST])
    if selection_class=='resource':
        summary['resourceCases']=json.loads((artifacts/'resource-outcomes.json').read_bytes())
        summary['artifactSha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts.iterdir() if p.is_file()}
        (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        with (root/'resource-receipt.json').open('x') as sink:
            sink.write(json.dumps(resource_receipt(summary),indent=2)+'\n')
        return
    summary['registeredObservers']=json.loads((artifacts/'registered-observers.json').read_bytes())
    require(len(summary['registeredObservers'])==9 and all(r['passed']==1 and r['failed']==r['skipped']==0 for r in summary['registeredObservers']))
    summary['kernel']=json.loads((artifacts/'kernel-closed.json').read_bytes())
    path=circuit/'cmd/pool-pk-load/runner_admission_tagged_test.go'; original=path.read_text()
    for i, name in enumerate(OBSERVERS):
        selection='PH11-X direct tagged library' if i==0 else 'PH11-X tagged genuine'
        try:
            marker='func '+name+'(t *testing.T) {'; require(original.count(marker)==1)
            path.write_text(original.replace(marker,marker+'\n t.Fatal("synthetic-poisoned-observer")'))
            tagged('poison-build-'+str(i)); suite('poison-'+str(i),[TEST],selection,1)
        finally: path.write_text(original)
        tagged('restore-build-'+str(i)); suite('restore-'+str(i),[TEST],selection)
    summary['artifactSha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts.iterdir() if p.is_file()}
    (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')

if __name__ == '__main__':
    try: main(sys.argv[1:])
    except Exception:
        print('mig01-runtime-control-refused', file=sys.stderr); sys.exit(1)
