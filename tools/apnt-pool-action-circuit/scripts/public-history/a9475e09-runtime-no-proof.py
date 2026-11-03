#!/usr/bin/python3
"""Outside-sandbox, no-proof entry; only closed summaries may be archived."""
import hashlib, json, os, signal, stat, subprocess, sys, tempfile, time
import pwd
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
NODE = Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.nvm/versions/node/v22.22.3/bin/node'
GO = '/opt/homebrew/bin/go'
PREFIX = 'tools/apnt-pool-action-circuit/'
TEST = 'tools/pool-action-modules/test/mig01-runtime-controls.test.ts'
OBSERVERS = ['TestMIG01R3RegisteredLibraryObservation', 'TestMIG01R3RegisteredDispatchObservation']
STEPS = set('control-start eligibility-start eligibility-complete eligibility-refused kernel-spawn observer-close runner-exit runner-close contact-P contact-A contact-W delivery-P delivery-A delivery-W kernel-canary-start kernel-canary-complete kernel-allow-start kernel-deny-start kernel-alias-allow-start kernel-alias-deny-start kernel-probes-complete classification-start classification-ready cleanup-start classification-closed cleanup-complete runner-wait runner-complete'.split())

def require(ok):
    if not ok: raise RuntimeError('mig01-runtime-control-refused')

def slot_available(lock_path='/private/tmp/bch-cloak-test-slot.lock'):
    """Allow a free slot or the inherited holder; never follow a lock symlink."""
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

def main(argv):
    os.umask(0o077)
    require(len(argv) <= 1 and slot_available())
    root = Path(argv[0]) if argv else Path(tempfile.mkdtemp(prefix='mig01-vr-runtime-', dir='/private/tmp'))
    require(root.is_absolute() and root.resolve() == root and root.parent.is_dir())
    require(subprocess.run(['/usr/bin/git','-C',str(root.parent),'rev-parse','--git-dir'], stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode != 0)
    if argv:
        require(not os.path.lexists(root)); root.mkdir(mode=0o700)
    fixture, raw, artifacts = [root / name for name in ('fixture-main', 'raw', 'observation-artifacts')]
    for path in (fixture, raw, artifacts): path.mkdir(mode=0o700)
    env = {k:os.environ[k] for k in ('HOME', 'USER', 'LOGNAME') if k in os.environ}
    env.update(PATH=str(NODE.parent)+':/opt/homebrew/bin:/usr/bin:/bin', LANG='C', TMPDIR='/private/tmp', GOENV='off', GOFLAGS='', GOPROXY='off', GOCACHE=str(root/'go-cache'))
    summary = {'schema':'mig01-runtime-no-proof-v1', 'commands':[], 'suites':[], 'composition':[]}
    def run(label, args, cwd=fixture, want=0):
        require(slot_available())
        tracked = label in {'runtime','poison-0','poison-1','restore-0','restore-1'}
        started = time.time(); last_change = time.monotonic(); size = -1; deadline = last_change + 1800; step = label
        (root/'active-step.json').write_text(json.dumps({'step':label,'at':started})+'\n')
        with (raw/(label+'.log')).open('xb') as sink:
            child = subprocess.Popen(args, cwd=cwd, env=env, stdout=sink, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while True:
                    try: status = child.wait(timeout=30); break
                    except subprocess.TimeoutExpired:
                        progress = artifacts/'runtime-steps.jsonl'
                        if tracked and progress.exists() and progress.stat().st_size != size:
                            size = progress.stat().st_size; require(size <= 1048576)
                            row = json.loads(progress.read_bytes().splitlines()[-1]); require(set(row) == {'at','control','step'} and row['step'] in STEPS and type(row['at']) is int and type(row['control']) is int)
                            step = row['step']; last_change = time.monotonic()
                        if time.monotonic() >= deadline or (tracked and time.monotonic()-last_change >= 120):
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
        if selection: args += ['-t',selection]
        status = run(label,args,want=None)
        result = json.loads(output.read_bytes())
        rows = [row for entry in result['testResults'] for row in entry['assertionResults'] if row['status'] != 'pending']
        require(rows and len(rows) == result['numPassedTests']+result['numFailedTests'])
        summary['suites'].append({'label':label,'tests':len(rows),'passed':result['numPassedTests'],'failed':result['numFailedTests'], 'rows':[{'name':r['fullName'],'status':r['status']} for r in rows]})
        (root/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
        print(label+' tests='+str(len(rows)), flush=True)
        require(status == want and (result['numFailedTests'] > 0 if want else result['success'] and result['numPassedTests'] == len(rows)))
        if selection is None: require(len(rows) == (117 if files == [TEST] else 11))
    require(git('status','--porcelain') == b'' and subprocess.check_output([str(NODE),'--version'],env=env).strip() == b'v22.22.3')
    summary['sourceHead'] = git('rev-parse','HEAD').decode().strip()
    archive = git('archive','--format=tar',summary['sourceHead'])
    summary['archiveSha256'] = hashlib.sha256(archive).hexdigest()
    subprocess.run(['/usr/bin/tar','-xf','-','-C',str(fixture)],input=archive,check=True,stderr=subprocess.DEVNULL)
    run('init',['/usr/bin/git','init','-b','main'])
    def commit(label):
        run(label+'-add',['/usr/bin/git','add','--force','.'])
        run(label+'-commit',['/usr/bin/git','-c','user.name=MIG01 Fixture','-c','user.email=fixture@invalid','-c','commit.gpgsign=false','commit','-m','Disposable runtime test composition'])
    commit('source')
    require(git('rev-parse','HEAD^{tree}') == subprocess.check_output(['/usr/bin/git','rev-parse','HEAD^{tree}'],cwd=fixture,env=env))
    # Explicit disposable composition; no lane selector or guard edits.
    edits = [(PREFIX+'scripts/measure-pk-load.sh','readonly PRIVATE_RUNNER_GENERATION=1','readonly PRIVATE_RUNNER_GENERATION=2'),
             (PREFIX+'cmd/pool-pk-load/main.go','result := run(os.Args, runDeps{','result := runV2(os.Args, runDeps{')]
    for relative, old, new in edits:
        path=fixture/relative; text=path.read_text(); require(text.count(old)==1); path.write_text(text.replace(old,new))
        summary['composition'].append({'path':relative,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    commit('composition')
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
    suite('runtime',[TEST])
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
