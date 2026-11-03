#!/usr/bin/python3
"""Opt-in one-row oracle discovery. Collection requires the separately approved PAM owner."""
import argparse, json, os, re, shutil, stat, subprocess, sys, time
from pathlib import Path
import importlib.util
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('setup_subject', Path(__file__).with_name('test-live-entry-no-proof.py'))
D = importlib.util.module_from_spec(spec); spec.loader.exec_module(D)
R = D.RUNTIME_ENTRY
I = D._load('setup_installation', D.REPO / 'tools/pool-action-modules/private-runner-installation.py')
CONTROLS = {'C2-c-main-dispatch':D.SETUP_HELPER_TITLE.format('stock'), 'C1-inbox-writer':D.INBOX_TITLE,
    **dict.fromkeys(('C9-stat','C9-grep','C9-validation','C9-execution-reopen'),D.SETUP_HELPER_TITLE.format('kernel'))}
PHASES = ('baseline', 'mutant', 'restored')
HELPER = 'expect({status,...JSON.parse(runnerDiagnostic(f))}).toMatchObject({status:1,\n    contacts:[1,1,1],deliveries:[1,1,1],outerRefusal:true,admissionCreated:true,\n    resultCreated:true,summaryCreated:false,memoryFloor:false,workFailure:false});'
CALLER = "runtimeStep('runner-complete');\n    requireFailClosed(f,status);"
def need(ok, code):
    if not ok: raise RuntimeError('setup-control-' + code)
def fresh(path, since=0, seen=None):
    info = path.lstat()
    need(path.resolve()==path and stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1 and info.st_mtime_ns>=since, 'fresh-file')
    if seen is not None:
        identity=(info.st_dev,info.st_ino); need(identity not in seen, 'duplicate-file'); seen.add(identity)
    return I.file_bytes(path.parent, path.name)
def write(path, value):
    with path.open('x') as sink: json.dump(value, sink, sort_keys=True)
def command(root, args, env, deadline, label, cwd=None, want=0):
    remaining=deadline-time.monotonic(); need(remaining>0, 'timeout')
    with (root/(label+'.log')).open('xb') as sink:
        result=subprocess.run(args, cwd=cwd or root/'fixture-main', env=env, stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT, timeout=remaining)
    need(result.returncode==want, 'child-exit')
def identity(fixture):
    receipt=D.capture_json(fresh(fixture/I.RECORD).decode()); entries=I.graph(fixture)
    need(receipt=={'schema':'private-runner-installation-record-v1','revision':D.git_output(fixture,'rev-parse','HEAD').decode().strip(),'entries':entries}, 'stale-build')
    return dict(installation=D.digest(json.dumps(entries,sort_keys=True).encode()),receipt=D.digest(fresh(fixture/I.RECORD)),observer=D.digest(fresh(fixture.parent/'macos-observer')))
def target(fixture, control):
    rows=[row for row in D.mutation_groups((fixture/D.SHELL).read_text()) if row[0]==control]
    need(len(rows)==1 and rows[0][1]==D.RUNTIME and re.search(rows[0][3],CONTROLS[control]), 'target')
    read=lambda path:(fixture/path).read_text()
    D.require_targets(read,rows); D.require_regular(fixture,[path for path,_,_ in rows[0][2]])
    return rows[0][2]
def firing(control, failure, fixture, inbox):
    need(type(failure) is dict and set(failure)=={'schema','failures'} and failure['schema']=='mig01-firing-failures-v1', 'firing-schema')
    failures=failure['failures']; need(type(failures) is list and len(failures)==1 and failures[0]['fullName']==CONTROLS[control] and len(failures[0]['errors'])==1, 'error-count')
    error=failures[0]['errors'][0]; need(set(error)=={'name','message','actual','stack'} and all(type(v) is str for v in error.values()) and 'timed out' not in error['message'].lower(), 'error')
    read=lambda path:(fixture/path).read_text()
    frames=D.stack_frames(error['stack'])
    if control=='C1-inbox-writer':
        D.require_bound_firing(control,[{'fullName':D.INBOX_TITLE,'status':'failed'}],[D.INBOX_TITLE],'^'+re.escape(D.INBOX_TITLE)+'$',failures,read,fixture,D.RUNTIME,inbox)
        return {'alternative':'inbox','error':error['name'],'actual':'undefined','projection':{},'frames':[[path,line,column] for (absolute,line,column),(path,_) in zip(frames,D.INBOX_CHAIN)],'inbox':inbox}
    alternative='terminal-leak' if error['actual']=='true' else 'helper'
    need(error['name']=='AssertionError' and len(frames)>= (2 if alternative=='helper' else 1), 'error-class')
    anchors=[(D.RUNTIME,D.TERMINAL_LEAK)] if alternative=='terminal-leak' else [(D.RUNTIME,HELPER),(D.RUNTIME,CALLER)]
    locations=[]; previous=None
    for path,anchor in anchors:
        text=read(path); D.anchor_line(text,anchor)
        expected,start,end=D.anchor_span(text,anchor.splitlines()[0] if anchor==HELPER else anchor)
        matches=[index for index,(absolute,line,column) in enumerate(frames) if absolute==str(fixture/path) and line==expected and start<=column<=end]
        need(len(matches)==1 and (previous is None or matches[0]==previous+1), 'location')
        previous=matches[0]; locations.append([path,*frames[previous][1:]])
    decoded=D.decode_setup_actual(control,CONTROLS[control],alternative,error['actual'])
    need(alternative!='helper' or (decoded['projection']!=D.HELPER_CONTRACT and not decoded['actual']['memoryFloor'] and not decoded['actual']['workFailure']), 'mutant-value')
    return dict(alternative=alternative,error='AssertionError',frames=locations,inbox=None,**decoded)
def phase(root, fixture, control, name, env, deadline):
    directory=root/name; directory.mkdir(mode=0o700)
    shutil.copy2(root/'macos-observer',directory/'macos-observer')
    output,report=directory/'result.json',directory/'firing.json'; since=time.time_ns(); seen=set()
    pattern='^'+re.escape(CONTROLS[control])+'$'; mutant=name=='mutant'
    child=dict(env,MIG01_RUNTIME_SELECTION='ordinary',MIG01_TEST_OUTPUT_ROOT=str(directory),MIG01_FIRING_REPORT=str(report))
    args=[str(D.PNPM),'exec','vitest','run',D.RUNTIME,'--maxWorkers=1','--minWorkers=1','--testTimeout=180000','--reporter=json','--outputFile='+str(output),'-t',pattern]
    if mutant:
        need(fresh(root/'firing-reporter.mjs')==D.FIRING_REPORTER.encode(), 'reporter'); args.append('--reporter='+str(root/'firing-reporter.mjs'))
    command(root,args,child,min(deadline,time.monotonic()+180),name,want=int(mutant))
    value=D.capture_json(fresh(output,since,seen).decode()); rows=D.vitest_rows(value,fixture)
    selection=R.require_runtime_selection(value,'ordinary',pattern)
    need(type(value['startTime']) is int and since//1000000<=value['startTime']<=time.time_ns()//1000000 and value['success']==(not mutant) and value['numFailedTestSuites']==int(mutant) and set(rows)=={D.RUNTIME}, 'phase')
    need(selection['selected']==1 and selection['deselected']==118 and rows[D.RUNTIME]==[next(row for row in rows[D.RUNTIME] if row['fullName']==CONTROLS[control])], 'row')
    observation=firing(control,D.capture_json(fresh(report,since,seen).decode()),fixture,D.capture_json(fresh(directory/'inbox-writer-observations.json',since,seen).decode()) if control=='C1-inbox-writer' else None) if mutant else None
    return dict(phase=name,exit=int(mutant),total=value['numTotalTests'],selected=selection['selected'],deselected=selection['deselected'],passed=value['numPassedTests'],failed=value['numFailedTests'],observation=observation)
def check_build(build):
    need(type(build) is dict and set(build)=={'installation','receipt','observer'} and all(type(v) is str and re.fullmatch(D.HEX64,v) for v in build.values()), 'build-type')
def check_identity(manifest):
    need(type(manifest) is dict and set(manifest)=={'head','tree','archive','collector','selection','build','fixture'}, 'identity-keys')
    for key,item in manifest.items():
        if key!='build': need(type(item) is str and re.fullmatch(D.HEX40 if key in ('head','tree','fixture') else D.HEX64,item), 'identity-type')
    check_build(manifest['build'])
def check_record(value):
    need(type(value) is dict and set(value)=={'schema','control','row','identity','builds','trees','revisions','phases','restored'}, 'record-keys')
    need(value['schema']=='setup-control-measurement-v1' and value['control'] in CONTROLS and value['row']==CONTROLS[value['control']], 'record-binding')
    need(value['restored'] is True, 'restoration')
    manifest=value['identity']; check_identity(manifest)
    need(type(value['builds']) is list and len(value['builds'])==3 and value['builds'][0]==value['builds'][2]==manifest['build'], 'builds')
    for build in value['builds']: check_build(build)
    for key,original in (('trees',manifest['tree']),('revisions',manifest['fixture'])):
        need(type(value[key]) is list and len(value[key])==3 and all(type(item) is str and re.fullmatch(D.HEX40,item) for item in value[key]) and value[key][0]==value[key][2]==original and value[key][1]!=original, 'revisions')
    need(type(value['phases']) is list and len(value['phases'])==3, 'phases')
    for name,row in zip(PHASES,value['phases']):
        want=dict(phase=name,exit=int(name=='mutant'),total=119,selected=1,deselected=118,passed=int(name!='mutant'),failed=int(name=='mutant'))
        need(type(row) is dict and set(row)=={*want,'observation'} and all(type(row[k]) is type(v) and row[k]==v for k,v in want.items()), 'phase-shape')
        observation=row['observation']
        if name!='mutant': need(observation is None, 'phase-observation'); continue
        need(type(observation) is dict and set(observation)=={'alternative','error','actual','projection','frames','inbox'}, 'observation-keys')
        alternative=observation['alternative']; frames=observation['frames']
        if value['control']=='C1-inbox-writer':
            need(alternative=='inbox' and observation['error']=='PrivateRunnerRefusal' and observation['actual']=='undefined' and observation['projection']=={}, 'inbox'); D.require_inbox_witness(observation['inbox'])
            paths=[path for path,_ in D.INBOX_CHAIN]
        else:
            decoded=D.decode_setup_actual(value['control'],value['row'],alternative,('' if alternative=='terminal-leak' else 'Object ')+json.dumps(observation['actual']))
            need(observation['error']=='AssertionError' and observation['inbox'] is None and json.dumps(decoded['projection'],sort_keys=True)==json.dumps(observation['projection'],sort_keys=True), 'actual'); paths=[D.RUNTIME]*(1 if alternative=='terminal-leak' else 2)
        need(type(frames) is list and len(frames)==len(paths) and all(type(f) is list and len(f)==3 and f[0]==p and all(type(n) is int and n>0 for n in f[1:]) for f,p in zip(frames,paths)), 'frames')
def terminal(root, record, deadline):
    pending=root/'measurement.pending.json'; write(pending,record)
    check_record(record)
    need(not os.path.lexists(root/'measurement.json') and D.capture_json(fresh(pending).decode())==record, 'terminal-file')
    need(deadline-time.monotonic()>0, 'timeout')
    pending.rename(root/'measurement.json') # Last operation: a later cleanup failure cannot leave a final record.
def verify_restoration(root, fixture, snapshot, paths, builds):
    need(builds[2]==builds[0] and identity(fixture)==builds[0] and all(I.file_bytes(fixture,path)==I.file_bytes(snapshot,path) for path in paths) and fresh(root/'macos-observer')==fresh(snapshot/'macos-observer') and D.git_output(fixture,'status','--porcelain')==b'', 'restoration')
def main(argv):
    parser=argparse.ArgumentParser(allow_abbrev=False); parser.add_argument('mode',choices=('prepare','observe')); parser.add_argument('--control',required=True,choices=tuple(CONTROLS)); parser.set_defaults(expected_head=os.environ.get('SETUP_HEAD','')); parser.add_argument('root',type=Path)
    args=parser.parse_args(argv); root=args.root; os.umask(0o077)
    need(root.is_absolute() and root.resolve()==root and root.parent==Path('/private/tmp') and re.fullmatch(D.HEX40,args.expected_head), 'arguments')
    need(D.git_output(D.REPO,'rev-parse','HEAD').decode().strip()==args.expected_head and D.git_output(D.REPO,'status','--porcelain')==b'', 'subject')
    env=dict(D.GIT_ENV,PATH=str(D.NODE.parent)+':/opt/homebrew/bin:/usr/bin:/bin',USER=D.ACCOUNT.pw_name,LOGNAME=D.ACCOUNT.pw_name,GOENV='off',GOFLAGS='',GOPROXY='off',GOCACHE=str(root/'go-cache'),RAYON_NUM_THREADS='4',CARGO_BUILD_JOBS='4',GIT_AUTHOR_NAME='Setup Fixture',GIT_AUTHOR_EMAIL='fixture@invalid',GIT_COMMITTER_NAME='Setup Fixture',GIT_COMMITTER_EMAIL='fixture@invalid')
    need(subprocess.check_output([str(D.NODE),'--version'],env=env)==b'v22.22.3\n','node')
    fixture=root/'fixture-main'; deadline=time.monotonic()+1200
    def run(label,command_args): command(root,command_args,env,deadline,label)
    def build(label):
        run(label+'-install',['/usr/bin/python3','tools/pool-action-modules/private-runner-installation.py','--build'])
        command(root,['/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',D.CIRCUIT+'scripts/mig01-macos-observer.c','-lproc','-o',str(root/'macos-observer')],env,deadline,label+'-observer')
        return identity(fixture)
    serial=0
    def git(*arguments):
        nonlocal serial
        serial+=1; run(args.mode+'-git-'+str(serial),['/usr/bin/git',*arguments])
    if args.mode=='prepare':
        root.mkdir(mode=0o700); fixture.mkdir(mode=0o700)
        head,inventory,archive=D.source_fixture(D.REPO,fixture)
        git('init','-b','main'); git('config','core.hooksPath','/dev/null'); git('config','commit.gpgsign','false')
        git('add','--force','.'); git('commit','-m','Disposable setup measurement fixture')
        D.verify_source_tree(D.REPO,fixture,head); D.compose(fixture); target(fixture,args.control)
        run('offline-install',[str(D.PNPM),'install','--offline','--frozen-lockfile','--ignore-scripts','--store-dir',str((D.REPO/'.pnpm-store').resolve())])
        manifest=dict(head=head,tree=D.git_output(fixture,'rev-parse','HEAD^{tree}').decode().strip(),archive=archive,collector=D.digest(Path(__file__).read_bytes()),selection=D.digest(R.SELECTION_FILE.read_bytes()),build=build('prepared'),fixture=D.git_output(fixture,'rev-parse','HEAD').decode().strip())
        write(root/'prepared.json',{'control':args.control,'identity':manifest}); (root/'firing-reporter.mjs').write_text(D.FIRING_REPORTER)
        return
    need(root.resolve()==root and root.stat().st_uid==os.geteuid() and stat.S_IMODE(root.stat().st_mode)==0o700 and (fixture/'.git').is_dir() and not (fixture/'.git').is_symlink(), 'fixture')
    (root/'attempt').mkdir(mode=0o700) # One attempt; refusal quarantines the fixture, never retries.
    need(not any(os.path.lexists(root/name) for name in ('measurement.json','measurement.pending.json')), 'terminal-exists')
    prepared=D.capture_json(fresh(root/'prepared.json').decode()); manifest=prepared['identity']; check_identity(manifest)
    need(set(prepared)=={'control','identity'} and prepared['control']==args.control and manifest['head']==args.expected_head and manifest['collector']==D.digest(Path(__file__).read_bytes()) and manifest['selection']==D.digest(R.SELECTION_FILE.read_bytes()), 'prepared')
    D.verify_source_tree(D.REPO,fixture,args.expected_head); D.compose(fixture)
    need(D.git_output(fixture,'rev-parse','HEAD^{tree}').decode().strip()==manifest['tree'], 'fixture-tree')
    need(D.git_output(fixture,'rev-parse','--show-toplevel').decode().strip()==str(fixture) and D.git_output(fixture,'branch','--show-current').strip()==b'main', 'fixture-git')
    need(D.git_output(fixture,'status','--porcelain')==b'' and D.git_output(fixture,'rev-parse','HEAD').decode().strip()==manifest['fixture'] and identity(fixture)==manifest['build'], 'prepared-build')
    edits=target(fixture,args.control); paths=sorted(set(D.git_output(fixture,'ls-files','-z').decode().strip('\0').split('\0')+[entry['path'] for entry in I.graph(fixture)]+[I.RECORD]))
    snapshot=root/'snapshot'; snapshot.mkdir(mode=0o700)
    for path in paths:
        D.require_regular(fixture,[path]); saved=snapshot/path; saved.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(fixture/path,saved)
    shutil.copy2(root/'macos-observer',snapshot/'macos-observer')
    builds=[identity(fixture)]; phases=[phase(root,fixture,args.control,'baseline',env,deadline)]; revisions=[manifest['fixture']]; trees=[manifest['tree']]
    try:
        need(target(fixture,args.control)==edits and identity(fixture)==builds[0], 'pre-mutation')
        for path,before,after in edits: (fixture/path).write_text((fixture/path).read_text().replace(before,after))
        git('add',*[path for path,_,_ in edits]); git('commit','-m',args.control)
        revisions.append(D.git_output(fixture,'rev-parse','HEAD').decode().strip()); trees.append(D.git_output(fixture,'rev-parse','HEAD^{tree}').decode().strip())
        builds.append(build('mutant')); phases.append(phase(root,fixture,args.control,'mutant',env,deadline))
    finally:
        for path,_,_ in edits: shutil.copy2(snapshot/path,fixture/path)
    # Only this newly prepared disposable repository is reset; the original revision/index returns.
    git('reset','--hard',manifest['fixture']); builds.append(build('restored'))
    verify_restoration(root,fixture,snapshot,paths,builds)
    revisions.append(D.git_output(fixture,'rev-parse','HEAD').decode().strip()); trees.append(D.git_output(fixture,'write-tree').decode().strip())
    phases.append(phase(root,fixture,args.control,'restored',env,deadline))
    need(deadline-time.monotonic()>0, 'timeout')
    verify_restoration(root,fixture,snapshot,paths,builds)
    need(deadline-time.monotonic()>0, 'timeout')
    terminal(root,dict(schema='setup-control-measurement-v1',control=args.control,row=CONTROLS[args.control],identity=manifest,builds=builds,trees=trees,revisions=revisions,phases=phases,restored=True),deadline)
if __name__=='__main__':
    try: main(sys.argv[1:])
    except Exception as error:
        print('setup-control-timeout' if str(error)=='setup-control-timeout' else 'setup-control-refused',file=sys.stderr); sys.exit(1)
