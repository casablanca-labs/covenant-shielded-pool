// OUTSIDE-SANDBOX, no-proof controls. The Python entry creates a clean main
// fixture and rebuilds its actual installation. Production/tagged binaries are
// separate. No production dependency, registry or native decoder is injectable.
import { createHash, createHmac } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { spawn, spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync, lstatSync, readdirSync, rmSync, unlinkSync, symlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterAll, beforeEach, expect, test, vi } from 'vitest';
import { pathToFileURL } from 'node:url';
import { secp256k1 } from '@bitauth/libauth';
import { observerDiagnostic } from './mig01-observer-diagnostic.mjs';
const observation = vi.hoisted(() => ({ mode: 'stock', after: '', expectation: '', operation: 'check-live', refusals: [] as any[], clock: 0, contacts: [] as string[], deliveries: [] as string[], stdout:[] as Buffer[], stderr:[] as Buffer[], terminalBytes:0,
  inboxCall: null as null | { token: object; store: string; request: string; calls: number; returned: number; matched: number },
  afterFresh:null as any, freshReads:0,kernelReadControls:null as any,responseEdit:null as null | ((bytes:Buffer)=>Buffer), invalidAnchorPhase:'', planCaptures:0, requestCaptures:0, planAcquisitions:0, requestAcquisitions:0, planIdentity:null as any, requestIdentity:null as any, readFailure: '', requestOverride: null as any, issuerLock: '', ready: null as null | (() => void), child: null as any, plan: '', request: '', profile: '', descriptorResult: null as null | Promise<any> }));
vi.mock('../payment-child-plan.mjs', async original => {
  const actual: any = await original();
  return { ...actual, actionChildPlanValues: (...args: any[]) => {
    // Synthetic fixture input only: the key-free formatter selects check-live.
    // The real writer authenticates it against the genuine native construction;
    // no test-only field or mode is added to any production writer or registry.
    if (observation.expectation && !['ok','fail','refuse-open'].includes(observation.expectation)) throw new Error('no-proof-fixture-required');
    // Operation is explicit test-fixture authority, never inferred from EXPECT.
    const replacement = ` ${observation.expectation || 'ok'} ${observation.operation} `;
    const text = actual.actionChildPlanValues(...args).replace(' ok prove ', replacement);
    if (!text.includes(replacement) || text.includes(' ok prove ')) throw new Error('no-proof-fixture-required');
    return text;
  }};
});
// Descriptor reads include native-source authentication by the inherited
// source-facts reader. Count the issuer's snapshot acquisition calls separately.
vi.mock('../lib/private-runner-route.mjs',async original=>{
  const actual:any=await original();return {...actual,
    withHarnessRunnerPlan:(...args:any[])=>{observation.planAcquisitions++;return actual.withHarnessRunnerPlan(...args);},
    withHarnessRunnerConstruction:(...args:any[])=>{observation.requestAcquisitions++;return actual.withHarnessRunnerConstruction(...args);},
  };
});
vi.mock('../lib/private-runner-eligibility.mjs',async original=>{
  const actual:any=await original();return {...actual,readHarnessRunnerEligibility:async(...args:any[])=>{observation.freshReads++;runtimeStep('eligibility-start');try{const result=await actual.readHarnessRunnerEligibility(...args);observation.afterFresh?.();runtimeStep('eligibility-complete');return result;}catch(error){runtimeStep('eligibility-refused');throw error;}}};
});
vi.mock('../../../packages/reference-wallet/dist/apnt_pool_wallet_inbox_v1.js',async original=>{
  const actual:any=await original();return {...actual,requireHarnessInboxConstruction:(...args:any[])=>{
    const call=observation.inboxCall;
    if(call)call.calls++;
    // Retain the actual module/token identity and refusal behavior. Only a
    // successful return, for this synchronous invocation's exact arguments,
    // can supply the witness. No mutant-created marker participates.
    const value=actual.requireHarnessInboxConstruction(...args);
    if(call){call.returned++;if(args.length===3&&args[0]===call.token&&args[1]===call.store&&args[2]===call.request)call.matched++;}
    return value;
  }};
});
vi.mock('../../../packages/reference-wallet/dist/apnt_pool_wallet_owner_v1.js',async original=>{
  const actual:any=await original();return {...actual,requireHarnessActionCurrentness:(entry:any,input:any)=>{
    if(observation.invalidAnchorPhase===observation.contacts.at(-1)){const record=input.record.slice();record[0]^=1;input={...input,record};}
    return actual.requireHarnessActionCurrentness(entry,input);
  }};
});
vi.mock('node:fs', async original => {
  const actual:any=await original();
  return {...actual,readFileSync:(file:any,...args:any[])=>{
    if(typeof file==='number') {const st=actual.fstatSync(file);
      for(const [identity,count] of [[observation.planIdentity,'planCaptures'],[observation.requestIdentity,'requestCaptures']] as const)
        if(identity&&st.dev===identity.dev&&st.ino===identity.ino)(observation as any)[count]++;
    }
    return actual.readFileSync(file,...args);
  }};
});
vi.mock('node:child_process', async original => {
  const actual: any = await original();
  return { ...actual, spawn: (binary: string, args: string[], options: any) => {
    if (binary === 'bash' && args[0] === 'tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh') {
      expect(args[3]).toBe('4'); expect(args.length).toBe(4);
      expect(options.stdio).toBe('inherit');
      // Observe the two terminal streams without emitting their bytes. The
      // production E1 launcher and its inherited-stdio selection stay intact.
      const observedOptions={...options,stdio:['ignore','pipe','pipe']};
      let child: any;
      if (observation.mode === 'manual') {
        // Tagged dispatch is tested separately from real ancestry. Only this
        // test's child scheduling is controlled; the real registrar is used.
        child = new EventEmitter(); child.kill = () => { queueMicrotask(() => child.emit('close', 1)); return true; };
      } else if (observation.mode === 'kernel') {
        runtimeStep('kernel-spawn');
        child = actual.spawn('/usr/bin/sandbox-exec', ['-p', observation.profile, '/bin/bash', ...args], observedOptions);
        const observer = actual.spawn(join(process.env.MIG01_TEST_OUTPUT_ROOT!,'macos-observer'),[String(child.pid),observation.plan,observation.request],{stdio:['pipe','pipe','pipe']});
        let metadata='';observer.stdout.on('data',(bytes:Buffer)=>metadata+=bytes.toString('utf8'));
        let diagnosticBytes=Buffer.alloc(0);
        observer.stderr.on('data',(bytes:Buffer)=>{if(diagnosticBytes.length<=256)diagnosticBytes=Buffer.concat([diagnosticBytes,bytes]);});
        child.once('close',()=>observer.stdin.end('stop'));
        observation.descriptorResult=new Promise(resolveMetadata=>observer.once('close',(code:number)=>{
          runtimeStep('observer-close');
          // Only the observer's fixed reason/errno record can enter diagnostics.
          const diagnostic=observerDiagnostic(diagnosticBytes);
          resolveMetadata({code,value:JSON.parse(metadata),diagnostic});
        }));
      } else child = actual.spawn(binary, args, observedOptions);
      child.once('exit',()=>runtimeStep('runner-exit'));child.once('close',()=>runtimeStep('runner-close'));
      for(const stream of ['stdout','stderr'] as const) child[stream]?.on('data',(bytes:Buffer)=>{
        observation.terminalBytes+=bytes.length;
        if(observation.terminalBytes<=1024*1024)observation[stream].push(bytes);else child.kill('SIGTERM');
      });
      observation.child = child; observation.ready?.(); return child;
    }
    return actual.spawn(binary, args, options);
  }};
});
vi.mock('node:net', async original => {
  const actual: any = await original();
  return { ...actual, createServer: (...args: any[]) => {
    const at = args.findIndex(value => typeof value === 'function'), listener = args[at];
    if (at >= 0) args[at] = (socket: any) => {
      let input = '';
      socket.on('data', (bytes: Buffer) => {
        input += bytes.toString('utf8');
        if (input.includes('\n')) { try { const value = JSON.parse(input.trim());
          if (value.schema === 'private-runner-admit-v1') {observation.contacts.push(value.phase);if(['P','A','W'].includes(value.phase))runtimeStep('contact-'+value.phase);}
        } catch {} }
      });
      const end = socket.end.bind(socket);
      socket.end = (bytes: any, ...rest: any[]) => {
        if (Buffer.isBuffer(bytes) && bytes.length >= 8) { try {
          const length = bytes.readUInt32BE(0), value = JSON.parse(bytes.subarray(8, 8 + length).toString('utf8')).value;
          if (value.schema === 'private-runner-snapshot-v1') {
            observation.deliveries.push(value.phase);
            if(['P','A','W'].includes(value.phase))runtimeStep('delivery-'+value.phase);
            if (observation.after === value.phase) observation.clock = 600001;
          }
          if (value.schema === 'private-runner-refusal-v1') {
            observation.refusals.push(value.error);
            if (observation.responseEdit) bytes=observation.responseEdit(bytes);
          }
        } catch {} }
        return end(bytes, ...rest);
      };
      return listener(socket);
    };
    return actual.createServer(...args);
  }};
});
import { constructionFixture } from './private-runner-construction.fixture.ts';
import { PrivateRunnerRefusal, writeHarnessProverRequest, writeHarnessRunnerPlan } from '../lib/private-runner-route.mjs';
import { privateRunnerCase } from '../lib/private-runner-plan.mjs';
import { canonicalJson } from '../lib/canonical.mjs';
import { artifactText, sealArtifact } from '../lib/artifact.mjs';
import { servePartySockets } from '../../pool-multiparty-sim/lib/party-socket-server.mjs';
import * as keystore from '../lib/keystore.mjs';
import * as walletKeys from '../../../packages/reference-wallet/dist/apnt_pool_wallet_keys_v1.js';
import { createCommands } from '../../../packages/pool-wallet-host/dist/commands.js';
import { walletSecrets } from '../../../packages/pool-wallet-host/dist/host.js';
const ROOT = resolve('.'), OUTPUT = process.env.MIG01_TEST_OUTPUT_ROOT;
// Observe the package-private function without exporting a production
// registrar. The disposable source copy keeps its body byte-identical and
// resolves imports/meta to the original installation, preserving the native
// construction module identity and this test's child scheduling observation.
if (!OUTPUT) throw new Error('outside-clean-main-driver-required');
let stepCount=0,controlCount=0;
// Fixed labels and timestamps only: no argv, paths, streams, IPC or wallet data.
function runtimeStep(step:string) {
  if(++stepCount>8192)throw new Error('runtime-step-limit');
  appendFileSync(join(OUTPUT!,'runtime-steps.jsonl'),JSON.stringify({at:Date.now(),control:controlCount,step})+'\n',{mode:0o600});
}
beforeEach(()=>{controlCount++;runtimeStep('control-start');});
const registrarURL=new URL('../harness-private-runner.mjs',import.meta.url);
let registrar=readFileSync(registrarURL,'utf8');
if(registrar.includes('export { withHarnessRunnerClassification }'))throw new Error('production-registrar-export-refused');
registrar=registrar.replace(/from ["']([^"']+)["']/g,(_match,specifier:string)=>`from ${JSON.stringify(specifier.startsWith('.')?new URL(specifier,registrarURL).href:specifier)}`)
  .replace(/\bimport\.meta\.url\b/g,JSON.stringify(registrarURL.href));
const observerSource=join(OUTPUT,'registrar-observation.mjs');
writeFileSync(observerSource,registrar+'\nexport { withHarnessRunnerClassification };\n',{mode:0o600,flag:'wx'});
const observerIdentity=lstatSync(observerSource);
afterAll(()=>{
  const now=lstatSync(observerSource);
  if(now.isFile()&&now.dev===observerIdentity.dev&&now.ino===observerIdentity.ino)unlinkSync(observerSource);
});
const {withHarnessRunnerClassification}=await import(/* @vite-ignore */ pathToFileURL(observerSource).href);
const GO = '/opt/homebrew/bin/go';
const goEnv = { ...process.env, GOENV: 'off', GOFLAGS: '', GOPROXY: 'off' };
const observerRows: { name: string; expectation: string; passed: number; failed: number; skipped: number }[] = [];
// Private diagnostic evidence for the mutation driver's exact Go assertion binding.
// This sidecar is never printed or copied into a closed summary.
const observerDiagnostics: {name:string; expectation:string; output:string; stderr:string}[] = [];
const inboxWriterRows: any[] = [];
afterAll(() => {
  writeFileSync(join(OUTPUT!, 'registered-observers.json'), JSON.stringify(observerRows)+'\n', {mode:0o600});
  writeFileSync(join(OUTPUT!, 'registered-observer-diagnostics.json'), JSON.stringify(observerDiagnostics)+'\n', {mode:0o600});
  writeFileSync(join(OUTPUT!, 'inbox-writer-observations.json'), JSON.stringify({schema:'mig01-inbox-writer-v1',rows:inboxWriterRows})+'\n', {mode:0o600});
});
function writeObservedInboxRequest(f:any) {
  expect(observation.inboxCall).toBeNull();expect(f.context.kind).toBe('inbox-deposit');
  const absent=(path:string)=>lstatSync(path,{throwIfNoEntry:false})===undefined;
  const before=f.stateDigests(), files=[f.source,f.source+'.runner-construction.json',f.source+'.runner-route.json'];
  expect(files.map(absent)).toEqual([true,true,true]);
  const call={token:f.token,store:f.paths.store,request:f.request,calls:0,returned:0,matched:0};
  observation.inboxCall=call;
  let returned=false,failure:any,stdoutBytes=0,stderrBytes=0;
  const out=vi.spyOn(process.stdout,'write').mockImplementation((bytes:any)=>{stdoutBytes+=Buffer.byteLength(bytes);return true;});
  const err=vi.spyOn(process.stderr,'write').mockImplementation((bytes:any)=>{stderrBytes+=Buffer.byteLength(bytes);return true;});
  try {
    writeHarnessProverRequest(f.paths,f.actionId,f.request,f.token,f.context);
    returned=true;
  } catch(error) {failure=error;}
  finally {observation.inboxCall=null;out.mockRestore();err.mockRestore();}
  const row={row:'PH11-ROUTE-WRITER genuine inbox source reaches the authenticated P/A/W issuer',invocation:inboxWriterRows.length+1,
    outcome:returned?'returned':'refused',guardCalls:call.calls,guardReturns:call.returned,matchingReturns:call.matched,
    assertionActualAbsent:returned||(failure!==null&&typeof failure==='object'&&!Object.hasOwn(failure,'actual')),
    stateUnchanged:JSON.stringify(f.stateDigests())===JSON.stringify(before),requestAbsent:absent(files[0]),receiptAbsent:absent(files[1]),routeAbsent:absent(files[2]),
    requestsAbsent:absent(f.paths.requests),planAbsent:absent(join(f.home,'plan-control')),runnerAbsent:observation.child===null,
    contacts:observation.contacts.length,deliveries:observation.deliveries.length,stdoutBytes,stderrBytes};
  inboxWriterRows.push(row);
  expect([row.assertionActualAbsent,row.stateUnchanged,row.planAbsent,row.runnerAbsent,row.contacts,row.deliveries,stdoutBytes,stderrBytes]).toEqual([true,true,true,true,0,0,0,0]);
  expect([call.calls,call.returned,call.matched]).toEqual(returned?[2,2,2]:[1,1,1]);
  expect([row.requestAbsent,row.receiptAbsent,row.routeAbsent,row.requestsAbsent]).toEqual(returned?[false,false,false,false]:[true,true,true,true]);
  if(!returned){
    expect(failure).toBeInstanceOf(PrivateRunnerRefusal);
    expect(failure.value).toEqual({code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-payment-host-authority-required'});
    throw failure; // Preserve the actual sourceConstruction rethrow stack.
  }
}
async function registeredObserver(f: any, name: string, phase: 'A'|'W', expectation: string) {
  const r = await execution(join(OUTPUT!, 'tagged-dispatch.test'), ['-test.v', `-test.run=^${name}$`], {
    env: {...goEnv, MIG01_TEST_RUN_ARGUMENTS: JSON.stringify(nativeArguments(f, phase)), MIG01_TEST_EXPECT: expectation},
  });
  // Go exits zero for an empty selection and for a skipped observer. Count the
  // actual named execution independently; never render its captured stream.
  const rows = r.out.toString('utf8').split('\n');
  const count = (status: string) => rows.filter(row => row.startsWith(`--- ${status}: ${name} (`)).length;
  const result = {name, expectation, passed:count('PASS'), failed:count('FAIL'), skipped:count('SKIP')};
  observerRows.push(result);
  observerDiagnostics.push({name, expectation, output:r.out.toString('utf8'), stderr:r.err.toString('utf8')});
  expect(rows.filter(row => row === `=== RUN   ${name}`)).toHaveLength(1);
  expect([r.status,result.passed,result.failed,result.skipped]).toEqual([0,1,0,0]);
}
function execution(binary: string, args: string[], options: any = {}) {
  const child = spawn(binary, args, { cwd: ROOT, env: process.env, stdio: ['ignore', 'pipe', 'pipe'], ...options });
  let out = Buffer.alloc(0), err = Buffer.alloc(0);
  child.stdout!.on('data', bytes => out = Buffer.concat([out, bytes])); child.stderr!.on('data', bytes => err = Buffer.concat([err, bytes]));
  return new Promise<{status:number|null;out:Buffer;err:Buffer}>(resolveResult => child.once('close', status => resolveResult({status,out,err})));
}
async function completeRestoreScan(f: any) {
  const paths = keystore.pathsUnder(f.home, f.context.handle.walletId);
  writeFileSync(paths.seed, f.syntheticSeed32, { mode: 0o600, flag: 'wx' });
  const chainFile = join(f.home, 'scan-chain.json');
  writeFileSync(chainFile, JSON.stringify(f.context.chain), { mode: 0o600 });
  const config = { backend: 'local' as const, walletHome: f.home, deployment: Buffer.from(f.context.handle.deploymentId32).toString('hex'), runDirectory: join(f.home, 'scan-run'), chainFile };
  const secrets = walletSecrets(paths, f.context.handle.deploymentId32);
  // The harness-only synthetic home is scanned through the real host command
  // and wallet modules. This scan-only adapter does not enroll it as a host
  // home, register a payment writer, or create native preparation authority.
  const commands = createCommands({ home: f.home, walletId: f.context.handle.walletId, paths, deploymentId32: f.context.handle.deploymentId32, secrets }, config,
    { instance: f.context.handle.walletId, epoch: '0123456789abcdeffedcba9876543210', network: 'local', deployment: config.deployment, zeroValue: true, keystore: 'test-0600' }, new Uint8Array(32));
  try {
    const result: any = await commands.command('wallet.scan', {}, 'owner');
    expect(result.restoreScan).toBe('not-pending');
    expect(result.scannedThrough).toBe(String(f.recorded.ledger.tip.height));
  } finally { commands.stop(); Object.values(secrets).forEach(value => value.fill(0)); }
}
async function registered(mode: string, after: string, use: (f: any) => Promise<void>, expectation = '', readFailure = '', options: { kind?: string; plan?: string; poison?:string; completeScan?: boolean; operation?: 'prove' } = {}) {
  if (!OUTPUT || !lstatSync(join(ROOT,'.git')).isDirectory()) throw new Error('outside-clean-main-driver-required');
  const f = await constructionFixture(true, options.kind ?? 'invoice-payment');
  let observing = false;
  let server: any, finished: Promise<number> | undefined, clock: any,seedTrap:any,rootTrap:any,signTrap:any,membershipTrap:any,mints=0,environmentRestore:Record<string,string|undefined>={};
  try {
    server = await servePartySockets({ label:'mig01-no-proof', parties:['payer'], transcriptDir:join(f.home,'transcripts'),
      handle: (_: string, method: string, params: any[]) => {
        if (!observing) return f.recorded!.request(null, method, params);
        if(observation.readFailure===observation.contacts.at(-1))throw new Error('synthetic-chain-read-refused');
        // The bridge has already released its lock before the issuer's fresh
        // asynchronous read. This independently held lock targets the issuer.
        if(observation.issuerLock&&!existsSync(observation.issuerLock))writeFileSync(observation.issuerLock,'synthetic-holder',{mode:0o600,flag:'wx'});
        return (observation.requestOverride ?? f.recorded!.request)(null,method,params);
      } });
    f.context.chain.endpoint.port = server.ports.payer;
    // Setup completes the wallet's own scan before runtime observation,
    // forbidden-effect traps, state digests, classification or P acquisition.
    if (options.completeScan !== false) await completeRestoreScan(f);
    observation.afterFresh=null;observation.responseEdit=null;observation.invalidAnchorPhase='';observation.planCaptures=0;observation.requestCaptures=0;observation.planAcquisitions=0;observation.requestAcquisitions=0;observation.planIdentity=null;observation.requestIdentity=null;observation.requestOverride = null; observation.stdout=[];observation.stderr=[];observation.terminalBytes=0;observation.mode = mode; observation.operation=options.operation ?? 'check-live'; observation.refusals=[]; observation.after = after; observation.expectation = expectation; observation.readFailure=readFailure;observation.issuerLock='';observation.clock = 0; observation.contacts = []; observation.deliveries = [];
    observation.freshReads=0;
    observation.kernelReadControls=null;
    observing = true;
    if(f.context.kind==='inbox-deposit')writeObservedInboxRequest(f);
    else writeHarnessProverRequest(f.paths,f.actionId,f.request,f.token,f.context);
    const dir = join(f.home,'plan-control'); mkdirSync(dir,{mode:0o700});
    const output = join(dir,'native-output'), plan = join(dir,'child.plan'); observation.plan = plan; observation.request = f.source;
    const flags = { payment:join(dir,'payment.json'),wallet:join(dir,'wallet.json'),'wallet-home':f.home,
      key:join(dir,'absent-pk'),r1cs:join(dir,'absent-r1cs'),vk:join(dir,'absent-vk'),plan,kind:f.context.kind,backend:'local' };
    writeFileSync(flags.payment,JSON.stringify({ok:true,agentFacing:{module:'p2-action',backend:'local',summary:{actionId:f.actionId,kind:f.context.kind,
      proverRequest:{entry:f.context.kind==='inbox-deposit'?'wallet-self-deposit':'wallet-payment',private:true,handedOff:false,where:`private/requests/${f.actionId}.json`}}}}),{mode:0o600});
    writeFileSync(flags.wallet,artifactText(sealArtifact({kind:'wallet-handle',network:'local-regtest',producer:{source:'genuine synthetic construction'},payload:f.context.handle})),{mode:0o600});
    writeHarnessRunnerPlan(flags);
    const bytes = readFileSync(plan), selected = privateRunnerCase(bytes,f.source,output);
    expect(selected.command).toBe(options.operation ?? 'check-live');
    if(process.env.MIG01_RUNTIME_SELECTION==='ordinary'&&selected.command!=='check-live')throw new Error('ordinary-private-operation-refused'); expect([existsSync(flags.key),existsSync(flags.r1cs),existsSync(flags.vk)]).toEqual([false,false,false]);
    // Independent profile allow/deny controls precede reliance on the observer.
    observation.profile = `(version 1) (allow default) (deny file-read* (literal ${JSON.stringify(plan)}))`;
    if (mode === 'kernel') {
      runtimeStep('kernel-canary-start');
      const canary=spawnSync(join(OUTPUT,'macos-observer'),['--canary',plan],{encoding:'utf8'});
      const canaryFacts=JSON.parse(canary.stdout);
      expect(canary.status, JSON.stringify({source:canaryFacts.sourceFstatDetectorFires===true,transport:canaryFacts.transportFstatDiffers===true,diagnosticBytes:canary.stderr.length})).toBe(0);expect(canaryFacts).toEqual({sourceFstatDetectorFires:true,transportFstatDiffers:true});
      runtimeStep('kernel-canary-complete');
      // 23 is emitted only by a successfully started Node which reaches this
      // exact read and receives the kernel's access refusal. Launch errors,
      // missing files and other IO errors have different statuses.
      const readProbe='try{require("node:fs").readFileSync(process.argv[1]);process.exitCode=0;}catch(e){process.exitCode=["EPERM","EACCES"].includes(e.code)?23:24;}';
      const probe = ['-e',readProbe,plan];
      runtimeStep('kernel-allow-start');
      const allow=spawnSync('/usr/bin/sandbox-exec',['-p','(version 1) (allow default)',process.execPath,...probe],{stdio:'ignore'}).status;
      runtimeStep('kernel-deny-start');
      const deny=spawnSync('/usr/bin/sandbox-exec',['-p',observation.profile,process.execPath,...probe],{stdio:'ignore'}).status;
      expect(allow).toBe(0);expect(deny).toBe(23);
      const alias=join(dir,'plan-alias');symlinkSync(plan,alias);
      const aliasProbe=['-e',readProbe,alias];
      runtimeStep('kernel-alias-allow-start');
      const aliasAllow=spawnSync('/usr/bin/sandbox-exec',['-p','(version 1) (allow default)',process.execPath,...aliasProbe],{stdio:'ignore'}).status;
      runtimeStep('kernel-alias-deny-start');
      const aliasDeny=spawnSync('/usr/bin/sandbox-exec',['-p',observation.profile,process.execPath,...aliasProbe],{stdio:'ignore'}).status;
      expect(aliasAllow).toBe(0);expect(aliasDeny).toBe(23);
      observation.kernelReadControls={allow,deny,aliasAllow,aliasDeny};
      unlinkSync(alias);
      runtimeStep('kernel-probes-complete');
    }
    if (options.plan) {
      const line = bytes.toString('utf8');
      const variants: Record<string,string> = { empty:'# comments only\n\n', two:line+line.replace(/^p2/u,'p3'), repeat:line+line,
        mixed:line+'public 17 asis ok sha256 --key /private/tmp/synthetic-public\n', comments:'# comment\n\n'+line+'# comment\n' };
      if (!Object.hasOwn(variants,options.plan)) throw new Error('synthetic-plan-variant');
      writeFileSync(plan, variants[options.plan]);
      authenticateFixtureRecord(plan+'.runner-construction.json', f.paths.handleKey, value => ({...value,snapshotDigest:createHash('sha256').update(variants[options.plan!]).digest('hex')}));
    }
    observation.planIdentity=lstatSync(plan);observation.requestIdentity=lstatSync(f.source);
    const before = f.stateDigests();
    let poisonMarker:string|undefined;
    if(options.poison){
      const planted:Record<string,string>={};
      if(options.poison==='git')Object.assign(planted,{GIT_DIR:join(dir,'foreign-git'),GIT_WORK_TREE:dir,GIT_INDEX_FILE:join(dir,'foreign-index')});
      else if(options.poison==='script')Object.assign(planted,{MEASURE_PK_LOAD_SELF:join(dir,'foreign-script'),MEASURE_PK_LOAD_HERE:dir});
      else if(options.poison==='preload')Object.assign(planted,{NODE_OPTIONS:'--import='+join(dir,'absent-preload.mjs'),NODE_PATH:join(dir,'foreign-modules')});
      else if(options.poison==='path'){
        const poisonBin=join(dir,'poison-bin');mkdirSync(poisonBin,{mode:0o700});poisonMarker=join(dir,'poison-invoked');
        for(const name of ['node','git','python3','go'])writeFileSync(join(poisonBin,name),'#!/bin/sh\n/bin/touch '+poisonMarker+'\nexit 99\n',{mode:0o700});
        planted.PATH=poisonBin+':'+process.env.PATH;
      }else throw new Error('synthetic-environment-control-required');
      environmentRestore=Object.fromEntries(Object.keys(planted).map(name=>[name,process.env[name]]));Object.assign(process.env,planted);
    }
    seedTrap=vi.spyOn(keystore,'readSeed').mockImplementation(()=>{throw new Error('synthetic-forbidden-seed-loader');});
    rootTrap=vi.spyOn(walletKeys,'walletRoot').mockImplementation(()=>{throw new Error('synthetic-forbidden-wallet-root');});
    signTrap=vi.spyOn(secp256k1,'signMessageHashSchnorr');
    const weakSet=WeakMap.prototype.set;
    membershipTrap=vi.spyOn(WeakMap.prototype,'set').mockImplementation(function(this:WeakMap<object,unknown>,held:object,value:any){
      if(value?.directory===f.paths.store&&value.step==='reserve'&&typeof value.epoch==='symbol')mints++;
      return weakSet.call(this,held,value);
    });
    new WeakMap().set({}, {directory:f.paths.store,step:'reserve',epoch:Symbol('synthetic-detector-control')});expect(mints).toBe(1);mints=0;
    clock = vi.spyOn(performance,'now').mockImplementation(() => observation.clock);
    const ready = new Promise<void>(resolveReady => observation.ready = resolveReady);
    runtimeStep('classification-start');
    finished = withHarnessRunnerClassification([output,plan,'4']);
    await Promise.race([ready,finished.then(()=>{throw new Error('registration-ended-before-child');})]);
    runtimeStep('classification-ready');
    await use({...f,output,plan,selected,finished});
    if(mode!=='manual') {
      expect(observation.terminalBytes<=1024*1024).toBe(true);
      const needles=[plan,f.source].flatMap(value=>[value,JSON.stringify(value),value.replaceAll('/',String.fromCharCode(92)+'/'),Buffer.from(value).toString('hex'),Buffer.from(value).toString('base64')]);
      needles.push('Traceback (most recent call last)','SYNTHETIC_PRIVATE_TEXT_CANARY');
      const leaks=(bytes:Buffer)=>needles.some(value=>bytes.includes(Buffer.from(value)));
      // Independent detector controls precede scanning the actual captured
      // terminal and generated measurement artifacts. Print booleans only.
      expect(leaks(Buffer.from('measure-pk-load: live-plan-refused\n'))).toBe(false);
      for(const value of needles)expect(leaks(Buffer.from(value))).toBe(true);
      expect(leaks(Buffer.concat(observation.stdout))).toBe(false);
      expect(leaks(Buffer.concat(observation.stderr))).toBe(false);
      if(existsSync(output)) for(const file of readdirSync(output,{recursive:true})) {
        const target=join(output,String(file));
        if(lstatSync(target).isFile()&&/\.(json|tsv|time|stdout|stderr|txt)$/u.test(target))expect(leaks(readFileSync(target))).toBe(false);
      }
    }
    expect([seedTrap.mock.calls.length,rootTrap.mock.calls.length]).toEqual([0,0]);
    expect([signTrap.mock.calls.length,mints]).toEqual([0,0]);
    if(poisonMarker)expect(existsSync(poisonMarker)).toBe(false);
    expect(f.stateDigests()).toEqual(before);
  } finally {
    runtimeStep('cleanup-start');
    if (mode === 'manual') observation.child?.emit('close',0); else observation.child?.kill('SIGTERM');
    if (finished) await finished;
    runtimeStep('classification-closed');
    observation.ready = null; observation.child = null; observation.responseEdit=null;clock?.mockRestore();seedTrap?.mockRestore();rootTrap?.mockRestore();signTrap?.mockRestore();membershipTrap?.mockRestore();
    for(const [name,value] of Object.entries(environmentRestore))if(value===undefined)delete process.env[name];else process.env[name]=value;
    await server?.close(); f.dispose();
    runtimeStep('cleanup-complete');
  }
}
function nativeArguments(f: any, phase: 'A'|'W') {
  const tuple = f.selected[phase], names = ['format','profile-id','pin-bytes','pin-sha256','r1cs-bytes','r1cs-sha256','vk-bytes','vk-sha256'];
  return ['pool-pk-load',tuple[1],'--request',tuple[0],...names.flatMap((name,i) => ['--'+name,tuple[i+2]]),'--live-cache',tuple[11],tuple[10]];
}
function runnerDiagnostic(f: any) {
  // Closed diagnostics only. Never render a captured stream, path or receipt.
  const stderr = Buffer.concat(observation.stderr);
  const results = join(f.output, 'results');
  let receipt: any;
  try { receipt = JSON.parse(readFileSync(join(results, 'p2.json'), 'utf8')); } catch {}
  return JSON.stringify({
    contacts: ['P','A','W'].map(phase => observation.contacts.filter(value => value === phase).length),
    deliveries: ['P','A','W'].map(phase => observation.deliveries.filter(value => value === phase).length),
    terminalBytes: observation.terminalBytes,
    outerRefusal: stderr.includes(Buffer.from('measure-pk-load: live-plan-refused')),
    memoryFloor: stderr.includes(Buffer.from('live-plan-memory-floor')) || stderr.includes(Buffer.from('live-request-memory-floor')),
    outputCreated: existsSync(f.output),
    runCreated: existsSync(join(results, 'run.json')),
    admissionCreated: existsSync(join(results, 'p2.admission.json')),
    resultCreated: existsSync(join(results, 'p2.json')),
    summaryCreated: existsSync(join(results, 'p2.summary.json')),
    workFailure: receipt?.error === 'live-request-work-failed',
    openStage: receipt?.errorStage === 'open',
  });
}
async function bridgeFrame(f:any,phase:'P'|'A'|'W',argumentsOverride?:string[]) {
  const child = spawn(process.execPath,[join(ROOT,'tools/pool-action-modules/private-runner-bridge.mjs')],{cwd:ROOT,
    env:{PATH:'/usr/bin:/bin',LANG:'C',TMPDIR:'/private/tmp'},stdio:['ignore','ignore','ignore','pipe']});
  let bytes = Buffer.alloc(0); (child.stdio[3] as any).on('data',(b:Buffer)=>bytes=Buffer.concat([bytes,b]));
  (child.stdio[3] as any).end(canonicalJson({phase,source:phase==='P'?f.plan:f.source,arguments:argumentsOverride??(phase==='P'?[f.output,f.plan,'4']:f.selected[phase])})+'\n');
  await new Promise(resolveClose=>child.once('close',resolveClose));
  expect(bytes.length > 8).toBe(true); const n=bytes.readUInt32BE(0), metadata=JSON.parse(bytes.subarray(8,8+n).toString('utf8'));
  expect(bytes.length).toBe(8+n+metadata.bytes);return metadata;
}
async function acquireP(f:any) {
  const metadata=await bridgeFrame(f,'P');expect([metadata.error,metadata.bytes>0]).toEqual([null,true]);
}
test('PH11-HREAD without restore scan completion P preserves the exact pending refusal', async () => {
  await registered('manual', '', async f => {
    expect(await bridgeFrame(f, 'P')).toEqual({ bytes: 0, error: { code: 'wallet-command-component-refused', cause: 'pool-wallet-restore-scan-pending', retry: 'after-sync' } });
    expect(observation.contacts).toEqual(['P']); expect(observation.deliveries).toEqual([]);
    expect(observation.freshReads).toBe(1);
    // The donor facts reader never opened the native request. The inherited
    // binding fix authenticates it once at registration and twice in the fresh
    // read (before/after await). Refusal still precedes snapshot acquisition.
    expect([observation.planCaptures, observation.requestCaptures]).toEqual([0, 3]);
    expect([observation.planAcquisitions, observation.requestAcquisitions]).toEqual([0, 0]);
    writeFileSync(join(OUTPUT!,'restore-closed.json'),JSON.stringify({schema:'mig01-pending-restore-v1',planReads:observation.planCaptures,
      requestReads:observation.requestCaptures,planAcquisitions:observation.planAcquisitions,requestAcquisitions:observation.requestAcquisitions,
      freshReads:observation.freshReads,deliveries:observation.deliveries.length})+'\n',{mode:0o600});
  }, '', '', { completeScan: false });
}, 180000);
const refusalCases=[
  'envelope-extra','envelope-missing-binding','envelope-missing-value','binding-type','bad-mac','noncanonical','duplicate','trailing-payload',
  'value-extra','challenge-mismatch','phase-mismatch','source-mismatch','epoch-format','schema-route','schema-snapshot','schema-pi02',
  'error-extra','error-code','error-retry','error-cause',
  ...['schema','challenge','epoch','phase','source','error'].flatMap(field=>['value-missing-'+field,'value-type-'+field]),
  ...['code','retry','cause'].flatMap(field=>['error-missing-'+field,'error-type-'+field]),
];
test.each(['A','W'].flatMap(phase=>Array.from({length:12},(_,position)=>[phase,position] as const)))('PH11-REFUSAL immutable %s tuple position %i refuses before capture',async(phase,position)=>{
  await registered('manual','',async f=>{
    await acquireP(f);if(phase==='W')expect((await bridgeFrame(f,'A')).error).toBeNull();
    const before=[...observation.deliveries],argumentsChanged=[...f.selected[phase]];argumentsChanged[position]+='-synthetic-foreign';
    expect(await bridgeFrame(f,phase as 'A'|'W',argumentsChanged)).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-payment-host-authority-required'}});
    expect(observation.deliveries).toEqual(before);expect(observation.contacts).toEqual(position===0?before:[...before,phase]);expect(observation.freshReads).toBe(before.length);
  });
},180000);
test.each(refusalCases)('PH11-REFUSAL real bridge collapses independent %s to ownership without snapshot delivery',async kind=>{
  await registered('manual','',async f=>{
    let edits=0;
    observation.responseEdit=(original:Buffer)=>{
      edits++;const size=original.readUInt32BE(0),record=JSON.parse(original.subarray(8,8+size).toString('utf8')),v=record.value;
      expect(v.error).toEqual({code:'wallet-command-component-refused',retry:'after-sync',cause:'pool-wallet-chain-stale'});
      if(kind==='value-extra')v.extra=true;
      if(kind==='challenge-mismatch')v.challenge=v.challenge==='0123456789abcdef'.repeat(4)?'fedcba9876543210'.repeat(4):'0123456789abcdef'.repeat(4);
      if(kind==='phase-mismatch')v.phase='A';
      if(kind==='source-mismatch')v.source='/private/tmp/synthetic-foreign-source';
      if(kind==='epoch-format')v.epoch='synthetic-invalid-epoch';
      if(kind.startsWith('schema-'))v.schema=kind==='schema-route'?'private-runner-route-v1':kind==='schema-snapshot'?'private-runner-snapshot-v1':'owner-execution-input-v2';
      if(kind==='error-extra')v.error.extra=true;
      if(kind==='error-code')v.error.code='wallet-command-invalid-request';
      if(kind==='error-retry')v.error.retry='none';
      if(kind==='error-cause')v.error.cause='synthetic-unknown-cause';
      if(kind.startsWith('value-missing-'))delete v[kind.slice('value-missing-'.length)];
      if(kind.startsWith('value-type-'))v[kind.slice('value-type-'.length)]=null;
      if(kind.startsWith('error-missing-'))delete v.error[kind.slice('error-missing-'.length)];
      if(kind.startsWith('error-type-'))v.error[kind.slice('error-type-'.length)]=null;
      const key=readFileSync(f.paths.handleKey);
      try{record.binding=createHmac('sha256',key).update(canonicalJson(v)).digest('hex');}finally{key.fill(0);}
      if(kind==='envelope-extra')record.extra=true;
      if(kind==='envelope-missing-binding')delete record.binding;
      if(kind==='envelope-missing-value')delete record.value;
      if(kind==='binding-type')record.binding=17;
      if(kind==='bad-mac')record.binding=(record.binding[0]==='0'?'1':'0')+record.binding.slice(1);
      let metadata=canonicalJson(record);
      if(kind==='noncanonical')metadata=JSON.stringify(record,null,2);
      if(kind==='duplicate')metadata=metadata.replace('"value":','"value":null,"value":');
      const encoded=Buffer.from(metadata),payload=kind==='trailing-payload'?Buffer.from('synthetic trailing payload'):Buffer.alloc(0),header=Buffer.alloc(8);
      header.writeUInt32BE(encoded.length,0);header.writeUInt32BE(payload.length,4);return Buffer.concat([header,encoded,payload]);
    };
    expect(await bridgeFrame(f,'P')).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-payment-host-authority-required'}});
    expect(edits).toBe(1);expect(observation.contacts).toEqual(['P']);expect(observation.deliveries).toEqual([]);
  },'','P');
},180000);
test.each(['P','A','W'] as const)('PH11-HREAD real narrow reader fails independently at %s with no snapshot or transition',async failedPhase=>{
  await registered('manual','',async f=>{
    const delivered:string[]=[];
    for(const phase of ['P','A','W'] as const){
      const metadata=await bridgeFrame(f,phase);
      if(phase===failedPhase){expect(metadata).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'after-sync',cause:'pool-wallet-chain-stale'}});break;}
      expect([metadata.error,metadata.bytes>0]).toEqual([null,true]);delivered.push(phase);
    }
    expect(observation.deliveries).toEqual(delivered);expect(observation.contacts).toEqual([...delivered,failedPhase]);
  },'',failedPhase);
},180000);
test.each(['P','A','W'] as const)('PH11-HREAD fresh verified deadline equality at %s refuses without releasing or rebuilding',async failedPhase=>{
  await registered('manual','',async f=>{
    const delivered:string[]=[];
    for(const phase of ['P','A','W'] as const){
      if(phase===failedPhase)f.recorded.ledger.mine(100);
      const metadata=await bridgeFrame(f,phase);
      if(phase===failedPhase){expect(metadata).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'reconcile',cause:'pool-wallet-execution-deadline'}});break;}
      expect([metadata.error,metadata.bytes>0]).toEqual([null,true]);delivered.push(phase);
    }
    expect(observation.deliveries).toEqual(delivered);
  });
},180000);
test('PH11-LOCK bridge contention refuses before issuer contact and child-exit teardown removes its registration',async()=>{
  await registered('manual','',async f=>{
    const lock=join(f.paths.store,'pool-wallet-state-v1.lock');writeFileSync(lock,'synthetic-holder',{mode:0o600,flag:'wx'});
    try{expect(await bridgeFrame(f,'P')).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-store-busy'}});expect(observation.contacts).toEqual([]);expect(observation.deliveries).toEqual([]);}
    finally{unlinkSync(lock);}
    observation.child.emit('close',1);expect(await f.finished).toBe(1);
    expect((await bridgeFrame(f,'P')).error.cause).toBe('pool-wallet-payment-host-authority-required');expect(observation.contacts).toEqual([]);
  });
},180000);
test('PH11-LOCK issuer contention after the fresh asynchronous read invalidates before authenticated refusal delivery',async()=>{
  await registered('manual','',async f=>{
    const lock=join(f.paths.store,'pool-wallet-state-v1.lock');observation.issuerLock=lock;
    try{expect(await bridgeFrame(f,'P')).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-store-busy'}});expect(observation.contacts).toEqual(['P']);expect(observation.deliveries).toEqual([]);}
    finally{observation.issuerLock='';unlinkSync(lock);}
    expect((await bridgeFrame(f,'P')).error.cause).toBe('pool-wallet-payment-host-authority-required');expect(observation.deliveries).toEqual([]);
  });
},180000);
test('PH11-LOCK force-killed disposable holder leaves an unchanged stale lock and no reclaim or issuer contact',async()=>{
  await registered('manual','',async f=>{
    const lock=join(f.paths.store,'pool-wallet-state-v1.lock');
    const holder=spawn(process.execPath,['-e','const fs=require("node:fs");fs.openSync(process.argv[1],"wx",0o600);process.send({ready:true});setInterval(()=>{},1000)',lock],{stdio:['ignore','ignore','ignore','ipc']});
    try{
      const ready=await new Promise(resolveReady=>holder.once('message',resolveReady));expect(ready).toEqual({ready:true});
      const identity=lstatSync(lock),exit=new Promise(resolveClose=>holder.once('close',(_code,signal)=>resolveClose(signal)));
      holder.kill('SIGKILL');expect(await exit).toBe('SIGKILL');
      expect(await bridgeFrame(f,'P')).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-store-busy'}});
      const still=lstatSync(lock);expect([still.dev,still.ino,still.size]).toEqual([identity.dev,identity.ino,identity.size]);expect(observation.contacts).toEqual([]);expect(observation.deliveries).toEqual([]);
    }finally{if(holder.exitCode===null&&holder.signalCode===null)holder.kill('SIGKILL');unlinkSync(lock);}
  });
},180000);
test('PH11-X-PROD ordinary artifact excludes the tagged hook and an ordinary hook caller cannot compile', async () => {
  if (!OUTPUT) throw new Error('outside-clean-main-driver-required');
  const cwd=join(ROOT,'tools/apnt-pool-action-circuit');
  const files=spawnSync(GO,['list','-tags=','-f','{{join .GoFiles " "}}','./internal/runneradmission'],{cwd,env:goEnv,encoding:'utf8'});
  expect(files.status).toBe(0);expect(files.stdout.includes('prerequisite_testbuild.go')).toBe(false);expect(files.stdout.includes('prerequisite.go')).toBe(true);
  const probe=join(cwd,'cmd/mig01-exclusion-probe');mkdirSync(probe,{recursive:true});
  const source=join(probe,'main.go');writeFileSync(source,'package main\nimport r "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/internal/runneradmission"\nfunc main(){r.SetTestPrerequisite(func(func()){},func()error{return nil})}\n');
  try {
    const ordinary=spawnSync(GO,['build','-tags=','-o',join(OUTPUT,'ordinary-hook-probe'),'./cmd/mig01-exclusion-probe'],{cwd,env:goEnv,encoding:'utf8'});
    expect(ordinary.status).not.toBe(0);expect(ordinary.stderr.includes('undefined: r.SetTestPrerequisite')).toBe(true);
    const tagged=spawnSync(GO,['build','-tags=private_runner_admission_test','-o',join(OUTPUT,'tagged-hook-probe'),'./cmd/mig01-exclusion-probe'],{cwd,env:goEnv,stdio:'ignore'});expect(tagged.status).toBe(0);
  } finally { const fs=await import('node:fs');fs.rmSync(probe,{recursive:true,force:true}); }
});
// Operator decision 2026-10-22: no cause asserted; the resource monitor (measure-pk-load.sh:500)
// and receipt summary int() rejection of 'not measured' cannot be distinguished from closed outcomes.
function requireFailClosed(f:any,status:number) {
  expect({status,...JSON.parse(runnerDiagnostic(f))}).toMatchObject({status:1,
    contacts:[1,1,1],deliveries:[1,1,1],outerRefusal:true,admissionCreated:true,
    resultCreated:true,summaryCreated:false,memoryFloor:false,workFailure:false});
}
test('P13 fixed committed public selector writes its public result then fails closed before the summary',async()=>{
  if (!OUTPUT) throw new Error('outside-clean-main-driver-required');
  const selected=join(ROOT,'tools/apnt-pool-action-circuit/scripts/public-pk-load.plan');
  const source=readFileSync(selected,'utf8');
  expect(source.split('\n').filter(row=>row.trim()&&!row.trimStart().startsWith('#')).every(row=>!['prove','setup','init','load','read','derive','roundtrip'].includes(row.trim().split(/\s+/u)[4]))).toBe(true);
  const output=join(OUTPUT,'public-selector-control');
  const first=source.split('\n').find(row=>row.trim()&&!row.trimStart().startsWith('#'))?.trim().split(/\s+/u)[0];
  expect(typeof first==='string'&&first.length>0).toBe(true);
  const result=await execution('/bin/bash',['tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh',output,selected,'4']);
  expect({status:result.status,outerRefusal:result.err.includes(Buffer.from('measure-pk-load: refusing: ')),
    resultCreated:existsSync(join(output,`results/${first}.json`)),
    caseSummaryCreated:existsSync(join(output,`results/${first}.summary.json`)),
    summaryCreated:existsSync(join(output,'results/summary.json'))})
    .toEqual({status:1,outerRefusal:true,resultCreated:true,caseSummaryCreated:false,summaryCreated:false});
},180000);
test.each(['stock','kernel'])('PH11-X-PROD/P0 genuine %s stock runner reaches P/A/W and writes its check-live result then fails closed before the summary', async mode => {
  await registered(mode,'',async f=>{
    runtimeStep('runner-wait');
    const status = await f.finished;
    runtimeStep('runner-complete');
    requireFailClosed(f,status);expect(observation.contacts).toEqual(['P','A','W']);expect(observation.deliveries).toEqual(['P','A','W']);
    const receipt=JSON.parse(readFileSync(join(f.output,'results/p2.json'),'utf8'));
    expect([receipt.command,!!receipt.admission,!!receipt.prove,!!receipt.read]).toEqual(['check-live',true,false,false]);
    if(mode==='kernel') {
      const observed=await observation.descriptorResult!;
      expect([observed.code,observed.value.observerRefused],JSON.stringify(observed.diagnostic)).toEqual([0,false]);
      expect(observed.value.samples>0&&observed.value.observedProcesses>0).toBe(true);
      expect(observed.value.fd8PipeProcesses+observed.value.fd8SocketProcesses>0).toBe(true);
      expect(observed.value.fd8IdentitiesCompared>0).toBe(true);expect(observed.value.fd8IdentitiesDifferent).toBe(observed.value.fd8IdentitiesCompared);expect(observed.value.fd8SourceIdentityMatches).toBe(0);
      // One registration read, two authentication reads per fresh phase,
      // one under P's PLAN capture, and the two A/W request acquisitions.
      expect(observation.planCaptures).toBe(1);expect(observation.requestCaptures).toBe(10);
      expect([observation.planAcquisitions,observation.requestAcquisitions]).toEqual([1,2]);
      expect(observed.value.sourceDescriptorMatches).toBe(0);expect(observed.value.nullStdioPrivateBridgeProcesses>0).toBe(true);
      expect(observed.value.inheritedProverLockBridges).toBe(0);
      expect(Object.keys(observed.value).sort()).toEqual(['samples','observedProcesses','fd8PipeProcesses','fd8SocketProcesses','fd8IdentitiesCompared','fd8IdentitiesDifferent','fd8SourceIdentityMatches','sourceDescriptorMatches','nullStdioPrivateBridgeProcesses','inheritedProverLockBridges','observerRefused'].sort());
      for(const [name,value] of Object.entries(observed.value))if(name!=='observerRefused')expect(Number.isSafeInteger(value)&&Number(value)>=0).toBe(true);
      writeFileSync(join(OUTPUT!,'kernel-closed.json'),JSON.stringify({schema:'mig01-kernel-observer-v1',readControls:observation.kernelReadControls,
        planCaptures:observation.planCaptures,requestCaptures:observation.requestCaptures,
        planAcquisitions:observation.planAcquisitions,requestAcquisitions:observation.requestAcquisitions,observer:observed.value})+'\n',{mode:0o600});
    }
  });
},180000);
test.each(['git','script','preload','path'])('PH11-BRIDGE/COPY genuine stock runner ignores independent %s redirection through P/A/W and its check-live result then fails closed before the summary',async poison=>{
  await registered('stock','',async f=>{
    const status = await f.finished;
    requireFailClosed(f,status);expect(observation.contacts).toEqual(['P','A','W']);expect(observation.deliveries).toEqual(['P','A','W']);
    const receipt=JSON.parse(readFileSync(join(f.output,'results/p2.json'),'utf8'));
    expect([receipt.command,!!receipt.admission,!!receipt.prove,!!receipt.read]).toEqual(['check-live',true,false,false]);
  },'','',{poison});
},180000);
// These helpers inspect closed outcomes only; no payload/receipt enters diagnostics.
function requireNoProof(receipt:any) {
  if((receipt.phases??[]).some((phase:any)=>['prove','load-vk','load-pk','evict','warm','read-and-hash','decode','verify','verify-flipped'].includes(phase.name)))throw new Error('resource-proof-phase-refused');
  for(const key of ['proofHex','proofBytes','proofSha256','verifyError','flippedError'])
    if(Object.hasOwn(receipt.prove??{},key))throw new Error('resource-proof-output-refused');
  if(receipt.prove?.verified || receipt.prove?.flippedRefused)throw new Error('resource-proof-output-refused');
}
function proofDetectorControls() {
  const safe={phases:[{name:'admit-request'},{name:'load-r1cs'}],prove:{verified:false,flippedRefused:false}};
  requireNoProof(safe);
  expect(()=>requireNoProof({...safe,phases:[...safe.phases,{name:'prove'}]})).toThrow('resource-proof-phase-refused');
  for(const key of ['proofHex','proofBytes','proofSha256','verifyError','flippedError','verified','flippedRefused'])
    expect(()=>requireNoProof({...safe,prove:{...safe.prove,[key]:key==='proofBytes'?1:key==='verified'||key==='flippedRefused'?true:'synthetic-proof'}})).toThrow('resource-proof-output-refused');
}
async function requireExpiry(f:any,after:string) {
  const status=await f.finished;
  expect(status,runnerDiagnostic(f)).toBe(1);
  expect(observation.contacts).toEqual(after==='P'?['P','A']:['P','A','W']);
  expect(observation.deliveries,runnerDiagnostic(f)).toEqual(after==='P'?['P']:['P','A']);
  expect(observation.refusals).toEqual([{code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-payment-host-authority-required'}]);
  expect(existsSync(join(f.output,'results/p2.admission.json'))).toBe(after==='A');
  expect(existsSync(join(f.output,'results/p2.json'))).toBe(false);
  expect(existsSync(join(f.output,'results/p2.summary.json'))).toBe(false);
  expect(Buffer.concat(observation.stderr).equals(Buffer.from('measure-pk-load: live-plan-refused reason=no-diagnostic\n'))).toBe(true);
  expect(JSON.parse(runnerDiagnostic(f)).memoryFloor).toBe(false);
}
function resourceRegistered(after:string,use:(f:any)=>Promise<void>,expectation:string) {
  return registered('stock',after,use,expectation,'',{operation:'prove'});
}
function recordResourceOutcome(f:any,title:string,stop:'open'|'W-expiry') {
  // Closed source/build telemetry only, after the genuine phase assertions.
  // The stock shell's actual native binary is distinct from sentinel units.
  const path=join(OUTPUT!,'resource-outcomes.json');
  const rows=existsSync(path)?JSON.parse(readFileSync(path,'utf8')):[];
  expect(Array.isArray(rows)&&rows.length<4&&!rows.some((row:any)=>row.title===title)).toBe(true);
  rows.push({title,stop,stockNativeSha256:createHash('sha256').update(readFileSync(join(f.output,'bin/pool-pk-load'))).digest('hex')});
  writeFileSync(path,JSON.stringify(rows.sort((a:any,b:any)=>a.title.localeCompare(b.title)))+'\n',{mode:0o600});
}
test.each(['P','A'])('PH11-X-PROD real issuer expiry after %s refuses the next phase without a native result', async phase=>{
  await registered('stock',phase,async f=>{await requireExpiry(f,phase);});
},180000);
for (const expected of ['ok','fail','refuse-open']) {
  if(expected!=='ok') test(`PH11-RESOURCE valid prove failure receipt preserves EXPECT ${expected}`,async()=>{
    proofDetectorControls();
    await resourceRegistered('',async f=>{
      const status = await f.finished;
      expect(status, runnerDiagnostic(f)).toBe(0);expect(observation.contacts).toEqual(['P','A','W']);expect(observation.deliveries).toEqual(['P','A','W']);
      const receipt=JSON.parse(readFileSync(join(f.output,'results/p2.json'),'utf8'));
      expect(receipt.command).toBe('prove');expect(receipt.error).toBe('live-request-work-failed');expect(receipt.errorStage).toBe('open');
      expect(receipt.phases.map((phase:any)=>phase.name)).toEqual(['admit-request','load-r1cs']);
      requireNoProof(receipt);
      recordResourceOutcome(f,`PH11-RESOURCE valid prove failure receipt preserves EXPECT ${expected}`,'open');
    },expected);
  },180000);
  for (const after of ['P','A']) test(`PH11-OUTPUT missing result after ${after} refuses even for EXPECT ${expected}`,async()=>{
    await registered('stock',after,async f=>{await requireExpiry(f,after);},expected);
  },180000);
  if(expected!=='ok') test(`PH11-RESOURCE missing prove result after A refuses even for EXPECT ${expected}`,async()=>{
    await resourceRegistered('A',async f=>{
      await requireExpiry(f,'A');
      recordResourceOutcome(f,`PH11-RESOURCE missing prove result after A refuses even for EXPECT ${expected}`,'W-expiry');
    },expected);
  },180000);
}
test('PH11-X-PROD raw ordinary caller with a LIVE registry refuses before bridge contact',async()=>{
  await registered('manual','',async f=>{
    const r=await execution(join(OUTPUT!,'ordinary-pool-pk-load'),nativeArguments(f,'A').slice(1));
    expect([r.status,r.out.length,r.err.length]).toEqual([1,0,0]);expect(observation.contacts).toEqual([]);expect(observation.deliveries).toEqual([]);
    expect(existsSync(f.selected.A[10])).toBe(false);
  });
});
test('PH11-X-PROD direct ordinary library with a LIVE registry refuses before bridge contact',async()=>{
  await registered('manual','',async f=>{
    await acquireP(f); const contacts=observation.contacts.length;
    const r=await execution(join(OUTPUT!,'ordinary-library-probe'),nativeArguments(f,'A').slice(1));
    expect(observation.contacts.length).toBe(contacts);expect(observation.deliveries).toEqual(['P']);expect([r.status,r.out.length,r.err.length]).toEqual([0,0,0]);
  });
});
test.each(['','P','A'])('PH11-X tagged genuine P/A/W observation with expiry after "%s"',async after=>{
  await registered('manual',after,async f=>{
    await acquireP(f);
    for (const phase of ['A','W'] as const) {
      const failure=after==='P'||(after==='A'&&phase==='W');
      await registeredObserver(f,'TestMIG01R3RegisteredDispatchObservation',phase,failure?'ownership':'success');
      if(failure)break;
    }
    expect(observation.deliveries).toEqual(after==='P'?['P']:after==='A'?['P','A']:['P','A','W']);
    expect(observation.contacts).toEqual(after==='P'?['P','A']:['P','A','W']);
  });
},180000);
test.each(['','P'])('PH11-X direct tagged library with expiry after "%s"',async after=>{
  await registered('manual',after,async f=>{
    await acquireP(f);
    await registeredObserver(f,'TestMIG01R3RegisteredLibraryObservation','A',after?'ownership':'success');
    expect(observation.contacts).toEqual(['P','A']);expect(observation.deliveries).toEqual(after?['P']:['P','A']);
  });
},180000);
test.each(['A','W'] as const)('PH11-X tagged binding refusal at %s executes the observer without a writer',async phase=>{
  await registered('manual','',async f=>{
    await acquireP(f);if(phase==='W')expect((await bridgeFrame(f,'A')).error).toBeNull();
    const deployment=join(f.home,f.context.handle.walletId,'deployment.json');
    const original=readFileSync(deployment),foreign=JSON.parse(original.toString('utf8'));
    const id=Buffer.from(foreign.deploymentId32.$hex,'hex');id[0]^=1;foreign.deploymentId32.$hex=id.toString('hex');
    writeFileSync(deployment,canonicalJson(foreign),{mode:0o600});
    try {await registeredObserver(f,'TestMIG01R3RegisteredDispatchObservation',phase,'binding');}
    finally {writeFileSync(deployment,original,{mode:0o600});}
    expect(observation.contacts).toEqual(phase==='A'?['P','A']:['P','A','W']);
    expect(observation.deliveries).toEqual(phase==='A'?['P']:['P','A']);
    expect(existsSync(f.selected[phase][10])).toBe(false);
  });
},180000);

// Synthetic authenticated fixture edits are made only by these controls. No
// production writer accepts arbitrary plans, clocks or construction records.
function authenticateFixtureRecord(file: string, keyFile: string, edit: (value:any)=>any) {
  const record = JSON.parse(readFileSync(file,'utf8')), key = readFileSync(keyFile);
  try { const value = edit(record.value); writeFileSync(file,canonicalJson({value,binding:createHmac('sha256',key).update(canonicalJson(value)).digest('hex')})); }
  finally { key.fill(0); }
}
test('PH11-ROUTE-WRITER genuine inbox source reaches the authenticated P/A/W issuer',async()=>{
  await registered('manual','',async f=>{
    for(const phase of ['P','A','W'] as const){expect((await bridgeFrame(f,phase)).error).toBeNull();expect(observation.deliveries.at(-1)).toBe(phase);}
    expect(observation.contacts).toEqual(['P','A','W']);
  },'','',{kind:'inbox-deposit'});
},180000);
test.each(['empty','two','repeat','mixed'])('PH11-ONECASE authenticated %s source refuses before P delivery and cannot reset the latch',async plan=>{
  await registered('manual','',async f=>{
    expect(await bridgeFrame(f,'P')).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-payment-binding'}});
    expect(observation.deliveries).toEqual([]);
    expect((await bridgeFrame(f,'P')).error.cause).toBe('pool-wallet-payment-host-authority-required');
  },'','',{plan});
},180000);
test('PH11-ONECASE authenticated comments preserve one P/A/W case and a second A cannot acquire again',async()=>{
  await registered('manual','',async f=>{
    await acquireP(f);expect((await bridgeFrame(f,'A')).error).toBeNull();
    expect((await bridgeFrame(f,'A')).error.cause).toBe('pool-wallet-payment-host-authority-required');
    expect(observation.deliveries).toEqual(['P','A']);
  },'','',{plan:'comments'});
},180000);
test.each(['P','A','W'] as const)('PH11-ONECASE original TTL equality at %s is not renewed by a previous phase',async expired=>{
  await registered('manual','',async f=>{
    const delivered:string[]=[];
    for(const phase of ['P','A','W'] as const){
      observation.clock=phase===expired?600000:599999;
      const result=await bridgeFrame(f,phase);
      if(phase===expired){expect(result).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-payment-host-authority-required'}});break;}
      expect(result.error).toBeNull();delivered.push(phase);
    }
    expect(observation.deliveries).toEqual(delivered);
  });
},180000);
test('PH11-ONECASE just below the original TTL all three distinct latches deliver once',async()=>{
  await registered('manual','',async f=>{observation.clock=599999;for(const phase of ['P','A','W'] as const)expect((await bridgeFrame(f,phase)).error).toBeNull();expect(observation.deliveries).toEqual(['P','A','W']);});
},180000);
test.each(['P','A','W'] as const)('PH11-HREAD authenticated construction basis changes at %s before capture',async stale=>{
  await registered('manual','',async f=>{
    const delivered:string[]=[];
    for(const phase of ['P','A','W'] as const){
      observation.afterFresh=phase===stale?()=>{authenticateFixtureRecord(f.source+'.runner-construction.json',f.paths.handleKey,value=>({...value,chain:{...value.chain,minimumConfirmations:2}}));observation.afterFresh=null;}:null;
      const result=await bridgeFrame(f,phase);
      if(phase===stale){expect(result).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'resnapshot',cause:'pool-wallet-execution-offer-basis-stale'}});break;}
      expect(result.error).toBeNull();delivered.push(phase);
    }
    expect(observation.deliveries).toEqual(delivered);
  });
},180000);

test('PH11-HREAD same-height independently mined hash change invalidates A before capture',async()=>{
  await registered('manual','',async f=>{
    f.recorded.ledger.mine(1);await acquireP(f);
    const old=f.recorded.ledger.tip;f.recorded.ledger.blocks.pop();
    // A real locally mined replacement header/coinbase, no fabricated read
    // object or accepted flag. Pool transactions below this empty tip remain.
    f.recorded.ledger.mineBlock([{lockingBytecode:new Uint8Array([0x51]),valueSatoshis:50_0000_0000n}],{spendableCoinbase:true});
    expect(f.recorded.ledger.tip.height===old.height&&f.recorded.ledger.tip.hashDisplay!==old.hashDisplay).toBe(true);
    expect(await bridgeFrame(f,'A')).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'resnapshot',cause:'pool-wallet-execution-offer-basis-stale'}});
    expect(observation.deliveries).toEqual(['P']);
  });
},180000);
test('PH11-HREAD original B then B+1 extension preserves unchanged anchor at A and W',async()=>{
  await registered('manual','',async f=>{
    const original=f.recorded.ledger.tip.height;await acquireP(f);f.recorded.ledger.mine(1);
    expect(f.recorded.ledger.tip.height).toBe(original+1);
    expect((await bridgeFrame(f,'A')).error).toBeNull();expect((await bridgeFrame(f,'W')).error).toBeNull();
    expect(observation.deliveries).toEqual(['P','A','W']);
  });
},180000);

// The independently invalid public anchor is injected at the native predicate
// boundary. Construction provenance still checks its original genuine record;
// this isolates per-phase invocation/refusal mapping, not forged association admission.
test.each(['P','A','W'] as const)('PH11-HREAD exact native anchor predicate fires independently at %s before delivery',async stale=>{
  await registered('manual','',async f=>{
    const delivered:string[]=[];
    for(const phase of ['P','A','W'] as const){
      observation.invalidAnchorPhase=phase===stale?stale:'';const result=await bridgeFrame(f,phase);
      if(phase===stale){expect(result).toEqual({bytes:0,error:{code:'wallet-command-component-refused',retry:'none',cause:'pool-wallet-anchor-stale'}});break;}
      expect(result.error).toBeNull();delivered.push(phase);
    }
    expect(observation.deliveries).toEqual(delivered);
  });
},180000);
