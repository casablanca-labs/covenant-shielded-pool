/** ENG-1197 production closure and explicitly separate historical test build.
 * No production build compiles test sources. No signing/network action here.
 */
import { existsSync, lstatSync, readdirSync, readFileSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

export const retiredDepositModules = Object.freeze({
  'pool-wallet-host': ['deposit-funding', 'deposit-local', 'deposit-local-chain'],
  'wizardconnect-client': ['funding_transport', 'local_transport', 'import_funding', 'caller_adapter_signers'],
});
export const retiredDepositSymbols = Object.freeze([
  'signWizardConnectApntImportFundingV0',
  'requestWizardConnectAuthenticatedAPNTImportFundingSignatureV0',
  'PoolDepositFundingV0', 'createWizardConnectFundingAdaptersV0',
  'PoolDepositFundingOptionsV0', 'PoolDepositAddressSourceV0', 'PoolDepositFundingTransportV0',
  'WizardConnectLocalClockV0', 'WizardConnectFundingReadyV0Local',
  'VerifiedBoundaryTransactionV0Local', 'LocalOwnerContinuation', 'LocalAmounts',
  'LocalSignRequest', 'PoolDepositFundingSessionV0Local', 'LocalDiagnostics',
  'LocalOwnerView', 'LocalTestOptions', 'POOL_DEPOSIT_LOCAL_DISCLOSURE',
  'isPoolDepositFundingSessionV0Local', 'isWizardConnectFundingReadyV0Local',
  'isVerifiedBoundaryTransactionV0Local',

  'createTestPoolDepositFundingSessionV0Local', 'WizardConnectLocalFakePeerV0',
  'WizardConnectLocalExchangeV0', 'WizardConnectLocalTransportError', 'LocalFakeChainSocket',
  'LocalFakeReservationStore', 'LocalFakeIssuer', 'LocalFakeChain', 'LocalFakeChainReply', 'readLocalChain',
  'signWizardConnectGenericTransactionWithTransientXpubsV0',
  'createWizardConnectGenericSignTransactionLiveAdapterV0',
  'signWizardConnectApntImportFundingWithTransientXpubsV0',
  'WizardConnectGenericSignTransactionLiveSessionRequestBuilderV0',
  'WizardConnectGenericSignTransactionLiveSessionResultV0',
  'WizardConnectApntImportFundingLiveSessionRequestBuilderV0',
  'WizardConnectApntImportFundingLiveSessionResultV0',
]);
const fail = (detail) => { throw Object.assign(new Error(`deposit-retired-export: ${detail}`), { code: 'deposit-retired-export' }); };
function files(directory) {
  if (!existsSync(directory)) fail('missing production tree');
  return readdirSync(directory).flatMap(name => {
    const path = join(directory, name), stat = lstatSync(path);
    if (stat.isSymbolicLink()) fail('linked production artifact');
    return stat.isDirectory() ? files(path) : [path];
  });
}
function dependencyLiteral(node) {
  const parent = node.parent;
  return ts.isImportDeclaration(parent) || ts.isExportDeclaration(parent) ||
    (ts.isLiteralTypeNode(parent) && ts.isImportTypeNode(parent.parent)) ||
    (ts.isCallExpression(parent) && (parent.expression.kind === ts.SyntaxKind.ImportKeyword ||
      (ts.isIdentifier(parent.expression) && parent.expression.text === 'require')));
}
const retiredNames = Object.values(retiredDepositModules).flat();
const socketModules = new Set(['pairing', 'pairing_only', 'session', 'utxos']);
// The new route is admitted by its private-constructor / B1-consumer / actual
// send-site structure, not its filename alone. Read-only socketModules above
// retain their original transitive no-sign rule.
const gatedSocketModule = 'local_live_transport';
function assertGatedDepositTransport(ast) {
  const bad = () => fail('ungated deposit transport');
  const exported = node => node.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword || m.kind === ts.SyntaxKind.DefaultKeyword);
  const functions = ast.statements.filter(n => ts.isFunctionDeclaration(n) && exported(n));
  if (functions.length !== 1 || functions[0].name?.text !== 'createWizardConnectLiveDepositTransport' ||
      functions[0].parameters.length !== 1 || functions[0].parameters[0].name.getText(ast) !== 'authority') bad();
  if (ast.statements.some(n => (ts.isClassDeclaration(n) || ts.isVariableStatement(n)) && exported(n) || ts.isExportDeclaration(n) && !n.isTypeOnly)) bad();
  const implementation = ast.statements.find(n => ts.isClassDeclaration(n) && n.name?.text === 'LiveTransport');
  if (!implementation || exported(implementation)) bad();
  const facade = implementation.members.find(n => ts.isMethodDeclaration(n) && n.name?.getText(ast) === 'facade');
  const returned = facade?.body?.statements.find(ts.isReturnStatement)?.expression;
  const surface = returned && ts.isCallExpression(returned) ? returned.arguments[0] : undefined;
  if (!surface || !ts.isObjectLiteralExpression(surface) || surface.properties.map(p => p.name?.getText(ast)).sort().join(',') !== 'close,connect,refresh,sign') bad();
  const compact = n => n ? n.getText(ast).replace(/\s+/gu, '').replaceAll("'", '"') : '';
  // Keep this syntax expectation separate from this script's own import.meta
  // expression; the historical canary loader relocates actual module URLs.
  const fixedImport = 'newURL("../../pool-wallet-host/dist/deposit-live-capability.js",' + 'import.meta' + '.url).href';
  let sockets = 0, constructions = 0, imports = 0, sends = 0, signSends = 0, controls = 0, subscriptions = 0;
  function visit(node) {
    if (ts.isImportDeclaration(node) && !node.importClause?.isTypeOnly &&
        !['ws', './nostr.js'].includes(node.moduleSpecifier.text)) bad();
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'LiveTransport') {
      constructions++;
      let parent = node; while (parent && parent !== functions[0]) parent = parent.parent;
      if (!parent || node.arguments?.length !== 1 || node.arguments[0].getText(ast) !== 'port') bad();
    }
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'WebSocket') {
      sockets++;
      if (compact(node.arguments?.[0]) !== 'this.#port.pairing.relayUrl') bad();
      let block = node.parent; while (block && !ts.isBlock(block)) block = block.parent;
      if (!block?.statements.some(s => s.pos < node.pos && compact(s) === 'this.#current();')) bad();
    }
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      imports++; if (compact(node.arguments[0]) !== fixedImport) bad();
    }
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && ['send', 'write'].includes(node.expression.name.text)) {
      sends++;
      if (node.expression.name.text !== 'send') bad();
      const argument = node.arguments[0];
      if (ts.isIdentifier(argument) && argument.text === 'frame') {
        let block = node.parent; while (block && !ts.isBlock(block)) block = block.parent;
        const initializer = block?.statements.filter(ts.isVariableStatement).flatMap(s => [...s.declarationList.declarations])
          .find(d => ts.isIdentifier(d.name) && d.name.text === 'frame' && d.pos < node.pos)?.initializer;
        const source = initializer && compact(initializer);
        if (source === 'this.#port.dispatchSign(grant)') signSends++;
        else if (source === 'this.#port.controlEnvelope(action)') controls++;
        else bad();
      } else if (ts.isCallExpression(argument) && compact(argument.expression) === 'JSON.stringify' &&
                 ts.isArrayLiteralExpression(argument.arguments[0]) && compact(argument.arguments[0].elements[0]) === '"REQ"') subscriptions++;
      else bad();
    }
    if (ts.isElementAccessExpression(node) && !ts.isNumericLiteral(node.argumentExpression)) bad();
    if (ts.isPropertyAccessExpression(node) && ['send', 'write'].includes(node.name.text) &&
        !(ts.isCallExpression(node.parent) && node.parent.expression === node)) bad();
    if (ts.isIdentifier(node) && node.text === 'WebSocket' &&
        !(ts.isImportClause(node.parent) || ts.isNewExpression(node.parent) || ts.isTypeReferenceNode(node.parent) ||
          ts.isQualifiedName(node.parent) || ts.isPropertyAccessExpression(node.parent) && ['OPEN', 'CLOSED', 'CONNECTING'].includes(node.parent.name.text))) bad();
    ts.forEachChild(node, visit);
  }
  visit(ast);
  const factory = compact(functions[0]);
  if (!factory.includes('Reflect.apply(consumeApprovedLiveDepositAuthority,undefined,Array.from(arguments))') ||
      !factory.includes('returnnewLiveTransport(port).facade()') || sockets !== 1 || constructions !== 1 || imports !== 1 ||
      sends !== 3 || signSends !== 1 || controls !== 1 || subscriptions !== 1) bad();
}
// REV-730 I1: a renamed caller-adapter signer must not escape the symbol list.
// Calls with arguments through callable caller parameters are orchestration. The two
// existing read-only UTXO functions are separately classified; zero-argument
// owner presentation/clocks and inert legacy-symbol canaries are not sign sinks.
function assertNoCallerAdapterSigner(ast, stem) {
  const dataMethods = new Set(['at', 'slice', 'subarray', 'map', 'filter', 'every', 'some', 'find', 'findIndex', 'forEach', 'reduce', 'reduceRight',
    'includes', 'indexOf', 'lastIndexOf', 'startsWith', 'endsWith', 'replace', 'replaceAll', 'split', 'join', 'toString', 'toLocaleString',
    'getUint8', 'getUint16', 'getUint32', 'getInt8', 'getInt16', 'getInt32', 'getBigUint64', 'set', 'get', 'has', 'fill', 'match']);
  function inspect(fn, name) {
    if ((stem === 'utxos' && name === 'lookupWizardConnectTransparentUtxosV0') ||
        (stem === 'authenticated_utxos' && name === 'requestWizardConnectAuthenticatedTransparentUtxosV0')) return;
    const params = new Set();
    function binding(n) { if (ts.isIdentifier(n)) params.add(n.text); else if (ts.isObjectBindingPattern(n) || ts.isArrayBindingPattern(n)) n.elements.forEach(e => { if (ts.isBindingElement(e)) binding(e.name); }); }
    fn.parameters.forEach(p => binding(p.name));
    function visit(n) {
      if (ts.isCallExpression(n) && n.arguments.length > 0) {
        let target = n.expression;
        while (ts.isPropertyAccessExpression(target) || ts.isElementAccessExpression(target)) target = target.expression;
        const method = ts.isPropertyAccessExpression(n.expression) ? n.expression.name.text : null;
        // This private retained pairing parser consumes only the authenticated
        // wallet_ready message and pairing secret. It is not a signing adapter.
        const readyParser = stem === 'pairing' && name === 'waitForWizardConnectWalletReadyWithParserV0' &&
          ts.isIdentifier(n.expression) && n.expression.text === 'parseWalletReady' && n.arguments.length === 2 &&
          n.arguments[0].getText(ast) === 'message' && n.arguments[1].getText(ast) === 'request.pairingSecret';
        if (ts.isIdentifier(target) && params.has(target.text) && !dataMethods.has(method) && !readyParser) fail('caller-adapter signing route');
      }
      ts.forEachChild(n, visit);
    }
    if (fn.body) visit(fn.body);
  }
  for (const node of ast.statements) {
    if (ts.isFunctionDeclaration(node)) inspect(node, node.name?.text);
    if (ts.isVariableStatement(node)) for (const d of node.declarationList.declarations)
      if (d.initializer && (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer))) inspect(d.initializer, d.name.getText(ast));
  }
}
/** Source and assembled dist, including declarations/maps and renamed modules.
 * This checks the artifact before evaluating it: a canary must never execute.
 */
export async function assertRetiredDepositBuild(directory, packageName, assembled = false) {
  if (!Object.hasOwn(retiredDepositModules, packageName)) fail('unknown package');
  const manifest = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'));
  if (JSON.stringify(manifest.files) !== '["dist"]') fail('production/test package boundary');
  const roots = assembled ? ['dist'] : ['src', 'dist'];
  const checked = [];
  for (const root of roots) for (const path of files(join(directory, root))) {
    const name = basename(path);
    // The current build wrapper writes this non-executable provenance record
    // after the clean compiler/check step. It is not TypeScript output.
    if (root === 'dist' && name === '.runtime-build.json') {
      if (JSON.parse(readFileSync(path, 'utf8')).schema !== 'pool-runtime-build-v2') fail('invalid build stamp');
      checked.push(path); continue;
    }
    if (retiredNames.some(m => name === m + '.ts' || name === m + '.js' || name === m + '.d.ts' || name === m + '.js.map' || name === m + '.d.ts.map')) fail('retired module artifact');
    if (!/\.(?:ts|js|map)$/u.test(name)) fail('unknown production artifact');
    const source = readFileSync(path, 'utf8');
    if (name.endsWith('.map')) {
      const map = JSON.parse(source);
      if (!Array.isArray(map.sources) || map.sources.some(s => /(?:^|\/)test(?:\/|$)|retired-/u.test(s))) fail('test source map');
    } else {
      const ast = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true);
      let socket = false;
      function visit(node) {
        if ((ts.isIdentifier(node) || (ts.isStringLiteralLike(node) && ts.isExportSpecifier(node.parent))) && retiredDepositSymbols.includes(node.text)) fail('retired runtime/declaration symbol');
        if (ts.isIdentifier(node) && node.text === 'WebSocket') socket = true;
        if (ts.isElementAccessExpression(node)) {
          let target = node.expression;
          while (ts.isParenthesizedExpression(target) || ts.isAsExpression(target) || ts.isTypeAssertionExpression(target)) target = target.expression;
          if (ts.isIdentifier(target) && ['globalThis', 'global', 'window', 'self'].includes(target.text)) fail('unresolved global access');
        }
        if (ts.isStringLiteralLike(node)) {
          if ((dependencyLiteral(node) || ts.isCallExpression(node.parent)) &&
              /^(?:ws(?:\/.*)?|(?:node:)?(?:net|tls))$|(?:^|\/)node_modules\/ws(?:\/|$)/u.test(node.text)) socket = true;
          if (dependencyLiteral(node) && /(?:^|\/)test(?:\/|$)|retired-(?:src|dist)/u.test(node.text)) fail('production/test dependency');
          if (retiredNames.some(m => node.text.endsWith('/' + m + '.js'))) fail('retired deep import');
        }
        ts.forEachChild(node, visit);
      }
      visit(ast);
      // Runtime transport inventory: native WebSocket and ws both count. New
      // transport modules need review even when every legacy name was renamed.
      const stem = name.replace(/\.d\.ts$|\.(?:js|ts)$/u, '');
      if (packageName === 'wizardconnect-client' && socket && !socketModules.has(stem)) {
        if (stem !== gatedSocketModule) fail('unreviewed socket/signing route');
        else assertGatedDepositTransport(ast);
      }
      if (packageName === 'wizardconnect-client') assertNoCallerAdapterSigner(ast, stem);
    }
    if (!assembled && root === 'dist') {
      const stem = name.replace(/\.js\.map$|\.d\.ts(?:\.map)?$|\.js$/u, '');
      if (!existsSync(join(directory, 'src', stem + '.ts'))) fail('generated output without source');
    }
    checked.push(path);
  }
  // Trace retained socket entry points through runtime imports/re-exports.
  // Renaming a delegate cannot connect a read-only socket to signing builders.
  // Third-party cryptographic serializers are not spend/deposit orchestration.
  if (packageName === 'wizardconnect-client') for (const root of roots) {
    const extension = root === 'src' ? '.ts' : '.js';
    const graph = new Map();
    for (const path of files(join(directory,root)).filter(p=>p.endsWith(extension) && !p.endsWith('.d.ts'))) {
      const ast=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true),edges=[];
      function visit(node) {
        if (ts.isImportDeclaration(node) && !node.importClause?.isTypeOnly &&
            !(node.importClause?.namedBindings && ts.isNamedImports(node.importClause.namedBindings) &&
              !node.importClause.name && node.importClause.namedBindings.elements.every(e=>e.isTypeOnly))) {
          if (ts.isStringLiteral(node.moduleSpecifier)) edges.push(node.moduleSpecifier.text);
        }
        if (ts.isExportDeclaration(node) && !node.isTypeOnly && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) edges.push(node.moduleSpecifier.text);
        if (ts.isCallExpression(node) && node.expression.kind===ts.SyntaxKind.ImportKeyword && node.arguments[0] && ts.isStringLiteralLike(node.arguments[0])) edges.push(node.arguments[0].text);
        ts.forEachChild(node,visit);
      }
      visit(ast);graph.set(basename(path,extension),edges);
    }
    for(const entry of socketModules) {
      const seen=new Set();
      function visit(name) {
        if(seen.has(name))return;seen.add(name);
        if(['import_funding_contract','authenticated_import_funding'].includes(name)) fail('socket/signing dependency');
        for(const specifier of graph.get(name)??[]) if(specifier.startsWith('./')) visit(basename(specifier,'.js'));
      }
      visit(entry);
    }
  }
  // No production path (or interrupted cleaner) can hide a callable old copy.
  for (const path of filesExceptTests(directory)) {
    if (retiredNames.some(m => new RegExp(`^${m.replaceAll('.', '\\.')}\\.(?:js|ts|js\\.map|d\\.ts(?:\\.map)?)$`, 'u').test(basename(path)))) fail('retired artifact outside dist');
  }
  for (const m of retiredDepositModules[packageName]) {
    try { await import(pathToFileURL(join(directory, 'dist', m + '.js')).href); }
    catch (error) { if (error?.code === 'ERR_MODULE_NOT_FOUND') continue; throw error; }
    fail('retired deep import loaded');
  }
  if (packageName === 'wizardconnect-client') {
    const namespace = await import(pathToFileURL(join(directory, 'dist/index.js')).href);
    if (retiredDepositSymbols.some(symbol => Object.hasOwn(namespace, symbol))) fail('retired namespace export');
  }
  return { packageName, artifacts: checked.length, deepImportsMissing: retiredDepositModules[packageName].length };
}
function filesExceptTests(directory) {
  return readdirSync(directory).flatMap(name => {
    if (['node_modules', 'test', 'scripts'].includes(name)) return [];
    const path = join(directory, name), stat = lstatSync(path);
    if (name.startsWith('.dist-clean-')) fail('unfinished dist cleanup');
    if (stat.isSymbolicLink()) fail('linked package artifact');
    return stat.isDirectory() ? filesExceptTests(path) : [path];
  });
}
export function buildRetiredDepositTests(root, packageName) {
  const packages = packageName === 'pool-wallet-host' ? ['wizardconnect-client', packageName] : [packageName];
  for (const pkg of packages) {
    const directory = join(root, 'packages', pkg), output = join(directory, 'test/retired-dist');
    rmSync(output, { recursive: true, force: true }); mkdirSync(output, { recursive: true });
    for (const moduleName of retiredDepositModules[pkg]) {
      const source = readFileSync(join(directory, 'test/retired-src', moduleName + '.ts'), 'utf8').replaceAll('../../src/', '../../dist/').replaceAll('/test/retired-src/', '/test/retired-dist/');
      const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022, sourceMap: true }, fileName: moduleName + '.ts', reportDiagnostics: true });
      if (compiled.diagnostics?.length) fail('historical test target compile');
      writeFileSync(join(output, moduleName + '.js'), compiled.outputText);
      const map = JSON.parse(compiled.sourceMapText); map.sources = ['../retired-src/' + moduleName + '.ts'];
      writeFileSync(join(output, moduleName + '.js.map'), JSON.stringify(map));
    }
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = dirname(dirname(fileURLToPath(import.meta.url))), [command, pkg] = process.argv.slice(2);
  if (command === 'check') console.log(JSON.stringify(await assertRetiredDepositBuild(join(root, 'packages', pkg), pkg)));
  else if (command === 'test-build' && Object.hasOwn(retiredDepositModules, pkg)) buildRetiredDepositTests(root, pkg);
  else fail('usage');
}
