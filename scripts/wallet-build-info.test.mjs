import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { generate, sourceState, compile } from './wallet-build-info.mjs';
const roots = [];
function fixture(git = true, name = 'pool-wallet-host') {
  const root = mkdtempSync('/private/tmp/sage-fees-version-build-'); roots.push(root);
  const dir = join(root, 'packages', name); mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: '@bch-cloak/' + name, version: '0.0.0' }));
  writeFileSync(join(dir, 'src/a.ts'), 'export const a = 1;\n');
  writeFileSync(join(root, '.gitignore'), '/packages/*/src/build-info.generated.ts\n/packages/*/dist/\n');
  const command = args => execFileSync('git', args, { cwd: root, stdio: 'pipe' });
  if (git) { command(['init', '-q']); command(['add', '.']); command(['-c', 'user.name=synthetic', '-c', 'user.email=synthetic@example.invalid', 'commit', '-qm', 'one']); }
  return { root, dir, command, target: join(dir, 'src/build-info.generated.ts') };
}
test('FV12 clean commits, exact packages, deterministic stamps, tracked and untracked source dirtiness', () => {
  for (const name of ['pool-wallet-host', 'pool-wallet-ink']) {
    const f = fixture(true, name); const first = sourceState(f.dir);
    assert.equal(first.revision.worktree, 'clean'); generate(f.dir); const bytes = readFileSync(f.target, 'utf8'); generate(f.dir); assert.equal(readFileSync(f.target, 'utf8'), bytes);
    writeFileSync(join(f.dir, 'src/a.ts'), 'export const a = 2;\n'); assert.equal(sourceState(f.dir).revision.worktree, 'dirty');
    f.command(['add', '.']); f.command(['-c', 'user.name=synthetic', '-c', 'user.email=synthetic@example.invalid', 'commit', '-qm', 'two']);
    generate(f.dir); assert.notEqual(sourceState(f.dir).revision.commit, first.revision.commit); assert.notEqual(readFileSync(f.target, 'utf8'), bytes);
    writeFileSync(join(f.dir, 'src/untracked.ts'), 'export const control = true;\n'); assert.equal(sourceState(f.dir).revision.worktree, 'dirty');
    rmSync(join(f.dir, 'src/untracked.ts')); assert.equal(sourceState(f.dir).revision.worktree, 'clean');
  }
});
test('FV12 outside Git is unavailable; malformed metadata and inside-checkout Git errors refuse stale output', () => {
  const f = fixture(false); generate(f.dir); assert.match(readFileSync(f.target, 'utf8'), /build-source-unavailable/u);
  for (const metadata of [{ name: '@bch-cloak/wrong', version: '0.0.0' }, { name: '@bch-cloak/pool-wallet-host', version: 'garbage' }]) {
    writeFileSync(f.target, 'stale'); writeFileSync(join(f.dir, 'package.json'), JSON.stringify(metadata));
    assert.throws(() => generate(f.dir), /wallet-build-package/u); assert.equal(existsSync(f.target), false);
  }
  const g = fixture(false); writeFileSync(join(g.root, '.git'), 'broken checkout marker'); writeFileSync(g.target, 'stale');
  assert.throws(() => generate(g.dir), /wallet-build-git/u); assert.equal(existsSync(g.target), false);
});
test('FV12 source race and interrupted compiler remove generated and compiled outputs', () => {
  for (const command of ['printf "export const a = 3;\\n" > src/a.ts; exit 0', 'exit 7']) {
    const f = fixture(true), bin = join(f.root, 'bin'); mkdirSync(bin);
    writeFileSync(join(bin, 'pnpm'), '#!/bin/sh\n' + command + '\n', { mode: 0o755 });
    mkdirSync(join(f.dir, 'dist')); writeFileSync(join(f.dir, 'dist/stale.js'), 'stale');
    const previous = process.env.PATH; process.env.PATH = bin + ':' + previous;
    try { assert.throws(() => compile(f.dir, ['-p', 'tsconfig.json']), command.includes('exit 0') ? /wallet-build-source-race/u : /wallet-build-compile/u); }
    finally { process.env.PATH = previous; }
    assert.equal(existsSync(f.target), false); assert.equal(existsSync(join(f.dir, 'dist')), false);
  }
});
function earlyMetadataControl(tool, change) {
  const f = fixture(), bin = join(f.root, 'bin'), marker = join(f.dir, 'compiler-invoked');
  mkdirSync(bin);
  writeFileSync(join(bin, 'pnpm'), '#!/bin/sh\n: > compiler-invoked\n', { mode: 0o755 });
  mkdirSync(join(f.dir, 'dist')); writeFileSync(join(f.dir, 'dist/stale.js'), 'stale');
  const parse = JSON.parse, previous = process.env.PATH;
  // Change tracked metadata just after acquisition, before generation's next
  // Git read. A compiler-time mutation cannot exercise this earlier window.
  const hook = mock.method(JSON, 'parse', (text, ...args) => {
    const value = parse(text, ...args);
    if (change && value.name === '@bch-cloak/pool-wallet-host') {
      writeFileSync(join(f.dir, 'package.json'), JSON.stringify({ ...value, version: '9.8.7' }));
    }
    return value;
  });
  process.env.PATH = bin + ':' + previous;
  try {
    if (change) {
      assert.throws(() => tool.compile(f.dir, []), { message: 'wallet-build-source-race' });
      assert.equal(existsSync(marker), false, 'compiler must not start');
      assert.equal(existsSync(f.target), false, 'stale generated metadata must be removed');
      assert.equal(existsSync(join(f.dir, 'dist')), false, 'stale compiled output must be removed');
      assert.equal(parse(readFileSync(join(f.dir, 'package.json'), 'utf8')).version, '9.8.7');
    } else {
      tool.compile(f.dir, []);
      assert.equal(existsSync(marker), true);
      assert.equal(parse(readFileSync(f.target, 'utf8').split(' = ')[1].split(' as const;')[0]).version, '0.0.0');
    }
  } finally { hook.mock.restore(); process.env.PATH = previous; }
}
test('FV12 early metadata change refuses before compilation and removes stale outputs', () => {
  earlyMetadataControl({ compile }, false);
  earlyMetadataControl({ compile }, true);
});
async function mutant(before, after) {
  let source=readFileSync(new URL('./wallet-build-info.mjs',import.meta.url),'utf8');
  assert.equal(source.split(before).length,2);source=source.replace(before,after);
  source=source.replace('fileURLToPath(import.meta.url)',JSON.stringify(new URL('./wallet-build-info.mjs',import.meta.url).pathname));
  return import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
}
test('mutation FV12 untracked compiled source disclosure',async()=>{
  const f=fixture();writeFileSync(join(f.dir,'src/new.ts'),'export const b=2;');
  const oracle=tool=>assert.equal(tool.sourceState(f.dir).revision.worktree,'dirty');
  oracle({sourceState});
  const altered=await mutant('|| untracked.length > 0','|| false');
  assert.throws(()=>oracle(altered));oracle({sourceState});
});
test('mutation FV12 compile fingerprint prevents mixed-source output',async()=>{
  const altered=await mutant("if (JSON.stringify(sourceState(directory)) !== JSON.stringify(before)) throw new Error('wallet-build-source-race');",';');
  const oracle=tool=>{
    const f=fixture(),bin=join(f.root,'bin');mkdirSync(bin);
    writeFileSync(join(bin,'pnpm'),'#!/bin/sh\nprintf "export const a = 4;\\n" > src/a.ts\n',{mode:0o755});
    const previous=process.env.PATH;process.env.PATH=bin+':'+previous;
    try{assert.throws(()=>tool.compile(f.dir,[]),/wallet-build-source-race/u);}finally{process.env.PATH=previous;}
  };
  oracle({compile});assert.throws(()=>oracle(altered));oracle({compile});
});
test('mutation FV12 metadata acquisition stays inside the source snapshot interval', async () => {
  const altered = await mutant(
    "const before = sourceState(dir);\n    const metadata = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));",
    "const metadata = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));\n    const before = sourceState(dir);",
  );
  earlyMetadataControl({ compile }, true);
  assert.throws(() => earlyMetadataControl(altered, true), { code: 'ERR_ASSERTION', operator: 'throws' });
  earlyMetadataControl({ compile }, true);
});
test.after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }); });
