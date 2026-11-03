// Research prototype — not reviewed (R-384).
//
// Creates one scratch build tree for the residue-construction generator, from the
// source archives retained at tag archive/seal-era-final (no third-party source is
// copied into this directory). Mirrors tools/verifier-intratx-measure/setup-scratch.py
// at that tag, except that the generator and compiler come from the tag's retained
// tarballs, checked against the tag's evidence manifest, instead of local checkouts.
//
//   generator: groth16_cashscript 0cff585 (mr-zwets; package licence field ISC, no licence file)
//   compiler:  cashscript 9fb1483 (cashc fork used by the generator; MIT)
//
// Dependencies are linked read-only: the generator's @bitauth/libauth 3.1.0-next.8 and
// @noble/curves 2.2.0, and the compiler's node_modules, from the local checkouts the
// September runs used. Their versions and package.json digests are recorded.
//
// usage: node setup-scratch.mjs DEST GENERATOR_NODE_MODULES COMPILER_NODE_MODULES
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const TAG = 'archive/seal-era-final';
const EVIDENCE = 'tools/verifier-intratx-measure/round2/evidence';
const ARCHIVES = {
  generator: { file: 'generator-source.tar.gz', sha256: 'a62a65ff00f6082bbfc0d24a67157dbf842dbacb1e68f311946089d778ff1eb4', revision: '0cff585eff44571bcb6917e006ecdd65446fdfe0' },
  compiler: { file: 'compiler-source.tar.gz', sha256: '35f560686b273206adfc5e6aa4075111aec8eeb542d9721e60db84853dfb9cee', revision: '9fb14833713449403104c8a77cb10973130993e1' },
};
const [destArg, genDeps, compDeps] = process.argv.slice(2);
assert(destArg && genDeps && compDeps, 'usage: setup-scratch.mjs DEST GENERATOR_NODE_MODULES COMPILER_NODE_MODULES');
const dest = resolve(destArg);
assert(!existsSync(dest), `refusing existing destination ${dest}`);
const repo = new URL('../../../', import.meta.url).pathname;
const sha = b => createHash('sha256').update(b).digest('hex');
const git = (...a) => execFileSync('git', ['-C', repo, ...a], { maxBuffer: 1 << 28 });
const record = { tag: TAG, tagCommit: git('rev-parse', `${TAG}^{commit}`).toString().trim(),
  worktreeHead: git('rev-parse', 'HEAD').toString().trim(), sources: {}, dependencies: {} };
mkdirSync(dest);
for (const [name, a] of Object.entries(ARCHIVES)) {
  const blob = git('show', `${TAG}:${EVIDENCE}/${a.file}`);
  assert.equal(sha(blob), a.sha256, `${a.file} does not match the tag's evidence manifest`);
  const manifest = JSON.parse(git('show', `${TAG}:${EVIDENCE}/MANIFEST.json`));
  assert.equal(manifest.files[a.file].sha256, a.sha256);
  mkdirSync(`${dest}/${name}`);
  execFileSync('tar', ['-xzf', '-', '-C', `${dest}/${name}`], { input: blob });
  record.sources[name] = { archive: `${TAG}:${EVIDENCE}/${a.file}`, sha256: a.sha256, revision: a.revision };
}
symlinkSync(resolve(compDeps), `${dest}/compiler/node_modules`);
mkdirSync(`${dest}/generator/node_modules`);
for (const scope of ['@bitauth', '@noble']) symlinkSync(resolve(genDeps, scope), `${dest}/generator/node_modules/${scope}`);
symlinkSync(`${dest}/compiler/packages/cashc`, `${dest}/generator/node_modules/cashc`);
mkdirSync(`${dest}/compiler/packages/cashc/node_modules/@cashscript`, { recursive: true });
symlinkSync(`${dest}/compiler/packages/utils`, `${dest}/compiler/packages/cashc/node_modules/@cashscript/utils`);
for (const pkg of ['@bitauth/libauth', '@noble/curves']) {
  const text = readFileSync(resolve(genDeps, pkg, 'package.json'));
  record.dependencies[pkg] = { version: JSON.parse(text).version, packageJsonSha256: sha(text) };
}
const tsc = `${repo}node_modules/typescript/bin/tsc`;
for (const p of ['utils', 'cashc']) execFileSync(process.execPath, [tsc, '-p', `${dest}/compiler/packages/${p}/tsconfig.build.json`], { stdio: 'inherit' });
record.typescript = JSON.parse(readFileSync(`${repo}node_modules/typescript/package.json`)).version;
writeFileSync(`${dest}/sources.json`, JSON.stringify(record, null, 2) + '\n');
console.log(JSON.stringify(record));
