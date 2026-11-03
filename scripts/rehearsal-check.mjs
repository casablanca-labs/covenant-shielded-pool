#!/usr/bin/env node
// Public acquisition and the existing no-proof build/check recipes.
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const mode = process.argv[2] ?? 'js';
if (process.argv.length > 3 || !['js', 'fetch-native', 'native-builds', '--help'].includes(mode)) {
  console.error('Usage: node scripts/rehearsal-check.mjs [js|fetch-native|native-builds|--help]');
  process.exit(2);
}
if (mode === '--help') {
  console.log('js (default): frozen install, build, typecheck, and the three declared JS test commands.');
  console.log('fetch-native: acquire locked public Go/Cargo dependencies; network access required.');
  console.log('native-builds: the four existing host builds, offline; no binaries or proofs run.');
  process.exit(0);
}
if (!['20.19.4', '22.22.3'].includes(process.versions.node)) {
  console.error('Use Node 20.19.4 (measured) or 22.22.3 (legacy declaration; unverified).');
  process.exit(1);
}
function run(command, args, env = {}, cwd = root) {
  console.log(`STEP ${command} ${args.join(' ')}`);
  const result = spawnSync(command, args, { cwd, env: { ...process.env, ...env }, stdio: 'inherit' });
  if (result.error || result.status !== 0) {
    console.error(`FAILED: ${command}; exit=${result.status}; signal=${result.signal ?? 'none'}; error=${result.error?.code ?? 'none'}`);
    process.exit(result.status > 0 ? result.status : 1);
  }
}
function requireVersion(command, args, expected) {
  const result = spawnSync(command, args, { cwd: root, encoding: 'utf8' });
  if (result.status !== 0 || !expected.test(result.stdout)) {
    console.error(`Toolchain mismatch or missing tool: ${command}. See docs/rehearsal/proof-material-acquisition.md.`);
    process.exit(1);
  }
  console.log(result.stdout.trim());
}

if (mode === 'js') {
  requireVersion('pnpm', ['--version'], /^9\.0\.0\s*$/);
  run('pnpm', ['install', '--frozen-lockfile', '--ignore-scripts']);
  for (const script of ['build', 'typecheck', 'test:identities', 'test:rehearsal', 'test:build-metadata']) run('pnpm', [script]);
} else {
  const nativeEnv = { GOTOOLCHAIN: 'local', GOFLAGS: '-mod=readonly' };
  const goVersion = spawnSync('go', ['version'], { cwd: root, env: { ...process.env, ...nativeEnv }, encoding: 'utf8' });
  if (goVersion.status !== 0 || !/^go version go1\.26\.5\s/.test(goVersion.stdout)) {
    console.error('Toolchain mismatch or missing Go 1.26.5.');
    process.exit(1);
  }
  console.log(goVersion.stdout.trim());
  requireVersion('rustc', ['--version'], /^rustc 1\.97\.0\s/);
  requireVersion('cargo', ['--version'], /^cargo 1\.97\.0\s/);
  requireVersion('protoc', ['--version'], /^libprotoc 36\.1\s*$/);
  const output = mkdtempSync(join(tmpdir(), 'csp-rehearsal-build-'));
  console.log(`Build/acquisition output: ${output}`);
  const modules = ['tools/apnt-pool-action-circuit', 'tools/apnt-pool-ceremony'];
  const manifests = ['tools/apnt-pool-aggregate-sp1/Cargo.toml', 'tools/sp1-canonical-guest-build/vkey-probe/Cargo.toml'];
  if (mode === 'fetch-native') {
    // Temporary module roots prevent acquisition from rewriting source sums.
    for (const module of modules) {
      const scratch = mkdtempSync(join(output, 'go-'));
      for (const name of ['go.mod', 'go.sum']) copyFileSync(join(root, module, name), join(scratch, name));
      run('go', ['mod', 'download'], { ...nativeEnv, GOPROXY: 'https://proxy.golang.org', GOSUMDB: 'sum.golang.org' }, scratch);
      for (const name of ['go.mod', 'go.sum']) {
        if (!readFileSync(join(root, module, name)).equals(readFileSync(join(scratch, name)))) {
          console.error(`Acquisition needs changed ${module}/${name}; source preserved. Stop and resolve the lock discrepancy.`);
          process.exit(1);
        }
      }
    }
    for (const manifest of manifests) run('cargo', ['fetch', '--locked', '--manifest-path', manifest], { CARGO_NET_OFFLINE: 'false' });
  } else {
    const env = { ...nativeEnv, GOPROXY: 'off', GOSUMDB: 'off', CARGO_NET_OFFLINE: 'true', GOCACHE: join(output, 'go-cache') };
    run('go', ['-C', modules[0], 'build', '-trimpath', '-buildvcs=false', '-o', `${output}/action/`, './cmd/pool-action-circuit', './cmd/pool-pk-load'], env);
    run('go', ['-C', modules[1], 'build', '-trimpath', '-buildvcs=false', '-o', `${output}/ceremony/`, './cmd/apnt-pool-ceremony-verify', './cmd/apnt-pool-ceremony-recheck'], env);
    run('cargo', ['build', '--offline', '--locked', '--manifest-path', manifests[0], '-p', 'apnt-pool-aggregate-runner', '--target-dir', `${output}/aggregate`], env);
    run('cargo', ['build', '--offline', '--locked', '--release', '--manifest-path', manifests[1], '--target-dir', `${output}/vkey`], env);
  }
}
console.log(`Completed ${mode} with Node ${process.versions.node}.`);
