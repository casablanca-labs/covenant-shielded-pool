// Build provenance only. No wallet paths, runtime Git, environment revision or
// retained diff body enters the generated constants.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const names = ['pool-wallet-host', 'pool-wallet-ink'];
const identifier = '(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)';
const semver = new RegExp('^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-' + identifier + '(?:\\.' + identifier + ')*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$', 'u');
function git(cwd, args) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error('wallet-build-git');
  return result.stdout;
}
export function sourceState(directory) {
  // Explicit filesystem absence distinguishes a source export from a broken
  // Git command inside a checkout (including worktrees' .git files).
  let root = resolve(directory);
  while (!existsSync(join(root, '.git'))) {
    const parent = resolve(root, '..');
    if (parent === root) return { revision: null, fingerprint: null };
    root = parent;
  }
  const commit = git(root, ['rev-parse', 'HEAD']).trim();
  if (!/^[0-9a-f]{40}$/u.test(commit)) throw new Error('wallet-build-git');
  const tracked = git(root, ['ls-files', '-z']).split('\0').filter(Boolean);
  const untracked = git(root, ['ls-files', '--others', '--exclude-standard', '-z', '--', 'packages']).split('\0')
    .filter(path => /^packages\/[^/]+\/(src|test)\//u.test(path));
  const hash = createHash('sha256');
  for (const path of [...tracked, ...untracked].sort()) {
    hash.update(path).update('\0');
    const full = join(root, path);
    hash.update(existsSync(full) ? readFileSync(full) : '<deleted>').update('\0');
  }
  const dirty = git(root, ['status', '--porcelain', '--untracked-files=no']).length > 0 || untracked.length > 0;
  return { revision: { commit, worktree: dirty ? 'dirty' : 'clean' }, fingerprint: hash.digest('hex') };
}
export function generate(directory) {
  const dir = resolve(directory), target = join(dir, 'src/build-info.generated.ts');
  rmSync(target, { force: true }); // A refused generation cannot leave usable old output.
  try {
    // Metadata acquisition belongs to the same interval as generation and tsc.
    const before = sourceState(dir);
    const metadata = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    const short = dir.split('/').at(-1);
    if (!dir.endsWith('/packages/' + short) || !names.includes(short) || metadata.name !== '@bch-cloak/' + short || typeof metadata.version !== 'string' || metadata.version.length > 64 || !semver.test(metadata.version)) throw new Error('wallet-build-package');
    const build = { schema: 'pool-wallet-build-v1', package: metadata.name, version: metadata.version, source: 'package-version',
      sourceRevision: before.revision === null ? { available: false, code: 'wallet-command-pending', blocker: 'build-source-unavailable' }
        : { available: true, value: before.revision } };
    writeFileSync(target, '// Generated at build time by scripts/wallet-build-info.mjs.\nexport const BUILD_INFO = ' + JSON.stringify(build, null, 2) + ' as const;\n');
    if (JSON.stringify(sourceState(dir)) !== JSON.stringify(before)) throw new Error('wallet-build-source-race');
    return { target, before };
  } catch (error) { rmSync(target, { force: true }); throw error; }
}
export function compile(directory, args) {
  const target = join(directory, 'src/build-info.generated.ts');
  try {
    const { before } = generate(directory);
    const result = spawnSync('pnpm', ['exec', 'tsc', ...args], { cwd: directory, stdio: 'inherit' });
    if (result.error || result.status !== 0) throw new Error('wallet-build-compile');
    if (JSON.stringify(sourceState(directory)) !== JSON.stringify(before)) throw new Error('wallet-build-source-race');
  } catch (error) {
    rmSync(target, { force: true });
    rmSync(join(directory, 'dist'), { force: true, recursive: true });
    throw error;
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv[2] === 'generate' && process.argv.length === 3) generate(process.cwd());
    else if (process.argv[2] === 'compile') compile(process.cwd(), process.argv.slice(3));
    else throw new Error('wallet-build-arguments');
  } catch (error) { process.stderr.write(String(error.message) + '\n'); process.exitCode = 1; }
}
