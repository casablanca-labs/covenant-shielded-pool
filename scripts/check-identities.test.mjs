import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { checkReleaseIdentities, readManifest } from './check-identities.mjs';

const checker = fileURLToPath(new URL('check-identities.mjs', import.meta.url));
test('every declared public identity passes on the released artifacts', () => {
  const rows = checkReleaseIdentities();
  assert.equal(rows.length, 7);
  assert.deepEqual(rows.filter(r => r.status !== 'PASS'), []);
});

for (const [id, mutate] of [
  ['network', m => { m.network = 'local'; }],
  ['circuit ID (published R1CS metadata)', m => { m.circuit.sha256 = '00'.repeat(32); }],
  ['action verifying key (published bytes)', m => { m.actionVerifyingKey.sha256 = '00'.repeat(32); }],
  ['action profile', m => { m.actionProfile.id = '00'.repeat(32); }],
  ['covenant bytecode (reference verdict factory)', m => { m.covenants[0].pin.referenceRedeemSha256 = '00'.repeat(32); }],
  ['aggregate digest (published canonical records)', m => { m.aggregate.guestElfSha256 = '00'.repeat(32); }],
  ['aggregate program VKey (published canonical records)', m => { m.aggregate.programVkeyHash = '00'.repeat(32); }],
]) {
  test(`refuses changed ${id}`, () => {
    const manifest = readManifest(); mutate(manifest);
    assert.equal(checkReleaseIdentities(manifest).find(r => r.id === id)?.status, 'FAIL');
  });
}

for (const [option, value, failure] of [
  ['--profile', '00'.repeat(32), 'FAIL action profile'],
  ['--network', 'mainnet', 'FAIL network'],
  ['--network', 'local', 'FAIL network'],
]) {
  test(`CLI refuses ${option} ${value.slice(0, 8)}`, () => {
    const result = spawnSync(process.execPath, [checker, option, value], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.ok(result.stdout.includes(failure));
    assert.ok(!result.stdout.includes(value));
  });
}

test('CLI refuses an unknown option without echoing input', () => {
  const result = spawnSync(process.execPath, [checker, '--other', 'not-printed'], { encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.ok(!result.stderr.includes('not-printed'));
});
