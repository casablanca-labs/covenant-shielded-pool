import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { userInfo } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

test('committed Node configuration ignores caller HOME and PATH', () => {
  const config = new URL('../lib/private-runner-installation.mjs', import.meta.url);
  const script = `import {PRIVATE_RUNNER_NODE as path, PRIVATE_RUNNER_NODE_VERSION as version} from ${JSON.stringify(config.href)}; process.stdout.write(JSON.stringify({path,version}));`;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    env: { HOME: '/synthetic/forged-home', PATH: '/synthetic/forged-bin' }, encoding: 'utf8',
  });
  assert.equal(result.status, 0);
  const selected = JSON.parse(result.stdout);
  assert.equal(selected.path === join(userInfo().homedir, '.nvm/versions/node/v22.22.3/bin/node'), true);
  assert.equal(selected.version, 'v22.22.3');
});
