#!/usr/bin/env node
// Internal trampoline. E1's argv/stdio/env additions do not change. P succeeds
// before the new continuation's snapshot FD8 is created. Neither this process
// nor that continuation opens the original private PLAN.
import { spawn, spawnSync } from "node:child_process";
import { lstatSync, realpathSync, unlinkSync } from "node:fs";
import { userInfo } from "node:os";
import { dirname, join } from "node:path";
import { canonicalJson, keysOf, parseCanonicalLine } from "./lib/canonical.mjs";
import { PRIVATE_RUNNER_NODE, PRIVATE_RUNNER_NODE_VERSION } from "./lib/private-runner-installation.mjs";
import { PrivateRunnerRefusal, RUNNER_LIMITS, canonicalRunnerPath } from "./lib/private-runner-route.mjs";
const refuse = () => { throw new PrivateRunnerRefusal(); };
// No ambient entry reaches Bash, including startup files, shell options and
// exported functions. HOME comes from the account, never the caller. The fixed
// noninteractive, nonlogin argv below does not read profile or rc files.
const cleanEnvironment = () => ({ HOME: userInfo().homedir, LANG: "C", TMPDIR: "/private/tmp",
  PATH: `${dirname(PRIVATE_RUNNER_NODE)}:/opt/homebrew/bin:/usr/bin:/bin` });
const fixedEnvironment = () => ({ PATH: "/usr/bin:/bin", LANG: "C", TMPDIR: "/private/tmp" });
let activeChild = null, interrupted = false;
const interrupt = () => { interrupted = true; activeChild?.kill("SIGTERM"); };
process.on("SIGINT", interrupt); process.on("SIGTERM", interrupt);
const current = () => { if (interrupted) refuse(); };
function childCompletion(child) {
  activeChild = child;
  return new Promise(resolve => {
    // close follows exit and drains the private pipe before a snapshot is used.
    child.once("error", () => {});
    child.once("close", code => { if (activeChild === child) activeChild = null; resolve(code === 0 && !interrupted ? 0 : 1); });
  });
}
function git(root, ...args) {
  const value = spawnSync("/usr/bin/git", ["-C", root, ...args], { env: fixedEnvironment(), encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
  if (value.status !== 0) refuse(); return value.stdout;
}
async function acquire(root, output, plan) {
  current();
  const child = spawn(PRIVATE_RUNNER_NODE, [join(root, "tools/pool-action-modules/private-runner-bridge.mjs")], {
    cwd: root, env: fixedEnvironment(), stdio: ["ignore", "ignore", "ignore", "pipe"] });
  const transport = child.stdio[3], maximum = 8 + RUNNER_LIMITS.metadata + RUNNER_LIMITS.plan;
  let raw = Buffer.alloc(0);
  let failed = false;
  const stop = () => { failed = true; child.kill("SIGTERM"); };
  const watchdog = setTimeout(stop, 35000); watchdog.unref();
  const completed = childCompletion(child);
  transport.on("data", bytes => { if (raw.length + bytes.length > maximum) stop(); else raw = Buffer.concat([raw, bytes]); });
  transport.on("error", () => child.kill("SIGTERM"));
  transport.end(Buffer.from(`${canonicalJson({ phase: "P", source: plan, arguments: [output, plan, "4"] })}\n`));
  const status = await completed; clearTimeout(watchdog);
  if (status !== 0 || failed || raw.length < 8) refuse();
  const metadataLength = raw.readUInt32BE(0), payloadLength = raw.readUInt32BE(4);
  if (metadataLength === 0 || metadataLength > RUNNER_LIMITS.metadata || payloadLength > RUNNER_LIMITS.plan || raw.length !== 8 + metadataLength + payloadLength) refuse();
  const metadata = parseCanonicalLine(raw.subarray(8, 8 + metadataLength));
  if (keysOf(metadata) !== "bytes,error" || metadata.error !== null || metadata.bytes !== payloadLength || payloadLength === 0) refuse();
  return Buffer.from(raw.subarray(8 + metadataLength));
}
async function bootstrap() {
  current();
  if (process.execPath !== PRIVATE_RUNNER_NODE || process.version !== PRIVATE_RUNNER_NODE_VERSION || process.argv.length !== 6 || process.argv[5] !== "4") refuse();
  const [script, output, plan] = process.argv.slice(2);
  const root = realpathSync(process.cwd());
  canonicalRunnerPath(script); canonicalRunnerPath(output); canonicalRunnerPath(plan);
  if (git(root, "rev-parse", "--show-toplevel").trim() !== root) refuse();
  const revision = git(root, "rev-parse", "HEAD").trim();
  if (spawnSync("/usr/bin/python3", [join(root, "tools/pool-action-modules/private-runner-installation.py"), "--bootstrap", script], { cwd: root, env: fixedEnvironment(), stdio: "ignore" }).status !== 0) refuse();
  const scriptStat = lstatSync(script);
  scriptIdentity = { script, device: scriptStat.dev, inode: scriptStat.ino };
  const selector = join(root, "tools/apnt-pool-action-circuit/scripts/public-pk-load.plan");
  let bytes;
  if (plan === selector) {
    bytes = Buffer.from(git(root, "show", "HEAD:tools/apnt-pool-action-circuit/scripts/public-pk-load.plan"));
    if (bytes.length === 0 || bytes.length > RUNNER_LIMITS.plan || /(^|\s)--?request(?:=|\s|$)/u.test(bytes.toString("utf8"))) refuse();
  } else bytes = await acquire(root, output, plan);
  current();
  if (git(root, "rev-parse", "HEAD").trim() !== revision) refuse();
  // Node creates only this private snapshot transport after authenticating P.
  // The original PLAN descriptor is neither opened nor inherited.
  const continuation = spawn("/bin/bash", [script, output, plan, "4"], { cwd: root, env: { ...cleanEnvironment(),
    MEASURE_PK_LOAD_SELF: script, MEASURE_PK_LOAD_HERE: join(root, "tools/apnt-pool-action-circuit") },
    stdio: ["inherit", "inherit", "inherit", "ignore", "ignore", "ignore", "ignore", "ignore", "pipe"] });
  const completed = childCompletion(continuation);
  continuation.stdio[8].on("error", () => continuation.kill("SIGTERM"));
  continuation.stdio[8].end(bytes);
  return await completed;
}
// Remember only the checked public script's inode. Cleanup never opens a
// private input, and never removes a replacement placed at the scratch path.
let scriptIdentity = null;
try {
  process.exitCode = await bootstrap();
} catch { process.exitCode = 1; }
finally {
  process.off("SIGINT", interrupt); process.off("SIGTERM", interrupt);
  if (scriptIdentity !== null) {
    try {
      const stat = lstatSync(scriptIdentity.script);
      if (stat.isFile() && stat.uid === process.geteuid?.() && stat.dev === scriptIdentity.device && stat.ino === scriptIdentity.inode) unlinkSync(scriptIdentity.script);
    } catch {}
  }
}
