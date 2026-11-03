import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, readFileSync, readdirSync, linkSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";
const ENTRY = process.env.MIG01_RESULT_PARSER ?? "tools/pool-action-modules/private-runner-result.py";
const SHELL = process.env.MIG01_RESULT_SHELL ?? "tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh";
const quote = (s: string) => "'" + s.replaceAll("'", "'\\''") + "'";
function privateBoundary(shell: string, directory: string) {
  const start = shell.indexOf("# ---- private diagnostic boundary ----"), end = shell.indexOf("# ---- end private diagnostic boundary ----", start);
  expect(start).toBeGreaterThan(0); expect(end).toBeGreaterThan(start);
  const dieStart = shell.indexOf("die() {"), dieEnd = shell.indexOf("\ncleanup() {", dieStart);
  expect(dieStart).toBeGreaterThan(0); expect(dieEnd).toBeGreaterThan(dieStart);
  return `set -euo pipefail\nPRIVATE_RUNNER_GENERATION=2\nhas_live=true\nout=\ncleanup() { :; }\nresults=${quote(directory)}\n` + shell.slice(dieStart, dieEnd) + "\n" + shell.slice(start, end) + "\n";
}
function diagnosticLaunch(shell: string) {
  const start = shell.indexOf(" # ---- native diagnostic routing ----"), end = shell.indexOf("\n\twhile kill -0", start);
  expect(start).toBeGreaterThan(0); expect(end).toBeGreaterThan(start);
  const source = shell.slice(start, end);
  const prefix = /POOL_PK_LOAD_HARNESS_PID=\$\$ GOMAXPROCS=\$procs \/usr\/bin\/caffeinate[^\n]+\\\n\s*\/usr\/bin\/nice -n 10 /g;
  expect([...source.matchAll(prefix)]).toHaveLength(2);
  return source.replace(prefix, "") + "\n";
}
function leaks(bytes: string | Buffer, directory: string) {
  const canaries = [directory, JSON.stringify(directory), directory.replaceAll("/", "\\/"), Buffer.from(directory).toString("hex"), Buffer.from(directory).toString("base64"),
    "Traceback (most recent call last)", "SYNTHETIC_PRIVATE_TEXT_CANARY"];
  return canaries.some(canary => Buffer.from(bytes).includes(Buffer.from(canary)));
}
function optionalResult(value: any) {
  const pin = { bytes: 528, sha256: "01".repeat(32) }, witness = { kind: "live-request", description: "synthetic assignment only", entry: "wallet-payment", entryKind: "positive" };
  return { ...value, target: "synthetic action", residencyAtStart: { pages: 10, residentPages: 5, fraction: 0.5, method: "synthetic" },
    r1csResidencyAtStart: { pages: 10, residentPages: 5, fraction: 0.5, method: "synthetic" },
    pin, read: { ...pin, readAndHashSeconds: 0.1 }, decode: { format: "image", decodeSeconds: 0.2, zeroCopy: true },
    shape: { wires: 1, nbInfinityA: 0, nbInfinityB: 0, g1A: 1, g1B: 1, g1Z: 1, g1K: 1, g2B: 1, commitmentBasisLengths: [1], domainCardinality: 2 },
    admission: { source: { ...witness }, profileId: "02".repeat(32), parameters: "synthetic", keyFilesLoaded: false },
    prove: { witness: { ...witness }, r1cs: { ...pin }, verifyingKey: { ...pin }, constraints: 1, publicInputs: 1, verified: false, flippedPublicIndex: 0, flippedPublicNote: "synthetic", flippedRefused: false } };
}
function fixture() {
  const directory = realpathSync(mkdtempSync("/private/tmp/mig01-rr-R-1822-result-")), result = join(directory, "SYNTHETIC_PRIVATE_PATH_CANARY.json");
  const value = { notice: "synthetic zero-value native result", command: "prove", args: null, goVersion: "go1.24.2", gomaxprocs: 4, numCPU: 8, GOGC: "", GOMEMLIMIT: "", error: "live-request-work-failed", errorStage: "pin", processWallSeconds: 0.5, processMaxRSSBytes: 128,
    phases: [{ name: "admit-request", seconds: 0.1, maxRSSBytesAtEnd: 64, goHeldBytesAtEnd: 64 }] };
  return { directory, result, value, write: (v: any = value) => writeFileSync(result, typeof v === "string" ? v : JSON.stringify(v), { mode: 0o600 }),
    run: () => spawnSync("/usr/bin/python3", ["-B", ENTRY, result], { encoding: "utf8" }),
    code: () => spawnSync("/usr/bin/python3", ["-B", "-c", 'import importlib.util,sys\ns=importlib.util.spec_from_file_location("result",sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\ntry: m.read_live_result(sys.argv[2])\nexcept ValueError as e: sys.exit(0 if str(e)=="result-refused" else 2)\nsys.exit(3)', ENTRY, result], { encoding: "utf8" }),
    dispose: () => rmSync(directory, { recursive: true, force: true }) };
}

// Slice A extracts only the receipt/EXPECT tail, never launch, cache, admission,
// key loading or proving. Pin its bytes so a moved/truncated decision cannot
// silently turn these fixtures into parser-only coverage.
const RECEIPT_TAIL_START = "\tlocal result_status=0\n";
const RECEIPT_TAIL_END = "\n}\n\n# The plan is read on fd 3 so that nothing a case runs can consume it.\n";
const RECEIPT_TAIL_SHA256 = "80b3f9783846255e143cfa9206b8669bb03ea9d0ab9ab0f3184f502f6c5c97f9";
function receiptDecisionTail(shell: string) {
  const start = shell.indexOf(RECEIPT_TAIL_START), end = shell.indexOf(RECEIPT_TAIL_END);
  if (start < 0 || end <= start || shell.split(RECEIPT_TAIL_START).length !== 2 || shell.split(RECEIPT_TAIL_END).length !== 2) {
    throw new Error("receipt-tail-boundary");
  }
  const tail = shell.slice(start, end);
  if (createHash("sha256").update(tail).digest("hex") !== RECEIPT_TAIL_SHA256) throw new Error("receipt-tail-identity");
  return tail;
}
type ReceiptDecision = { expect: "ok" | "fail" | "refuse-open"; status: number; stage: string;
  receipt?: "present" | "missing" | "malformed" | "unsafe"; tripped?: string };
function runReceiptDecision(shell: string, tail: string, row: ReceiptDecision) {
  const f = fixture();
  try {
    const receipt = row.receipt ?? "present";
    const value = { ...f.value, errorStage: row.stage, phases: [...f.value.phases,
      { name: "load-r1cs", seconds: 0.2, maxRSSBytesAtEnd: 128, goHeldBytesAtEnd: 64 }] };
    if (receipt !== "missing") writeFileSync(join(f.directory, "p2.json"), receipt === "malformed" ? "{" :
      JSON.stringify(receipt === "unsafe" ? { ...value, args: ["SYNTHETIC_PRIVATE_TEXT_CANARY"] } : value), { mode: 0o600 });
    writeFileSync(join(f.directory, "p2.samples.tsv"), "epoch_s\tswap_used_bytes\tavailable_bytes\tphase_rss_bytes\n1\t0\t100\t64\n2\t1\t90\t128\n", { mode: 0o600 });
    writeFileSync(join(f.directory, "p2.time"), "0.5 real\n128 maximum resident set size\n256 peak memory footprint\n", { mode: 0o600 });
    // Keep the real diagnostic collector/EXIT cleanup, containing its disposable
    // reason files here so their removal is observable on success and refusal.
    const boundary = privateBoundary(shell.replace("/private/tmp/measure-pk-load-reason.XXXXXXXX", join(f.directory, "reason.XXXXXXXX")), f.directory);
    const setup = boundary + `repo=${quote(process.cwd())}\nname=p2\ncache=asis\nstatus=${row.status}\nswap0=0\ntripped=${quote(row.tripped ?? "")}\nexpect=${quote(row.expect)}\nlive=true\n`;
    const child = spawnSync("/bin/bash", ["-s"], { input: setup + "receipt_decision() {\n" + tail +
      '\n}\nreceipt_decision\nprintf "tail-returned\\n" >"$results/decision-returned"\n', encoding: "utf8", timeout: 10000 });
    expect(child.error).toBeUndefined(); expect(child.signal).toBeNull();
    expect(leaks(child.stdout + child.stderr, f.directory)).toBe(false);
    const files = readdirSync(f.directory);
    expect(files.some(file => file.startsWith("reason."))).toBe(false);
    for (const file of files) {
      // The deliberately poisoned INPUT must fire the detector; every derived
      // artifact and terminal stream must remain clear of the same canary.
      expect(leaks(readFileSync(join(f.directory, file)), f.directory), file).toBe(receipt === "unsafe" && file === "p2.json");
    }
    const summary = files.includes("p2.summary.json") ? JSON.parse(readFileSync(join(f.directory, "p2.summary.json"), "utf8")) : null;
    return { exit: [child.status, child.stdout, child.stderr], returned: files.includes("decision-returned"), summary };
  } finally { f.dispose(); }
}
function assertReceiptDecision(result: ReturnType<typeof runReceiptDecision>, row: ReceiptDecision, status: number) {
  expect(result.exit).toEqual([status, "", status === 0 ? "" : "measure-pk-load: live-plan-refused reason=no-diagnostic\n"]);
  expect(result.returned).toBe(status === 0);
  if ((row.receipt ?? "present") !== "present") expect(result.summary).toBeNull();
  else expect(result.summary).toEqual({ case: "p2", cache: "asis", expect: row.expect, exitStatus: row.status, tripped: row.tripped || null,
    samples: 2, swapBaselineBytes: 0, swapGrowthMaxBytes: 1, availableMinBytes: 90, sampledRSSMaxBytes: 128,
    timeRealSeconds: 0.5, timeMaxRSSBytes: 128, timePeakMemoryFootprintBytes: 256, evicted: [],
    residencyAtStart: null, r1csResidencyAtStart: null, processWallSeconds: 0.5, processMaxRSSBytes: 128,
    error: "live-request-work-failed", errorStage: row.stage,
    steps: { "admit-request": { seconds: 0.1, maxRSSBytesAtEnd: 64 }, "load-r1cs": { seconds: 0.2, maxRSSBytesAtEnd: 128 } } });
}

// Keep these titles outside the certification driver's existing RESULT regexes.
test.each(["fail", "refuse-open"] as const)("ARCH654 receipt decision StageOpen accepts EXPECT %s", expected => {
  const shell = readFileSync(SHELL, "utf8"), row: ReceiptDecision = { expect: expected, status: 1, stage: "open" };
  assertReceiptDecision(runReceiptDecision(shell, receiptDecisionTail(shell), row), row, 0);
});
const receiptStatusRows = (["ok", "fail", "refuse-open"] as const).flatMap(expected => [0, 1, 2].flatMap(status =>
  ["open", "decode", ""].filter(stage => !(status === 1 && stage === "open" && expected !== "ok"))
    .map(stage => ({ expect: expected, status, stage }))));
test.each(receiptStatusRows)("ARCH654 receipt decision status/stage $expect / $status / '$stage'", row => {
  const shell = readFileSync(SHELL, "utf8");
  const accepted = row.expect === "ok" ? row.status === 0 : row.status === 1 && (row.expect === "fail" || row.stage === "open");
  assertReceiptDecision(runReceiptDecision(shell, receiptDecisionTail(shell), row), row, accepted ? 0 : 1);
});
test.each((["ok", "fail", "refuse-open"] as const).flatMap(expected => (["missing", "malformed", "unsafe"] as const)
  .map(receipt => ({ expect: expected, status: expected === "ok" ? 0 : 1, stage: "open", receipt }))))(
  "ARCH654 receipt decision $receipt input refuses EXPECT $expect", row => {
    const shell = readFileSync(SHELL, "utf8");
    assertReceiptDecision(runReceiptDecision(shell, receiptDecisionTail(shell), row), row, 1);
  });
test.each((["ok", "fail", "refuse-open"] as const).flatMap(expected =>
  ["resource monitor unavailable", "swap grew 9 bytes over its baseline 0", "case RSS 25 bytes"]
    .map(tripped => ({ expect: expected, status: expected === "ok" ? 0 : 1, stage: "open", tripped }))))(
  "ARCH654 receipt decision monitor '$tripped' refuses EXPECT $expect", row => {
    const shell = readFileSync(SHELL, "utf8");
    assertReceiptDecision(runReceiptDecision(shell, receiptDecisionTail(shell), row), row, 1);
  });
test.each(["empty", "missing-start", "missing-end", "duplicate-start", "duplicate-end", "reversed", "empty-tail", "truncated-decision", "changed-decision"])(
  "ARCH654 receipt extraction rejects %s", kind => {
    const shell = readFileSync(SHELL, "utf8"), tail = receiptDecisionTail(shell);
    expect(Buffer.byteLength(tail)).toBe(3747);
    let invalid = shell;
    if (kind === "empty") invalid = "";
    if (kind === "missing-start") invalid = shell.replace(RECEIPT_TAIL_START, "");
    if (kind === "missing-end") invalid = shell.replace(RECEIPT_TAIL_END, "");
    if (kind === "duplicate-start") invalid = RECEIPT_TAIL_START + shell;
    if (kind === "duplicate-end") invalid = shell + RECEIPT_TAIL_END;
    if (kind === "reversed") invalid = RECEIPT_TAIL_END + RECEIPT_TAIL_START;
    if (kind === "empty-tail") invalid = RECEIPT_TAIL_START + RECEIPT_TAIL_END;
    if (kind === "truncated-decision") invalid = shell.replace(tail, tail.slice(0, tail.indexOf('\n\tif [[ $expect == ok ]]')));
    if (kind === "changed-decision") invalid = shell.replace("((status == 1))", "((status == 2))");
    expect(() => receiptDecisionTail(invalid)).toThrowError(["empty-tail", "truncated-decision", "changed-decision"].includes(kind) ? "receipt-tail-identity" : "receipt-tail-boundary");
  });
const receiptMutants: { name: string; before: string; after: string; row: ReceiptDecision; expected: number }[] = [
  { name: "ok status guard", before: "((status == 0))", after: "true", row: { expect: "ok", status: 2, stage: "open" }, expected: 1 },
  { name: "negative status guard", before: "((status == 1))", after: "true", row: { expect: "fail", status: 2, stage: "open" }, expected: 1 },
  { name: "stage equality", before: '[[ $expect == fail || refuse-$stage == "$expect" ]]', after: "true", row: { expect: "refuse-open", status: 1, stage: "decode" }, expected: 1 },
  { name: "generic fail alternative", before: '$expect == fail || ', after: "", row: { expect: "fail", status: 1, stage: "decode" }, expected: 0 },
  { name: "mandatory bounded parse", before: "    except Exception:\n        sys.exit(1)", after: '    except Exception:\n        native_result = {"phases": []}', row: { expect: "ok", status: 0, stage: "open", receipt: "missing" }, expected: 1 },
  { name: "parse status enforcement", before: '(( result_status == 0 )) || die "native result refused"', after: ":", row: { expect: "ok", status: 0, stage: "open", receipt: "malformed" }, expected: 1 },
  { name: "final stage binding", before: 'stage="$(/usr/bin/python3 "$repo/tools/pool-action-modules/private-runner-result.py" "$results/$name.json" 2>/dev/null)" || die "native result refused"', after: "stage=open", row: { expect: "refuse-open", status: 1, stage: "decode" }, expected: 1 },
  { name: "monitor trip guard", before: '[[ -z $tripped ]] || die "$name killed: $tripped"', after: ":", row: { expect: "refuse-open", status: 1, stage: "open", tripped: "resource monitor unavailable" }, expected: 1 },
];
test.each(receiptMutants)("ARCH654 receipt classifier mutant $name fires and restores", mutant => {
  const shell = readFileSync(SHELL, "utf8"), tail = receiptDecisionTail(shell);
  assertReceiptDecision(runReceiptDecision(shell, tail, mutant.row), mutant.row, mutant.expected);
  expect(tail.split(mutant.before)).toHaveLength(2);
  // Mutate only the already identity-checked scratch string, so a digest refusal
  // cannot stand in for the intended classifier regression. No source is edited.
  const changed = runReceiptDecision(shell, tail.replace(mutant.before, mutant.after), mutant.row);
  const changedStatus = mutant.expected === 0 ? 1 : 0;
  expect(changed.exit).toEqual([changedStatus, "", changedStatus === 0 ? "" : "measure-pk-load: live-plan-refused reason=no-diagnostic\n"]);
  expect(changed.returned).toBe(changedStatus === 0);
  expect(() => assertReceiptDecision(changed, mutant.row, mutant.expected)).toThrowError();
  assertReceiptDecision(runReceiptDecision(shell, receiptDecisionTail(shell), mutant.row), mutant.row, mutant.expected);
});
test.each("notice command args phases goVersion gomaxprocs numCPU GOGC GOMEMLIMIT processWallSeconds processMaxRSSBytes".split(" "))("PH11-OUTPUT missing native required field %s refuses", key => {
  const f = fixture(); try { const v: any = structuredClone(f.value); delete v[key]; f.write(v); const child = f.run(); expect([child.status, child.stdout.length, child.stderr.length]).toEqual([1, 0, 0]); expect(f.code().status).toBe(0); } finally { f.dispose(); }
});
test("PH11-OUTPUT complete optional native records decode and unknown nested fields refuse", () => {
  const f = fixture(); try {
    const v: any = optionalResult(f.value);
    f.write(v); let child = f.run(); expect([child.status, child.stdout, child.stderr]).toEqual([0, "pin\n", ""]);
    for (const path of ["pin", "read", "decode", "shape", "admission", "admission.source", "prove", "prove.witness", "prove.r1cs", "prove.verifyingKey"]) {
      const invalid = structuredClone(v); let target = invalid; for (const field of path.split(".")) target = target[field]; target.private = "SYNTHETIC_PRIVATE_TEXT_CANARY";
      f.write(invalid); child = f.run(); expect([child.status, child.stdout.length, child.stderr.length]).toEqual([1, 0, 0]);
    }
  } finally { f.dispose(); }
});
test.each(["residencyAtStart", "r1csResidencyAtStart", "pin", "read", "decode", "shape", "admission", "admission.source", "prove", "prove.witness", "prove.r1cs", "prove.verifyingKey", "phases.0"])("PH11-OUTPUT integer unknown nested field %s refuses at the closed key set", path => {
  const f = fixture(); try {
    const value: any = optionalResult(f.value); f.write(value);
    let child = f.run(); expect([child.status, child.stdout, child.stderr]).toEqual([0, "pin\n", ""]);
    let target = value; for (const field of path.split(".")) target = target[field]; target.private = 7;
    f.write(value); child = f.run(); expect([child.status, child.stdout.length, child.stderr.length]).toEqual([1, 0, 0]); expect(f.code().status).toBe(0);
  } finally { f.dispose(); }
});
test.each(["", "pin", "open", "size", "read", "digest", "decode"])("PH11-OUTPUT bounded parser preserves exact ordinary failure stage '%s'", stage => {
  const f = fixture(); try { f.value.errorStage = stage; f.write(); const child = f.run(); expect([child.status, child.stdout === stage + "\n", child.stderr.length]).toEqual([0, true, 0]); } finally { f.dispose(); }
});
test.each(["unknown", "missing", "case", "stage-case", "args", "cpu-type", "cpu-bool", "version", "wall-null", "env", "residency-extra", "residency-missing", "residency-fraction", "residency-type", "nested-type"])("PH11-OUTPUT closed native schema refuses %s without public output", kind => {
  const f = fixture(); try {
    const v: any = structuredClone(f.value);
    if (kind === "unknown") v.private = "SYNTHETIC_PRIVATE_TEXT_CANARY";
    if (kind === "missing") delete v.args;
    if (kind === "case") v.case = "foreign";
    if (kind === "stage-case") v.errorStage = "PIN";
    if (kind === "args") v.args = ["SYNTHETIC_PRIVATE_TEXT_CANARY"];
    if (kind === "cpu-type") v.numCPU = "8";
    if (kind === "cpu-bool") v.numCPU = true;
    if (kind === "version") v.goVersion = "foreign";
    if (kind === "wall-null") v.processWallSeconds = null;
    if (kind === "env") v.GOMEMLIMIT = "SYNTHETIC_PRIVATE_TEXT_CANARY";
    if (kind.startsWith("residency")) v.residencyAtStart = { pages: 10, residentPages: 5, fraction: 0.5, method: "synthetic" };
    if (kind === "residency-extra") v.residencyAtStart.private = "SYNTHETIC_PRIVATE_TEXT_CANARY";
    if (kind === "residency-missing") delete v.residencyAtStart.pages;
    if (kind === "residency-fraction") v.residencyAtStart.fraction = 2;
    if (kind === "residency-type") v.residencyAtStart.pages = "10";
    if (kind === "nested-type") v.pin = { bytes: true, sha256: "synthetic" };
    f.write(v); const child = f.run(); expect([child.status, child.stdout.length, child.stderr.length]).toEqual([1, 0, 0]);
    expect(f.code().status).toBe(0);
  } finally { f.dispose(); }
});
test.each(["absent", "removed", "directory", "symlink", "hardlink", "mode", "empty", "malformed", "duplicate", "trailing", "nan", "large", "command", "stage-type", "stage-text", "error-text", "wall-type", "rss-type", "residency-type", "phase-type", "phase-name", "phase-missing", "phase-number"])("PH11-OUTPUT independently refuses %s silently", kind => {
  const f = fixture(); try {
    let value: any = structuredClone(f.value);
    if (kind === "empty") value = "";
    if (kind === "malformed") value = "{";
    if (kind === "duplicate") value = '{"command":"prove","command":"admit-request"}';
    if (kind === "trailing") value = JSON.stringify(value) + "{}";
    if (kind === "nan") value = '{"command":"prove","processWallSeconds":NaN}';
    if (kind === "large") value = " ".repeat(1024 * 1024 + 1);
    if (kind === "command") value.command = "foreign";
    if (kind === "stage-type") value.errorStage = {};
    if (kind === "stage-text") value.errorStage = "SYNTHETIC_PRIVATE_TEXT_CANARY";
    if (kind === "error-text") value.error = "SYNTHETIC_PRIVATE_TEXT_CANARY";
    if (kind === "wall-type") value.processWallSeconds = "SYNTHETIC_PRIVATE_TEXT_CANARY";
    if (kind === "rss-type") value.processMaxRSSBytes = -1;
    if (kind === "residency-type") value.residencyAtStart = 1;
    if (kind === "phase-type") value.phases = "SYNTHETIC_PRIVATE_TEXT_CANARY";
    if (kind === "phase-name") value.phases[0].name = "SYNTHETIC_PRIVATE_TEXT_CANARY";
    if (kind === "phase-missing") delete value.phases[0].seconds;
    if (kind === "phase-number") value.phases[0].seconds = "SYNTHETIC_PRIVATE_TEXT_CANARY";
    if (kind !== "absent" && kind !== "directory") f.write(value);
    if (kind === "removed") rmSync(f.result);
    if (kind === "directory") mkdirSync(f.result);
    if (kind === "symlink") { const other = join(f.directory, "other"); f.write(); writeFileSync(other, JSON.stringify(f.value), { mode: 0o600 }); rmSync(f.result); symlinkSync(other, f.result); }
    if (kind === "hardlink") linkSync(f.result, join(f.directory, "other"));
    if (kind === "mode") chmodSync(f.result, 0o644);
    const child = f.run(); expect([child.status, child.stdout.length, child.stderr.length]).toEqual([1, 0, 0]);
  } finally { f.dispose(); }
});
test("PH11-OUTPUT path/traceback detector fires on independent canaries and excludes safe fixed stage text", () => {
  const f = fixture(); try {
    const leaks = (text: string) => text.includes(f.result) || text.includes("SYNTHETIC_PRIVATE_PATH_CANARY") || text.includes("Traceback (most recent call last)") || text.includes("SYNTHETIC_PRIVATE_TEXT_CANARY");
    for (const representation of [f.result, JSON.stringify(f.result), 'Traceback (most recent call last)', "SYNTHETIC_PRIVATE_TEXT_CANARY"]) expect(leaks(representation)).toBe(true);
    expect(leaks("measure-pk-load: live-plan-refused\npin\n")).toBe(false);
    expect(leaks(f.run().stderr)).toBe(false);
  } finally { f.dispose(); }
});

test.each(["remove-before-open", "replace-before-open", "truncate-after-stat", "append-after-stat"])("PH11-OUTPUT raced native result %s silently refuses after an existence observation", kind => {
  const f = fixture();
  try {
    f.write();
    const program = `import importlib.util, os, sys
spec=importlib.util.spec_from_file_location("guarded_result",sys.argv[1]); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
source=sys.argv[2]; original_open=module.os.open; original_stat=module.os.fstat
assert os.path.isfile(source)
def raced_open(path,flags):
 if ${JSON.stringify(kind)}=="remove-before-open": os.unlink(path)
 if ${JSON.stringify(kind)}=="replace-before-open":
  os.unlink(path)
  with open(path,"w") as file: file.write("malformed-private-result")
  os.chmod(path,0o600)
 return original_open(path,flags)
def raced_stat(fd):
 value=original_stat(fd)
 if ${JSON.stringify(kind)}=="truncate-after-stat":
  with open(source,"w") as file: file.write("{")
 if ${JSON.stringify(kind)}=="append-after-stat":
  with open(source,"a") as file: file.write(chr(10))
 return value
module.os.open=raced_open; module.os.fstat=raced_stat
try: module.read_live_result(source)
except Exception: sys.exit(1)
sys.exit(0)`;
    const child = spawnSync("/usr/bin/python3", ["-B", "-c", program, ENTRY, f.result], { encoding: "utf8" });
    expect([child.status, child.stdout.length, child.stderr.length]).toEqual([1, 0, 0]);
  } finally { f.dispose(); }
});
test("PH11-OUTPUT leak-detector representation and artifact matrix fires and safe lookalikes remain clear", () => {
  const f = fixture();
  try {
    const canaries = [f.result, JSON.stringify(f.result), f.result.replaceAll("/", "\\/"), Buffer.from(f.result).toString("hex"),
      Buffer.from(f.result).toString("base64"), "Traceback (most recent call last)", "SYNTHETIC_PRIVATE_TEXT_CANARY"];
    const artifacts = ["terminal.stdout", "terminal.stderr", "native-result.json", "outer-summary.json", "samples.tsv", "time.txt", "closed-report.txt"];
    const leaks = (bytes: Buffer) => canaries.some(canary => bytes.includes(Buffer.from(canary)));
    for (const artifact of artifacts) {
      const file = join(f.directory, artifact);
      writeFileSync(file, "measure-pk-load: live-plan-refused\npin\n", { mode: 0o600 });
      expect(leaks(readFileSync(file))).toBe(false);
      for (const canary of canaries) {
        writeFileSync(file, canary, { mode: 0o600 });
        expect(leaks(readFileSync(file)), artifact).toBe(true);
      }
    }
    const parser = f.run(); expect(parser.stdout.length).toBe(0); expect(parser.stderr.length).toBe(0);
    // Deliberately restore the old unguarded parse on an absent synthetic
    // path. Its traceback must fire this same independently checked detector.
    const unsafe = spawnSync("/usr/bin/python3", ["-c", "import json,sys; print(json.load(open(sys.argv[1])).get('errorStage',''))", f.result], { encoding: "utf8" });
    expect(unsafe.status).toBe(1); expect(leaks(Buffer.from(unsafe.stderr))).toBe(true);
  } finally { f.dispose(); }
});
test.each(["valid", "missing-samples", "empty-samples", "output-directory", "time-directory", "missing-result"])("PH11-OUTPUT private shell summary unit %s contains diagnostics and preserves refusal", kind => {
  const f = fixture(); try {
    // Exact owned summary unit, not the production entry/P/A/W or a prove.
    const shell = readFileSync(SHELL, "utf8"), start = shell.indexOf("\tlocal result_status=0");
    const unit = shell.slice(start, shell.indexOf('\n\techo "measure-pk-load: $name ended', start)); expect(start).toBeGreaterThan(0);
    if (kind !== "missing-result") writeFileSync(join(f.directory, "p2.json"), JSON.stringify(f.value), { mode: 0o600 });
    if (kind === "output-directory") mkdirSync(join(f.directory, "p2.summary.json"));
    if (kind === "time-directory") mkdirSync(join(f.directory, "p2.time"));
    const header = "epoch_s\tswap_used_bytes\tavailable_bytes\tphase_rss_bytes\n";
    if (kind !== "missing-samples") writeFileSync(join(f.directory, "p2.samples.tsv"), header + (kind === "empty-samples" ? "" : "1\t0\t100\t128\n"), { mode: 0o600 });
    const setup = privateBoundary(shell, f.directory) + `repo=${quote(process.cwd())}\nname=p2\ncache=asis\nstatus=0\nswap0=0\ntripped=''\nexpect=ok\nlive=true\n`;
    const child = spawnSync("/bin/bash", ["-s"], { input: setup + "summary_unit() {\n" + unit + "\n}\nsummary_unit\n", encoding: "utf8" });
    expect(leaks(child.stdout + child.stderr, f.directory)).toBe(false);
    // The missing native result is refused silently by the bounded parser.
    // Empty stderr has its own closed observation; writer tracebacks stay unknown.
    const reason = kind === "missing-result" ? "no-diagnostic" : "unclassified";
    expect([child.status, child.stdout, child.stderr]).toEqual([kind === "valid" ? 0 : 1, "", kind === "valid" ? "" : `measure-pk-load: live-plan-refused reason=${reason}\n`]);
    for (const file of readdirSync(f.directory)) {
      if (file === "p2.summary.json" && kind === "output-directory" || file === "p2.time" && kind === "time-directory") continue;
      expect(leaks(readFileSync(join(f.directory, file)), f.directory)).toBe(false);
    }
  } finally { f.dispose(); }
});
test.each(["valid", "missing-case-summary", "missing-run-record", "malformed-run-record", "output-directory", "output-dangling-link"])("PH11-OUTPUT final combined summary %s contains diagnostics and preserves refusal", kind => {
  const f = fixture(); try {
    const shell = readFileSync(SHELL, "utf8"), start = shell.indexOf('/usr/bin/python3 - "$results" "${names[@]}"');
    expect(start).toBeGreaterThan(0);
    const unit = shell.slice(start, shell.indexOf('\nif $has_live; then echo "measure-pk-load: done', start));
    if (kind !== "missing-run-record") writeFileSync(join(f.directory, "run.json"), kind === "malformed-run-record" ? "{" : '{"repo":null,"outDir":null}', { mode: 0o600 });
    if (kind !== "missing-case-summary") writeFileSync(join(f.directory, "p2.summary.json"), '{"case":"p2"}', { mode: 0o600 });
    if (kind === "output-directory") mkdirSync(join(f.directory, "summary.json"));
    if (kind === "output-dangling-link") symlinkSync(join(f.directory, "missing", "summary.json"), join(f.directory, "summary.json"));
    const child = spawnSync("/bin/bash", ["-s"], { input: privateBoundary(shell, f.directory) + "names=(p2)\n" + unit, encoding: "utf8" });
    expect(leaks(child.stdout + child.stderr, f.directory)).toBe(false);
    expect([child.status, child.stdout.length, child.stderr === (kind === "valid" ? "" : "measure-pk-load: live-plan-refused reason=unclassified\n")]).toEqual([kind === "valid" ? 0 : 1, 0, true]);
    for (const file of readdirSync(f.directory)) {
      if (file === "summary.json" && kind.startsWith("output-")) continue;
      expect(leaks(readFileSync(join(f.directory, file)), f.directory)).toBe(false);
    }
    if (kind === "valid") expect(JSON.parse(readFileSync(join(f.directory, "summary.json"), "utf8"))).toEqual({ run: { repo: null, outDir: null }, cases: [{ case: "p2" }] });
  } finally { f.dispose(); }
});
test.each(["valid", "metadata-output-directory", "shell-output-directory", "cleanup-valid", "cleanup-failure", "cleanup-marker-failure"])("PH11-OUTPUT earlier private writer %s contains diagnostics and preserves refusal", kind => {
  const f = fixture(); try {
    const shell = readFileSync(SHELL, "utf8"), start = shell.indexOf('/usr/bin/python3 - "$results/run.json"');
    expect(start).toBeGreaterThan(0);
    const unit = shell.slice(start, shell.indexOf("\n# ---- cases ----", start));
    if (kind === "metadata-output-directory") mkdirSync(join(f.directory, "run.json"));
    const setup = privateBoundary(shell, f.directory) + `repo=${quote(process.cwd())}\nout=${quote(f.directory)}\nbin=/bin/echo\nprocs=4\nhead_commit=synthetic\nSWAP_GROWTH_TRIP_BYTES=8589934592\nRSS_TRIP_BYTES=25769803776\nSAMPLE_SECONDS=1\n`;
    const cleanupStart = shell.indexOf("cleanup() {"), cleanupEnd = shell.indexOf("\ntrap cleanup EXIT", cleanupStart);
    expect(cleanupStart).toBeGreaterThan(0); expect(cleanupEnd).toBeGreaterThan(cleanupStart);
    if (kind === "cleanup-valid" || kind === "cleanup-marker-failure") writeFileSync(join(f.directory, "self-copy"), "synthetic public script", { mode: 0o600 });
    if (kind === "cleanup-marker-failure") mkdirSync(join(f.directory, "marker-directory"));
    const marker = join(f.directory, kind === "cleanup-marker-failure" ? "marker-directory/marker" : "marker");
    const cleanupSetup = `\nmarker_owned=${kind === "cleanup-failure" ? "false" : "true"}\nMEASURE_PK_LOAD_SELF=${quote(kind === "cleanup-failure" ? f.directory : join(f.directory, "self-copy"))}\nPROVER_MARKER=${quote(marker)}\n` + (kind !== "cleanup-failure" ? 'printf "pid %s\\n" "$$" >"$PROVER_MARKER"\n' : "") + (kind === "cleanup-marker-failure" ? `/bin/chmod 500 ${quote(join(f.directory, "marker-directory"))}\n` : "");
    const command = kind === "shell-output-directory" ? 'printf safe >"$results"\n' : kind.startsWith("cleanup-") ? shell.slice(cleanupStart, cleanupEnd) + cleanupSetup : unit;
    const child = spawnSync("/bin/bash", ["-s"], { input: setup + command, encoding: "utf8" });
    expect(leaks(child.stdout + child.stderr, f.directory)).toBe(false);
    const valid = kind === "valid" || kind === "cleanup-valid";
    expect([child.status, child.stdout.length, child.stderr === (valid ? "" : "measure-pk-load: live-plan-refused reason=unclassified\n")]).toEqual([valid ? 0 : 1, 0, true]);
    if (kind === "cleanup-valid") expect(readdirSync(f.directory)).toEqual([]);
    if (kind === "cleanup-marker-failure") expect(readdirSync(f.directory)).toEqual(["marker-directory"]);
    if (kind === "valid") expect(leaks(readFileSync(join(f.directory, "run.json")), f.directory)).toBe(false);
  } finally { if (kind === "cleanup-marker-failure") chmodSync(join(f.directory, "marker-directory"), 0o700); f.dispose(); }
});
test("PH11-OUTPUT staged marker omits private paths", () => {
  const f = fixture(); try {
    const shell = readFileSync(SHELL, "utf8"), start = shell.indexOf('(\n\tset -o noclobber'); expect(start).toBeGreaterThan(0);
    const unit = shell.slice(start, shell.indexOf("\nmarker_owned=true", start));
    const marker = join(f.directory, "marker");
    const child = spawnSync("/bin/bash", ["-s"], { input: privateBoundary(shell, f.directory) + `PROVER_MARKER=${quote(marker)}\nout=${quote(f.directory)}\n` + unit, encoding: "utf8" });
    expect([child.status, child.stdout.length, child.stderr.length]).toEqual([0, 0, 0]);
    expect(leaks(readFileSync(marker), f.directory)).toBe(false); expect(readFileSync(marker, "utf8")).toMatch(/^pid [0-9]+\n$/);
  } finally { f.dispose(); }
});
test("PH11-OUTPUT staged native diagnostic files discard a planted path", () => {
  const f = fixture(); try {
    const shell = readFileSync(SHELL, "utf8");
    // Exact owned routing, with a synthetic child replacing the native argv.
    const launch = diagnosticLaunch(shell);
    const bin = join(f.directory, "synthetic-child");
    writeFileSync(bin, '#!/bin/sh\nprintf "%s\\n" "$1"\nprintf "%s\\n" "$1" >&2\nprintf child-executed >"$2.executed"\n', { mode: 0o700 });
    const child = spawnSync("/bin/bash", ["-s", "--", f.directory], { input: privateBoundary(shell, f.directory) + `name=p2\nlive=true\nbin=${quote(bin)}\n` + launch + '\nwait "$pid"\n', encoding: "utf8" });
    expect(leaks(child.stdout + child.stderr, f.directory)).toBe(false);
    expect([child.status, child.stdout.length, child.stderr]).toEqual([0, 0, ""]);
    expect(readFileSync(join(f.directory, "p2.json.executed"), "utf8")).toBe("child-executed");
    for (const file of readdirSync(f.directory)) expect(leaks(readFileSync(join(f.directory, file)), f.directory)).toBe(false);
  } finally { f.dispose(); }
});
test.each([
  ["valid", "check-live", 17, ""],
  ["live-plan-memory-floor", "prove", 16, "live-plan-memory-floor"],
  ["check-live-below-floor", "check-live", 16, ""],
  ["prove-at-floor", "prove", 17, ""],
  ["live-plan-main-checkout", "check-live", 17, "live-plan-main-checkout"],
] as const)("PH11-OUTPUT closed shell refusal reason %s survives without a receipt", (kind, command, floor, reason) => {
  const f = fixture(); try {
    const shell = readFileSync(SHELL, "utf8"), start = shell.indexOf("# ---- the plan, checked before anything runs ----");
    const end = shell.indexOf("# ---- output directory ----", start);
    expect(start).toBeGreaterThan(0); expect(end).toBeGreaterThan(start);
    const repo = join(f.directory, "main");
    expect(spawnSync("/usr/bin/git", ["init", "-q", "-b", "main", repo]).status).toBe(0);
    // A real checkout off main, never the suite's own checkout: the no-proof
    // driver runs this suite inside a clean main fixture.
    const other = join(repo, "lane");
    if (kind === "live-plan-main-checkout") expect(spawnSync("/usr/bin/git", ["init", "-q", "-b", "lane", other]).status).toBe(0);
    // Prove still refuses below 17 GiB; the equivalent check-live plan does
    // not. Both controls stop before receipt creation, key work or launch.
    const setup = privateBoundary(shell, f.directory) + `repo=${quote(kind === "live-plan-main-checkout" ? other : repo)}\nhas_prove=false\nplan_source() { printf '%s\\n' 'p2 ${floor} asis ok ${command} --request absent'; }\n`;
    const child = spawnSync("/bin/bash", ["-s"], { input: setup + shell.slice(start, end), encoding: "utf8" });
    expect(leaks(child.stdout + child.stderr, f.directory)).toBe(false);
    expect([child.status, child.stdout, child.stderr]).toEqual([reason ? 1 : 0, "", reason ? `measure-pk-load: live-plan-refused reason=${reason}\n` : ""]);
    expect(readdirSync(f.directory)).toEqual(["main"]); // No receipt, key work or output creation.
  } finally { f.dispose(); }
});
test.each(["result-write", "written-receipt", "empty", "unknown", "safe-plus-private", "safe-plus-newline", "safe-plus-nul", "two-safe-codes", "no-newline", "crlf", "long-unknown"])("PH11-OUTPUT closed child refusal reason %s survives the missing-receipt boundary", kind => {
  const f = fixture(); try {
    const shell = readFileSync(SHELL, "utf8"), start = shell.indexOf("\tlocal result_status=0");
    expect(start).toBeGreaterThan(0);
    const summary = shell.slice(start, shell.indexOf('\n\techo "measure-pk-load: $name ended', start));
    const safe = "live-request-result-write\n", privateText = f.directory + " SYNTHETIC_PRIVATE_TEXT_CANARY";
    const messages: Record<string, string> = { "result-write": safe, "written-receipt": "live-request-memory-floor\n", "empty": "", "unknown": privateText,
      "safe-plus-private": safe + privateText, "safe-plus-newline": safe + "\n", "safe-plus-nul": safe + "\0",
      "two-safe-codes": safe + safe, "no-newline": safe.trimEnd(), "crlf": safe.replace("\n", "\r\n"), "long-unknown": safe + privateText.repeat(256) };
    const bin = join(f.directory, "synthetic-child");
    writeFileSync(bin, '#!/usr/bin/python3 -I\nimport sys\nsys.stderr.buffer.write(bytes.fromhex(sys.argv[1]))\nsys.exit(1)\n', { mode: 0o700 });
    writeFileSync(join(f.directory, "p2.samples.tsv"), "epoch_s\tswap_used_bytes\tavailable_bytes\tphase_rss_bytes\n1\t0\t100\t128\n", { mode: 0o600 });
    if (kind === "written-receipt") writeFileSync(join(f.directory, "p2.json"), JSON.stringify({ ...f.value, error: "live-request-memory-floor" }), { mode: 0o600 });
    const setup = privateBoundary(shell, f.directory) + `repo=${quote(process.cwd())}\nname=p2\ncache=asis\nstatus=0\nswap0=0\ntripped=''\nexpect=fail\nlive=true\nbin=${quote(bin)}\n`;
    const child = spawnSync("/bin/bash", ["-s", "--", Buffer.from(messages[kind]).toString("hex")], {
      input: setup + diagnosticLaunch(shell) + '\nwait "$pid" || status=$?\nsummary_unit() {\n' + summary + '\n}\nsummary_unit\nexit "$status"\n', encoding: "utf8", timeout: 10000 });
    expect(leaks(child.stdout + child.stderr, f.directory)).toBe(false);
    // Classification comes from the exact stderr stream, independently of
    // receipt existence. A named memory refusal must remain a failure.
    const reason = kind === "result-write" ? "live-request-result-write" : kind === "written-receipt" ? "live-request-memory-floor" : kind === "empty" ? "no-diagnostic" : "unclassified";
    expect([child.status, child.stdout, child.stderr]).toEqual([1, "", `measure-pk-load: live-plan-refused reason=${reason}\n`]);
    for (const file of readdirSync(f.directory)) expect(leaks(readFileSync(join(f.directory, file)), f.directory), file).toBe(false);
    expect(readdirSync(f.directory).includes("p2.json")).toBe(kind === "written-receipt");
    expect(readdirSync(f.directory).includes("p2.stderr")).toBe(false);
    if (kind === "written-receipt") {
      const result = JSON.parse(readFileSync(join(f.directory, "p2.summary.json"), "utf8"));
      expect([result.error, result.errorStage]).toEqual(["live-request-memory-floor", "pin"]);
    }
  } finally { f.dispose(); }
});
test.each(["valid", "writer-failure", "removal-failure", "removal-failure-named", "removal-failure-unknown", "open-failure", "inherited-python"])("PH11-OUTPUT closed reason collector %s reaps and preserves cleanup status", kind => {
  const f = fixture(); try {
    let shell = readFileSync(SHELL, "utf8").replace("/private/tmp/measure-pk-load-reason.XXXXXXXX", join(f.directory, "reason.XXXXXXXX"));
    const replaceOnce = (before: string, after: string) => {
      expect(shell.split(before).length - 1).toBe(1);
      shell = shell.replace(before, after);
    };
    const removalFailure = kind.startsWith("removal-failure");
    if (kind === "writer-failure") replaceOnce('print(codes.get(raw, "unclassified"))', 'print("unclassified"); sys.exit(1)');
    if (removalFailure) replaceOnce('/bin/rm -f "$private_runner_diagnostic_file" || status=1', 'false || status=1');
    if (kind === "open-failure") replaceOnce('exec 2>"$private_runner_diagnostic_file.stream"', 'false');
    if (kind === "inherited-python") writeFileSync(join(f.directory, "sitecustomize.py"), 'from pathlib import Path\nPath("python-hook-fired").write_text("SYNTHETIC_PRIVATE_TEXT_CANARY")\n');
    const diagnostic = kind === "removal-failure-named" ? 'printf "live-request-memory-floor\\n" >&2\n' : kind === "removal-failure-unknown" ? 'printf "SYNTHETIC_PRIVATE_TEXT_CANARY\\n" >&2\n' : "";
    const child = spawnSync("/bin/bash", ["-s"], { input: privateBoundary(shell, f.directory) + diagnostic, cwd: f.directory,
      env: { ...process.env, PYTHONPATH: f.directory }, encoding: "utf8", timeout: 10000 });
    expect(leaks(child.stdout + child.stderr, f.directory)).toBe(false);
    const valid = kind === "valid" || kind === "inherited-python";
    // A failed removal still forces exit 1, even when the child was successful
    // and silent. Retain the independently classified stream, never raw bytes.
    const reason = kind === "removal-failure" ? "no-diagnostic" : kind === "removal-failure-named" ? "live-request-memory-floor" : "unclassified";
    expect([child.status, child.stdout, child.stderr]).toEqual([valid ? 0 : 1, "", valid ? "" : `measure-pk-load: live-plan-refused reason=${reason}\n`]);
    const files = readdirSync(f.directory);
    if (removalFailure) {
      expect(files).toHaveLength(1); expect(files[0]).toMatch(/^reason\.[a-zA-Z0-9]+$/);
      const retained = join(f.directory, files[0], "reason");
      expect(readdirSync(join(f.directory, files[0]))).toEqual(["reason"]);
      expect(readFileSync(retained, "utf8")).toBe(reason + "\n");
      expect(leaks(readFileSync(retained), f.directory)).toBe(false);
    } else expect(files).toEqual(kind === "inherited-python" ? ["sitecustomize.py"] : []);
  } finally { f.dispose(); }
});
test("PH11-OUTPUT diagnostic scanner fires on planted stdout stderr and file paths", () => {
  const f = fixture(); try {
    for (const representation of [f.directory, JSON.stringify(f.directory), f.directory.replaceAll("/", "\\/"), Buffer.from(f.directory).toString("hex"), Buffer.from(f.directory).toString("base64")]) {
      const child = spawnSync("/usr/bin/python3", ["-B", "-c", 'import sys; print(sys.argv[1]); print(sys.argv[1],file=sys.stderr)', representation], { encoding: "utf8" });
      expect(child.status).toBe(0); expect(leaks(child.stdout, f.directory)).toBe(true); expect(leaks(child.stderr, f.directory)).toBe(true);
      const file = join(f.directory, "planted-output"); writeFileSync(file, representation, { mode: 0o600 }); expect(leaks(readFileSync(file), f.directory)).toBe(true);
    }
    expect(leaks("measure-pk-load: live-plan-refused\npin\n", f.directory)).toBe(false);
  } finally { f.dispose(); }
});
