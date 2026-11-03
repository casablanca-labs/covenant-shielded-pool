#!/usr/bin/env python3
"""ENG-559: public-data live adapter controls and one gated execute-only run.

Usage: python3 -B test/aggregate-live-input.test.py RUNNER CANONICAL-ELF NEW-SCRATCH
RUNNER must have been freshly built with --locked --release --features prove.
No setup/prove command is executed. The positive uses the actual gated harness,
which builds its own runner. Negatives have an absent ELF as a second barrier.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import shutil

runner, elf, scratch = [Path(p).resolve() for p in sys.argv[1:]]
scratch.mkdir(parents=True, exist_ok=False)
tool = Path(__file__).resolve().parent.parent
root = tool.parent.parent
vectors = json.loads((tool / "fixtures/pool-aggregate-statement-vectors-v5.json").read_text())
vector = next(v for v in vectors["vectors"] if v["name"] == "b1-rel1")
proofs = tool / "fixtures/simulated-ceremony-zero-value-rev3/proofs"
good = {
    "schema": "apnt-pool-aggregate-live-input-v1",
    "label": "SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY",
    "deploymentId": hashlib.sha256(b"ENG-559 public test deployment; not chain truth").hexdigest(),
    "profileId": vectors["profileId"],
    "actions": [{"recordHex": vector["records"][0], "proofHex":
                 (proofs / "rel1-real-real-deposit-withdrawal.proof.bin").read_bytes().hex()}],
}
assert good["deploymentId"] != vectors["deploymentId"]
input_file = scratch / "live.public.json"
input_file.write_text(json.dumps(good, indent=2) + "\n")
env = dict(os.environ, RAYON_NUM_THREADS="4", CARGO_BUILD_JOBS="4", TMPDIR=str(scratch))
checks = []


def refuse(name, value, cause, batch="live-b1"):
    path = scratch / (name + ".json")
    path.write_text(json.dumps(value) + "\n")
    result = subprocess.run([str(runner), "proof-dry-run", "--batch", batch,
                             "--canonical-elf", str(scratch / "absent.elf"),
                             "--live-input", str(path)], env=env, capture_output=True, text=True)
    (scratch / (name + ".stdout")).write_text(result.stdout)
    (scratch / (name + ".stderr")).write_text(result.stderr)
    assert result.returncode == 1 and result.stderr.strip() == "Error: " + cause, (name, result)
    assert not result.stdout, name
    checks.append({"case": name, "cause": cause, "exit": result.returncode})
    print("PASS", name, cause, flush=True)


for count in (0, 65536):
    value = copy.deepcopy(good)
    value["actions"] *= count
    refuse("count-" + str(count), value, "pool-live-batch-size")
value = copy.deepcopy(good)
value["profileId"] = "42" * 32
refuse("profile", value, "pool-aggregate-profile-not-allowlisted")
value = copy.deepcopy(good)
value["actions"][0]["recordHex"] = "00"
refuse("record-length", value, "pool-record-length")
value = copy.deepcopy(good)
record = bytearray.fromhex(value["actions"][0]["recordHex"])
record[96] = 4
value["actions"][0]["recordHex"] = record.hex()
refuse("record-key", value, "pool-record-key")
value = copy.deepcopy(good)
value["actions"][0]["proofHex"] = (proofs / "dummy-dummy-deposit.proof.bin").read_bytes().hex()
refuse("proof-for-other-record", value, "pool-aggregate-proof-rejected")
value = copy.deepcopy(good)
value["actions"][0]["proofHex"] = (proofs.parent / "transform/alt-proof.bin").read_bytes().hex()
refuse("proof-under-other-key", value, "pool-aggregate-proof-rejected")
value = copy.deepcopy(good)
value["privateWitness"] = "unexpected-field-control"
refuse("extra-field", value, "pool-live-input-fields")

# Canonical B=3 and B=17 batches of existing public children. The supplied
# deployment changes ad order, so derive it explicitly (unsigned byte order).
big = next(v for v in vectors["vectors"] if v["name"] == "b17-reversed")
def public_batch(count):
    value = copy.deepcopy(good)
    actions = [{"recordHex": r, "proofHex": (proofs / (n + ".proof.bin")).read_bytes().hex()}
               for r, n in zip(big["records"][:count], big["recordNames"][:count])]
    dep = bytes.fromhex(value["deploymentId"])
    actions.sort(key=lambda a: hashlib.sha256(b"APNT-POOL-v1:action-auth" + dep + bytes.fromhex(a["recordHex"])).digest())
    value["actions"] = actions
    return value
batch3 = public_batch(3)
for name, edit, cause in [
    ("shuffled-three", lambda a: a.reverse(), "pool-live-action-order"),
    ("duplicate-three", lambda a: a.__setitem__(1, copy.deepcopy(a[0])), "pool-live-action-order"),
    ("proof-mismatch-three", lambda a: a[1].__setitem__("proofHex", a[0]["proofHex"]), "pool-aggregate-proof-rejected"),
    ("private-field-three", lambda a: a[1].__setitem__("noteOpening", "forbidden-field-control"), "pool-live-input-fields"),
]:
    value = copy.deepcopy(batch3); edit(value["actions"])
    refuse(name, value, cause, "live-b3")
refuse("selector-mismatch", batch3, "pool-live-batch-selector-mismatch", "live-b2")
for selector in ("live-b0", "live-b03", "live-b65536", "live-bx", "live-b+3"):
    refuse("selector-" + selector, batch3, "pool-live-batch-selector", selector)

# Shell selector negatives and a single-check mutation: all stop at argument
# admission, before the runner build, lock, memory check or any SDK call.
harness = tool / "scripts/aggregate-proof-runner.sh"
mutant_dir = scratch / "shell-mutant"; mutant_dir.mkdir()
shutil.copy2(tool / "scripts/prover-supervision.sh", mutant_dir / "prover-supervision.sh")
shutil.copy2(tool / "scripts/prover-processes.py", mutant_dir / "prover-processes.py")
shutil.copytree(tool / "scripts/docker-shim", mutant_dir / "docker-shim")
source = harness.read_text()
check = '[[ $count =~ ^[1-9][0-9]{0,4}$ && $count -le 65535 ]] || fail "pool-live-batch-selector"'
assert source.count(check) == 1
mutant = mutant_dir / "aggregate-proof-runner.sh"
mutant.write_text(source.replace(check, ": # selector check removed for firing control"))
for selector in ("live-b0", "live-b03", "live-b65536"):
    def shell_result(script):
        return subprocess.run(["bash", str(script), "dry-run", selector, str(root), str(elf)], env=env, capture_output=True, text=True)
    closed = shell_result(harness); opened = shell_result(mutant)
    (scratch / ("shell-" + selector + ".stderr")).write_text(closed.stderr)
    (scratch / ("shell-" + selector + ".mutation.stderr")).write_text(opened.stderr)
    assert closed.returncode == 1 and "error=pool-live-batch-selector" in closed.stderr
    assert opened.returncode == 1 and "error=pool-live-input-required" in opened.stderr
    checks.append({"case": "shell-" + selector, "cause": "pool-live-batch-selector", "exit": closed.returncode,
                   "mutationExit": opened.returncode, "mutationCause": "pool-live-input-required"})

# One full gated execute-only path, at B=3. B=1 and B=17 also execute with the
# fresh host runner and the exact same pinned ELF. No setup/prove is reached.
input_file.write_text(json.dumps(batch3, indent=2) + "\n")
with (scratch / "harness.stdout").open("w") as out, (scratch / "harness.stderr").open("w") as err:
    result = subprocess.run([str(harness), "dry-run", "live-b3", str(root), str(elf), "--live-input", str(input_file)], env=env, stdout=out, stderr=err)
assert result.returncode == 0, "harness dry run failed; see harness.stderr"
receipt = dict(line.split("=", 1) for line in (scratch / "harness.stdout").read_text().splitlines())
guest = json.loads(receipt["runner_dry_run"])
assert receipt["batch"] == "live-b3" and receipt["shared_prover_lock_held"] == "true"
assert guest["batchSize"] == 3 and guest["case"] == "live-b3"
assert guest["deploymentId"] == good["deploymentId"] and guest["profileId"] == good["profileId"]
assert guest["exitCode"] == 0 and guest["committedHex"] == guest["runBind32"]
assert guest["setupCallCount"] == guest["proveCallCount"] == 0 and not guest["proofConstructed"]
assert guest["inputBytes"] == 566 + 510 * 3
checks.append({"case": "gated-live-b3-execute", "exit": result.returncode, "guest": guest,
               "memoryAdmissionPassed": receipt["admission_passed"]})
for count in (1, 17):
    value = good if count == 1 else public_batch(count)
    path = scratch / ("positive-b" + str(count) + ".json")
    path.write_text(json.dumps(value, indent=2) + "\n")
    result = subprocess.run([str(runner), "proof-dry-run", "--batch", "live-b" + str(count), "--canonical-elf", str(elf), "--live-input", str(path)], env=env, capture_output=True, text=True)
    (scratch / ("execute-b" + str(count) + ".stderr")).write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    guest = json.loads(result.stdout)
    assert guest["batchSize"] == count and guest["exitCode"] == 0
    assert guest["committedHex"] == guest["runBind32"] and guest["setupCallCount"] == guest["proveCallCount"] == 0
    assert guest["inputBytes"] == 566 + 510 * count and not guest["proofConstructed"]
    checks.append({"case": "live-b" + str(count) + "-execute", "exit": result.returncode, "guest": guest})
(scratch / "results.json").write_text(json.dumps(checks, indent=2) + "\n")
print("PASS gated-live-b3 and live-b1/live-b17 execute-only", flush=True)
