// ENG-510 (task 5.4 slice 2a): the pool aggregate guest's compiled inputs and their digest.
//
// A canonical build of the guest is a function of these files (and of the
// canonical builder's pinned image), so the Chipnet build's pins in
// chipnet-zero-value-rev3-canonical-build-v1.json hold only while this digest
// is unchanged. core/src/tests.rs is included although the guest never
// compiles it: the set errs toward demanding a rebuild.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

export const GUEST_INPUT_PATHS = [
  "tools/apnt-pool-aggregate-sp1/Cargo.toml",
  "tools/apnt-pool-aggregate-sp1/Cargo.lock",
  "tools/apnt-pool-aggregate-sp1/core",
  "tools/apnt-pool-aggregate-sp1/program",
  "tools/apnt-pool-aggregate-sp1/program-chipnet-zero-value-rev3",
];
export const GUEST_INPUT_DOMAIN = "BCH Cloak APNT pool aggregate guest inputs v1\0";

const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u64be = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };

/** SHA-256 over (path, mode, bytes) of every file, sorted by path bytes. */
export function digestEntries(entries) {
  const sorted = [...entries].sort((a, b) => Buffer.from(a.path).compare(Buffer.from(b.path)));
  const h = createHash("sha256");
  h.update(GUEST_INPUT_DOMAIN);
  for (const e of sorted) {
    const path = Buffer.from(e.path), mode = Buffer.from(e.mode);
    h.update(u32be(path.length)); h.update(path);
    h.update(u32be(mode.length)); h.update(mode);
    h.update(u64be(e.bytes.length)); h.update(e.bytes);
  }
  return { files: sorted.length, sha256: h.digest("hex") };
}

/** The guest inputs as committed at `commit`. */
export function guestInputsAtCommit(repo, commit) {
  const raw = execFileSync("git", ["-C", repo, "ls-tree", "-r", "-z", commit, "--", ...GUEST_INPUT_PATHS]);
  const entries = raw.toString("utf8").split("\0").filter(Boolean).map((line) => {
    const [header, path] = line.split("\t");
    const [mode, type, object] = header.split(" ");
    if (type !== "blob") throw new Error(`guest input ${path} is not a blob`);
    return { path, mode, bytes: execFileSync("git", ["-C", repo, "cat-file", "blob", object], { maxBuffer: 1 << 26 }) };
  });
  return digestEntries(entries);
}

/** The guest inputs in the working tree: every tracked file under the paths, as it is on disk now. */
export function guestInputsInWorkingTree(repo) {
  const raw = execFileSync("git", ["-C", repo, "ls-files", "-s", "-z", "--", ...GUEST_INPUT_PATHS]);
  const entries = raw.toString("utf8").split("\0").filter(Boolean).map((line) => {
    const [header, path] = line.split("\t");
    const [mode] = header.split(" ");
    return { path, mode, bytes: readFileSync(`${repo}/${path}`) };
  });
  return digestEntries(entries);
}
