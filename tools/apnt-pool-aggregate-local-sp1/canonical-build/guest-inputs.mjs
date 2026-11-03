// The local guest's input manifest. The hashing/entry encoding is shared with
// the frozen Chipnet guard; this list deliberately does not change its list.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { digestEntries } from "../../apnt-pool-aggregate-sp1/canonical-build/guest-inputs.mjs";

export const LOCAL_GUEST_INPUT_PATHS = [
  "tools/apnt-pool-aggregate-local-sp1/Cargo.toml",
  "tools/apnt-pool-aggregate-local-sp1/Cargo.lock",
  "tools/apnt-pool-aggregate-local-sp1/program",
  "tools/apnt-pool-aggregate-sp1/core",
];

const entries = (repo, args, fromWorkingTree) => {
  const raw = execFileSync("git", ["-C", repo, ...args, "--", ...LOCAL_GUEST_INPUT_PATHS]);
  return raw.toString("utf8").split("\0").filter(Boolean).map((line) => {
    const [header, path] = line.split("\t");
    const [mode, type, object] = header.split(" ");
    if (!fromWorkingTree && type !== "blob") throw new Error(`local guest input ${path} is not a blob`);
    const bytes = fromWorkingTree
      ? readFileSync(`${repo}/${path}`)
      : execFileSync("git", ["-C", repo, "cat-file", "blob", object], { maxBuffer: 1 << 26 });
    return { path, mode, bytes };
  });
};

export const localGuestInputsAtCommit = (repo, commit) =>
  digestEntries(entries(repo, ["ls-tree", "-r", "-z", commit], false));

export const localGuestInputsInWorkingTree = (repo) =>
  digestEntries(entries(repo, ["ls-files", "-s", "-z"], true));

/** A changed local source must refuse before its recorded identity is used. */
export function assertLocalGuestInputDigest(actual) {
  const pinned = JSON.parse(readFileSync(new URL('./local-zero-value-guest-inputs-v1.json', import.meta.url), 'utf8'));
  if (actual.files !== pinned.files || actual.sha256 !== pinned.sha256) {
    throw new Error('LOCAL_GUEST_INPUT_PIN');
  }
  return actual;
}

export const assertLocalGuestInputsInWorkingTree = (repo) =>
  assertLocalGuestInputDigest(localGuestInputsInWorkingTree(repo));
