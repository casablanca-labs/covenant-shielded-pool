import { lstatSync, mkdtempSync, renameSync, rmdirSync, rmSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Removes the generated `dist` of the workspace package whose build runs it: the package directory is the working
// directory, where pnpm runs a package's scripts. protocol-runtime runs this file as ./scripts/clean-dist.mjs and
// reference-wallet runs the same file as ../protocol-runtime/scripts/clean-dist.mjs; each removes only its own dist.
// A working directory that is not a direct child of this repository's packages directory is refused.
//
// Builds of one package can run at once: two validations in one worktree, or a package's prebuild rebuilding a sibling
// that another build is also rebuilding. So dist is moved aside by one atomic rename into a fresh directory no other
// cleaner can name, and only that moved copy is deleted. A cleaner that finds dist already moved has nothing to do,
// and no cleaner can fail on a file another one removed first. If a crash leaves the moved copy behind, it is
// <package>/.dist-clean-XXXXXX/dist, which the repository's dist/ ignore rule covers.

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const packagesDirectory = resolve(scriptDirectory, "..", "..");
const packageDirectory = resolve(process.cwd());
const generatedDirectory = join(packageDirectory, "dist");

function cleanDist() {
  if (basename(packagesDirectory) !== "packages" || dirname(packageDirectory) !== packagesDirectory) {
    throw new Error("clean-dist: refused a working directory that is not a workspace package");
  }
  let target;
  try {
    target = lstatSync(generatedDirectory);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  if (target.isSymbolicLink() || !target.isDirectory()) {
    throw new Error("clean-dist: dist must be a real package-local directory");
  }
  const holding = mkdtempSync(join(packageDirectory, ".dist-clean-"));
  try {
    renameSync(generatedDirectory, join(holding, "dist"));
  } catch (error) {
    rmdirSync(holding);
    if (error?.code === "ENOENT") return;
    throw error;
  }
  // rmSync removes a symbolic link itself, never its target.
  rmSync(holding, { recursive: true, force: false });
}

cleanDist();
