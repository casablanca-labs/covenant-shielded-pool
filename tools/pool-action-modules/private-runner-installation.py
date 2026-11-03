#!/usr/bin/python3
"""Installation closure, never a wallet reader. Refusals carry fixed codes.

--build runs the fixed dependency build and writes a hash receipt only after it
succeeds. The receipt checks stale/changed installed files; it is not a prover
pin, a wallet authority certificate or protection against malicious same-UID
code replacing the whole installation and its local receipt.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import pwd

PACKAGES = ("protocol-runtime", "chain-io", "reference-aggregator", "reference-wallet", "wizardconnect-client", "pool-wallet-host")
PREFIX = "tools/pool-action-modules/"
RECORD = PREFIX + "dist/private-runner-installation.json"
PROCESS_READER = PREFIX + "dist/private-runner-process"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "TMPDIR": "/private/tmp"}

class InstallationRefusal(Exception):
    def __init__(self, code):
        self.code = code

def require(ok, code):
    if not ok:
        raise InstallationRefusal(code)

def build_log(root, command, environment):
    directory = root / PREFIX / "dist"
    directory.mkdir(mode=0o700, exist_ok=True)
    require(directory.resolve() == directory and directory.stat().st_uid == os.geteuid() and stat.S_IMODE(directory.stat().st_mode) == 0o700, "build-log-directory")
    descriptor = os.open(directory / "private-runner-build.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "build-log-file")
        with os.fdopen(descriptor, "wb", closefd=False) as sink:
            result = subprocess.run(command, cwd=root, env=environment, stdout=sink, stderr=subprocess.STDOUT)
            sink.flush(); os.fsync(descriptor)
        require(result.returncode == 0, "child-build-failed")
    finally:
        os.close(descriptor)

def git(root, *arguments):
    return subprocess.check_output(["/usr/bin/git", "-C", str(root), *arguments], env=ENV, stderr=subprocess.DEVNULL)

def file_bytes(root, relative, private=False):
    require(isinstance(relative, str) and not relative.startswith("/") and ".." not in relative.split("/") and not any(c.isspace() for c in relative), "file-relative-path")
    path = root / relative
    require(path.resolve() == path, "file-realpath")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink >= 1 and not info.st_mode & 0o022 and info.st_size <= 16 * 1024 * 1024, "file-metadata")
        if private:
            require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "file-private-mode-links")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            value = source.read(16 * 1024 * 1024 + 1)
        require(len(value) == info.st_size, "file-read-size")
        return value
    finally:
        os.close(descriptor)

def graph(root):
    tracked = git(root, "ls-files", "-z").decode().split("\0")
    sources = sorted(path for path in tracked if path and (
        (path.startswith(PREFIX) and path.endswith((".mjs", ".py", ".c")) and not any(part in path.split("/") for part in ("test", "record", "packets", "templates")))
        or any(path.startswith("packages/" + package + "/") and ("/src/" in path or "/scripts/" in path or "/tools/" in path or "/native/" in path
            or path.endswith(("package.json", "tsconfig.json"))) for package in PACKAGES)
        or path in ("pnpm-lock.yaml", "pnpm-workspace.yaml", "package.json", "tsconfig.base.json", ".npmrc", ".nvmrc")))
    reader = root / PROCESS_READER
    reader_stat = reader.lstat()
    require(stat.S_ISREG(reader_stat.st_mode) and reader_stat.st_uid == os.geteuid()
        and reader_stat.st_mode & 0o111 and not reader_stat.st_mode & 0o6022, "process-reader-metadata")
    outputs = [PROCESS_READER]
    for package in PACKAGES:
        directory = root / "packages" / package / "dist"
        require(directory.is_dir() and directory.resolve() == directory, "dist-directory-" + package)
        files = sorted(path for path in directory.rglob("*") if path.is_file())
        entry = "host.js" if package == "pool-wallet-host" else "index.js"
        require(files and (directory / entry).is_file(), "dist-entry-" + package)
        outputs.extend(str(path.relative_to(root)) for path in files)
    native = root / "packages/reference-aggregator/.local-generated/pool-action-verifier"
    require(native.is_dir() and native.resolve() == native, "native-directory-reference-aggregator")
    outputs.extend(str(path.relative_to(root)) for path in sorted(native.iterdir()) if path.is_file())
    # Bind the installed runtime dependency closure as well as sibling dist.
    # Resolve pnpm's links first; only regular files below this checkout's
    # node_modules are measured. No wallet, request or retained input is read.
    seen = set()
    def dependencies(package_directory, owner_package):
        package = json.loads((package_directory / "package.json").read_bytes())
        for name, version in sorted(package.get("dependencies", {}).items()):
            if version.startswith("workspace:"):
                continue
            ancestor = package_directory
            resolved = None
            while ancestor == root or root in ancestor.parents:
                candidate = ancestor / "node_modules" / name
                if candidate.is_dir():
                    resolved = candidate.resolve(); break
                ancestor = ancestor.parent
            require(resolved is not None and root / "node_modules" in resolved.parents, "dependency-resolve-" + owner_package)
            if resolved in seen:
                continue
            seen.add(resolved)
            for path in sorted(resolved.rglob("*")):
                if path.is_file():
                    require(path.resolve() == path, "dependency-realpath-" + owner_package)
                    outputs.append(str(path.relative_to(root)))
            dependencies(resolved, owner_package)
    for package in PACKAGES:
        dependencies(root / "packages" / package, package)
    paths = sorted(set(sources + outputs))
    require(len(paths) == len(sources) + len(outputs) and len(paths) <= 10000, "graph-unique-count")
    for source in sources:
        owner = next((package for package in PACKAGES if source.startswith("packages/" + package + "/")), "runner-workspace")
        require(file_bytes(root, source) == git(root, "show", "HEAD:" + source), "source-committed-" + owner)
    return [{"path": path, "sha256": hashlib.sha256(file_bytes(root, path)).hexdigest()} for path in paths]

def node_selection(installation):
    relative = re.search(rb'export const PRIVATE_RUNNER_NODE_RELATIVE = "([^"\n]+)";', installation)
    version = re.search(rb'export const PRIVATE_RUNNER_NODE_VERSION = "([^"\n]+)";', installation)
    require(relative is not None and version is not None, "node-constant-schema")
    require(relative[1] == b".nvm/versions/node/v22.22.3/bin/node" and version[1] == b"v22.22.3", "node-pinned-selection")
    home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    require(home.is_absolute() and home.resolve() == home, "node-account-home")
    return str(home / relative[1].decode()), version[1].decode()

def main(argv):
    build = len(argv) == 1 and argv[0] == "--build"
    bootstrap = len(argv) == 2 and argv[0] == "--bootstrap"
    continuation = len(argv) == 5 and argv[0] == "--continuation" and argv[4] == "4"
    node_path_output = len(argv) == 2 and argv[0] == "--node-path"
    root = Path(__file__).resolve().parents[2] if build else Path.cwd() if bootstrap or continuation else Path(argv[1]) if node_path_output else Path(argv[0]) if len(argv) == 1 else None
    require(root is not None and root.is_absolute() and root.resolve() == root, "root")
    require((root / ".git").is_dir() and not (root / ".git").is_symlink(), "checkout")
    require(git(root, "rev-parse", "--show-toplevel").decode().strip() == str(root), "checkout-toplevel")
    require(git(root, "branch", "--show-current").strip() == b"main" and git(root, "status", "--porcelain") == b"", "clean-main")
    revision = git(root, "rev-parse", "HEAD").decode().strip()
    installation = git(root, "show", "HEAD:" + PREFIX + "lib/private-runner-installation.mjs")
    require(installation == file_bytes(root, PREFIX + "lib/private-runner-installation.mjs"), "installation-source-committed")
    node_path, expected_version = node_selection(installation)
    require(subprocess.check_output([node_path, "--version"], env=ENV, stderr=subprocess.DEVNULL) == (expected_version + "\n").encode(), "node-measured-version")
    if build:
        command = [str(Path(node_path).parent / "pnpm"), "--filter", "@bch-cloak/pool-wallet-host...", "build"]
        account_home = pwd.getpwuid(os.geteuid()).pw_dir
        environment = {**ENV, "PATH": str(Path(node_path).parent) + ":" + account_home + "/.cargo/bin:/opt/homebrew/bin:/usr/bin:/bin", "HOME": account_home}
        build_log(root, command, environment)
        build_log(root, ["/usr/bin/clang", "-O2", "-Wall", "-Wextra", "-Werror", str(root / PREFIX / "private-runner-process.c"),
                        "-lproc", "-o", str(root / PROCESS_READER)], environment)
        entries = graph(root)
        require(git(root, "rev-parse", "HEAD").decode().strip() == revision and git(root, "status", "--porcelain") == b"", "build-source-unchanged")
        directory = root / PREFIX / "dist"
        directory.mkdir(mode=0o700, exist_ok=True)
        require(directory.resolve() == directory and directory.stat().st_uid == os.geteuid() and stat.S_IMODE(directory.stat().st_mode) == 0o700, "record-directory")
        value = {"schema": "private-runner-installation-record-v1", "revision": revision, "entries": entries}
        target, temporary = root / RECORD, root / (RECORD + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as sink:
                sink.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()); sink.flush(); os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, target)
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    raw = file_bytes(root, RECORD, private=True)
    value = json.loads(raw)
    require(json.dumps(value, sort_keys=True, separators=(",", ":")).encode() == raw and set(value) == {"schema", "revision", "entries"}, "record-canonical-keys")
    require(value["schema"] == "private-runner-installation-record-v1" and value["revision"] == revision and value["entries"] == graph(root), "record-schema-revision-graph")
    if bootstrap or continuation:
        script = Path(argv[1])
        require(script.is_absolute() and script.resolve() == script, "bootstrap-script-realpath")
        require(re.fullmatch(r"/private/tmp/measure-pk-load\.[A-Za-z0-9]+", str(script)) is not None, "bootstrap-script-location")
        info = script.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and not info.st_mode & 0o022, "bootstrap-script-metadata")
        require(script.read_bytes() == git(root, "show", "HEAD:tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh"), "bootstrap-script-committed")
    if continuation:
        descriptor = os.fstat(8)
        require(stat.S_ISFIFO(descriptor.st_mode) or stat.S_ISSOCK(descriptor.st_mode), "continuation-fd8-type")
        # This is a private continuation made by the fixed, checked Node
        # trampoline after P. A caller's FD8 alone cannot enter it. Captured
        # kernel arguments are compared privately and never printed.
        reader = str(root / PROCESS_READER)
        parent = subprocess.check_output([reader, "-p", str(os.getppid()), "-o", "ppid="], stderr=subprocess.DEVNULL).decode().strip()
        require(parent.isdecimal() and int(parent) > 1, "continuation-parent-id")
        executable = subprocess.check_output([reader, "-p", parent, "-o", "comm="], stderr=subprocess.DEVNULL).decode().strip()
        arguments = subprocess.check_output([reader, "-ww", "-p", parent, "-o", "args="], stderr=subprocess.DEVNULL).decode().strip().split()
        require(Path(executable).resolve() == Path(node_path).resolve(), "continuation-parent-executable")
        require(arguments == [node_path, str(root / PREFIX / "private-runner-bootstrap.mjs"), *argv[1:]], "continuation-parent-arguments")
    require(git(root, "rev-parse", "HEAD").decode().strip() == revision and git(root, "status", "--porcelain") == b"", "final-source-unchanged")
    if node_path_output:
        print(node_path)  # Only after every installation/source/version/receipt check.

if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as error:
        code = error.code if isinstance(error, InstallationRefusal) else "git" if isinstance(error, subprocess.CalledProcessError) else "io" if isinstance(error, OSError) else "record"
        print("private-runner-installation-refused:" + code, file=sys.stderr)
        sys.exit(1)
