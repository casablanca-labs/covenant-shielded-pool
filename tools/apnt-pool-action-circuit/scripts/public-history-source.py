"""Closed public source fixture. No Git, network or caller-selected fallback."""
import hashlib
import json
import stat
from pathlib import Path


SOURCE = {
    "commit": "29e57d17cf5358e87e6c67bd66a3c47bf7853d8b",
    "path": "tools/apnt-pool-action-circuit/scripts/mig01-macos-observer.c",
    "file": "29e57d17-macos-observer.c",
    "mode": "100644",
    "bytes": 7106,
    "gitBlob": "8ac17190d52fdc94b8403331d5802147ca1acb63",
    "sha256": "74f3a3bf36916a3fdd4a99ee2d741a1248b3237dde510acd66c8c85c974faf0c",
}


DRIVER_SOURCE = {
    "commit": "a9475e0908c00fa17a5ed71b3bffa0c4e901141c",
    "path": "tools/apnt-pool-action-circuit/scripts/test-private-runner-runtime-no-proof.py",
    "file": "a9475e09-runtime-no-proof.py",
    "mode": "100644",
    "bytes": 10421,
    "gitBlob": "9e5ff9f580517608d8ce696126954a5780032664",
    "sha256": "cb0944c367150a39d074f86f9f990ee80210929461bb5b4323e035e8fcdaaf06"
}
SOURCES = {(s["commit"], s["path"]): s for s in (SOURCE, DRIVER_SOURCE)}


def closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("public-history-duplicate")
        result[key] = value
    return result


def read_source(commit, path):
    if (commit, path) not in SOURCES:
        raise ValueError("public-history-origin")
    here = Path(__file__).absolute().parent
    if any(p.is_symlink() for p in (here, *here.parents)):
        raise ValueError("public-history-path")
    directory = here / "public-history"
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("public-history-path")
    if {p.name for p in directory.iterdir()} != {"manifest.json", *(s["file"] for s in SOURCES.values())}:
        raise ValueError("public-history-entries")
    for name in ("manifest.json", *(s["file"] for s in SOURCES.values())):
        value = (directory / name).lstat()
        if not stat.S_ISREG(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o644:
            raise ValueError("public-history-mode")
    manifest = json.loads((directory / "manifest.json").read_bytes(), object_pairs_hook=closed_object)
    if manifest != {"schemaVersion": "pool-public-history-source/1", "sources": list(SOURCES.values())}:
        raise ValueError("public-history-manifest")
    result = {}
    for origin, source in SOURCES.items():
        data = (directory / source["file"]).read_bytes()
        blob = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
        if (len(data), hashlib.sha256(data).hexdigest(), hashlib.sha1(blob).hexdigest()) != (
            source["bytes"], source["sha256"], source["gitBlob"]
        ):
            raise ValueError("public-history-content")
        result[origin] = data
    return result[(commit, path)]
