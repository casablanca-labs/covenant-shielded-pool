#!/usr/bin/python3
"""Synthetic setup controls only; no package build, wallet or runner launch."""
import ast
import copy
import hashlib
import json
import re
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[3]
# Loaded modules write no bytecode into the checkout under test.
sys.dont_write_bytecode = True
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value
driver = module("driver", Path(__file__).with_name("test-live-entry-no-proof.py"))
installation = module("installation", REPO / "tools/pool-action-modules/private-runner-installation.py")
# The B1 inventory, independently listed: 41 runner groups, then the one Sage group.
B1_GROUPS = ("C2-a-exact-tuple C2-b-before-writer C2-c-main-dispatch C2-d-production-prerequisite C2-e-library-prerequisite "
    "C2-f-ordinary-hook C3-outer-diagnostics C1-inbox-writer C4-authenticated-singlecase C4-original-ttl C4-distinct-latches "
    "C5-final-capture-basis C5-same-height-hash C5-anchor C5-fresh-read-cause C5-deadline-equality H1-before-membership "
    "H1-locked-session H1-close-revocation H1-sync-revocation H1-connection H1-epoch-binding C10-refusal-authentication "
    "C10-refusal-challenge C10-refusal-keys C10-refusal-error-keys C10-immutable-tuple C8-close-inheritance C8-loader-stderr "
    "C3-guarded-diagnostics C3-raced-size C6-preload-stripping C7-bridge-interruption C7-supervisor-initial-interruption "
    "C7-supervisor-route-interruption C9-source-detector C9-transport-detector C9-stat C9-grep C9-validation "
    "C9-execution-reopen Sage-import-completion").split()

def composed_reader():
    """Read the checkout as the driver's fixture sees it after the fixed composition."""
    edits = {path: (old, new) for path, old, new in driver.COMPOSITION}
    def read(path):
        source = REPO / path
        if not source.is_file(): return None
        text = source.read_text()
        if path in edits: text = text.replace(*edits[path])
        return text
    return read

class SetupControls(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="sage-owner-execution-v2-r1721-setup-", dir="/private/tmp")
        self.root = Path(self.scratch.name); self.repo = self.root / "repo"; self.repo.mkdir()
        self.git("init", "-b", "main")
        for i in range(16):
            path = self.repo / "packages/protocol-runtime/src/cashassembly" / (str(i) + ".casm")
            path.parent.mkdir(parents=True, exist_ok=True); path.write_text("synthetic assembly\n")
        (self.repo / ".gitignore").write_text("CLAUDE.md\n")
        (self.repo / "CLAUDE.md").write_text("@AGENTS.md\n")
        (self.repo / "executable").write_bytes(b"synthetic\x00asset"); (self.repo / "executable").chmod(0o755)
        (self.repo / "alias").symlink_to("executable")
        self.commit()
    def tearDown(self): self.scratch.cleanup()
    def git(self, *args):
        return subprocess.check_output(["/usr/bin/git", "-C", str(self.repo), *args], stderr=subprocess.DEVNULL)
    def commit(self):
        self.git("add", "--force", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "synthetic source")
    def test_exact_tree_includes_all_assets_modes_and_force_tracked_files(self):
        fixture = self.root / "fixture"; fixture.mkdir()
        head, inventory, digest = driver.source_fixture(self.repo, fixture)
        self.assertEqual(len([p for p in inventory if p["path"].endswith(".casm")]), 16)
        self.assertEqual(len(inventory), len(self.git("ls-files", "-z").split(b"\0")) - 1)
        self.assertEqual(len(digest), 64)
        self.assertEqual((fixture / "CLAUDE.md").read_bytes(), b"@AGENTS.md\n")
        self.assertTrue((fixture / "alias").is_symlink())
        # Git records only the executable bit; other mode bits follow the
        # caller's umask (the driver itself extracts under 077).
        self.assertTrue((fixture / "executable").stat().st_mode & 0o100)
        self.assertFalse((fixture / "CLAUDE.md").stat().st_mode & 0o111)
        subprocess.run(["/usr/bin/git", "init", "-b", "main", str(fixture)], stdout=subprocess.DEVNULL, check=True)
        subprocess.run(["/usr/bin/git", "-C", str(fixture), "add", "--force", "."], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(fixture), "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)
        driver.verify_source_tree(self.repo, fixture, head)
        (fixture / "packages/protocol-runtime/src/cashassembly/0.casm").unlink()
        subprocess.run(["/usr/bin/git", "-C", str(fixture), "add", "-u"], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(fixture), "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "omit asset"], check=True)
        with self.assertRaisesRegex(RuntimeError, "mig01-no-proof-control-refused"):
            driver.verify_source_tree(self.repo, fixture, head)
    def test_dirty_source_cannot_become_reviewed_fixture(self):
        (self.repo / "uncommitted.casm").write_text("synthetic\n")
        fixture = self.root / "fixture"; fixture.mkdir()
        with self.assertRaisesRegex(RuntimeError, "mig01-no-proof-control-refused"):
            driver.source_fixture(self.repo, fixture)
    def test_caller_git_redirection_cannot_select_another_source(self):
        foreign = self.root / "foreign"; foreign.mkdir()
        subprocess.run(["/usr/bin/git", "init", "-q", "-b", "main", str(foreign)], check=True)
        (foreign / "foreign.casm").write_text("synthetic foreign\n")
        subprocess.run(["/usr/bin/git", "-C", str(foreign), "add", "."], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(foreign), "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "foreign"], check=True)
        fixture = self.root / "fixture"; fixture.mkdir()
        prior = {key: os.environ.get(key) for key in ("GIT_DIR", "GIT_WORK_TREE")}
        os.environ.update(GIT_DIR=str(foreign / ".git"), GIT_WORK_TREE=str(foreign))
        try:
            self.assertEqual(subprocess.check_output(["/usr/bin/git", "-C", str(self.repo), "ls-files"]), b"foreign.casm\n")
            head, inventory, _ = driver.source_fixture(self.repo, fixture)
        finally:
            for key, value in prior.items():
                if value is None: os.environ.pop(key, None)
                else: os.environ[key] = value
        self.assertEqual(head, self.git("rev-parse", "HEAD").decode().strip())
        self.assertFalse((fixture / "foreign.casm").exists()); self.assertEqual(len([p for p in inventory if p["path"].endswith(".casm")]), 16)
    def test_driver_entry_writes_no_bytecode_beside_the_checkout(self):
        # Even its argument refusal loads the runtime entry; that load must not
        # dirty the source checkout the driver later archives at its exact head.
        env = {key: value for key, value in os.environ.items() if key not in ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX")}
        source = Path(__file__).with_name("test-live-entry-no-proof.py").read_text()
        self.assertEqual(source.count("\nsys.dont_write_bytecode = True\n"), 1)
        observed = []
        for mutated in (False, True, False):
            scripts = self.root / ("scripts-" + str(len(observed))); scripts.mkdir()
            (scripts / "test-live-entry-no-proof.py").write_text(source.replace("\nsys.dont_write_bytecode = True\n", "\npass\n") if mutated else source)
            (scripts / "test-private-runner-runtime-no-proof.py").write_bytes(Path(__file__).with_name("test-private-runner-runtime-no-proof.py").read_bytes())
            # Observe bytecode wherever this interpreter would place it.
            env["PYTHONPYCACHEPREFIX"] = str(scripts / "bytecode")
            result = subprocess.run([sys.executable, str(scripts / "test-live-entry-no-proof.py")], env=env, capture_output=True, timeout=60)
            self.assertEqual((result.returncode, result.stdout), (1, b""))
            observed.append(len([path for path in scripts.rglob("*.pyc") if path.name.startswith(("test-private-runner-runtime-no-proof.", "test-live-entry-no-proof."))]))
        self.assertEqual([count > 0 for count in observed], [False, True, False])
    def test_rewritten_targets_are_regular_files_inside_the_fixture(self):
        fixture = self.root / "fixture"; outside = self.root / "outside"
        for directory in (fixture / "a", outside): directory.mkdir(parents=True)
        (fixture / "a/target.txt").write_text("synthetic target\n"); (outside / "target.txt").write_text("safe canary\n")
        driver.require_regular(fixture, ["a/target.txt"])
        (fixture / "a/link.txt").symlink_to(outside / "target.txt"); (fixture / "linked").symlink_to(outside)
        for path in ("a/link.txt", "linked/target.txt"):
            with self.assertRaisesRegex(RuntimeError, "mig01-no-proof-control-refused"):
                driver.require_regular(fixture, [path])
        shell, main = (fixture / path for path, _, _ in driver.COMPOSITION)
        shell.parent.mkdir(parents=True); main.parent.mkdir(parents=True)
        (outside / "shell").write_bytes((REPO / driver.SHELL).read_bytes()); shell.symlink_to(outside / "shell")
        main.write_bytes((REPO / driver.COMPOSITION[1][0]).read_bytes())
        with self.assertRaisesRegex(RuntimeError, "mig01-no-proof-control-refused"):
            driver.compose(fixture)
        self.assertEqual(((outside / "shell").read_bytes(), (outside / "target.txt").read_text()), ((REPO / driver.SHELL).read_bytes(), "safe canary\n"))
    def test_failed_child_retains_both_streams_privately_and_has_exact_reason(self):
        (self.repo / installation.PREFIX).mkdir(parents=True)
        with self.assertRaises(installation.InstallationRefusal) as caught:
            installation.build_log(self.repo, ["/bin/sh", "-c", "echo setup-stdout; echo setup-stderr >&2; exit 7"], os.environ.copy())
        self.assertEqual(caught.exception.code, "child-build-failed")
        log = self.repo / installation.PREFIX / "dist/private-runner-build.log"
        self.assertEqual(log.read_bytes(), b"setup-stdout\nsetup-stderr\n")
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        installation.build_log(self.repo, ["/usr/bin/true"], os.environ.copy())
    def test_build_log_link_refuses_without_overwriting_target(self):
        directory = self.repo / installation.PREFIX / "dist"; directory.mkdir(parents=True, mode=0o700)
        target = self.root / "target"; target.write_bytes(b"safe canary"); target.chmod(0o600)
        (directory / "private-runner-build.log").symlink_to(target)
        with self.assertRaises(OSError): installation.build_log(self.repo, ["/usr/bin/true"], os.environ.copy())
        self.assertEqual(target.read_bytes(), b"safe canary")
    def test_every_installation_requirement_has_an_explicit_reason(self):
        syntax = ast.parse(Path(installation.__file__).read_text())
        calls = [node for node in ast.walk(syntax) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "require"]
        self.assertGreater(len(calls), 30)
        self.assertTrue(all(len(call.args) == 2 for call in calls))
        self.assertFalse(any(isinstance(node, ast.Constant) and node.value == "invariant" for node in ast.walk(syntax)))
    def test_package_entry_controls_name_the_package_and_restore(self):
        for package in installation.PACKAGES:
            directory = self.repo / "packages" / package
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "package.json").write_text('{"dependencies":{}}\n')
        self.commit()
        native = self.repo / "packages/reference-aggregator/.local-generated/pool-action-verifier"
        native.mkdir(parents=True)
        # The installation graph binds the built process reader before any dist.
        reader = self.repo / installation.PROCESS_READER; reader.parent.mkdir(parents=True)
        reader.write_bytes(b"synthetic reader"); reader.chmod(0o755)
        entries = {}
        for package in installation.PACKAGES:
            directory = self.repo / "packages" / package / "dist"; directory.mkdir()
            entry = directory / ("host.js" if package == "pool-wallet-host" else "index.js")
            entry.write_text("synthetic output\n"); entries[package] = entry
        self.assertGreater(len(installation.graph(self.repo)), 0)
        for package, entry in entries.items():
            original = entry.read_bytes(); entry.unlink()
            with self.assertRaises(installation.InstallationRefusal) as caught:
                installation.graph(self.repo)
            self.assertEqual(caught.exception.code, "dist-entry-" + package)
            entry.write_bytes(original)
            self.assertGreater(len(installation.graph(self.repo)), 0)
        reader.chmod(0o775)
        with self.assertRaises(installation.InstallationRefusal) as caught:
            installation.graph(self.repo)
        self.assertEqual(caught.exception.code, "process-reader-metadata")

class InventoryControls(unittest.TestCase):
    def groups(self, read=None):
        return driver.mutation_groups((read or composed_reader())(driver.SHELL))
    def test_inventory_is_exactly_the_b1_groups_in_order(self):
        groups = self.groups()
        self.assertEqual([group[0] for group in groups], B1_GROUPS)
        self.assertEqual((len(B1_GROUPS), len(set(B1_GROUPS))), (42, 42))
        driver.require_inventory(groups)
        for changed in (groups[:-1], groups[1:], groups + groups[:1], groups[:40] + [groups[41], groups[40]], [groups[0], ("Sage-second",) + groups[1][1:]] + groups[2:]):
            with self.assertRaisesRegex(RuntimeError, "mig01-no-proof-control-refused"):
                driver.require_inventory(changed)
    def test_every_target_and_selected_test_exists_once_on_the_composed_tree(self):
        read = composed_reader()
        groups = self.groups(read)
        driver.require_targets(read, groups)
        driver.require_bindings(read, groups)
        titles=driver.RUNTIME_ENTRY.runtime_titles('union')
        resource=set(driver.RUNTIME_ENTRY.runtime_titles('resource'))
        runtime=[group for group in groups if group[1]==driver.RUNTIME]
        self.assertEqual(len(runtime),26)
        for _,_,_,pattern in runtime:
            family=driver.family(titles,pattern)
            self.assertTrue(family)
            self.assertFalse(resource.intersection(family))
        self.assertEqual((driver.RUNTIME_ROWS,driver.OBSERVER_ROWS,driver.RUNTIME_SELECTION),(115,9,'ordinary'))
        selected = {group[1] for group in groups}
        self.assertEqual(selected, {driver.RUNTIME, driver.H1, driver.SAGE, driver.GO_EXEC, "tools/pool-action-modules/test/private-runner-result.test.ts",
            "tools/pool-action-modules/test/private-runner-bootstrap.test.ts", "tools/pool-action-modules/test/private-runner-lock-process.test.ts"})
        self.assertTrue(all(group[1] in {test for _, files in driver.BASELINES for test in files} | {driver.RUNTIME, driver.GO_EXEC} for group in groups))
        name, test, edits, selection = next(group for group in groups if group[0] == "C5-anchor")
        path, before, after = edits[0]
        for text in ("", read(path).replace(before, ""), read(path) + before):
            with self.assertRaisesRegex(RuntimeError, "mig01-no-proof-control-refused"):
                driver.require_targets(lambda candidate: text if candidate == path else read(candidate), [(name, test, edits, selection)])
        with self.assertRaisesRegex(RuntimeError, "mig01-no-proof-control-refused"):
            driver.require_targets(lambda candidate: None if candidate == driver.H1 else read(candidate), groups)
    def test_staged_strings_keep_the_same_firing_targets(self):
        read = composed_reader()
        groups = {group[0]: group for group in self.groups(read)}
        self.assertEqual(read(driver.INBOX_ROUTE).count(driver.INBOX_SOURCE), 1)
        self.assertEqual(groups['C1-inbox-writer'][2], [(driver.INBOX_ROUTE, driver.INBOX_SOURCE, driver.INBOX_MUTANT)])
        self.assertIn('if (kind === "withdrawal") {', driver.INBOX_SOURCE)
        self.assertEqual(driver.INBOX_MUTANT, driver.INBOX_SOURCE.replace('requireHarnessInboxConstruction(token, store, request)',
            '(() => { requireHarnessInboxConstruction(token, store, request); throw new PrivateRunnerRefusal(); })()'))
        mutated = read(driver.INBOX_ROUTE).replace(driver.INBOX_SOURCE, driver.INBOX_MUTANT)
        self.assertEqual([driver.anchor_line(mutated if path == driver.INBOX_ROUTE else read(path), anchor)
                          for path, anchor in driver.INBOX_CHAIN], [141,170,160,200,281,741])
        runtime = read(driver.RUNTIME)
        contract = re.search(r'function requireFailClosed\(.*?\.toMatchObject\((\{.*?\})\);', runtime, re.S)[1]
        self.assertEqual(driver.HELPER_CONTRACT, json.loads(re.sub(r'(\w+):', r'"\1":', contract)))
        diagnostic = runtime.split('function runnerDiagnostic(',1)[1].split('async function bridgeFrame(',1)[0]
        self.assertEqual({'status',*re.findall(r'^    (\w+):', diagnostic, re.M)},
                         {'status','contacts','deliveries','terminalBytes',*driver.HELPER_FLAGS})
        # The composed dispatch is the one the runtime controls execute.
        self.assertIn("runV2(", groups["C2-c-main-dispatch"][2][0][1])
        shell = read(driver.SHELL)
        for name, loop in (("C9-validation", 'done < <(plan_source)'), ("C9-execution-reopen", 'done 3< <(plan_source)')):
            _, _, [(path, before, after)], _ = groups[name]
            mutated = shell.replace(before, after)
            self.assertEqual((path, shell.count(loop), mutated.count(loop)), (driver.SHELL, 1, 0))
            self.assertEqual(mutated.count('< "$plan"'), shell.count('< "$plan"') + 1)
        with self.assertRaisesRegex(RuntimeError, "mig01-no-proof-control-refused"):
            driver.mutation_groups(shell.replace('done 3< <(plan_source)', 'done 3< <(plan_source) # copy\ndone 3< <(plan_source)'))
    def test_composition_is_the_runtime_entry_composition(self):
        entry = Path(__file__).with_name("test-private-runner-runtime-no-proof.py")
        syntax = ast.parse(entry.read_text())
        main = next(node for node in syntax.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        assigned = [node.value for node in ast.walk(main) if isinstance(node, ast.Assign) and [getattr(t, "id", None) for t in node.targets] == ["edits"]]
        self.assertEqual(len(assigned), 1)
        edits = eval(compile(ast.Expression(assigned[0]), str(entry), "eval"), {"PREFIX": driver.CIRCUIT})
        self.assertEqual(tuple(map(tuple, edits)), driver.COMPOSITION)
        fixture = Path(tempfile.mkdtemp(prefix="mig01-vd-composition-", dir="/private/tmp"))
        try:
            for path, _, _ in driver.COMPOSITION:
                (fixture / path).parent.mkdir(parents=True, exist_ok=True); (fixture / path).write_bytes((REPO / path).read_bytes())
            # C1: production carries the composition, so compose() verifies it in
            # place and edits nothing; a fixture still holding either v1 form refuses.
            self.assertEqual(driver.compose(fixture), [path for path, _, _ in driver.COMPOSITION])
            for path, _, _ in driver.COMPOSITION:
                self.assertEqual((fixture / path).read_bytes(), (REPO / path).read_bytes())
            for path, old, new in driver.COMPOSITION:
                current = (fixture / path).read_text()
                self.assertEqual((current.count(new), current.count(old)), (1, 0))
                (fixture / path).write_text(current.replace(new, old))
                with self.assertRaisesRegex(RuntimeError, "mig01-no-proof-control-refused"):
                    driver.compose(fixture)
                (fixture / path).write_text(current)
            self.assertEqual(driver.compose(fixture), [path for path, _, _ in driver.COMPOSITION])
        finally:
            subprocess.run(["/bin/rm", "-rf", str(fixture)], check=True)

def report(rows, fixture, path="tools/pool-action-modules/test/synthetic.test.ts", **override):
    value = {"success": all(row["status"] != "failed" for row in rows), "numFailedTestSuites": 0,
             "numTotalTests": len(rows), "numPassedTests": sum(row["status"] == "passed" for row in rows),
             "numFailedTests": sum(row["status"] == "failed" for row in rows),
             "numPendingTests": sum(row["status"] in ("skipped", "pending") for row in rows),
             "testResults": [{"name": str(fixture / path), "assertionResults": rows}]}
    value.update(override)
    return value

class AccountingControls(unittest.TestCase):
    fixture = Path("/private/tmp/synthetic-fixture")
    def row(self, name, status, message="AssertionError: expected undefined to be 'wallet-command-component-refused'"):
        return {"fullName": name, "status": status, "failureMessages": [message] if status == "failed" else []}
    def test_deselected_rows_are_never_executed_and_counts_must_agree(self):
        rows = [self.row("A selected", "failed"), self.row("A other", "skipped"), self.row("A pending", "pending")]
        executed = driver.vitest_rows(report(rows, self.fixture), self.fixture)
        self.assertEqual({path: [row["fullName"] for row in values] for path, values in executed.items()},
                         {"tools/pool-action-modules/test/synthetic.test.ts": ["A selected"]})
        for override in ({"numPendingTests": 1}, {"numPassedTests": 1}, {"numFailedTests": 0}, {"numTotalTests": 2}, {"success": "true"}, {"numTotalTests": -1}):
            with self.assertRaisesRegex(RuntimeError, "mig01-no-proof-control-refused"):
                driver.vitest_rows(report(rows, self.fixture, **override), self.fixture)
        for status in ("todo", None, "PASSED"):
            with self.assertRaisesRegex(RuntimeError, "mig01-no-proof-control-refused"):
                driver.vitest_rows(report([dict(rows[0], status=status)], self.fixture, numTotalTests=1, numPassedTests=0, numFailedTests=0, numPendingTests=0), self.fixture)
        with self.assertRaises(ValueError):
            driver.vitest_rows(report(rows, self.fixture, testResults=[{"name": "/private/tmp/foreign/x.test.ts", "assertionResults": rows}]), self.fixture)
    def test_go_rows_refuse_skips_timeouts_and_non_json(self):
        lines = ['{"Action":"run","Test":"TestMIG01ActualExecX"}', '{"Action":"output","Test":"TestMIG01ActualExecX","Output":"ok\\n"}',
                 '{"Action":"pass","Test":"TestMIG01ActualExecX"}', '{"Action":"fail","Test":"TestMIG01ActualExecX/sub"}', '{"Action":"pass"}']
        rows = driver.go_rows("\n".join(lines).encode())
        self.assertEqual([(row["fullName"], row["status"]) for row in rows], [("TestMIG01ActualExecX", "passed"), ("TestMIG01ActualExecX/sub", "failed")])
        for extra in ('{"Action":"skip","Test":"TestMIG01ActualExecX/other"}', '{"Action":"output","Output":"panic: test timed out after 3m0s\\n"}', "# build failed", "[]"):
            with self.assertRaises(Exception):
                driver.go_rows("\n".join(lines + [extra]).encode())
    def test_restored_oracle_requires_every_family_row_to_pass(self):
        expected = ["a", "b"]
        self.assertEqual(driver.require_restored([self.row("a", "passed"), self.row("b", "passed")], expected), 2)
        for rows in ([self.row("a", "passed")], [self.row("a", "passed"), self.row("b", "failed")], [self.row("a", "passed"), self.row("b", "passed"), self.row("c", "passed")]):
            with self.assertRaisesRegex(RuntimeError, "mig01-no-proof-control-refused"):
                driver.require_restored(rows, expected)

class BindingControls(unittest.TestCase):
    fixture = Path('/private/tmp/SYNTHETIC PRIVATE PATH')
    def firing(self, name='C4-original-ttl'):
        read = composed_reader()
        group = next(group for group in driver.mutation_groups(read(driver.SHELL)) if group[0] == name)
        _, selected, _, selection = group
        title = ('PH11-ONECASE original TTL equality at P is not renewed by a previous phase'
                 if name == 'C4-original-ttl' else 'PH02 H1 foreign-epoch host refuses')
        site, caller, _ = driver.FIRING[name]['sites'][0]
        line, column, _ = driver.anchor_span(read(selected), site)
        stack = f'AssertionError: synthetic\n    at {self.fixture / selected}:{line}:{column}'
        if caller: stack += f'\n    at {self.fixture / selected}:{driver.anchor_line(read(selected), caller)}:1'
        actual = 'Object {\n  "bytes": 27,\n  "error": null,\n}' if name == 'C4-original-ttl' else 'undefined'
        error = {'name':'AssertionError', 'message':"expected undefined to be 'wallet-command-component-refused'", 'actual':actual, 'stack':stack}
        return [name, [{'fullName':title,'status':'failed'}], [title], selection,
                [{'fullName':title,'errors':[error]}], read, self.fixture, selected]
    def refused(self, args):
        with self.assertRaisesRegex(RuntimeError, '^mig01-no-proof-control-refused$'):
            driver.require_bound_firing(*args)
    def test_exact_assertion_location_value_and_family(self):
        for name in ('C4-original-ttl', 'H1-epoch-binding'):
            valid = self.firing(name)
            self.assertEqual(driver.require_bound_firing(*valid), 'bound-assertion')
            for kind in ('passed','missing','extra','wrong-line','wrong-column','foreign-file','fixture','timeout','wrong-value','extra-error','wrong-title'):
                args = copy.deepcopy(valid); error = args[4][0]['errors'][0]
                if kind == 'passed': args[1][0]['status'] = 'passed'
                elif kind == 'missing': args[1].clear()
                elif kind == 'extra': args[1].append({'fullName':'other','status':'passed'})
                elif kind == 'wrong-line': error['stack'] = re.sub(r':\d+:\d+', ':1:1', error['stack'])
                elif kind == 'wrong-column': error['stack'] = re.sub(r':(\d+):\d+', r':\1:99999', error['stack'])
                elif kind == 'foreign-file': error['stack'] = error['stack'].replace(args[7], 'foreign.test.ts')
                elif kind == 'fixture': error.update(message='AssertionError: unrelated fixture setup expected 1 to be 0', stack='AssertionError\n    at /fixture.ts:1:1')
                elif kind == 'timeout': error['message'] = 'AssertionError: Test timed out'
                elif kind == 'wrong-value': error['actual'] = '0'
                elif kind == 'extra-error': args[4][0]['errors'].append(dict(error))
                else: args[4][0]['fullName'] = 'other'
                with self.subTest(group=name, invalid=kind): self.refused(args)
        # A native canary's exit 1 also covers observation failures. Its
        # independently projected facts must identify just the intended detector.
        read=composed_reader()
        for name,source,transport in (('C9-source-detector',False,True),('C9-transport-detector',True,False)):
            title='PH11-X-PROD/P0 genuine kernel stock runner reaches P/A/W and writes its check-live result then fails closed before the summary'
            line,column,_=driver.anchor_span(read(driver.RUNTIME),driver.CANARY_SITE)
            facts={'source':source,'transport':transport,'diagnosticBytes':0}
            error={'name':'AssertionError','actual':'1','message':json.dumps(facts,separators=(',',':'))+': expected 1 to be +0',
                   'stack':f'AssertionError\n    at {self.fixture / driver.RUNTIME}:{line}:{column}'}
            args=[name,[{'fullName':title,'status':'failed'}],[title],'PH11-X-PROD/P0 genuine kernel',
                  [{'fullName':title,'errors':[error]}],read,self.fixture,driver.RUNTIME]
            self.assertEqual(driver.require_bound_firing(*args),'bound-assertion')
            for bad in ({**facts,'diagnosticBytes':1},{**facts,'source':False,'transport':False}):
                changed=copy.deepcopy(args);changed[4][0]['errors'][0]['message']=json.dumps(bad,separators=(',',':'))+': expected 1 to be +0'
                self.refused(changed)
        # SYNTHETIC only: the nine assertion fields, without helper diagnostics.
        synthetic = dict(status=2, contacts=[3,5,7], deliveries=[11,13,17],
            outerRefusal=True, memoryFloor=False, admissionCreated=True,
            resultCreated=False, summaryCreated=True, workFailure=False)
        pretty = 'Object ' + json.dumps(synthetic, indent=2).replace(': [', ': Array [')
        projection = {key: synthetic[key] for key in ('status','contacts','deliveries','outerRefusal','admissionCreated',
            'resultCreated','summaryCreated','memoryFloor','workFailure')}
        for control, mode in (('C2-c-main-dispatch','stock'),('C9-stat','kernel'),('C9-grep','kernel'),
                              ('C9-validation','kernel'),('C9-execution-reopen','kernel')):
            title = 'PH11-X-PROD/P0 genuine ' + mode + ' stock runner reaches P/A/W and writes its check-live result then fails closed before the summary'
            self.assertEqual(driver.decode_setup_actual(control,title,'helper',pretty), {'actual':synthetic,'projection':projection})
        terminal = ['C9-grep',title,'terminal-leak','true']
        self.assertEqual(driver.decode_setup_actual(*terminal), {'actual':True,'projection':{}})
        for index, wrong in ((0,'C9-stat'),(0,'C1-inbox-writer'),(1,title.replace('kernel','stock')),
                             (1,title+' extra'),(2,'other'),(2,'helper'),(3,'false'),(3,True),(3,' true')):
            invalid = terminal.copy(); invalid[index] = wrong
            with self.subTest(synthetic_alternative=(index,wrong)), self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):
                driver.decode_setup_actual(*invalid)
        # ARCH-748 B / SO1545u / SO0455g: compare to authenticated freeze bytes,
        # not a second hand-written oracle. These replays launch no real runner.
        frozen_file = Path(os.environ['PRIVATE_RUNNER_FROZEN_ORACLES'])
        frozen_bytes = frozen_file.read_bytes()
        self.assertEqual(hashlib.sha256(frozen_bytes).hexdigest(), driver.SETUP_FREEZE_SHA256, 'freeze-bytes')
        frozen = json.loads(frozen_bytes)
        self.assertIs(frozen['bindingReady'], True)
        self.assertEqual({e['control'] for e in frozen['entries']}, set(driver.SETUP_ORACLES))
        read = composed_reader(); groups = {g[0]:g for g in driver.mutation_groups(read(driver.SHELL))}
        for entry in frozen['entries']:
            name = entry['control']; observed = entry['observation']; row = entry['row']
            driver.require_setup_oracle(name, entry)  # every bound field, including provenance
            replay_read = lambda path: read(path).replace(driver.INBOX_SOURCE, driver.INBOX_MUTANT) if name == 'C1-inbox-writer' and path == driver.INBOX_ROUTE else read(path)
            stack = observed['error'] + '\n' + '\n'.join(f'    at {self.fixture/path}:{line}:{column}' for path,line,column in observed['frames'])
            actual = 'Object ' + json.dumps(observed['actual']) if observed['alternative'] == 'helper' else observed['actual']
            error = dict(name=observed['error'], message='private-runner-refused' if name == 'C1-inbox-writer' else 'offline frozen replay', actual=actual, stack=stack)
            args = [name,[{'fullName':row,'status':'failed'}],[row],groups[name][3],
                    [{'fullName':row,'errors':[error]}],replay_read,self.fixture,driver.RUNTIME,observed['inbox']]
            self.assertEqual(driver.require_bound_firing(*args), 'bound-refusal' if name == 'C1-inbox-writer' else 'bound-assertion', name)
            for field in ('sourceRecordSha256','control','row','observation'):
                bad = copy.deepcopy(entry)
                if field == 'sourceRecordSha256': bad[field] = '0'*64
                elif field == 'control': bad[field] = 'C9-grep' if name != 'C9-grep' else 'C9-stat'
                elif field == 'row': bad[field] += ' extra'
                else: bad[field]['actual'] = {'plantedUnmeasuredValue':True}
                with self.subTest(frozen=name, invalid=field), self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):
                    driver.require_setup_oracle(name,bad)
            for other in frozen['entries']:
                if other['control'] == name: continue
                with self.subTest(swapped=(name,other['control'])), self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):
                    driver.require_setup_oracle(name,other)
            if name not in driver.SETUP_HELPER_ROWS: continue
            for field, value in observed['actual'].items():
                for position in range(3) if type(value) is list else (None,):
                    planted = copy.deepcopy(observed['actual'])
                    if position is not None: planted[field][position] += 1
                    else: planted[field] = not value if type(value) is bool else value + 1
                    bad = copy.deepcopy(args); bad[4][0]['errors'][0]['actual'] = 'Object ' + json.dumps(planted)
                    with self.subTest(frozen=name, field=field, position=position): self.refused(bad)
            for kind in ('value','site','span','caller','caller-span','family','error','unknown','missing','interposed','duplicate','terminal-leak'):
                bad = copy.deepcopy(args); error = bad[4][0]['errors'][0]
                if kind == 'value': error['actual'] = 'Object ' + json.dumps({**observed['actual'],'status':37})
                elif kind == 'site': error['stack'] = error['stack'].replace(':566:',':567:')
                elif kind == 'span': error['stack'] = error['stack'].replace(':566:55',':566:99999')
                elif kind == 'caller': error['stack'] = error['stack'].replace(':590:',':616:')
                elif kind == 'caller-span': error['stack'] = error['stack'].replace(':590:5',':590:99999')
                elif kind == 'family':
                    wrong = row.replace('genuine kernel','genuine stock') if 'genuine kernel' in row else row.replace('genuine stock','genuine kernel')
                    bad[1][0]['fullName'] = bad[2][0] = bad[4][0]['fullName'] = wrong
                elif kind == 'error': error['name'] = 'TypeError'
                elif kind == 'unknown': error['actual'] = 'Object ' + json.dumps({**observed['actual'],'terminalBytes':1})
                elif kind == 'missing': error['actual'] = 'Object ' + json.dumps({k:v for k,v in observed['actual'].items() if k != 'status'})
                elif kind == 'interposed': error['stack'] = error['stack'].replace('\n    at '+str(self.fixture/driver.RUNTIME)+':590:', '\n    at /foreign.ts:1:1\n    at '+str(self.fixture/driver.RUNTIME)+':590:')
                elif kind == 'duplicate': error['stack'] += '\n' + error['stack'].splitlines()[1]
                else:
                    line,column,_ = driver.anchor_span(read(driver.RUNTIME),driver.TERMINAL_LEAK)
                    error.update(actual='true',stack=f'AssertionError\n    at {self.fixture/driver.RUNTIME}:{line}:{column}')
                with self.subTest(frozen=name, invalid=kind): self.refused(bad)
    def test_review_six_wrong_values_are_rejected(self):
        read = composed_reader(); groups = {g[0]: g for g in driver.mutation_groups(read(driver.SHELL))}
        def object_value(fields):
            return 'Object {\n' + ''.join('  ' + json.dumps(k) + ': ' + json.dumps(v) + ',\n' for k, v in sorted(fields.items())) + '}'
        delivered = 'Object {\n  "bytes": 27,\n  "error": null,\n}'
        stale = 'Object {\n  "bytes": 0,\n  "error": Object {\n    "cause": "pool-wallet-chain-stale",\n    "code": "wallet-command-component-refused",\n    "retry": "after-sync",\n  },\n}'
        busy = stale.replace('pool-wallet-chain-stale', 'pool-wallet-store-busy').replace('after-sync', 'none')
        cases = [
            ('C5-same-height-hash', {'PH11-HREAD same-height independently mined hash change invalidates A before capture': stale}),
            ('C5-anchor', {'PH11-HREAD exact native anchor predicate fires independently at '+p+' before delivery': delivered for p in 'PAW'}),
            ('C5-deadline-equality', {'PH11-HREAD fresh verified deadline equality at '+p+' refuses without releasing or rebuilding': delivered for p in 'PAW'}),
        ]
        # Independent expected effects: no call to the driver's lock_values.
        lock_cases = [('C7-bridge-interruption', 'bridge', (1,), 1, 0, 1),
                      ('C7-supervisor-initial-interruption', 'supervisor', (1,2,3), 4, 0, 0),
                      ('C7-supervisor-route-interruption', 'supervisor', (4,), 4, 2, 2)]
        fields_by_title = {}
        for name, role, acquisitions, completed, servers, issuer in lock_cases:
            values = {}
            for nth in acquisitions:
                for signal in ('SIGINT', 'SIGTERM'):
                    title = f'PH11-LOCK {role} delivered signals {signal} at exclusive acquisition {nth} drain before exit'
                    fields = dict(acquired=completed, closed=completed, unlinked=completed, servers=servers, contacts=0,
                                  issuerChecks=issuer, sent=1, delivered=1, firedAt=nth, deliveryAfterRelease=True, heldAtExit=0)
                    fields_by_title[title] = fields; values[title] = object_value(fields)
            cases.append((name, values))
        for name, values in cases:
            _, selected, _, selection = groups[name]; site, caller, _ = driver.FIRING[name]['sites'][0]
            line, column, _ = driver.anchor_span(read(selected), site)
            rows = [{'fullName':title,'status':'failed'} for title in values]
            failures = [{'fullName':title,'errors':[{'name':'AssertionError','message':'expected guard effect', 'actual':value,
                         'stack':f'AssertionError\n    at {self.fixture/selected}:{line}:{column}'}]} for title,value in values.items()]
            args = [name,rows,sorted(values),selection,failures,read,self.fixture,selected]
            self.assertEqual(driver.require_bound_firing(*args), 'bound-assertion')
            # Exact review probes and variants: every row must bind, not merely the first.
            for index, title in enumerate(values):
                invalid = [busy, 'Object {\n  "fixtureUnavailable": true,\n}', 'arbitrary-unrelated-actual', None,
                           'Object {\n  "bytes": 0,\n  "error": null,\n}', 'prefix'+values[title], values[title]+'suffix']
                if name.startswith('C7'):
                    fields = fields_by_title[title]
                    for key, value in fields.items():
                        invalid.append(object_value({**fields, key: not value if type(value) is bool else value+1}))
                        invalid.append(object_value({k:v for k,v in fields.items() if k != key}))
                    invalid.append(object_value({**fields, 'fixtureUnavailable':True}))
                else:
                    invalid.extend([stale if name != 'C5-same-height-hash' else delivered,
                                    stale.replace('"after-sync"','"none"'), stale.replace('wallet-command-component-refused','wrong-code')])
                for value in invalid:
                    changed = copy.deepcopy(args); changed[4][index]['errors'][0]['actual'] = value
                    with self.subTest(group=name, row=index): self.refused(changed)
    def test_every_binding_requires_its_value_or_exact_exception(self):
        read = composed_reader(); groups = driver.mutation_groups(read(driver.SHELL))
        driver.require_bindings(read, groups)
        # The disconnected H1 row invokes current and legacy preparation;
        # one membership alone is not the complete expected observation.
        minted = driver.FIRING['H1-before-membership']['sites'][0][2]
        self.assertIsNotNone(re.fullmatch(minted, '2'))
        for wrong in ('0', '1', '3', '22'): self.assertIsNone(re.fullmatch(minted, wrong))
        for name, bound in driver.FIRING.items():
            for index, (site, caller, actual) in enumerate(bound['sites']):
                original = copy.deepcopy(bound)
                try:
                    if bound['error'] == 'AssertionError':
                        for unchecked in (None, '^.*$'):
                            bound['sites'][index] = (site, caller, unchecked)
                            with self.subTest(group=name):
                                with self.assertRaisesRegex(RuntimeError, '^mig01-no-proof-control-refused$'):
                                    driver.require_bindings(read, groups)
                        bound['sites'][index] = (site, caller, actual)
                        if name in driver.SETUP_HELPER_ROWS: continue  # Typed projections are replayed above.
                        # A numeric exit or an injected NODE_OPTIONS must not
                        # be a substring match accepting any unrelated value.
                        patterns = actual.values() if type(actual) is dict else (actual,)
                        for pattern in patterns:
                            self.assertIsNone(re.fullmatch(pattern, 'arbitrary-unrelated-actual'))
                            self.assertIsNone(re.fullmatch(pattern, ''))
                    else:
                        if name in ('C1-inbox-writer', 'C4-distinct-latches'):
                            self.assertEqual(actual, '^undefined$')
                            for unchecked in (None, '^.*$', '^null$'):
                                bound['sites'][index] = (site, caller, unchecked)
                                with self.assertRaisesRegex(RuntimeError, '^mig01-no-proof-control-refused$'):
                                    driver.require_bindings(read, groups)
                            bound['sites'][index] = (site, caller, actual)
                        else:self.assertIsNone(actual)
                        for key in ('message', 'error'):
                            bound[key] = None
                            with self.assertRaisesRegex(RuntimeError, '^mig01-no-proof-control-refused$'):
                                driver.require_bindings(read, groups)
                            bound.update(copy.deepcopy(original))
                finally: bound.clear(); bound.update(original)
        # C4 binds Vitest's serialized undefined exactly. This encoding alone
        # does not distinguish absent, explicit undefined or that raw string.
        # Its unique assertion site is bound; it has no separate caller anchor.
        for name, title in [('C4-distinct-latches','a second A cannot acquire again')]:
            group = next(g for g in groups if g[0] == name); bound = driver.FIRING[name]
            site, _, _ = bound['sites'][0]; line,column,_ = driver.anchor_span(read(group[1]),site)
            stack = f'{bound["error"]}\n    at {self.fixture/group[1]}:{line}:{column}'
            if bound['thrown']:
                path, anchor = bound['thrown']; stack = f'{bound["error"]}\n    at {self.fixture/path}:{driver.anchor_line(read(path),anchor)}:1\n' + stack
            message = 'private-runner-refused' if name=='C1-inbox-writer' else "Cannot read properties of null (reading 'cause')"
            error = {'name':bound['error'],'message':message,'actual':'undefined','stack':stack}
            args=[name,[{'fullName':title,'status':'failed'}],[title],group[3],[{'fullName':title,'errors':[error]}],read,self.fixture,group[1]]
            driver.require_bound_firing(*args)
            for wrong in (None, 0, True, 'null', 'arbitrary-unrelated-actual', 'prefixundefined', 'undefinedsuffix'):
                changed=copy.deepcopy(args);changed[4][0]['errors'][0]['actual']=wrong;self.refused(changed)
            for kind in ('wrong-error','wrong-message','timeout','extra-error','wrong-title','wrong-file','wrong-line','wrong-column'):
                changed=copy.deepcopy(args);bad=changed[4][0]['errors'][0]
                if kind=='wrong-error':bad['name']='AssertionError'
                elif kind=='wrong-message':bad['message']="Cannot read properties of undefined (reading 'cause')"
                elif kind=='timeout':bad['message']='Test timed out'
                elif kind=='extra-error':changed[4][0]['errors'].append(dict(bad))
                elif kind=='wrong-title':changed[4][0]['fullName']='unrelated fixture'
                elif kind=='wrong-file':bad['stack']=bad['stack'].replace(group[1],'foreign.test.ts')
                elif kind=='wrong-line':bad['stack']=re.sub(r':\d+:\d+',':1:1',bad['stack'])
                elif kind=='wrong-column':bad['stack']=re.sub(r':(\d+):\d+',r':\1:99999',bad['stack'])
                with self.subTest(c4_invalid=kind):self.refused(changed)
    def test_inbox_firing_requires_successful_same_invocation_and_exact_rethrow_chain(self):
        original = composed_reader()
        def read(path):
            text = original(path)
            return text.replace(driver.INBOX_SOURCE, driver.INBOX_MUTANT) if path == driver.INBOX_ROUTE else text
        title = 'PH11-ROUTE-WRITER genuine inbox source reaches the authenticated P/A/W issuer'
        frames = []
        for path, anchor in driver.INBOX_CHAIN:
            line, column, _ = driver.anchor_span(read(path), anchor)
            frames.append(f'    at {self.fixture/path}:{line}:{column}')
        witness = {'schema':'mig01-inbox-writer-v1','rows':[{
            'row':title,'invocation':1,'outcome':'refused','guardCalls':1,'guardReturns':1,'matchingReturns':1,
            'assertionActualAbsent':True,'stateUnchanged':True,'requestAbsent':True,'receiptAbsent':True,'routeAbsent':True,'requestsAbsent':True,
            'planAbsent':True,'runnerAbsent':True,'contacts':0,'deliveries':0,'stdoutBytes':0,'stderrBytes':0}]}
        error = {'name':'PrivateRunnerRefusal','message':'private-runner-refused','actual':'undefined',
                 'stack':'PrivateRunnerRefusal: private-runner-refused\n'+'\n'.join(frames)}
        valid = ['C1-inbox-writer',[{'fullName':title,'status':'failed'}],[title],'genuine inbox source reaches',
                 [{'fullName':title,'errors':[error]}],read,self.fixture,driver.RUNTIME,witness]
        self.assertEqual(driver.require_bound_firing(*valid),'bound-refusal')
        for index in range(len(frames)):
            args=copy.deepcopy(valid)
            args[4][0]['errors'][0]['stack']=error['stack'].replace(frames[index],f'    at {self.fixture/driver.RUNTIME}:1:1')
            with self.subTest(wrong_frame=index):self.refused(args)
        args=copy.deepcopy(valid);args[4][0]['errors'][0]['stack']='PrivateRunnerRefusal\n'+'\n'.join([frames[1],frames[0],*frames[2:]])
        with self.subTest(wrong_chain_order=True):self.refused(args)
        for field,value in [('guardCalls',0),('guardCalls',2),('guardReturns',0),('matchingReturns',0),('invocation',2),
                            ('row','unrelated inbox fixture'),('outcome','returned'),('stateUnchanged',1),
                            *[(key,False) for key in ('assertionActualAbsent','stateUnchanged','requestAbsent','receiptAbsent','routeAbsent','requestsAbsent','planAbsent','runnerAbsent')],
                            *[(key,1) for key in ('contacts','deliveries','stdoutBytes','stderrBytes')]]:
            args=copy.deepcopy(valid);args[8]['rows'][0][field]=value
            with self.subTest(wrong_witness=field,value=value):self.refused(args)
        for kind in ('missing','unknown','missing-field','duplicate','wrong-actual','missing-actual','wrong-error','extra-error','timeout','ambiguous','unmutated','fault-before-guard','wrong-column','later-source-call'):
            args=copy.deepcopy(valid);error=args[4][0]['errors'][0]
            if kind=='missing':args[8]=None
            elif kind=='unknown':args[8]['rows'][0]['argv']='synthetic'
            elif kind=='missing-field':del args[8]['rows'][0]['guardReturns']
            elif kind=='duplicate':args[8]['rows'].append(copy.deepcopy(args[8]['rows'][0]))
            elif kind=='wrong-actual':error['actual']='arbitrary-unrelated-actual'
            elif kind=='missing-actual':error['actual']=None
            elif kind=='wrong-error':error['name']='AssertionError'
            elif kind=='extra-error':args[4][0]['errors'].append(dict(error))
            elif kind=='timeout':error['message']='Test timed out'
            elif kind=='ambiguous':args[5]=lambda path:read(path)+('\n'+driver.INBOX_MUTANT if path==driver.INBOX_ROUTE else '')
            elif kind=='unmutated':args[5]=original
            elif kind=='fault-before-guard':args[5]=lambda path:read(path).replace('requireHarnessInboxConstruction(token, store, request); throw new PrivateRunnerRefusal();','throw new PrivateRunnerRefusal(); requireHarnessInboxConstruction(token, store, request);')
            elif kind=='wrong-column':error['stack']=error['stack'].replace(frames[0],re.sub(r':\d+$',':99999',frames[0]))
            elif kind=='later-source-call':
                line,column,_=driver.anchor_span(read(driver.INBOX_ROUTE),'const original = sourceConstruction(token, paths.store, request, context.kind);')
                error['stack']=error['stack'].replace(frames[1],f'    at {self.fixture/driver.INBOX_ROUTE}:{line}:{column}')
            with self.subTest(invalid=kind):self.refused(args)
        driver.require_bindings(original,driver.mutation_groups(original(driver.SHELL)))
        def ambiguous(path):return original(path)+('\n'+driver.INBOX_SOURCE if path==driver.INBOX_ROUTE else '')
        with self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):
            driver.require_bindings(ambiguous,driver.mutation_groups(original(driver.SHELL)))
    def test_review_native_fixture_and_wrong_subtest_probes_are_rejected(self):
        read = composed_reader(); parent = driver.EXEC
        names = [parent] + [parent+'/'+variant for variant in ('descriptor-and-orphan','early-loader','uncaught-error','unhandled-rejection')]
        for group in ('C8-close-inheritance', 'C8-loader-stderr'):
            bound = driver.FIRING[group]['native']; events = []
            for name in names:
                message = bound.get(name)
                if message:
                    message = message.removeprefix('^').removesuffix('$')
                    anchor = 't.Fatal("terminal diagnostic escaped")' if 'terminal diagnostic' in message else 't.Fatalf("exec descriptor identity mismatch:'
                    line = driver.anchor_line(read(driver.CIRCUIT+'internal/runneradmission/exec_process_test.go'), anchor)
                    events.append({'Action':'output','Test':name,'Output':f'    exec_process_test.go:{line}: {message}\n'})
                events.append({'Action':'fail' if name in bound else 'pass','Test':name})
            rows = driver.go_rows('\n'.join(json.dumps(event) for event in events))
            args = [group,rows,sorted(names),'TestMIG01ActualExec',None,read,self.fixture,driver.GO_EXEC]
            self.assertEqual(driver.require_bound_firing(*args),'bound-native')
            for kind in ('review-fixture','review-wrong-subtest','exec-refused','same-message-wrong-site','unlocated-output','extra-output','wrong-status'):
                changed = copy.deepcopy(args)
                if kind.startswith('review-'):
                    stream = [{'Action':'output','Test':name,'Output':'fixture unavailable\n'} for name in names]
                    stream += [{'Action':('fail' if kind=='review-fixture' or name in (parent,parent+'/early-loader') else 'pass'),'Test':name} for name in names]
                    changed[1] = driver.go_rows('\n'.join(json.dumps(event) for event in stream))
                elif kind == 'wrong-status':
                    next(row for row in changed[1] if row['fullName']==parent)['status']='passed'
                else:
                    row = next(row for row in changed[1] if row['fatal'])
                    if kind=='exec-refused': row['fatal']=['    exec_process_test.go:132: exec control refused\n']
                    elif kind=='same-message-wrong-site': row['fatal']=[re.sub(r':\d+:',':1:',row['fatal'][0])]
                    elif kind=='unlocated-output': row['fatal']=['fixture unavailable\n']
                    else: row['fatal'].append('unexpected native output\n')
                with self.subTest(group=group, invalid=kind): self.refused(changed)
    def test_registered_observer_fixture_failure_is_not_a_firing(self):
        read=composed_reader(); test='TestMIG01R3RegisteredDispatchObservation'
        message='exact registered dispatch refusal or no-write boundary'
        line=driver.anchor_line(read(driver.TAGGED_GO),'t.Fatal("'+message+'")')
        rows=[{'name':test,'expectation':expectation,'passed':int(expectation=='success'),'failed':int(expectation!='success'),'skipped':0} for expectation in ('success','ownership')]
        diagnostics=[{'name':test,'expectation':row['expectation'],'stderr':'','output':f'=== RUN   {test}\n'+
                     (f'    runner_admission_tagged_test.go:{line}: {message}\n' if row['failed'] else '')+
                     f'--- {"FAIL" if row["failed"] else "PASS"}: {test} (0.01s)\n'+('FAIL\n' if row['failed'] else 'PASS\n')} for row in rows]
        driver.require_observer_rows(rows,'ownership',diagnostics,read,'C2-a-exact-tuple')
        other='dispatch prerequisite or console boundary'
        other_line=driver.anchor_line(read(driver.TAGGED_GO),'t.Fatal("'+other+'")')
        before_writer=copy.deepcopy(diagnostics)
        before_writer[1]['output']=before_writer[1]['output'].replace(f':{line}: {message}',f':{other_line}: {other}')
        driver.require_observer_rows(rows,'ownership',before_writer,read,'C2-b-before-writer')
        with self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):
            driver.require_observer_rows(rows,'ownership',diagnostics,read,'C2-b-before-writer')
        for kind in ('fixture','stderr','site','missing'):
            changed=copy.deepcopy(diagnostics)
            if kind=='fixture': changed[1]['output']=changed[1]['output'].replace(message,'closed no-proof test invocation required')
            elif kind=='stderr': changed[1]['stderr']='fixture unavailable'
            elif kind=='site': changed[1]['output']=changed[1]['output'].replace(f':{line}:',':1:')
            else: changed.pop()
            with self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):
                driver.require_observer_rows(rows,'ownership',changed,read,'C2-a-exact-tuple')

class ClosedControls(unittest.TestCase):
    def valid(self):
        names = B1_GROUPS + [row[0] for row in driver.POISON]
        kernel = dict.fromkeys(('samples','observedProcesses','fd8PipeProcesses','fd8SocketProcesses','fd8IdentitiesCompared','fd8IdentitiesDifferent',
                               'fd8SourceIdentityMatches','sourceDescriptorMatches','nullStdioPrivateBridgeProcesses','inheritedProverLockBridges'),1)
        kernel['observerRefused']=False
        value={'schema':'mig01-no-proof-controls-v2','mode':'mutations','sourceHead':'1'*40,'sourceTree':'2'*40,'composedTree':'3'*40,
               'sourceArchiveSha256':'4'*64,'compositionSha256':dict.fromkeys(('shell','dispatch'),'5'*64),
               'toolchain':{'node':'v22.22.3','go':'go1.24.0','clang':'clang-1700.0.13'},'stages':[{'stage':'init','exit':0}],
               'buildIdentities':{phase:{'fixtureHead':'1'*40,'privateRunnerProcess':'6'*64,**({key:'7'*64 for key in driver.ARTIFACTS} if phase=='composition' else {})} for phase in ('source','composition')},
               'runtimeSelection':{'class':'ordinary','total':119,'selected':115,'deselected':4,**{key:'a'*64 for key in ('inventorySha256','sourceSha256','selectedSha256','deselectedSha256')}},
               'suites':[{'suite':'runtime-controls','tests':115,'passed':115}],
               'nativeInventoryControls':{'selected':3,'exit':0},'registeredObservers':{'rows':9,'passed':9},
               'kernelObservation':{'readControls':dict.fromkeys(('allow','deny','aliasAllow','aliasDeny'),1),
                                    **dict.fromkeys(('planCaptures','requestCaptures','planAcquisitions','requestAcquisitions'),1),'observer':kernel},
               'groups':[],'observerPoison':[]}
        for index,name in enumerate(names):
            value['groups' if index<42 else 'observerPoison'].append({'group':name,'family':1,'restoredFamily':1,'failingRows':1,
                'result':'fired-restored','firing':'bound-native' if name.startswith('C8-') else 'bound-assertion',
                'targetsSha256':{'original':'a'*64,'mutated':'b'*64,'restored':'a'*64}})
        return value,names
    def test_closed_summary_rejects_paths_argv_unknown_missing_and_wrong_types_at_every_location(self):
        value,names=self.valid();driver.require_closed_summary(value,names)
        # Walk every schema location, not just a field named "secret". These
        # are synthetic paths in POSIX, Windows, URI, relative and encoded form.
        def paths(obj,path=()):
            yield path,obj
            if isinstance(obj,dict):
                for key,child in obj.items(): yield from paths(child,path+(key,))
            elif isinstance(obj,list):
                for key,child in enumerate(obj): yield from paths(child,path+(key,))
        canaries=['/private/tmp/SYNTHETIC','C:\\private\\SYNTHETIC','file:///SYNTHETIC','../SYNTHETIC','%2Fprivate%2FSYNTHETIC','--request=SYNTHETIC']
        for path,obj in paths(value):
            for canary in canaries:
                changed=copy.deepcopy(value); parent=changed
                for key in path[:-1]: parent=parent[key]
                if not path: changed=canary
                else: parent[path[-1]]=canary
                with self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):
                    driver.require_closed_summary(changed,names)
            if isinstance(obj,dict):
                for extra in ('argv','path','unknown'):
                    changed=copy.deepcopy(value); target=changed
                    for key in path: target=target[key]
                    target[extra]=['SYNTHETIC']
                    with self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):
                        driver.require_closed_summary(changed,names)
                for missing in obj:
                    changed=copy.deepcopy(value); target=changed
                    for key in path: target=target[key]
                    del target[missing]
                    with self.assertRaises((RuntimeError,KeyError)):
                        driver.require_closed_summary(changed,names)
        # Projection discards raw state but the emitted record itself refuses
        # unknowns. No raw report/command/installation hash is in this schema.
        self.assertNotIn('raw_sha256',json.dumps(value))
        self.assertNotIn('installationRecord',json.dumps(value))
        state={key:value[key] for key in ('mode','sourceHead','sourceTree','sourceArchiveSha256','composedTree','groups','observerPoison','runtimeSelection')}
        state.update(composition=list(value['compositionSha256'].values()),toolchain=value['toolchain'],identities=value['buildIdentities'],
                     stages=[{'label':'init','exit':0,'argv':['/private/tmp/SYNTHETIC'],'cwd':'/private/tmp/SYNTHETIC'}],
                     suites=[{'label':'runtime-controls','rows':[{'fullName':'/private/tmp/SYNTHETIC-'+str(i),'status':'passed'} for i in range(115)],'path':'/private/tmp/SYNTHETIC'}],
                     native=value['nativeInventoryControls'],observers=[{'passed':1,'raw':'/private/tmp/SYNTHETIC'} for _ in range(9)],
                     kernel=value['kernelObservation'],raw='/private/tmp/SYNTHETIC')
        projected=driver.closed_summary(state,names)
        self.assertNotIn('SYNTHETIC',json.dumps(projected))
        self.assertNotIn('titlesSha256',json.dumps(projected))
        self.assertEqual(projected,value)
    def test_promotion_recipe_replaces_exactly_one_runtime_entry(self):
        recipe=module('recipe',Path(__file__).with_name('mig01-certification.py'))
        scripts=json.loads((REPO/'package.json').read_bytes())['scripts']
        plan=recipe.recipe(scripts)
        self.assertEqual(sum(kind=='mutation-driver' for kind,_ in plan),1)
        self.assertFalse(any(step==recipe.ENTRY for _,step in plan))
        expected=[]
        for step in scripts['validate:all-safe:steps'].split(' && '):
            expected.extend(scripts['validate:pool-action-modules'].split(' && ')[:-1]+[None,None,None] if step==recipe.MODULES else [step])
        self.assertEqual([step for _,step in plan],expected)
        runtime=driver.RUNTIME_ENTRY;selected=set(runtime.runtime_titles('resource'))
        accounting=runtime.require_runtime_selection({'testResults':[{'assertionResults':[
            {'fullName':title,'status':'passed' if title in selected else 'pending'} for title in runtime.runtime_titles('union')]}],
            'numPassedTests':4,'numFailedTests':0,'numPendingTests':115,'success':True},'resource')
        resource={'schema':'mig01-resource-controls-v1','sourceHead':'1'*40,'sourceTree':'2'*40,'fixtureHead':'4'*40,
            'selection':accounting,'buildIdentities':dict.fromkeys(('process','installation','native'),'a'*64),
            'cases':[{'title':title,'stop':'open' if 'valid prove failure' in title else 'W-expiry','stockNativeSha256':'b'*64}
                for title in runtime.runtime_titles('resource')]}
        record={'schema':'mig01-certification-v3','mode':'aggregate','sourceHead':'1'*40,'sourceBase':'3'*40,'executionSeconds':14400,'teardownSeconds':120,'runtimeBaselines':1,'resourceControls':resource,
                'steps':[{'step':i,'kind':kind,'commandSha256':'2'*64 if step else None,'exit':0} for i,(kind,step) in enumerate(plan)]}
        recipe.require_record(record)
        for field in ('argv','path','unknown'):
            changed=copy.deepcopy(record);changed['steps'][0][field]='/private/tmp/SYNTHETIC'
            with self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'):recipe.require_record(changed)
        for field,addition in (('validate:all-safe:steps',' && '+recipe.MODULES),('validate:pool-action-modules',' && '+recipe.ENTRY)):
            changed=dict(scripts);changed[field]+=addition
            with self.assertRaisesRegex(RuntimeError,'^mig01-no-proof-control-refused$'): recipe.recipe(changed)

if __name__ == "__main__": unittest.main()
