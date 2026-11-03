#!/usr/bin/env python3
"""Deterministic admission checks only: no build, keys, Setup, or prover.

Execute explicitly scoped production plan-validation and per-case guard units,
ending before key admission. Resource samples are synthetic; a disposable
clean main fixture satisfies the unchanged checkout checks in these units.
These extracted units do not exercise P/A/W or production entry admission. The
production entry has no fixture environment bypass. Aggregate checks likewise stop before any build or process launch.
Prover inventory units stub only the scan (and awk for its error controls);
the native global scan and genuine kernel stock runner need host controls.
"""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[3]
CHILD = ROOT / 'tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh'
AGGREGATE = ROOT / 'tools/apnt-pool-aggregate-sp1/scripts'
GIB = 1 << 30


def between(text, start, end):
    assert text.count(start) == 1 and text.count(end) == 1
    return text.split(start, 1)[1].split(end, 1)[0]


class ProverInventory(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='other-provers-')
        self.addCleanup(self.scratch.cleanup)
        self.base = Path(self.scratch.name)
        self.source = CHILD.read_text()

    def inventory(self, ps_body, awk_body=None, live=False, available=None, marker=''):
        # Extract both actual guard functions, under the production error mode.
        # Replacement is confined to these units: no production PATH/env hook.
        units = 'other_provers() {' + between(
            self.source, 'other_provers() {', '# ---- locks:')
        self.assertEqual(units.count('runner_process_scan'), 1)
        units = units.replace('runner_process_scan', 'stub_ps')
        if awk_body is not None:
            self.assertEqual(units.count('/usr/bin/awk'), 1)
            units = units.replace('/usr/bin/awk', 'stub_awk')
        die = 'die() {' + between(self.source, 'die() {', '\ncleanup() {')
        downstream = self.base / 'downstream'
        memory = self.base / 'memory'
        setup = f'''set -euo pipefail
PRIVATE_RUNNER_GENERATION=2
has_live={'true' if live else 'false'}
out=""
SP1_EXCLUSIVE_MARKER={shlex.quote(str(self.base / 'sp1-marker'))}
PROVER_MARKER={shlex.quote(str(self.base / 'prover-marker'))}
stub_ps() {{
 [[ "$*" == '-axo pid=,comm=' ]] || return 99
 {ps_body}
}}
available_bytes() {{ : >{shlex.quote(str(memory))}; {'return 42' if available == 'unavailable' else 'echo '+str(17 * GIB if available is None else available)}; }}
'''
        if marker == 'sp1':
            (self.base/'sp1-marker').touch()
        elif marker == 'foreign':
            (self.base/'prover-marker').write_text('synthetic foreign marker\n')
        elif marker == 'own':
            setup += 'printf "pid %s\\n" "$$" >' + shlex.quote(str(self.base/'prover-marker')) + '\n'
        if awk_body is not None:
            setup += 'stub_awk() { ' + awk_body + '; }\n'
        diagnostics = ''
        if live:
            diagnostics = between(self.source, '# ---- private diagnostic boundary ----',
                                  '# ---- end private diagnostic boundary ----')
            temporary = '/usr/bin/mktemp -d /private/tmp/measure-pk-load-reason.XXXXXXXX'
            self.assertEqual(diagnostics.count(temporary), 1)
            diagnostics = diagnostics.replace(temporary, '/usr/bin/mktemp -d ' +
                                              shlex.quote(str(self.base / 'reason.XXXXXXXX')))
            # Cleanup of a copied production script/real marker is outside this
            # extracted unit. The actual FIFO collector and EXIT handler run.
            setup += 'cleanup() { :; }\n'
        result = subprocess.run(['/bin/bash', '-s'], input=setup + die + '\n' + diagnostics + units +
                                '\nrequire_quiet_machine start ' + str(17 * GIB) +
                                '\n: >' + shlex.quote(str(downstream)) + '\n',
                                text=True, capture_output=True, timeout=10)
        return result, memory.exists(), downstream.exists()

    def assert_inventory_refused(self, ps_body, reason, awk_body=None, live=False):
        result, memory, downstream = self.inventory(ps_body, awk_body, live)
        self.assertEqual(result.returncode, 1)
        prefix = 'measure-pk-load: live-plan-refused reason=' if live else 'measure-pk-load: refusing: '
        self.assertEqual(result.stderr, prefix + reason + '\n')
        self.assertEqual(result.stdout, '')
        self.assertFalse(memory)
        self.assertFalse(downstream)
        self.assertEqual(list(self.base.glob('reason.*')), [])

    def test_scan_dispatch_selects_installed_native_only_for_v2(self):
        source = 'runner_process_scan() {' + between(self.source, 'runner_process_scan() {', 'phase_rss_bytes() {')
        native = '"$repo/tools/pool-action-modules/dist/private-runner-process"'
        self.assertEqual(source.count(native), 1)
        # C1 retired generation 1: no ps fallback remains, and the installed
        # native reader is selected whatever a generation variable says.
        self.assertNotIn('/bin/ps', source)
        source = source.replace(native, 'stub_native')
        for generation in (1, 2):
            result = subprocess.run(['/bin/bash', '-c', 'set -euo pipefail\nPRIVATE_RUNNER_GENERATION=' + str(generation) +
                                    '\nstub_native(){ [[ "$*" == "-axo pid=,comm=" ]] || exit 99; echo native; }\n' +
                                    source + '\nrunner_process_scan -axo pid=,comm='], capture_output=True, text=True)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, 'native\n', ''))
        # Keep the finite ordinary inventory's existing entry; each RSS
        # consumer is a named subtest and runs whenever this entry is selected.
        rss = MissingRSSControls(); rss.setUp()
        checks = sorted(method for method in dir(rss) if method.startswith('check_'))
        self.assertEqual(len(checks), 5)
        for name in checks:
            with self.subTest(rss_consumer=name): getattr(rss, name)()

    def test_entry_fd_close_preserves_closed_stderr_and_old_form_fires(self):
        grouped = ' { exec 9>&-; } 2>/dev/null || true'
        self.assertEqual(self.source.count(grouped), 1)
        for statement, expected in ((grouped, b'SYNTHETIC_CLOSED_CODE\n'), ('exec 9>&- 2>/dev/null || true', b'')):
            result = subprocess.run(['/bin/bash', '-c', 'exec 9>/dev/null\n'+statement+'\nprintf "SYNTHETIC_CLOSED_CODE\\n" >&2'], capture_output=True)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', expected))

    def test_empty_successful_inventory_remains_quiet(self):
        result, memory, downstream = self.inventory(':')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        self.assertTrue(memory)
        self.assertTrue(downstream)

    def test_quiet_inventory_and_self_reach_downstream(self):
        result, memory, downstream = self.inventory(
            'printf "  %s /synthetic/pool-pk-load\\n  492 /bin/bash\\n" "$$"')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        self.assertTrue(memory)
        self.assertTrue(downstream)

    def test_genuine_other_provers_refuse_without_pid_exemptions(self):
        # No parent/child exemptions: every non-self PID remains subject to all
        # existing name patterns. Adjacent synthetic PIDs are distinct from self;
        # this unit does not claim to observe real process ancestry.
        names = ('pool-pk-load', 'pool-action-circuit', 'apnt-pool-action-circuit.test',
                 'apnt-pool-ceremony', 'cargo-prove', 'sp1-prover', 'sp1_core-worker',
                 'apnt-action-runner-worker', 'synthetic-prover', 'r2-run', 'r3-run',
                 'relation-r2-run', 'apnt-successor-child-circuits.test',
                 'apnt-child-circuits-cost.test')
        for name in names:
            with self.subTest(name=name):
                result, memory, downstream = self.inventory(
                    'printf "  %s /synthetic/' + name + '\\n" "$(( $$ + 1 ))"')
                self.assertEqual(result.returncode, 1)
                self.assertRegex(result.stderr, r'^measure-pk-load: refusing: start: another prover is running:\n  [0-9]+ /synthetic/' + re.escape(name) + r'\n$')
                self.assertEqual(result.stdout, '')
                self.assertFalse(memory)
                self.assertFalse(downstream)

    def test_live_genuine_other_prover_refuses_without_listing(self):
        self.assert_inventory_refused("printf '  492 /synthetic/pool-pk-load\\n'",
                                      'live-plan-other-prover', live=True)

    def test_ps_failure_is_not_a_quiet_inventory(self):
        self.assert_inventory_refused('return 42', 'live-plan-prover-inventory-ps')

    def test_partial_ps_failure_is_not_a_prover_match(self):
        self.assert_inventory_refused("printf '  492 /synthetic/pool-pk-load\\n'; return 42",
                                      'live-plan-prover-inventory-ps')

    def test_awk_failure_and_pipeline_failure_refuse(self):
        for ps_status, reason in ((0, 'awk'), (42, 'pipeline')):
            with self.subTest(reason=reason):
                self.assert_inventory_refused('return ' + str(ps_status),
                                              'live-plan-prover-inventory-' + reason,
                                              '/bin/cat >/dev/null; return 43')

    def test_sigpipe_refuses_without_forwarding_raw_errors(self):
        # Deterministic signal exit status, not a timing-dependent real ps race.
        self.assert_inventory_refused("printf 'SYNTHETIC_RAW_DIAGNOSTIC\\n' >&2; return 141",
                                      'live-plan-prover-inventory-sigpipe', live=True)

    def test_live_diagnostic_codes_are_closed(self):
        source = 'private_runner_diagnostics() {' + between(
            self.source, 'private_runner_diagnostics() {', '\nprivate_runner_diagnostic_file=""')
        for suffix in ('ps', 'awk', 'pipeline', 'sigpipe'):
            code = 'live-plan-prover-inventory-' + suffix
            ps_status = {'ps': 42, 'awk': 0, 'pipeline': 42, 'sigpipe': 141}[suffix]
            awk_body = '/bin/cat >/dev/null; return 43' if suffix in ('awk', 'pipeline') else None
            self.assert_inventory_refused("printf 'SYNTHETIC_RAW_DIAGNOSTIC\\n' >&2; return " +
                                          str(ps_status), code, awk_body, live=True)
            for raw, expected in ((f'measure-pk-load: {code}\n', code),
                                  (f'measure-pk-load: {code}\nSYNTHETIC_EXTRA\n', 'unclassified')):
                with self.subTest(code=code, extra=expected == 'unclassified'):
                    result = subprocess.run(['/bin/bash', '-c', source + '\nprivate_runner_diagnostics'],
                                            input=raw, text=True, capture_output=True, timeout=10)
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (0, expected + '\n', ''))


class PrivateDiagnostics(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='other-provers-reason-', dir='/private/tmp')
        self.addCleanup(self.scratch.cleanup)
        self.base = Path(self.scratch.name)
        self.source = CHILD.read_text()
        spec = importlib.util.spec_from_file_location('reproduction', CHILD.with_name('reproduce-kernel-stock-no-proof.py'))
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def observe(self, raw, source=None, status=1):
        boundary = between(source or self.source, '# ---- private diagnostic boundary ----',
                           '# ---- end private diagnostic boundary ----')
        boundary = boundary.replace('/usr/bin/mktemp -d /private/tmp/measure-pk-load-reason.XXXXXXXX',
                                    '/usr/bin/mktemp -d ' + shlex.quote(str(self.base / 'reason.XXXXXXXX')))
        script = ('set -euo pipefail\nPRIVATE_RUNNER_GENERATION=2\nhas_live=true\ncleanup(){ :; }\n' + boundary +
                  "\nprintf '%s' " + shlex.quote(raw) + ' >&2\nexit ' + str(status) + '\n')
        result = subprocess.run(['/bin/bash', '-c', script], capture_output=True, timeout=10)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(list(self.base.glob('reason.*')), [])
        return result.returncode, result.stderr

    def test_all_fixed_names_and_empty_stream_cross_both_allowlists(self):
        for code in self.module.OUTER_REASONS:
            if code == 'unclassified':
                continue
            raw = '' if code == 'no-diagnostic' else ('measure-pk-load: ' if code.startswith('live-plan-') else '') + code + '\n'
            self.assertEqual(self.observe(raw), (1, ('measure-pk-load: live-plan-refused reason=' + code + '\n').encode()))
        self.assertEqual(self.observe('', status=0), (0, b''))

    def test_extra_private_bytes_wrong_newlines_and_lookalikes_stay_unclassified(self):
        expected = (1, b'measure-pk-load: live-plan-refused reason=unclassified\n')
        for raw in ('SYNTHETIC_PRIVATE_TEXT_CANARY', 'no-diagnostic\n', 'live-request-harness-required',
                    'live-request-harness-required\r\n', 'live-request-harness-required-extra\n',
                    'live-request-harness-required\nlive-request-harness-required\n',
                    'SYNTHETIC_PRIVATE_TEXT_CANARY\nlive-request-process-list-unavailable\n',
                    'live-request-process-list-unavailable\nSYNTHETIC_PRIVATE_TEXT_CANARY\n', 'X' * 100000):
            self.assertEqual(self.observe(raw), expected)

    def test_each_allowlist_mutation_fires_then_original_is_restored(self):
        code = 'live-request-process-list-unavailable'
        raw = code + '\n'
        expected = (1, ('measure-pk-load: live-plan-refused reason=' + code + '\n').encode())
        entries = (' b"' + code + '\\n": "' + code + '",\n', '|' + code + '|')
        for entry in entries:
            self.assertEqual(self.source.count(entry), 1)
            mutant = self.source.replace(entry, '' if entry.startswith(' b') else '|')
            # A specific classification failure is the oracle; neither a
            # timeout nor a generic exception satisfies it.
            self.assertEqual(self.observe(raw, mutant), (1, b'measure-pk-load: live-plan-refused reason=unclassified\n'))
            self.assertNotEqual(self.observe(raw, mutant), expected)
            self.assertEqual(self.observe(raw), expected)

    def quiet_guard(self, options, source=None):
        control = ProverInventory()
        control.setUp()
        try:
            if source is not None:
                control.source = source
            return control.inventory(live=True, **options)
        finally:
            control.doCleanups()

    def test_each_pre_admission_shell_refusal_has_an_exact_code_and_no_continuation(self):
        cases = (({'ps_body':"printf '  492 /synthetic/pool-pk-load\\n'"}, 'live-plan-other-prover', False),
                 ({'ps_body':':', 'marker':'sp1'}, 'live-plan-sp1-marker', False),
                 ({'ps_body':':', 'marker':'foreign'}, 'live-plan-prover-marker', False),
                 ({'ps_body':':', 'available':'unavailable'}, 'live-plan-memory-unavailable', True),
                 ({'ps_body':':', 'available':17*GIB-1}, 'live-plan-memory-floor', True))
        for options, code, memory_expected in cases:
            expected = 'measure-pk-load: live-plan-refused reason=' + code + '\n'
            result, memory, continuation = self.quiet_guard(options)
            self.assertEqual((result.returncode,result.stdout,result.stderr,memory,continuation),
                             (1,'',expected,memory_expected,False))
            # Disable only this diagnostic branch. The underlying guard must
            # still refuse; the exact-code regression must fail, then restore.
            before = '$has_live && die ' + code
            self.assertEqual(self.source.count(before),1)
            result, memory, continuation = self.quiet_guard(options,self.source.replace(before,'$has_live && :'))
            self.assertEqual((result.returncode,result.stderr,memory,continuation),
                             (1,'measure-pk-load: live-plan-refused reason=no-diagnostic\n',memory_expected,False))
            self.assertNotEqual(result.stderr,expected)
            result, memory, continuation = self.quiet_guard(options)
            self.assertEqual((result.returncode,result.stderr,memory,continuation),(1,expected,memory_expected,False))
        for options in ({'ps_body':':'}, {'ps_body':':','marker':'own'}, {'ps_body':':','available':17*GIB}):
            result, memory, continuation = self.quiet_guard(options)
            self.assertEqual((result.returncode,result.stdout,result.stderr,memory,continuation),(0,'','',True,True))

    def test_pre_admission_checkout_refusal_is_classified_and_never_checks_resources(self):
        repo=self.base/'main';repo.mkdir()
        subprocess.run(['/usr/bin/git','init','-q','-b','main',str(repo)],check=True,capture_output=True)
        reached=self.base/'quiet';continued=self.base/'admission'
        die='die() {'+between(self.source,'die() {','\ncleanup() {')
        guard='run_case() {'+between(self.source,'run_case() {','\t# Admit private input')+'\n}\n'
        for mutate,dirty in ((False,False),(False,True),(True,True),(False,True),(False,False)):
            target=repo/'untracked'
            if dirty:target.touch()
            else:target.unlink(missing_ok=True)
            reached.unlink(missing_ok=True);continued.unlink(missing_ok=True)
            before='$has_live && die live-plan-main-checkout'
            self.assertEqual(guard.count(before),1)
            unit=guard.replace(before,'$has_live && :') if mutate else guard
            admission=between(self.source,'# ---- the plan, checked before anything runs ----','names=()')
            setup=('repo='+shlex.quote(str(repo))+'\nout=""\nrequire_runner_exclusivity(){ : >'+shlex.quote(str(reached))+'; }\n'+admission+die+'\n'+unit+
                   '\nrun_case child 17 asis ok check-live\n: >'+shlex.quote(str(continued))+'\n')
            boundary=between(self.source,'# ---- private diagnostic boundary ----','# ---- end private diagnostic boundary ----')
            boundary=boundary.replace('/usr/bin/mktemp -d /private/tmp/measure-pk-load-reason.XXXXXXXX',
                                     '/usr/bin/mktemp -d '+shlex.quote(str(self.base/'reason.XXXXXXXX')))
            result=subprocess.run(['/bin/bash','-c','set -euo pipefail\nPRIVATE_RUNNER_GENERATION=2\nhas_live=true\ncleanup(){ :; }\n'+boundary+setup],capture_output=True,timeout=10)
            expected='no-diagnostic' if mutate else 'live-plan-main-checkout'
            self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',('measure-pk-load: live-plan-refused reason='+expected+'\n').encode()) if dirty else (0,b'',b''))
            self.assertEqual((reached.exists(),continued.exists()),(not dirty,not dirty))


class MemoryFloors(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='memory-floor-')
        self.addCleanup(self.scratch.cleanup)
        self.base = Path(self.scratch.name)
        self.repo = self.base / 'main'
        subprocess.run(['git', 'init', '-q', '-b', 'main', str(self.repo)], check=True, timeout=10)
        self.child = CHILD.read_text()

    def shell(self, source, args=(), env=None):
        result = subprocess.run(['/bin/bash', '-s', '--', *map(str, args)], input=source,
                                text=True, capture_output=True, env=env, timeout=10)
        print(f'dry guard exit={result.returncode}; {result.stdout.strip()} {result.stderr.strip()}')
        return result

    def test_child_plan_validation(self):
        source = between(self.child, '# ---- the plan, checked before anything runs ----', '# ---- output directory ----')
        env = dict(os.environ)
        for command in ('prove', 'check-live'):
            for live in (False, True):
                for floor in (16, 17, 20):
                    expected = int(command == 'prove' and floor < 17)
                    with self.subTest(command=command, live=live, floor=floor):
                        print(f'child plan: command={command}, live={live}, floor={floor} GiB')
                        plan = self.base / 'plan'
                        plan.write_text(f'child {floor} asis ok {command}' +
                                        (' --request absent' if live else '') + '\n')
                        out = self.base / 'out'
                        # Synthetic already-captured bytes: only the admitted plan-validation
                        # unit is extracted, never the bootstrap or a forged FD8.
                        setup = 'set -euo pipefail\nrepo=' + shlex.quote(str(self.repo)) + '\nhas_live=' + ('true' if live else 'false') + '\n'
                        setup += 'die() { echo "$*" >&2; exit 1; }\n'
                        setup += 'PRIVATE_RUNNER_GENERATION=2\nplan_source() { printf \'%s\\n\' "${plan_lines[@]}"; }\n'
                        setup += 'plan_lines=(' + shlex.quote(plan.read_text().strip()) + ')\n'
                        result = self.shell(setup + source + '\necho plan-accepted\n', env=env)
                        self.assertEqual(result.returncode, expected)
                        self.assertIn('live-plan-memory-floor' if expected else 'plan-accepted',
                                      result.stderr if expected else result.stdout)
                        self.assertFalse(out.exists())

    def child_case_guard(self, command, floor, available, source=None, expectation='ok', references=(), reject_quiet=False):
        # Stop before cache work or binary invocation, even for prove.
        source = self.child if source is None else source
        guard = 'run_case() {' + between(source, 'run_case() {',
                                         '\t# Admit private input') + '\n}\n'
        admission = between(source, '# ---- the plan, checked before anything runs ----', 'names=()')
        quiet = 'require_runner_exclusivity() {' + between(
            source, 'require_runner_exclusivity() {', '# ---- locks:')
        if reject_quiet:
            quiet = quiet.replace('require_quiet_machine() {', 'require_quiet_machine() { exit 86;')
        setup = f'''set -euo pipefail
repo={shlex.quote(str(self.repo))}
has_live=false
SP1_EXCLUSIVE_MARKER={shlex.quote(str(self.base / 'sp1-marker'))}
PROVER_MARKER={shlex.quote(str(self.base / 'prover-marker'))}
die() {{ echo "$*" >&2; exit 1; }}
other_provers() {{ :; }}
available_bytes() {{ echo {available * GIB}; }}
'''
        return self.shell(setup + admission + quiet + guard + '\n' +
                          shlex.join(['run_case','child',str(floor),'asis',expectation,command,*references])+'\necho case-accepted\n')

    def test_startup_and_case_floor_removal_oracles(self):
        # Independent admission layers: no earlier startup check can mask the
        # per-case oracle. Each accepted boundary is a harmless echo sentinel.
        def startup(source):
            for command in ('prove','load'):
                low=self.startup_mode([command],11,source)
                self.assertEqual((low.returncode,low.stdout,low.stderr),
                    (1,'',f'start: {11*GIB} bytes available (free + inactive + speculative), below the floor of {12*GIB}\n'))
                high=self.startup_mode([command],12,source)
                self.assertEqual((high.returncode,high.stdout,high.stderr),(0,'startup-accepted\n',''))
        def case(source):
            low=self.child_case_guard('prove',17,16,source)
            self.assertEqual((low.returncode,low.stdout,low.stderr),
                (1,'',f'child: {16*GIB} bytes available (free + inactive + speculative), below the floor of {17*GIB}\n'))
            high=self.child_case_guard('prove',17,17,source)
            self.assertEqual((high.returncode,high.stdout,high.stderr),(0,'case-accepted\n',''))
        for before,after,regression in (
            ('require_quiet_machine "start" $((12 * 1024 * 1024 * 1024))',':',startup),
            ('require_quiet_machine "$name" $((floor * 1024 * 1024 * 1024))',':',case)):
            self.assertEqual(self.child.count(before),1)
            regression(self.child)
            with self.assertRaises(AssertionError):regression(self.child.replace(before,after))
            regression(self.child)
        # Independently remove the shell's parser and case minimums. These
        # mutants are test copies; no real key work is reachable.
        def plan_min(source):
            plan=between(source,'# ---- the plan, checked before anything runs ----','# ---- output directory ----')
            setup='set -euo pipefail\nrepo='+shlex.quote(str(self.repo))+'''\nhas_live=false
PRIVATE_RUNNER_GENERATION=2
die(){ echo "$*" >&2; exit 1; }
plan_source(){ printf '%s\\n' 'child 16 asis ok prove'; }
'''
            result=self.shell(setup+plan+'\necho plan-accepted\n')
            self.assertEqual((result.returncode,result.stdout,result.stderr),(1,'','live-plan-memory-floor\n'))
        def case_min(source):
            result=self.child_case_guard('prove',16,17,source)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(1,'','child: proving requires at least 17 GiB\n'))
        for before,regression in (
            ('((floor >= 17)) || die "live-plan-memory-floor"',plan_min),
            ('((floor >= 17)) || die "$name: proving requires at least 17 GiB"',case_min)):
            self.assertEqual(self.child.count(before),1)
            regression(self.child)
            with self.assertRaises(AssertionError):regression(self.child.replace(before,':'))
            regression(self.child)

    def test_prove_floor_independent_of_expect_and_artifact_existence(self):
        present=self.base/'harmless-reference';present.write_bytes(b'synthetic-not-a-key')
        for expectation in ('ok','fail','refuse-open'):
            for reference in (self.base/'absent-reference',present):
                low=self.child_case_guard('prove',17,16,expectation=expectation,
                    references=('--key',str(reference),'--r1cs',str(reference),'--vk',str(reference)))
                self.assertEqual((low.returncode,low.stdout,low.stderr),
                    (1,'',f'child: {16*GIB} bytes available (free + inactive + speculative), below the floor of {17*GIB}\n'))
                self.assertEqual(self.child_case_guard('prove',17,17,expectation=expectation).stdout,'case-accepted\n')
        before='require_quiet_machine "$name" $((floor * 1024 * 1024 * 1024))'
        for exemption in ('[[ $expect != fail ]] || return 0', '[[ -e $3 ]] || return 0'):
            self.assertEqual(self.child.count(before),1)
            mutant=self.child.replace(before,exemption+'\n\t\t'+before)
            result=self.child_case_guard('prove',17,16,mutant,expectation='fail',references=('--key',str(self.base/'absent-reference')))
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,'case-accepted\n',''))
            with self.assertRaises(AssertionError):self.assertEqual(result.returncode,1)
            restored=self.child_case_guard('prove',17,16,expectation='fail')
            self.assertEqual((restored.returncode,restored.stdout),(1,''))

    def test_child_case_guard(self):
        for command in ('prove', 'check-live'):
            for floor, available, expected, message in (
                (16, 17, 1, 'proving requires at least 17 GiB'),
                (17, 17, 0, 'case-accepted'),
                (17, 16, 1, 'below the floor of'),
                (20, 20, 0, 'case-accepted'),
            ):
                if command == 'check-live':
                    expected, message = 0, 'case-accepted'
                with self.subTest(command=command, floor=floor, available=available):
                    print(f'child case: command={command}, floor={floor}, available={available} GiB')
                    result = self.child_case_guard(command, floor, available)
                    self.assertEqual(result.returncode, expected)
                    self.assertIn(message, result.stderr if expected else result.stdout)

    def test_key_loading_case_floor_retained(self):
        for command in ('load', 'derive', 'roundtrip'):
            refused = self.child_case_guard(command, 17, 16)
            self.assertEqual((refused.returncode, refused.stdout, refused.stderr),
                             (1, '', f'child: {16 * GIB} bytes available (free + inactive + speculative), below the floor of {17 * GIB}\n'))
            admitted = self.child_case_guard(command, 17, 17)
            self.assertEqual((admitted.returncode, admitted.stdout, admitted.stderr), (0, 'case-accepted\n', ''))

    def startup_mode(self, commands, available, source=None, reject_quiet=False):
        source = self.child if source is None else source
        plan = between(source, '# ---- the plan, checked before anything runs ----', '# ---- output directory ----')
        quiet = 'require_runner_exclusivity() {' + between(source, 'require_runner_exclusivity() {', '# ---- locks:')
        if reject_quiet:
            quiet = quiet.replace('require_quiet_machine() {', 'require_quiet_machine() { exit 86;')
        startup = 'if $has_resource_work; then' + between(
            source, 'if $has_resource_work; then', '\nmkdir -p "$(dirname "$PROVER_MARKER")"')
        setup = f'''set -euo pipefail
repo={shlex.quote(str(self.repo))}
has_live=false
PRIVATE_RUNNER_GENERATION=2
SP1_EXCLUSIVE_MARKER={shlex.quote(str(self.base / 'absent-sp1'))}
PROVER_MARKER={shlex.quote(str(self.base / 'absent-prover'))}
die() {{ echo "$*" >&2; exit 1; }}
other_provers() {{ :; }}
available_bytes() {{ echo {available * GIB}; }}
plan_source() {{
'''
        setup += '\n'.join('printf \'%s\\n\' ' + shlex.quote(f'case{i} 17 asis ok {cmd}') for i, cmd in enumerate(commands))
        return self.shell(setup + '\n}\n' + plan + quiet + startup + '\necho startup-accepted\n')

    def test_child_startup_mode_and_mutations(self):
        # These are the actual plan derivation, startup call and quiet guard;
        # no key work, process launch, lock acquisition or build is executed.
        cases = tuple(([command], available, expected) for command in ('load','derive','roundtrip','prove')
                      for available,expected in ((11,1),(12,0))) + ((['sha256','load'],11,1),)
        def check(source):
            for commands in (['sha256'], ['residency'], ['evict'], ['check-live'], ['sha256','check-live']):
                result=self.startup_mode(commands,0,source,reject_quiet=True)
                self.assertEqual((result.returncode,result.stdout,result.stderr),(0,'startup-accepted\n',''),
                                 'ORDINARY_STARTUP_ADMISSION_ORACLE')
            for commands, available, expected in cases:
                result = self.startup_mode(commands, available, source)
                self.assertEqual(result.returncode, expected, 'PROVING_STARTUP_ADMISSION_ORACLE')
                if expected:
                    self.assertIn(f'below the floor of {12 * GIB}', result.stderr)
                else:
                    self.assertEqual(result.stdout, 'startup-accepted\n')
        check(self.child)
        # Independently remove and invert the operation derivation. Each must
        # fail this exact low-memory oracle, then the original must pass.
        selector = 'if requires_proving_admission "$cmd"; then has_resource_work=true; fi'
        self.assertEqual(self.child.count(selector), 1)
        for mutant in (':', '[[ $cmd == check-live ]] || has_resource_work=true'):
            with self.assertRaises(AssertionError):
                check(self.child.replace(selector, mutant))
            check(self.child)
            print('STARTUP_ADMISSION_MUTATION: baseline PASS; mutation fires; restored PASS')

    def test_child_case_mode_mutation(self):
        selector = 'if requires_proving_admission "$1"; then'
        self.assertEqual(self.child.count(selector), 1)
        def check(source):
            for command in ('sha256','residency','evict','check-live'):
                ordinary=self.child_case_guard(command,17,0,source,reject_quiet=True)
                self.assertEqual((ordinary.returncode,ordinary.stdout,ordinary.stderr),(0,'case-accepted\n',''),
                                 'ORDINARY_CASE_ADMISSION_ORACLE')
            for command in ('load','derive','roundtrip','prove'):
                proving=self.child_case_guard(command,17,16,source)
                self.assertEqual((proving.returncode,proving.stdout,proving.stderr),
                                 (1,'',f'child: {16 * GIB} bytes available (free + inactive + speculative), below the floor of {17 * GIB}\n'),
                                 'PROVING_CASE_ADMISSION_ORACLE')
                self.assertEqual(self.child_case_guard(command,17,17,source).returncode,0)
        check(self.child)
        for mutation in ('if false; then','if [[ $1 != check-live ]]; then'):
            with self.assertRaises(AssertionError):check(self.child.replace(selector,mutation))
            check(self.child)
            print('CASE_ADMISSION_MUTATION: baseline PASS; mutation fires; restored PASS')

    def test_check_live_floor_free_exclusivity_and_mutation(self):
        # Execute both actual dispatches through retained runner guards, stopping before
        # keys/launch/locks. A low-memory valid control must never sample memory.
        quiet = 'require_runner_exclusivity() {' + between(self.child, 'require_runner_exclusivity() {', '# ---- locks:')
        admission = between(self.child, '# ---- the plan, checked before anything runs ----', 'names=()')
        startup = 'if $has_resource_work; then' + between(
            self.child, 'if $has_resource_work; then', '\nmkdir -p "$(dirname "$PROVER_MARKER")"')
        case = 'run_case() {' + between(self.child, 'run_case() {', '\t# Admit private input') + '\n}\nrun_case child 17 asis ok check-live\n'
        sp1, prover = self.base / 'sp1', self.base / 'prover'
        sampled, continued = self.base / 'sampled', self.base / 'continued'
        for dispatch in (startup, case):
            call='require_runner_exclusivity "start"' if dispatch==startup else 'require_runner_exclusivity "$name"'
            self.assertEqual(dispatch.count(call),1)
            mutant=dispatch.replace(call,':')
            for blocker, code in (('', ''), ('other', 'live-plan-other-prover'),
                                  ('sp1', 'live-plan-sp1-marker'), ('foreign', 'live-plan-prover-marker')):
                def check(selected_dispatch):
                    for path in (sp1, prover, sampled, continued):
                        path.unlink(missing_ok=True)
                    if blocker == 'sp1': sp1.touch()
                    if blocker == 'foreign': prover.write_text('pid 999999999\n')
                    setup = f'''set -euo pipefail
repo={shlex.quote(str(self.repo))}
has_live=true
has_resource_work=false
SP1_EXCLUSIVE_MARKER={shlex.quote(str(sp1))}
PROVER_MARKER={shlex.quote(str(prover))}
die() {{ echo "$*" >&2; exit 1; }}
other_provers() {{ {'echo synthetic-prover' if blocker == 'other' else ':'}; }}
available_bytes() {{ : >{shlex.quote(str(sampled))}; echo {GIB}; }}
'''
                    result = self.shell(setup + admission + quiet + selected_dispatch + '\n: >' + shlex.quote(str(continued)) + '\n')
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (1, '', code + '\n') if code else (0, '', ''))
                    self.assertFalse(sampled.exists())
                    self.assertEqual(continued.exists(), not bool(code))
                with self.subTest(dispatch='startup' if dispatch == startup else 'case', blocker=blocker):
                    check(dispatch)
                    if code:
                        with self.assertRaises(AssertionError): check(mutant)
                        check(dispatch)

    def test_aggregate_shell_floors_remain_20(self):
        for file, constant in (('aggregate-proof-runner.sh', 'ADMISSION_BYTES'),
                               ('prove-dev-batch.sh', 'MIN_AVAILABLE_BYTES')):
            source = (AGGREGATE / file).read_text()
            declarations = '\n'.join(re.findall(r'^readonly ' + constant + r'=.*$', source, re.M))
            self.assertTrue(declarations)
            if constant == 'ADMISSION_BYTES':
                gates = re.findall(r'^\s*\(\(available >= ADMISSION_BYTES\)\) \|\| fail .*$', source, re.M)
                self.assertEqual(len(gates), 2)  # before and after build
                cases = gates
            else:
                cases = ['require_quiet_machine dry-run']
                declarations += '\nrequire_quiet_machine() {' + between(
                    source, 'require_quiet_machine() {', '[[ ! -L $SHARED_PROVER_LOCK ]]')
            for gate in cases:
                for available, expected in ((19, 1), (20, 0)):
                    with self.subTest(file=file, gate=gate, available=available):
                        print(f'aggregate gate: file={file}, available={available} GiB')
                        setup = f'''set -euo pipefail
available={available * GIB}
SP1_EXCLUSIVE_MARKER={shlex.quote(str(self.base / 'absent-sp1'))}
PROVER_MARKER={shlex.quote(str(self.base / 'absent-prover'))}
fail() {{ echo "$*" >&2; exit 1; }}
die() {{ fail "$@"; }}
other_provers() {{ :; }}
available_bytes() {{ echo "$available"; }}
'''
                        result = self.shell(setup + declarations +
                                            f'\n[[ ${constant} == {20 * GIB} ]] || fail wrong-floor\n' +
                                            gate + '\necho aggregate-accepted\n')
                        self.assertEqual(result.returncode, expected)
                        if expected:
                            self.assertIn('admission-refused' if constant == 'ADMISSION_BYTES' else 'below the floor', result.stderr)
                        else:
                            self.assertIn('aggregate-accepted', result.stdout)
        docker = re.search(r'^readonly DOCKER_MIN_BYTES=.*$',
                           (AGGREGATE / 'aggregate-proof-runner.sh').read_text(), re.M).group()
        result = self.shell(docker + f'\n[[ $DOCKER_MIN_BYTES == {20 * GIB} ]]\n')
        self.assertEqual(result.returncode, 0)

    def test_aggregate_measurement_floor_remains_20(self):
        spec = importlib.util.spec_from_file_location('memory_measure', AGGREGATE / 'memory-measure.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        class DryOutput:
            def mkdir(self, **_):
                raise RuntimeError('dry-boundary-before-process-launch')
        with patch.object(module, 'MARKER', self.base / 'absent-marker'):
            for available, message in ((19, 'below-20-gib-admission-floor'),
                                       (20, 'dry-boundary-before-process-launch')):
                with self.subTest(available=available), patch.object(module, 'memory', return_value=(available * GIB, 0)):
                    with self.assertRaisesRegex(RuntimeError, '^' + message + '$'):
                        module.run(None, DryOutput(), {})
                    print(f'memory-measure available={available} GiB; {message}; processLaunch=false')


class MissingRSSControls(unittest.TestCase):
    """Synthetic listings only; extract consumers, never execute the runner."""
    def setUp(self):
        self.source = CHILD.read_text()

    def shell(self, source):
        return subprocess.run(['/bin/bash', '-c', 'set -euo pipefail\n' + source],
                              capture_output=True, text=True, timeout=5)

    def phase(self, rows, source=None):
        unit = 'phase_rss_bytes() {' + between(source or self.source, 'phase_rss_bytes() {', '\nother_provers() {')
        return 'runner_process_scan(){ [[ "$*" == "-axo rss=,comm=" ]] || exit 99; printf %s ' + shlex.quote(rows) + '; }\n' + unit

    def check_rows_and_absence_guard_mutation(self):
        def absent(source):
            for rows in ('', '20 /synthetic/helper\n'):
                r = self.shell(self.phase(rows, source) + '\nphase_rss_bytes')
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, 'not measured\n', ''))
        absent(self.source)
        with self.assertRaises(AssertionError): absent(self.source.replace('if (found)', 'if (1)'))
        absent(self.source)
        print('MISSING_RSS_MUTATION: baseline PASS; missing -> 0 fires; restored PASS')
        for rows, expected in [('10 /synthetic/pool-pk-load\n7 /other/pool-pk-load\n20 /synthetic/helper\n', '17408\n'),
                               ('0 /synthetic/pool-pk-load\n', '0\n')]:
            r = self.shell(self.phase(rows) + '\nphase_rss_bytes')
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, expected, ''))

    def check_sample_preserves_explicit_missing_value(self):
        unit = 'sample() {' + between(self.source, 'sample() {', '\ninputs_of()')
        with tempfile.TemporaryDirectory(prefix='eng1760-rss-', dir='/private/tmp') as directory:
            path = Path(directory) / 'samples'
            for rows, value in [('', 'not measured'), ('17 /synthetic/pool-pk-load\n', '17408')]:
                path.unlink(missing_ok=True)
                r = self.shell(self.phase(rows) + '\nswap_used_bytes(){ echo 0; }\navailable_bytes(){ echo 100; }\n' + unit + '\nsample ' + shlex.quote(str(path)))
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, '0 100 ' + value + '\n', ''))
                self.assertEqual(path.read_text().split('\t')[1:], ['0', '100', value + '\n'])

    def check_monitor_refuses_missing_before_both_numeric_comparisons_and_mutation(self):
        unit = self.source.split('read -r swap avail rss <<<"$(sample "$samples")"\n', 1)[1].split('\n\t\tif [[ -n $tripped ]]', 1)[0]
        self.assertNotIn('/usr/bin/pkill', unit)
        constants = '\n'.join(re.findall(r'^readonly (?:SWAP_GROWTH_TRIP_BYTES|RSS_TRIP_BYTES)=.*$', self.source, re.M))
        def check(source, rss='not measured', swap=0, expected='resource monitor unavailable'):
            r = self.shell(constants + '\nswap0=0\navail=100\ntripped=\nswap=' + str(swap) + '\nrss=' + shlex.quote(rss) + '\n' + source + '\nprintf "%s\\n" "$tripped"')
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, expected + '\n', ''))
        check(unit)
        with self.assertRaises(AssertionError): check(unit.replace("[[ $rss == 'not measured' ]] || ", ''))
        check(unit)
        print('MONITOR_MISSING_RSS_MUTATION: baseline PASS; removed guard fires; restored PASS')
        check(unit, str(24 * GIB), expected='')
        check(unit, str(24 * GIB + 1), expected=f'case RSS {24 * GIB + 1} bytes')
        check(unit, '17408', 8 * GIB, '')
        check(unit, '17408', 8 * GIB + 1, f'swap grew {8 * GIB + 1} bytes over its baseline 0')

    def check_summary_refuses_missing_and_receipt_tail_pin_is_unchanged(self):
        tail = self.source.split('\tlocal result_status=0\n', 1)[1].split('\n}\n\n# The plan is read on fd 3', 1)[0]
        pinned = (ROOT / 'tools/pool-action-modules/test/private-runner-result.test.ts').read_text()
        self.assertEqual(hashlib.sha256(('\tlocal result_status=0\n' + tail).encode()).hexdigest(), re.search(r'const RECEIPT_TAIL_SHA256 = "([0-9a-f]{64})";', pinned)[1])
        unit = tail.split("<<'PY' || result_status=$?\n", 1)[1].split('\nPY\n', 1)[0]
        with tempfile.TemporaryDirectory(prefix='eng1760-rss-', dir='/private/tmp') as directory:
            summary = Path(directory) / 'synthetic.summary.json'
            for value in ('not measured', '17408'):
                (Path(directory) / 'synthetic.samples.tsv').write_text('epoch_s\tswap_used_bytes\tavailable_bytes\tphase_rss_bytes\n1\t0\t100\t' + value + '\n')
                r = subprocess.run([sys.executable, '-c', unit, directory, 'synthetic', 'asis', '0', '0', '', 'ok', 'false', str(ROOT), '2'], capture_output=True, text=True, timeout=5)
                if value == 'not measured':
                    self.assertEqual(r.returncode, 1); self.assertIn("ValueError: invalid literal for int() with base 10: 'not measured'", r.stderr)
                    self.assertFalse(summary.exists())
                else:
                    self.assertEqual((r.returncode, r.stderr), (0, '')); self.assertEqual(json.loads(summary.read_text())['sampledRSSMaxBytes'], 17408)

    def check_attribution_refuses_missing_validity_and_mutation(self):
        source = ast.parse((CHILD.parent / 'kernel-attribution.py').read_text())
        calls = [node for node in ast.walk(source) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'change' and len(node.args) == 3 and isinstance(node.args[1], ast.Constant) and node.args[1].value == 'rss="$(phase_rss_bytes)" || rss=-1']
        self.assertEqual(len(calls), 1); unit = ast.literal_eval(calls[0].args[2])
        def check(source, rows='', expected='sample-invalid 1\n'):
            r = self.shell(self.phase(rows) + '\nswap=0\navail=100\neng1436_trace(){ printf "%s %s\\n" "$@"; }\n' + source)
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, expected, ''))
        check(unit)
        with self.assertRaises(AssertionError): check(unit.replace('[[ $rss == "not measured" ]] || ', ''))
        check(unit)
        print('ATTRIBUTION_MISSING_RSS_MUTATION: baseline PASS; removed guard fires; restored PASS')
        check(unit, '17 /synthetic/pool-pk-load\n', 'sample-valid 0\n')
        capture = ast.parse((CHILD.parent / 'kernel-attribution-capture.py').read_text())
        helper = next(ast.literal_eval(node.value) for node in ast.walk(capture) if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'helper' for t in node.targets))
        number = 'eng1436_number() {' + helper.split('eng1436_number() {', 1)[1]
        with tempfile.TemporaryDirectory(prefix='eng1760-rss-', dir='/private/tmp') as directory:
            path = Path(directory) / 'trace'; path.touch()
            for value in ('not measured', '17408'):
                r = self.shell(number.replace('TRACE', shlex.quote(str(path))) + '\neng1436_number rss-initial-rss 0 ' + shlex.quote(value))
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, '', ''))
                self.assertEqual(path.read_text(), '' if value == 'not measured' else '{"producer":"number","branch":"rss-initial-rss","status":0,"errno":0,"auxStatus":0,"value":17408}\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
