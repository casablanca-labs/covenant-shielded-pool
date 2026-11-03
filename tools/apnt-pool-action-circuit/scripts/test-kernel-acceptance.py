#!/usr/bin/python3
"""Focused old-comparison and uninstrumented acceptance closure controls."""
import importlib.util
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parent
ROOT=SCRIPTS.parents[2]
def load(name):
    spec=importlib.util.spec_from_file_location(name,SCRIPTS/name)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

BASE=load('test-kernel-attribution.py')
REPRO=BASE.REPRO


class KernelAcceptance(unittest.TestCase):
    setUp=BASE.AttributionControls.setUp
    fixture=BASE.AttributionControls.fixture

    def quiet_control(self,source,status):
        dispatch='runner_process_scan() {'+source.split('runner_process_scan() {',1)[1].split('phase_rss_bytes() {',1)[0]
        dispatch=dispatch.replace('"$repo/tools/pool-action-modules/dist/private-runner-process"','synthetic_reader').replace('/bin/ps','synthetic_reader')
        checks='other_provers() {'+source.split('other_provers() {',1)[1].split('# ---- locks:',1)[0]
        memory=self.base/'memory';continued=self.base/'continued'
        memory.unlink(missing_ok=True);continued.unlink(missing_ok=True)
        script='''set -euo pipefail
readonly PRIVATE_RUNNER_GENERATION=2
has_live=true
synthetic_reader(){ [[ "$*" == '-axo pid=,comm=' ]] || return 99; return STATUS; }
die(){ printf '%s\\n' "$1" >&2; exit 19; }
available_bytes(){ : >MEMORY; echo 21474836480; }
SP1_EXCLUSIVE_MARKER=ABSENT_SP1
PROVER_MARKER=ABSENT_MARKER
'''.replace('STATUS',str(status)).replace('MEMORY',str(memory)).replace('ABSENT_SP1',str(self.base/'absent-sp1')).replace('ABSENT_MARKER',str(self.base/'absent-marker'))
        script+=dispatch+checks+'\nrequire_quiet_machine start 1\n: >'+str(continued)+'\n'
        actual=subprocess.run(['/bin/bash','-c',script],capture_output=True,timeout=5)
        return (actual.returncode,actual.stdout,actual.stderr,memory.exists(),continued.exists())

    def test_instrumented_legacy_dispatch_keeps_failed_reader_status_and_guard(self):
        fixture,_=self.fixture();source=(fixture/REPRO.RUNNER).read_text()
        for legacy in (False,True):
            selected=source.replace(REPRO.NATIVE,REPRO.OLD) if legacy else source
            self.assertEqual(self.quiet_control(selected,0),(0,b'',b'',True,True))
            self.assertEqual(self.quiet_control(selected,23),(19,b'',b'live-plan-prover-inventory-ps\n',False,False))

    def test_historical_comment_mutation_fires_guard_and_dispatch_oracles_then_restores(self):
        fixture,_=self.fixture();source=(fixture/REPRO.RUNNER).read_text().replace('readonly PRIVATE_RUNNER_GENERATION=1','readonly PRIVATE_RUNNER_GENERATION=2')
        fixed=source.replace(REPRO.NATIVE,REPRO.OLD)
        broken=source.replace(REPRO.NATIVE,'/bin/ps "$@" # ENG1436 firing mutation')
        guard=[];dispatch=[]
        for text in (fixed,broken,fixed):
            guard.append(0 if self.quiet_control(text,23)==(19,b'',b'live-plan-prover-inventory-ps\n',False,False) else 19)
            try:REPRO.scan_dispatch(text);dispatch.append(0)
            except RuntimeError as error:self.assertEqual(str(error),'kernel-reproduction-refused');dispatch.append(19)
        self.assertEqual(guard,[0,19,0]);self.assertEqual(dispatch,[0,19,0])
        print('legacy-comment-oracle='+json.dumps({'guardRegressionStatuses':guard,'dispatchRegressionStatuses':dispatch,'readerInputStatus':23,'globalQueries':False}))

    def replay(self,failed=False):
        control=load('test-native-process-scan.py').ReproductionSelection()
        value=control.replay_composition(instrumented=False,fixed_failure=failed)
        return control,value

    def test_acceptance_runs_exactly_three_stages_even_after_failed_candidate(self):
        for failed in (False,True):
            control,(module,summary,calls,_,phases)=self.replay(failed)
            self.assertEqual(list(phases),['kernel-old','kernel-post-w-old','kernel-fixed'])
            self.assertEqual(summary['diagnosticInstrumentation'],False);self.assertTrue(summary['acceptanceComposition'])
            self.assertNotIn('attributionBranches',summary)
            self.assertFalse(any('quiet-diagnostic' in label for label in calls))
            self.assertIn('acceptance-controls',calls)
            for stage,source in phases.items():
                self.assertEqual(module.scan_dispatch(source.decode()),'ps' if stage=='kernel-old' else 'native')
                self.assertEqual(self.quiet_control(source.decode(),23),(19,b'',b'live-plan-prover-inventory-ps\n',False,False))
                self.assertNotIn(b'ENG1436_DIAGNOSTIC_ROLE',source)
            for stage,sources in control.composition_sources.items():
                for source in sources.values():
                    self.assertNotIn(b'ENG1436_DIAGNOSTIC_ROLE',source);self.assertNotIn(b'eng1436_trace',source)
        with patch.object(REPRO,'attribution_module',side_effect=AssertionError('capture import forbidden')):
            source=REPRO.acceptance_driver(ROOT)
        self.assertNotIn('instrument_attribution(',source);self.assertNotIn('instrument_live(',source)
        self.assertNotIn('quiet_return_diagnostic(',source)

    def test_acceptance_source_binding_is_exact_and_rejects_every_hook_and_source_mismatch(self):
        control,(_,summary,_,_,_)=self.replay()
        fixture=self.base/'acceptance';fixture.mkdir()
        def install(stage):
            for path,raw in control.composition_sources[stage].items():
                target=fixture/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        for stage in ('kernel-old','kernel-post-w-old','kernel-fixed'):
            install(stage);value=REPRO.acceptance_sources(fixture,stage,ROOT)
            self.assertEqual(set(value),{'schema','diagnosticHooksAbsent','sources'})
            self.assertEqual(value['schema'],'eng1436-uninstrumented-sources-v1');self.assertTrue(value['diagnosticHooksAbsent'])
            self.assertEqual(len(value['sources']),10)
        expected=control.composition_sources['kernel-fixed']
        for path,raw in expected.items():
            target=fixture/path;target.write_bytes(raw+b'\nSYNTHETIC_UNEXPECTED_CODE\n')
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):REPRO.acceptance_sources(fixture,'kernel-fixed',ROOT)
            target.write_bytes(raw);REPRO.acceptance_sources(fixture,'kernel-fixed',ROOT)
        absent=set(REPRO.OVERLAYS)-set(REPRO.ACCEPTANCE_OVERLAYS)|{BASE.ATTR.GO_TRACE}
        for path in absent:
            target=fixture/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text('synthetic hook\n')
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):REPRO.acceptance_sources(fixture,'kernel-fixed',ROOT)
            target.unlink();REPRO.acceptance_sources(fixture,'kernel-fixed',ROOT)
        # The real control input is forbidden in production too, even though
        # its bytes are required by the separate RSS inventory fixture.
        target=fixture/REPRO.ATTRIBUTION
        target.write_bytes((ROOT/REPRO.ATTRIBUTION).read_bytes())
        with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):
            REPRO.acceptance_sources(fixture,'kernel-fixed',ROOT)
        target.unlink();REPRO.acceptance_sources(fixture,'kernel-fixed',ROOT)
        print('acceptance-attribution-source-oracle='+json.dumps({'statuses':[0,1,0],'actualControlSourceInProductionRefused':True}))
        print('acceptance-source-closure='+json.dumps({'stages':3,'exactProductionSources':10,'independentSourceMismatches':len(expected),'independentForbiddenHookPaths':len(absent),'instrumentationAbsent':True}))

    def test_original_assertions_observer_and_production_bytes_are_preserved(self):
        control,(_,summary,_,_,_)=self.replay()
        # Historical driver/production donor is unchanged; TEST alone follows
        # the current 119-row inventory (the explicit Slice B overlay).
        current=(ROOT/REPRO.TEST).read_text()
        original=[line for line in current.splitlines() if 'expect(' in line]
        def assertions(source):
            self.assertEqual([line for line in source.splitlines() if 'expect(' in line],original)
        assertions(current)
        # Independently delete one assertion: the changed comparison must fire.
        mutant=current.replace(original[0], '', 1)
        with self.assertRaises(AssertionError):assertions(mutant)
        assertions(current)
        print('runtime-donor-overlay-oracle='+json.dumps({'assertionDeletionFired':True,'restored':True,'historicalDonorChanged':False}))
        for stage,source in control.composition_test_sources.items():
            assertions(source)
            self.assertNotIn('eng1436Control(',source);self.assertNotIn('eng1436Metric(',source)
            self.assertEqual(control.composition_sources[stage][REPRO.OBSERVER],(ROOT/REPRO.OBSERVER).read_bytes())
        for stage in ('kernel-old','kernel-post-w-old','kernel-fixed'):
            self.assertEqual(control.composition_sources[stage]['tools/pool-action-modules/private-runner-process.c'],(ROOT/'tools/pool-action-modules/private-runner-process.c').read_bytes())

    def test_cli_routes_only_to_acceptance_before_any_kernel_work(self):
        expected='01'*20;routes=[];output=self.base/'closed.json'
        def check(args,**options):
            if args==[REPRO.NODE,'--version']:return b'v22.22.3\n'
            if args==['/usr/bin/git','rev-parse','HEAD']:return (expected+'\n').encode()
            if args==['/usr/bin/git','status','--porcelain']:return b''
            raise AssertionError('unexpected external query')
        def builder(root):
            routes.append('acceptance')
            return 'def main(args):\n raise RuntimeError("synthetic-stop-before-kernel")\n'
        with patch.object(REPRO.subprocess,'check_output',side_effect=check),patch.object(REPRO,'acceptance_driver',side_effect=builder),\
             patch.object(REPRO,'diagnostic_driver',side_effect=AssertionError('diagnostic route forbidden')),\
             patch.object(REPRO,'attribution_module',side_effect=AssertionError('capture import forbidden')):
            self.assertEqual(REPRO.main(expected,str(output)),1)
        value=json.loads(output.read_bytes());self.assertEqual(routes,['acceptance'])
        self.assertEqual(value['schema'],'eng1436-kernel-acceptance-v1');self.assertFalse(value['expectationMet'])
        self.assertNotIn('sameInvocationAttribution',value)

    def test_acceptance_expectations_are_byte_identical_to_reviewed_entry(self):
        path='tools/apnt-pool-action-circuit/scripts/reproduce-kernel-stock-no-proof.py'
        previous=subprocess.check_output(['/usr/bin/git','show','33776c76c74e5c7cd53cb952a3a7ac9fa82d6168:'+path],cwd=ROOT,stderr=subprocess.DEVNULL).decode()
        current=(ROOT/path).read_text()
        def function(text):return ast.get_source_segment(text,next(node for node in ast.parse(text).body if isinstance(node,ast.FunctionDef) and node.name=='require_kernel_expectations'))
        historical=function(previous)
        self.assertEqual(historical.count("'deselected':116"),2)
        self.assertEqual(hashlib.sha256(historical.encode()).hexdigest(),'d41a0fbed4ab01614b7dbd152dea62bf0d8c393999d9e5c5bbcecad9507abd7b')
        reviewed=historical.replace("'deselected':116","'deselected':118")
        # Preserve the historical comparisons and selected-PASS/descriptor tail;
        # only the fixed runner's contract follows faca3964's reviewed refusal.
        self.assertEqual(function(current).split("    require(fixed['status']",1)[0],reviewed.split("    require(fixed['status']",1)[0])
        self.assertEqual(function(current).split("    require(result['selected']",1)[1],reviewed.split("    require(result['selected']",1)[1])
        self.assertEqual(REPRO.RUNTIME_SOURCE,'a9475e0908c00fa17a5ed71b3bffa0c4e901141c')
        fixed={'status':1,'contacts':[1,1,1],'deliveries':[1,1,1],'terminalBytes':1,'inventoryReason':None,
               'outerReason':'unclassified','runnerBinarySha256':'01'*32,'outerRefusal':True,
               'outputCreated':True,'runCreated':True,'admissionCreated':True,'resultCreated':True,
               'summaryCreated':False,'processListUnavailable':False,'memoryFloor':False,'workFailure':False,'openStage':False}
        old={**fixed,'contacts':[1,0,0],'deliveries':[1,0,0],'inventoryReason':'ps','terminalBytes':72,
             'outerReason':'live-plan-prover-inventory-ps','runCreated':False,'admissionCreated':False,'resultCreated':False}
        post={**fixed,'outerReason':'live-request-process-list-unavailable','processListUnavailable':True,'summaryCreated':True,
              'terminalBytes':len(b'measure-pk-load: live-plan-refused reason=live-request-process-list-unavailable\n')}
        passed={'executed':1,'passed':1,'failed':0,'deselected':118};failed={**passed,'passed':0,'failed':1}
        value={'observations':{'kernel-old':old,'kernel-post-w-old':post,'kernel-fixed':fixed},
               'selected':{'kernel-old':failed,'kernel-post-w-old':failed,'kernel-fixed':passed},
               'descriptorObservations':{'kernel-fixed':{'code':0}}}
        self.assertIsNone(REPRO.require_kernel_expectations(value))
        # Neither a measured byte count nor a guessed causal reason is an oracle.
        for terminal in (1,73,4096):
            for reason in REPRO.OUTER_REASONS:
                value['observations']['kernel-fixed']={**fixed,'terminalBytes':terminal,'outerReason':reason}
                self.assertIsNone(REPRO.require_kernel_expectations(value))
        invalids=[{**fixed,'status':0},{**fixed,'terminalBytes':0},{**fixed,'inventoryReason':'ps'},
                  {**fixed,'outerReason':None},{**fixed,'outerReason':'SYNTHETIC_UNKNOWN_REASON'}]
        invalids.extend({**fixed,key:False} for key in ('outerRefusal','outputCreated','runCreated','admissionCreated','resultCreated'))
        invalids.extend({**fixed,key:True} for key in ('summaryCreated','processListUnavailable','memoryFloor','workFailure','openStage'))
        invalids.extend({**fixed,key:[1 if index!=phase else 0 for index in range(3)]}
                        for key in ('contacts','deliveries') for phase in range(3))
        for invalid in invalids:
            value['observations']['kernel-fixed']=invalid
            with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):REPRO.require_kernel_expectations(value)
        value['observations']['kernel-fixed']=fixed
        value['selected']['kernel-fixed']=failed
        with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):REPRO.require_kernel_expectations(value)
        value['selected']['kernel-fixed']=passed
        value['descriptorObservations']['kernel-fixed']['code']=77
        with self.assertRaisesRegex(RuntimeError,'^kernel-reproduction-refused$'):REPRO.require_kernel_expectations(value)
        value['descriptorObservations']['kernel-fixed']['code']=0
        self.assertIsNone(REPRO.require_kernel_expectations(value))
        print('acceptance-expectations='+json.dumps({'historicalComparisonsPreserved':True,'currentFailClosedContract':True,
              'fixedStateNegatives':len(invalids),'sha256':hashlib.sha256(function(current).encode()).hexdigest()}))


if __name__=='__main__':unittest.main()
