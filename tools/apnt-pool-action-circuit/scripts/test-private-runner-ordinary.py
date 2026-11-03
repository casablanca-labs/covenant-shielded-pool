#!/usr/bin/python3
"""Finite ordinary MIG01 controls. No real-kernel runner or capture invocation."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import unittest

SCRIPTS=Path(__file__).resolve().parent
SELECTIONS=(
 ('test-prove-memory-floors.py',(('ProverInventory',11),('PrivateDiagnostics',5),('MemoryFloors',10))),
 ('test-native-process-scan.py',(('NativeScan',20),('ReproductionSelection',13))),
 ('test-live-process-scan.py',(('LiveProcessScan',11),('QuietReturnDiagnostic',1))),
 ('test-native-scan-race.py',(('TableRace',4),)),
 ('test-native-requery.py',(('RequeryControls',17),)),
 ('test-native-inventory-availability.py',(('AvailabilityHarness',8),)),
 ('test-macos-observer.py',(('ObserverControls',15),)),
 ('test-observer-continuation.py',(('ContinuationObserver',1),)),
 ('test-observer-interference.py',(('ObserverInterference',3),)),
 ('test-kernel-attribution.py',(('AttributionControls',10),)),
 ('test-kernel-attribution-boundaries.py',(('BoundaryControls',11),)),
 ('test-kernel-acceptance.py',(('KernelAcceptance',7),)),
 ('test-private-runner-ordinary-selection.py',(('OrdinarySelection',10),)),
 ('test-private-runner-driver-setup.py',(('SetupControls',9),('InventoryControls',4),('AccountingControls',3),('BindingControls',6),('ClosedControls',2))),
 ('test-private-runner-driver-progress.py',(('ProgressControls',8),)),
 ('test-mig01-certification.py',(('RecipeControls', 10), ('LifecycleControls', 10))),
)
HOST_ONLY=frozenset((
 'NativeScan.test_kernel_vanished_pid_einval_has_independent_exit_confirmation',
 'NativeScan.test_kernel_scan_and_guard_fire_without_profile_loosening',
 'NativeScan.test_kernel_live_einval_recovery_preserves_named_prover_guard',
 'NativeScan.test_kernel_whole_host_inventory_availability_eng1459',
))
EXPECTED=209

def require(ok):
    if not ok:raise RuntimeError('mig01-ordinary-control-refused')

def inventory():
    selected=[]
    for filename,classes in SELECTIONS:
        tree=ast.parse((SCRIPTS/filename).read_text())
        found={node.name:sorted(method.name for method in node.body if isinstance(method,ast.FunctionDef) and method.name.startswith('test_'))
               for node in tree.body if isinstance(node,ast.ClassDef) and any(isinstance(method,ast.FunctionDef) and method.name.startswith('test_') for method in node.body)}
        require(set(found)=={name for name,_ in classes})
        ids=[]
        for name,count in classes:
            methods=[name+'.'+method for method in found[name]]
            omitted=set(methods)&HOST_ONLY if filename=='test-native-process-scan.py' else set()
            require(omitted==(HOST_ONLY if name=='NativeScan' else set()))
            chosen=[method for method in methods if method not in omitted]
            require(len(chosen)==count)
            ids.extend(chosen)
        selected.append((filename,ids))
    require(sum(len(ids) for _,ids in selected)==EXPECTED)
    return selected

def execute(suite,expected):
    output=io.StringIO();diagnostics=io.StringIO()
    with contextlib.redirect_stdout(output),contextlib.redirect_stderr(output):
        result=unittest.TextTestRunner(stream=diagnostics).run(suite)
    # Failed assertions and captured streams never become diagnostic output.
    ids={test.id() for test,_ in result.failures+result.errors+result.skipped}
    builds=[]
    for line in output.getvalue().splitlines():
        if not line.startswith('fresh-unit-build='):continue
        value=json.loads(line.split('=',1)[1]);require(type(value) is dict)
        hashes={key:value[key] for key in ('sourceSha256','productionSha256','binarySha256') if key in value}
        require('sourceSha256' in hashes and 'binarySha256' in hashes
                and all(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) for value in hashes.values()))
        builds.append(hashes)
    return {'tests':result.testsRun,'expected':expected,'failures':len(result.failures),'errors':len(result.errors),
            'skipped':len(result.skipped),'failedIds':sorted(ids),'reportedBuilds':builds,
            'passed':result.testsRun==expected and result.wasSuccessful() and not result.skipped}

def main():
    require(len(sys.argv)==1)
    # Keep the source checkout clean for the later exact-head runtime export.
    # Cover this interpreter and Python children, without requiring a caller flag.
    sys.dont_write_bytecode = True
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    selections=inventory();passed=True
    for filename,ids in selections:
        path=SCRIPTS/filename
        spec=importlib.util.spec_from_file_location(filename,path)
        module=importlib.util.module_from_spec(spec)
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            spec.loader.exec_module(module)
        suite=unittest.TestSuite(getattr(module,item.split('.')[0])(item.split('.')[1]) for item in ids)
        row=execute(suite,len(ids));passed=passed and row['passed']
        print(json.dumps({'schema':'mig01-ordinary-controls-v1','file':filename,
            'sourceSha256':hashlib.sha256(path.read_bytes()).hexdigest(),'selected':ids,**row}),flush=True)
    print(json.dumps({'schema':'mig01-ordinary-total-v1','selected':EXPECTED,'passed':passed,'hostOnlyExcluded':sorted(HOST_ONLY)}))
    return 0 if passed else 1

if __name__=='__main__':
    try:status=main()
    except Exception:
        print('{"schema":"mig01-ordinary-total-v1","passed":false,"reason":"mig01-ordinary-control-refused"}')
        status=1
    sys.exit(status)
