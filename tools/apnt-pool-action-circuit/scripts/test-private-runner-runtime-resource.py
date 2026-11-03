#!/usr/bin/python3
"""Outside-sandbox resource negatives; supported shared slot and proving floors.

Exactly four genuine prove invocations stop at R1CS open or W expiry. A refused
admission is NOT PASS. The package recipe uses the existing slot wrapper,
including its nested-holder semantics; this entry invents no token or bypass.
"""
import importlib.util
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
spec=importlib.util.spec_from_file_location('mig01_runtime',Path(__file__).with_name('test-private-runner-runtime-no-proof.py'))
DRIVER=importlib.util.module_from_spec(spec);spec.loader.exec_module(DRIVER)
spec=importlib.util.spec_from_file_location('mig01_resource_stages',Path(__file__).with_name('test-live-entry-no-proof.py'))
STAGES=importlib.util.module_from_spec(spec);spec.loader.exec_module(STAGES)

def main(argv):
    # Resource evidence always uses the shared slot; the temporary ordinary
    # override cannot authorize these four genuine prove dispatches.
    DRIVER.require('BCH_CLOAK_TEST_SLOT_LOCK_PATH' not in os.environ)
    previous=DRIVER.STAGE_DRIVER
    try:
        with STAGES.LIFECYCLE.inherited_scope(Path(argv[0]) if argv else Path('/private/tmp/mig01-resource')) as scope, STAGES.stage_scope(scope):
            DRIVER.STAGE_DRIVER=STAGES
            return DRIVER.main(argv,selection_class='resource')
    finally: DRIVER.STAGE_DRIVER=previous

if __name__=='__main__':
    try: main(sys.argv[1:])
    except Exception:
        print('mig01-runtime-control-refused',file=sys.stderr);sys.exit(1)
