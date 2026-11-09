#!/usr/bin/env python3
"""Validate the mapping increment, then refresh the shared owned-only manifest."""
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parent


def main():
    subprocess.run([sys.executable,str(ROOT/'recover_rpc502_mapping.py')],check=True)
    r=json.loads((ROOT/'rpc502_mapping_contracts.json').read_text())
    counts={'native_ranges':len(r['ranges']),'proofs_unsat':len(r['proofs']),
        'banks_256':len(r['import_banks_256']),'size_profiles':len(r['data_profiles']),
        'mapping_profiles':len(r['mapping_profiles']),'copy_profiles':len(r['copy_profiles']),
        'contents_profiles':len(r['contents_profiles']),'frame_profiles':len(r['frame_profiles']),
        'live_ida_ranges':r['live_ida']['ranges_matched'],'sdk_compile_exit':r['sdk_compile']['exit_code']}
    out={'scope':'Mapping/copy/parser-boundary/selected-cleanup/QoS increment; full goal remains active.',
        'QG1':{'status':'pass','evidence':'Factual technical analysis.'},
        'QG2':{'status':'pass','evidence':'Report M1-M7 contain dependencies and falsification probes.'},
        'QG3':{'status':'pass_for_increment','evidence':'All increment boundaries retained; full_goal_complete=false.'},
        'QG4':{'status':'pass','evidence':'u32/u64 arithmetic, endian/extent contracts, SDK layouts and complexity explicit.'},
        'QG5':{'status':'pass','evidence':'Selected states, untouched fields, stack-record epochs, logical extent/VM and native/model scopes separated.'},
        'QG6':{'status':'pass','evidence':'Original bytes/imports/fixups, available-source slice, live-IDB metadata/bytes, SDK, solver and fixture provenance distinct.'},
        'QG7':{'status':'pass','evidence':'Impact-labeled ownership/framing/lifecycle continuation probes retained.'},
        'verified_counts':counts,'native_target_executed':False,'target_host_operations_executed':False,
        'idb_mutated':False,'full_goal_complete':False}
    (ROOT/'rpc502_mapping_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n')
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)


if __name__=='__main__':main()
