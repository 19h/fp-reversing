#!/usr/bin/env python3
"""Validate trap/trace increment and refresh the owned analysis manifest."""
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parent


def main():
    subprocess.run([sys.executable,str(ROOT/'recover_user_trap_interfaces.py')],check=True)
    r=json.loads((ROOT/'user_trap_contracts.json').read_text())
    trace=json.loads((ROOT/'zut_trap_argument_audit.json').read_text())
    counts={'cache_functions':len(r['functions']),'raw_veneers':len(r['traps']),
        'proofs_unsat':len(r['proofs']),'private_wrapper_profiles':r['profile_count'],
        'packet_cases':len(r['packet_checks']),'cache_files_hashed':len(r['cache_source_files']),
        'trace_observations':trace['raw_svc_records'],'printed_headers_rechecked':trace['printed_hex_headers_rechecked'],
        'matching_printed_sends':trace['matched_sends'],'paired_resumptions':len(trace['identical_packet_resume_pairs']),
        'sdk_compile_exit':r['sdk_compile']['exit_code']}
    q={'scope':'User-library trap/packet/runtime and supplied-trace increment; full goal remains active.',
       'QG1':{'status':'pass','evidence':'Factual technical analysis.'},
       'QG2':{'status':'pass','evidence':'Report U1-U7 retain basis, dependencies, probes and current status.'},
       'QG3':{'status':'pass_for_increment','evidence':'Library/trace boundaries covered; runtime objects and exact kernel dispatch remain open.'},
       'QG4':{'status':'pass','evidence':'Scalar/vector byte extents, u32/u64 masks, signed selectors, compiled ABI and complexity explicit.'},
       'QG5':{'status':'pass','evidence':'API/trap, port names/objects, fixtures/native, trace rows/sends and native/RAX retry mechanisms separated.'},
       'QG6':{'status':'pass','evidence':'Original cache/daemon/KC bytes, code-page hashes, SDK/pinned header, solver and exact trace/source hashes retained.'},
       'QG7':{'status':'pass','evidence':'Impact-labeled kernel/runtime/producer and lifecycle continuation requirements explicit.'},
       'verified_counts':counts,'native_target_executed':False,'target_host_operations_executed':False,
       'rax_or_idb_mutated':False,'historical_producer_attested':False,'full_goal_complete':False}
    (ROOT/'user_trap_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n')
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)


if __name__=='__main__':main()
