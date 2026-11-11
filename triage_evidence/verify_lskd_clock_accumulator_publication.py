#!/usr/bin/env python3
"""Replay conditional accumulator contracts and verify exact publication scope."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from compression import zstd
import z3

from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent
PREVIOUS='ad5b3d44c142d7225c8fd8f5a1f06d7b2b4946d1'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={
    'lskd_clock_reader_report.md','lskd_clock_completion_report.md',
    'lskd_secure_time_report.md','lskd_continuations_report.md',
    'foundational_triage_report.md','interface_abi_report.md',
    'interface_investigation_status.md','triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED={
    'lskd_clock_accumulator_report.md','triage_evidence/recover_lskd_clock_accumulator.py',
    'triage_evidence/lskd_clock_accumulator_checks.json',
    'triage_evidence/verify_lskd_clock_accumulator_publication.py',
}
ARCHIVES={MANIFEST,'triage_evidence/lskd_clock_accumulator_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}


def check(query,expected=z3.unsat):
    solver=z3.Solver();solver.set(timeout=10000);solver.from_string(query)
    assert solver.check()==expected


def main():
    raw=zstd.decompress(subprocess.check_output(['git','show',PREVIOUS+':'+MANIFEST+'.zst'],cwd=BASE))
    assert sha256(raw).hexdigest()=='e74e0059ad779e34f1da1be2410737e989399b94d2b49f3a9b2bf5faf426f096'
    previous=json.loads(raw);current=json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8046
    assert len(new)==len(current['files'])==8050
    assert not old.keys()-new.keys() and new.keys()-old.keys()==ADDED
    assert {n for n in old if old[n]!=new[n]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for row in current['inputs_preserved']:
        assert sha(BASE/row['path'])==row['sha256'] and size(BASE/row['path'])==row['size_bytes']
    for name in CHANGED|ADDED:
        assert sha(BASE/name)==new[name]['sha256'] and size(BASE/name)==new[name]['size_bytes']
    report=read(BASE/'lskd_clock_accumulator_report.md')
    assert all(f'| CA{i} |' in report for i in range(1,9))
    assert all(f'**QG{i}**' in report for i in range(1,8))
    evidence=json.loads(read(ROOT/'lskd_clock_accumulator_checks.json'))
    assert evidence['generator_sha256']==sha(ROOT/'recover_lskd_clock_accumulator.py')
    for name,digest in evidence['dependencies'].items():assert sha(ROOT/name)==digest
    assert len(evidence['proofs'])==34 and len(evidence['negative_controls'])==2
    for proof in evidence['proofs'].values():
        assert proof['result']=='unsat';check(proof['query'])
    for control in evidence['negative_controls'].values():
        assert control['result']=='sat' and control['model'];check(control['query'],z3.sat)
    wrap=evidence['negative_controls']['decoded_accumulator_can_wrap']['model']
    assert int(wrap['elapsed64'],16)<=0xffffffff and int(wrap['positive_clock_delta64'],16)<=0xffffffff
    prior=json.loads(read(ROOT/'lskd_clock_reader_checks.json'))
    assert len(prior['proofs'])==15
    for proof in prior['proofs'].values():assert proof['result']=='unsat';check(proof['query'])
    writer=json.loads(read(ROOT/'lskd_clock_completion_checks.json'))
    for name in ['clock_field_30_and_zero_38','field_10_and_zero_20']:
        assert writer['proofs'][name]['result']=='unsat';check(writer['proofs'][name]['query'])
    adapters=json.loads(read(ROOT/'lskd_continuations_proofs.json'))
    selected=[p for p in adapters['proofs'] if p['name'] in {
        'unlock_record_selector','unlock_explicit_pointer_gate','unlock_cached_pointer_gate'}]
    assert len(selected)==3
    for proof in selected:
        assert proof['result']=='unsat' and sha(ROOT/proof['original_file'])==proof['original_sha256']
        check(read(ROOT/proof['original_file']))
    assert len(evidence['spans'])==4
    for row in evidence['spans']:
        data=bytes.fromhex(row['bytes_hex'])
        assert len(data)==int(row['end'],16)-int(row['start'],16)
        assert len(row['instructions'])*4==len(data)
    slot=evidence['advance_slot']
    assert slot['slot']=='0xfffffe00084707d0' and slot['target']=='0xfffffe000a534e34'
    assert slot['chain_membership_verified'] and slot['authenticated'] and slot['diversity']=='0x4c8d'
    assert slot['slot'] in report and slot['target'] in report
    stores=evidence['continuation_record_stores']
    written={b for s in stores for b in range(s['offset_B'],s['offset_B']+s['size_B'])}
    assert len(stores)==7 and written==set(range(40))-set(range(16,20))
    ida=evidence['IDA_readback']
    assert len(ida['ranges'])==2 and sum(r['size_B'] for r in ida['ranges'])==128
    for row in ida['ranges']:assert len(bytes.fromhex(row['bytes_hex']))==row['size_B']
    assert len(ida['scoped_recall'])==2 and all(r['count']==0 and not r['truncated'] for r in ida['scoped_recall'])
    contract=evidence['selected_contract']
    assert contract['conditional_incoming_phase32']=='0x6e3' and contract['flag32']==255
    assert contract['fresh_clock_B']==4 and contract['accumulator_B']==8 and contract['elapsed_max']=='0xffffffff'
    assert not any(contract[k] for k in ['actual_incoming_phase_proven','actual_frame_roots_proven',
        'actual_helper_targets_proven','upstream_request_recovered','native_epoch_matched'])
    assert evidence['new_IDA_access'] and not evidence['new_native_execution']
    assert not evidence['new_IDB_mutations'] and not evidence['full_goal_complete']
    counts=evidence['verified_counts']
    assert counts=={'spans':4,'instructions':814,'code_B':3256,'source_lifted_instances':754,
        'queries_unsat':34,'negative_controls_sat':2,'record_written_B':36,'record_envelope_B':40,'IDA_spotcheck_B':128}
    assert sum(evidence['source_lift_counts'].values())==754
    assert current['validation']['lskd_clock_accumulator_increment_checks']==counts
    assert current['validation']['lskd_clock_accumulator_static_scope']==evidence['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active' and len(OWNED)==13
    for name in ARCHIVES:assert not (BASE/name).exists()
    for name in OWNED:path_hygiene((BASE/name).read_bytes())
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
        'original_inputs_preserved':3,'new_queries_rechecked':34,'SAT_controls_rechecked':2,
        'predecessor_queries_rechecked':20,'source_instructions_retained':814,
        'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
