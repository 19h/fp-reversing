#!/usr/bin/env python3
"""Verify corrected source handoff, conditional context predicate and publication."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from compression import zstd
import z3

from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent
PREVIOUS='0b9ac40a4f3fad6e6d9cccc6bbaa30c0bd1e2468'
MANIFEST='triage_evidence/interface_manifest.json'
PRIOR='triage_evidence/lskd_clock_accumulator_checks.json'
CHANGED={
    'lskd_clock_accumulator_report.md','lskd_clock_reader_report.md','lskd_clock_completion_report.md',
    'lskd_secure_time_report.md','lskd_continuations_report.md','foundational_triage_report.md',
    'interface_abi_report.md','interface_investigation_status.md',
    'triage_evidence/recover_lskd_clock_accumulator.py','triage_evidence/lskd_clock_accumulator_checks.json',
    'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED={
    'lskd_context_compare_report.md','triage_evidence/recover_lskd_context_compare.py',
    'triage_evidence/lskd_context_compare_checks.json','triage_evidence/verify_lskd_context_compare_publication.py',
}
ARCHIVES={MANIFEST,PRIOR,'triage_evidence/lskd_context_compare_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected=z3.unsat):
    solver=z3.Solver();solver.set(timeout=10000);solver.from_string(query)
    assert solver.check()==expected


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='060f32f97ce4e103e5144355db9f0c6e87e34767dd73147a396d2d0e01cea3db'
    previous=json.loads(raw);current=json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8050
    assert len(new)==len(current['files'])==8054
    assert not old.keys()-new.keys() and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for row in current['inputs_preserved']:
        assert sha(BASE/row['path'])==row['sha256'] and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:
        assert sha(BASE/p)==new[p]['sha256'] and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'lskd_context_compare_report.md')
    assert all(f'| CX{i} |' in report for i in range(1,9))
    assert all(f'**QG{i}**' in report for i in range(1,8))
    e=json.loads(read(ROOT/'lskd_context_compare_checks.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_lskd_context_compare.py')
    for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
    assert set(e['proofs'])=={
        'comparator_key','comparator_operands','comparator_predicate','comparator_payload_offset','comparator_result',
        'producer_carry_handoff','producer_record_fields','producer_key','record_to_two_indices',
        'record_index_fits_positive_signed32','different_carries_routing','equal_carries_routing',
        'equal_carries_common_state','different_carries_control_reload','context_operand_normalization',
        'complete_unsigned_context_comparison','comparison_join_route','comparison_join_state',
        'control_byte_gate','status_dispatch','composed_context_and_control_gate','alternate_hop'}
    for proof in e['proofs'].values():assert proof['result']=='unsat';check(proof['query'])
    assert set(e['negative_controls'])=={'old_seed_handoff_is_false','wrapped_operands_alone_are_insufficient'}
    for control in e['negative_controls'].values():
        assert control['result']=='sat' and control['model'];check(control['query'],z3.sat)
    prior=json.loads(read(BASE/PRIOR))
    frozen=json.loads(zstd.decompress(git('show',PREVIOUS+':'+PRIOR+'.zst')))
    assert prior['spans']==frozen['spans'] and prior['verified_counts']==frozen['verified_counts']
    assert prior['source_lift_counts']==frozen['source_lift_counts']
    assert prior['proofs'].keys()==frozen['proofs'].keys()
    changed_queries={n for n in prior['proofs'] if prior['proofs'][n]!=frozen['proofs'][n]}
    assert changed_queries=={'context_compare_operands','continuation_record_fields'}
    assert prior['generator_sha256']==sha(ROOT/'recover_lskd_clock_accumulator.py')
    assert prior['selected_contract']['continuation_operand_role']=='zero-extended XOR of the two context comparison carry flags; not seed98'
    for p,digest in prior['dependencies'].items():assert sha(ROOT/p)==digest
    assert len(prior['proofs'])==34 and len(prior['negative_controls'])==2
    for proof in prior['proofs'].values():assert proof['result']=='unsat';check(proof['query'])
    for control in prior['negative_controls'].values():
        assert control['result']=='sat' and control['model'];check(control['query'],z3.sat)
    assert e['corrected_predecessor']['sha256']==sha(BASE/PRIOR)
    assert e['corrected_predecessor']['predecessor_counts']==prior['verified_counts']
    assert 'seed98 - K64' not in read(BASE/'lskd_clock_accumulator_report.md')
    counts=e['verified_counts']
    assert counts=={'spans':9,'instructions':260,'code_B':1040,'source_lifted_instances':143,
        'queries_unsat':22,'negative_controls_sat':2,'helper_window_slots':256,
        'matching_diversity_candidates':3,'original_slots':11,'helper_result_written_B':4}
    assert sum(e['source_lift_counts'].values())==143
    assert sum(e['source_lift_counts'][n] for n in ['comparator_key','comparator_operands',
        'comparator_predicate','comparator_payload_offset','comparator_result'])==36
    assert len(e['spans'])==9
    for row in e['spans']:
        data=bytes.fromhex(row['bytes_hex']);start=int(row['start'],16)
        assert len(data)==int(row['end'],16)-start==4*len(row['instructions'])
        assert [int(i['ea'],16) for i in row['instructions']]==list(range(start,start+len(data),4))
    helper=next(s for s in e['spans'] if s['label']=='comparator')
    assert len(helper['instructions'])==38
    assert helper['instructions'][0]['mnemonic']=='bti' and helper['instructions'][-1]['mnemonic']=='ret'
    assert not any(i['mnemonic'].startswith('bl') for i in helper['instructions'])
    assert e['result_stores']==[{'pc':'0xfffffe000a52f4e8','offset_B':16,'size_B':4}]
    nop=next(s for s in e['spans'] if s['label']=='noop_candidate')
    assert [i['mnemonic'] for i in nop['instructions']]==['bti','ret']
    window=e['helper_window'];assert len(window)==256
    assert [int(r['index'],16) for r in window]==list(range(0x9fe,0xafe))
    for row in window:
        assert int(row['slot'],16)==0xfffffe000846c420+8*int(row['index'],16)
        word=int(row['original_word'],16)
        assert row['matches_auth_flag_and_diversity']==bool(word>>63 and (word>>32)&0xffff==0x2971)
    matches=[r for r in window if r['matches_auth_flag_and_diversity']]
    assert [r['index'] for r in matches]==['0xa0c','0xa20','0xa35']
    for row in matches:
        assert row['original_fixup']==e['slots'][row['index']]
        assert row['normalized_target']==row['original_fixup']['target']
    assert len(e['slots'])==11
    for ix,slot in e['slots'].items():
        assert int(slot['slot'],16)==0xfffffe000846c420+8*int(ix,16)
        assert slot['chain_membership_verified'] and slot['authenticated']
        assert slot['slot'] in report and slot['target'] in report
    assert e['candidate_exact_symbols']['0xfffffe000c4ba95c'][0]['name']=='_IOMallocTypeVarImpl'
    source=e['supplied_reference'];assert sha(BASE/source['path'])==source['sha256']
    lines=read(BASE/source['path']).splitlines(keepends=True)
    for row in source['excerpts']:assert row['text']==''.join(lines[row['first_line']-1:row['last_line']])
    contract=e['selected_contract']
    assert contract['conditional_phase32']==contract['conditional_saved_phase32']=='0x6e3'
    assert contract['conditional_helper_bank_constant8']=='0x37'
    assert contract['conditional_helper_target']=='0xfffffe000a52f458'
    assert contract['context_decoding_additive64']=='0xab53c9aeec0afc05'
    assert not any(contract[k] for k in ['actual_helper_bank_roots_proven','actual_saved_phase_proven',
        'context_root_producer_proven','control_word_producer_proven','upstream_request_recovered','native_epoch_matched'])
    assert not any(e[k] for k in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
    assert current['validation']['lskd_context_compare_increment_checks']==counts
    assert current['validation']['lskd_context_compare_static_scope']==e['scope']
    assert current['validation']['lskd_clock_accumulator_increment_checks']==prior['verified_counts']
    assert current['validation']['reports']==previous['validation']['reports']+1
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active' and len(OWNED)==16
    for p in ARCHIVES:assert not (BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
        'original_inputs_preserved':3,'new_queries_rechecked':22,'new_SAT_controls_rechecked':2,
        'corrected_predecessor_queries_rechecked':34,'predecessor_SAT_controls_rechecked':2,
        'source_instructions_retained':260,'helper_window_slots':256,'analyst_path_literals_absent':True,
        'all_checks_pass':True}))


if __name__=='__main__':main()
