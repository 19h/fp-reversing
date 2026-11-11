#!/usr/bin/env python3
"""Audit the named-wrapper lineage increment, source contracts and publication.

Read-only verification. Source-template certificates do not establish a native
transaction. O(total owned bytes + retained source + 256R); SMT cost separate.
"""
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from compression import zstd
import z3

from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from kernel_native_reader import Kernel
from kext_port_tools import IMAGE
from recover_kext_cold_init import pointer

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent
PREVIOUS='d216d94b48df56fd2bd243cb591a9c86f983a3ed'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={
 'lskd_clock_reader_report.md','lskd_clock_accumulator_report.md','lskd_context_compare_report.md',
 'legacy_stack_report.md','lskd_secure_time_report.md','obfuscated_routines_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED={
 'lskd_reader_lineage_report.md','triage_evidence/recover_lskd_reader_lineage.py',
 'triage_evidence/lskd_reader_lineage_checks.json','triage_evidence/verify_lskd_reader_lineage_publication.py',
}
ARCHIVES={MANIFEST,'triage_evidence/lskd_reader_lineage_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
 s=z3.Solver();s.set(timeout=10000);s.from_string(query);assert s.check()==expected


def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
 assert sha256(raw).hexdigest()=='87c3e358949451db08727b222808ce67c12658e365a08a085d99217fcefe9cea'
 previous=json.loads(raw);current=json.loads(read(BASE/MANIFEST))
 old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
 assert len(old)==len(previous['files'])==8054
 assert len(new)==len(current['files'])==8058
 assert not old.keys()-new.keys() and new.keys()-old.keys()==ADDED
 assert {p for p in old if old[p]!=new[p]}==CHANGED
 assert current['inputs_preserved']==previous['inputs_preserved']
 for row in current['inputs_preserved']:
  assert sha(BASE/row['path'])==row['sha256'] and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:
  assert sha(BASE/p)==new[p]['sha256'] and size(BASE/p)==new[p]['size_bytes']
 report=read(BASE/'lskd_reader_lineage_report.md')
 assert all(f'| RL{i} |' in report for i in range(1,9))
 assert all(f'**QG{i}**' in report for i in range(1,8))
 e=json.loads(read(ROOT/'lskd_reader_lineage_checks.json'))
 assert e['generator_sha256']==sha(ROOT/'recover_lskd_reader_lineage.py')
 for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
 assert len(e['proofs'])==26
 for proof in e['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
 assert set(e['negative_controls'])=={'odd_record_key_join_fails','unmodeled_transform_does_not_prove_pointer_identity'}
 for control in e['negative_controls'].values():
  assert control['result']=='sat' and control['model'];check(control['query'],z3.sat)
 for name,count in [('lskd_context_compare_checks.json',22),('lskd_clock_reader_checks.json',15)]:
  p=json.loads(read(ROOT/name));assert len(p['proofs'])==count and len(p['negative_controls'])==2
  for proof in p['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
  for control in p['negative_controls'].values():assert control['result']=='sat';check(control['query'],z3.sat)
 counts=e['verified_counts']
 assert counts=={'spans':24,'instructions':1331,'code_B':5324,'source_lifted_instances':191,
  'queries_unsat':26,'negative_controls_sat':2,'bank_rules':15,'bank_byte_inputs':3840,'original_slots':33,
  'text_words_scanned':422089,'text_words_decoded':422038,'text_words_undecoded':51,
  'saved_cell_store_candidates':62,'transform_register_audit_rows':140}
 assert sum(e['source_lift_counts'].values())==191
 assert sum(e['source_lift_counts'][n] for n in ['flag_decoder_key','flag_decoder_operands',
  'flag_decoder_predicate','flag_decoder_result'])==38
 k=Kernel();assert e['kernel_collection_sha256']==k.sha256
 for row in e['spans']:
  raw=bytes.fromhex(row['bytes_hex']);a=int(row['start'],16)
  assert len(raw)==int(row['end'],16)-a==4*len(row['instructions'])
  assert raw==k.read(a,len(raw))==IMAGE.read(a,len(raw))
  assert [int(i['ea'],16) for i in row['instructions']]==list(range(a,a+len(raw),4))
 leaf=next(s for s in e['spans'] if s['label']=='flag_decoder')
 assert len(leaf['instructions'])==40 and leaf['instructions'][0]['mnemonic']=='bti'
 assert leaf['instructions'][-1]['mnemonic']=='ret'
 assert not any(i['mnemonic'].startswith('bl') for i in leaf['instructions'])
 assert [i for i in leaf['instructions'] if i['mnemonic'].startswith('st')]==[
  {'ea':'0xfffffe000a52f7c8','mnemonic':'str','operands':'w8, [x0]'}]
 for bank in e['banks'].values():
  left=bytes.fromhex(bank['left256_hex']);right=bytes.fromhex(bank['right256_hex']);key=int(bank['key'],16)
  assert len(left)==len(right)==256 and bank['inputs_checked']==256
  assert left==IMAGE.read(int(bank['left'],16),256) and right==IMAGE.read(int(bank['right'],16),256)
  assert {x^right[left[x]^key] for x in range(256)}=={int(bank['constant'],16)}
  assert int(bank['index'],16)==int(bank['additive'],16)+int(bank['constant'],16)
  slot=int(bank['slot'],16);original=pointer(k,slot);assert original==bank['original_fixup']
  assert (int(original['target'],16)+int(bank['bias'],16))&((1<<64)-1)==int(bank['target'],16)
 for original in e['slots'].values():assert pointer(k,int(original['slot'],16))==original
 expected={'reader_acquire':('0x9ae','0xfffffe000a54e220','0x560f'),
  'reader_sysctl':('0xa1d','0xfffffe000a508d74','0x6e7d'),
  'reader_release':('0xa0f','0xfffffe000a551f38','0x84cc'),
  'reader_comparator':('0xa35','0xfffffe000a52f458','0x2971')}
 for name,(index,target,diversity) in expected.items():
  row=e['banks'][name];assert (row['index'],row['target'],row['original_fixup']['diversity'])==(index,target,diversity)
 assert e['exact_symbols']==k.symbols([0xfffffe000a50e618,0xfffffe000a561344,0xfffffe000c2de71c])
 assert e['exact_symbols']['0xfffffe000a561344']==[]
 source=e['supplied_reference'];assert sha(BASE/source['path'])==source['sha256']
 lines=read(BASE/source['path']).splitlines(keepends=True)
 for row in source['excerpts']:assert row['text']==''.join(lines[row['first_line']-1:row['last_line']])
 scan=e['saved_cell_store_census'];assert scan['text_B']==1688356==4*scan['words']
 assert scan['decoded']+len(scan['undecoded'])==scan['words']
 assert len(scan['matching_stores'])==62
 assert all(not row['reaching_frame_identity_proven'] for row in scan['matching_stores'])
 audit=e['transform_boundary_audit'];assert len(audit['register_write_rows'])==140
 assert not any(set(row['writes'])&{'w8','x8','w9','x9'} for row in audit['register_write_rows'])
 assert {row['SP_offset_B'] for row in audit['direct_SP_stores']}=={
  0x220,0x227,0x226,0x228,0x225,0x224,0x223,0x222,0x22c,0x229,0x22a,0x22b,0x22d,0x22e,0x22f,0x118,0x14c}
 assert not audit['numerical_pointer_identity_proven'] and audit['nonaliasing_transform_access_is_premise']
 contract=e['selected_contract']
 assert contract['named_outer_source_phase']=='0x6e3' and contract['outer_record_required_even']
 assert (contract['entry_frame_B'],contract['entry_local_B'],contract['entry_save_B'])==(848,720,128)
 assert (contract['context_control_offset_B'],contract['context_comparison_offset_B'])==(372,376)
 assert contract['reader_control_byte_required']==1
 assert contract['all_reader_banks_bound_on_selected_source_template'] and contract['saved_phase_bound_on_selected_source_template']
 assert not any(contract[n] for n in ['transform_pointer_codec_proven','whole_named_operation_completed',
  'daemon_request_lineage_proven','native_epoch_matched'])
 assert not any(e[n] for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
 assert current['validation']['lskd_reader_lineage_increment_checks']==counts
 assert current['validation']['lskd_reader_lineage_static_scope']==e['scope']
 assert current['validation']['reports']==previous['validation']['reports']+1
 assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
 assert current['goal_status']=='active' and len(OWNED)==15
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:path_hygiene((BASE/p).read_bytes())
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
  'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':26,'new_SAT_controls_rechecked':2,
  'prior_UNSAT_queries_rechecked':37,'prior_SAT_controls_rechecked':4,'bank_inputs_rechecked':3840,
  'saved_cell_store_candidates':62,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
