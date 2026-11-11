#!/usr/bin/env python3
"""Verify the paired context representation and its exact publication delta.

Read-only source/certificate audit. Native epochs remain unproved. Time/space
O(source input/index bytes + owned bytes + retained code + queries); solver cost
is separate.
"""
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

from compression import zstd
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
import z3

from kernel_native_reader import Kernel
from kext_port_tools import IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent
PREVIOUS='49e6a016c57ce0ab5e2df2364ee22ea618d70710'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={
 'lskd_reader_lineage_report.md','lskd_element_population_report.md','lskd_vector_origin_report.md',
 'lskd_context_compare_report.md','lskd_secure_time_report.md','obfuscated_routines_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED={
 'lskd_context_codec_report.md','triage_evidence/recover_lskd_context_codec.py',
 'triage_evidence/lskd_context_codec_checks.json','triage_evidence/verify_lskd_context_codec_publication.py',
}
ARCHIVES={MANIFEST,'triage_evidence/lskd_context_codec_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
 s=z3.Solver();s.set(timeout=10000);s.from_string(query);assert s.check()==expected


def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
 assert sha256(raw).hexdigest()=='282473072e30cc96f46205fd1a3d5e0d34a65d35cc7cb804bb311a3ea3326155'
 previous=json.loads(raw);current=json.loads(read(BASE/MANIFEST))
 old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
 assert len(old)==len(previous['files'])==8058 and len(new)==len(current['files'])==8062
 assert not old.keys()-new.keys() and new.keys()-old.keys()==ADDED
 assert {p for p in old if old[p]!=new[p]}==CHANGED
 assert current['inputs_preserved']==previous['inputs_preserved']
 for row in current['inputs_preserved']:
  assert sha(BASE/row['path'])==row['sha256'] and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:
  assert sha(BASE/p)==new[p]['sha256'] and size(BASE/p)==new[p]['size_bytes']
 report=read(BASE/'lskd_context_codec_report.md')
 assert all(f'| CC{i} |' in report for i in range(1,9)) and all(f'**QG{i}**' in report for i in range(1,8))
 e=json.loads(read(ROOT/'lskd_context_codec_checks.json'))
 assert e['generator_sha256']==sha(ROOT/'recover_lskd_context_codec.py')
 for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
 assert len(e['proofs'])==48
 assert {'composed_pointer_codec_roundtrip','reader_SIMD_byte_relation','context_byte_relation_roundtrip',
  'word_transposition_involution','initial_reader_fields','initial_context_limit_normalizes_to_zero',
  'initial_context_limit_cannot_exceed_accumulator','aligned_OR_equals_byte_add'}<=e['proofs'].keys()
 for proof in e['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
 assert set(e['negative_controls'])=={'encoded_slot_is_not_generically_raw_pointer','mismatched_seed_can_change_decoded_pointer'}
 for control in e['negative_controls'].values():
  assert control['result']=='sat' and control['model'];check(control['query'],z3.sat)
 for name,count in [('lskd_element_population_checks.json',22),('lskd_reader_lineage_checks.json',26)]:
  prior=json.loads(read(ROOT/name));assert len(prior['proofs'])==count
  for proof in prior['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
  for control in prior.get('negative_controls',{}).values():assert control['result']=='sat';check(control['query'],z3.sat)
 counts=e['verified_counts'];assert counts=={'queries_unsat':48,'negative_controls_sat':2,
  'source_lifted_instances':356,'source_pieces':26,'spans':5,'instructions':460,'code_B':1840,'preservation_audit_rows':275}
 assert sum(e['source_lift_counts'].values())==356 and len(e['source_pieces'])==26
 k=Kernel();assert e['kernel_collection_sha256']==k.sha256
 for row in e['spans']:
  data=bytes.fromhex(row['bytes_hex']);a=int(row['start'],16)
  assert len(data)==int(row['end'],16)-a==4*len(row['instructions'])
  assert data==k.read(a,len(data))==IMAGE.read(a,len(data))
  assert [int(i['ea'],16) for i in row['instructions']]==list(range(a,a+len(data),4))
  assert not any(i['mnemonic'].startswith('bl') for i in row['instructions'])
 for name,piece in e['source_pieces'].items():
  a,z=int(piece['start'],16),int(piece['end'],16)
  assert piece['instructions']==(z-a)//4==e['source_lift_counts'][name]
  assert any(int(s['start'],16)<=a<z<=int(s['end'],16) for s in e['spans'])
 constant=e['constants'];a=int(constant['start'],16);data=bytes.fromhex(constant['bytes_hex'])
 assert len(data)==128 and data==k.read(a,128)==IMAGE.read(a,128)
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
 for audit in e['register_preservation_audits'].values():
  a,z=int(audit['start'],16),int(audit['end'],16);rows=[]
  for ins in cs.disasm(k.read(a,z-a),a):
   writes=[]
   for reg in ins.regs_access()[1]:
    name=ins.reg_name(reg);name={'fp':'x29','lr':'x30'}.get(name,name)
    name=re.sub(r'^w(?=\d)','x',name);writes.append(re.sub(r'^[bhsdq](?=\d)','v',name))
   assert not set(writes)&set(audit['protected_registers']) and not ins.mnemonic.startswith('bl')
   rows.append({'pc':hex(ins.address),'writes':writes})
  assert rows==audit['rows'] and len(rows)==(z-a)//4
  assert audit['indirect_object_writes_disjoint_from_stack_is_premise']
 schedule=e['shuffle_schedule'];assert schedule['writer']==list(range(63,0,-1))
 assert schedule['reader']==list(reversed(schedule['writer'])) and schedule['transposition_involution_used']
 assert [d['divisor'] for d in e['division_domain_lemmas']]==[7,6,5,3]
 source=e['supplied_reference'];assert sha(BASE/source['path'])==source['sha256']
 lines=read(BASE/source['path']).splitlines(keepends=True)
 for row in source['excerpts']:assert row['text']==''.join(lines[row['first_line']-1:row['last_line']])
 arm=e['external_primary_reference'];assert arm['instruction_page']==1460 and not arm['full_document_committed']
 assert arm['download_size_B']==15314151 and arm['download_sha256']=='b7baa6869789722df70da60170d999a62810409aaabbb6db1ef729ed68686bdf'
 assert arm['url'] in report and arm['download_sha256'] in report
 contract=e['selected_contract'];assert (contract['flag32'],contract['seed_byte_offset_B'],contract['object_extent_B'])==(255,28,512)
 assert int(contract['frame_fixture_base'],16)>1<<32 and not contract['frame_fixture_is_native']
 assert contract['same_seed_and_slot_epoch_required'] and contract['same_context_allocation_pointer_under_paired_codec']
 assert not contract['native_context_identity_proven'] and not contract['daemon_request_lineage_proven']
 assert not any(e[n] for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
 assert current['validation']['lskd_context_codec_increment_checks']==counts
 assert current['validation']['lskd_context_codec_static_scope']==e['scope']
 assert current['validation']['reports']==previous['validation']['reports']+1
 assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
 assert current['goal_status']=='active' and len(OWNED)==15
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:path_hygiene((BASE/p).read_bytes())
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
  'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':48,'new_SAT_controls_rechecked':2,
  'prior_UNSAT_queries_rechecked':48,'prior_SAT_controls_rechecked':2,'preservation_audit_rows':275,
  'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
