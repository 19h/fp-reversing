#!/usr/bin/env python3
"""Rebuild continuation/projection receipts and verify publication custody.
Linear owned-byte/corpus work; source SMT search has explicit query limits.
"""
import json
from hashlib import sha256
from compression import zstd
from kext_port_tools import ROOT,SOURCE,qword
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
from verify_userclient_message_initialization_delivery import equivalent_queries
import recover_userclient_zero_tag_return as R
import audit_userclient_zero_tag_return as A
PREVIOUS='5c7c86e8c94599763be61d43470265f391c47978'
BASELINE_SHA='a51b808a642461f78784232c1b9e98cb89e9d1d559f3134e25da5777f34f2cd7'
CHECKS_SHA='cb373730b6e5f027bb2eef3fa0b37aae926071d5d84c3015d27ef05e4bdcf4eb'
AUDIT_SHA='d9712fd01f9046792f0a5ae2bb667b8681712a03697b8b26994800c150f7ec0c'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED=set(['foundational_triage_report.md', 'interface_abi_report.md', 'interface_investigation_status.md', 'mach_ports_report.md', 'obfuscated_routines_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'userclient_caller_return_report.md', 'userclient_transfer_boundary_report.md', 'userclient_zero_tag_unwind_report.md'])
ADDED=set(['triage_evidence/audit_userclient_zero_tag_return.py', 'triage_evidence/recover_userclient_zero_tag_return.py', 'triage_evidence/userclient_zero_tag_return_audit.json', 'triage_evidence/userclient_zero_tag_return_checks.json', 'triage_evidence/verify_userclient_zero_tag_return_delivery.py', 'userclient_zero_tag_return_report.md'])
ARCHIVES=set(['triage_evidence/interface_manifest.json', 'triage_evidence/userclient_zero_tag_return_audit.json', 'triage_evidence/userclient_zero_tag_return_checks.json'])
OWNED=set(['foundational_triage_report.md', 'interface_abi_report.md', 'interface_investigation_status.md', 'mach_ports_report.md', 'obfuscated_routines_report.md', 'triage_evidence/audit_userclient_zero_tag_return.py', 'triage_evidence/interface_manifest.json.zst', 'triage_evidence/recover_userclient_zero_tag_return.py', 'triage_evidence/userclient_zero_tag_return_audit.json.zst', 'triage_evidence/userclient_zero_tag_return_checks.json.zst', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'triage_evidence/verify_userclient_zero_tag_return_delivery.py', 'userclient_caller_return_report.md', 'userclient_transfer_boundary_report.md', 'userclient_zero_tag_return_report.md', 'userclient_zero_tag_unwind_report.md'])
COUNTS={'source_spans': 7, 'captured_words': 60, 'prefix_states': 30, 'saved_cells_per_prefix': 17, 'reconstructed_saved_cells': 510, 'reconstructed_bytes': 4080, 'original_pointer_slots': 3, 'frame_extent_bytes': 4336, 'frame_pointer_offset_bytes': 4320, 'guard_offset_bytes': 4192, 'guard_outcomes': 2, 'external_guard_range_bytes': 8, 'prefix_guard_range_separation_checks': 30, 'carried_source_words': 839, 'carried_instruction_instances': 1151, 'native_target_calls': 0, 'input_content_bytes_supplied': 0}
TOTALS={'new_source_queries_unsat': 44, 'prior_queries_unsat': 157, 'frame_refined_actual_cut_admission_SAT_queries': 20, 'omitted_guard_separation_SAT_queries': 2, 'negative_source_controls': 3, 'new_source_words_covered': 60, 'carried_source_words': 839, 'combined_source_words': 899, 'normal_exit_source_words': 18, 'failure_exit_source_words': 11, 'frame_probe_instruction_instances': 37, 'parent_source_stores_classified': 859, 'continuation_source_stores_classified': 35, 'prefix_saved_cells': 510, 'prefix_saved_bytes': 4080, 'original_probe_byte_reads': 2, 'workspace_return_premises': 1, 'native_target_calls': 0, 'input_content_bytes_supplied': 0}

def compare_queries(old,new,field='query'):
 assert len(old)==len(new)
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop(field),q.pop(field));assert p==q
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 for field in ['source_proofs','actual_cut_admission_checks','omitted_guard_separation_checks']:compare_queries(x.pop(field),y.pop(field))
 compare_queries(x.pop('negative_source_controls'),y.pop('negative_source_controls'),'satisfiable_violation_query')
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert len(a['source_proofs'])==44 and all(p['result']=='unsat'and p['premises_nonvacuous']for p in a['source_proofs'])
 assert len(a['rechecked_prior_proofs'])==157 and all(p['result']=='unsat'for p in a['rechecked_prior_proofs'])
 assert len(a['actual_cut_admission_checks'])==20 and all(p['result']=='sat'and p['additional_frame_guard_separation_assumed']and not p['native_reachability_or_guard_equality_established']for p in a['actual_cut_admission_checks'])
 assert len(a['omitted_guard_separation_checks'])==2 and all(p['result']=='sat'and p['old_frame_ownership_does_not_entail_guard_separation']and not p['native_frame_guard_alias_established']for p in a['omitted_guard_separation_checks'])
 assert [p['parent_source_stores_classified']for p in a['frame_preservation_certificates']]==[446,413]and len(a['continuation_store_ledger'])==35
 for p in a['frame_preservation_certificates']:assert p['FP_refinement_from_original_prologue_required']and p['opaque_FP_passthrough_preserved']and not p['native_alias_writer_exclusion_established']
 f=a['frame_access_footprint'];assert len(f['frame_cells'])==22 and len(f['static_reads'])==6 and f['same_frame_disjoint_integer_pairs']==231 and f['source_access_instances']==48 and f['all_accesses_classified']and f['no_post_workspace_return_context_or_workspace_access']
 assert a['workspace_return_premise']['ordinary_return_assumed']and a['workspace_return_premise']['callee_saved_SP_and_frame_storage_preservation_assumed']and not a['workspace_return_premise']['native_callee_effects_established']
 assert a['normal_exit']['local_result_u32']=='0xffff5bbc'and a['normal_exit']['X0_zero_extended']and a['normal_exit']['SP_delta_bytes']==4336 and a['normal_exit']['restored_GPRs']==list(range(19,30))and a['normal_exit']['restored_D_low64']==list(range(8,12))and a['normal_exit']['RETAB_boundary']['PC']=='0xfffffe000a6662f8'and not a['normal_exit']['RETAB_boundary']['native_authentication_or_return_established']
 assert a['failure_exit']['target']=='0xfffffe000c629694'and a['failure_exit']['modifier']=='0xfffffe000847c478'and not a['failure_exit']['native_callee_effects_established']
 assert not a['guard_value_model']['native_equality_established']and not a['prologue_PAC_event']['native_signature_computed']
 assert [p['mutated_PC']for p in a['negative_source_controls']]==['0xfffffe000a6662cc','0xfffffe000a6662c8','0xfffffe000a6662d8']and all(p['normal_oracle_rejected']and not p['native_target_executed']for p in a['negative_source_controls'])
 assert len(a['proved_pcs'])==60
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for p in e['source']['original_pointers']:assert int(p['target'],16)==qword(int(p['slot'],16))
 assert len(e['prefix_frames'])==30 and sum(len(p['saved_cells'])for p in e['prefix_frames'])==510
 for p in e['prefix_frames']:assert p['frame_guard_range_disjoint']and len(p['saved_cells'])==17 and not p['native_frame_or_PAC_established']
 assert e['external_guard_range']['additional_frame_separation_required']and e['external_guard_range']['address']=='0xfffffe000cacb000'and e['external_guard_range']['size_bytes']==8 and not e['external_guard_range']['runtime_value_from_file_assumed']
 report=read(BASE/'userclient_zero_tag_return_report.md');assert 'PENDING'not in report and CHECKS_SHA in report and AUDIT_SHA in report
 for j in range(1,8):assert '**QG'+str(j)+'**: Pass.'in report
 for j in range(1,9):assert '| ZR-A'+str(j)+':'in report and '| ZR'+str(j)+' |'in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_zero_tag_return_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_zero_tag_return_established']is True
  for key in R.FALSE:assert obj[key]is False
 for p in OWNED-{q+'.zst'for q in ARCHIVES}:
  if(BASE/p).exists():path_hygiene((BASE/p).read_bytes())
 print(json.dumps({'new_queries_rebuilt':44,'prior_queries_rechecked':157,'refined_actual_cut_admission_SAT_checks':20,'old_model_omission_SAT_checks':2,'source_mutation_controls':3,'saved_cells_reconstructed':510,'native_target_calls':0,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9781 and len(after)==9787 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',TOTALS['new_source_queries_unsat']),('prior_queries_unsat',TOTALS['prior_queries_unsat']),('negative_source_controls',3)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==663 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':663,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
