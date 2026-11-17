#!/usr/bin/env python3
"""Rebuild failure-unwind proofs, retirement interfaces and publication custody.
Linear owned-byte/corpus work; source SMT search has explicit query limits.
"""
import json
from hashlib import sha256
from compression import zstd
from kext_port_tools import ROOT,SOURCE,TABLE,qword
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
from verify_userclient_message_initialization_delivery import equivalent_queries
import recover_userclient_message_failure as R
import audit_userclient_message_failure as A
PREVIOUS='0b0722982149f272066934fef4d4f485f9a0c3d6'
BASELINE_SHA='1cb67bb0fb78de782dcefcf833e552d1aa271a0f60f077af3d1c8efd819389cb'
CHECKS_SHA='9f728757b0c37f2a84729651cb2c3dc9bb75282685b783e958beedbc7b15390d'
AUDIT_SHA='768141cad04eca672907e136c9548e67284cdf86bffc89d8c68d63c31282a007'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','userclient_message_initialization_report.md','userclient_message_attributes_report.md','userclient_message_parser_report.md','userclient_parser_cleanup_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_message_failure_report.md','triage_evidence/recover_userclient_message_failure.py','triage_evidence/audit_userclient_message_failure.py','triage_evidence/verify_userclient_message_failure_delivery.py','triage_evidence/userclient_message_failure_checks.json','triage_evidence/userclient_message_failure_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_message_failure_checks.json','triage_evidence/userclient_message_failure_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'source_spans': 25, 'captured_words': 413, 'bank_rules': 4, 'certified_bank_inputs': 1024, 'original_literal_pointers': 4, 'original_branch_pointers': 21, 'prefix_states': 30, 'additional_cells_per_state': 3, 'additional_cell_bytes_per_state': 16, 'retirement_descriptors': 2, 'message_extent_bytes': 128, 'attribute_extent_bytes': 112, 'retirement_calls_per_case': 2, 'input_content_bytes_supplied': 0}
TOTALS={'new_source_queries_unsat': 126, 'new_semantic_contracts': 6, 'prior_source_queries_unsat': 14, 'new_source_words_covered': 413, 'lifted_instruction_instances': 928030, 'composed_modes': 2, 'retirement_calls_per_mode': 2, 'additional_prefix_cells_reconstructed': 90, 'additional_prefix_bytes_reconstructed': 480, 'negative_source_controls': 3, 'new_controller_reads_per_mode': 4, 'new_bank_applications_per_mode': 4, 'input_content_bytes_supplied': 0, 'native_target_calls': 0}

def compare_queries(old,new,field):
 assert len(old)==len(new)
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop(field),q.pop(field));assert p==q
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 old,new=x.pop('source_proofs'),y.pop('source_proofs');compare_queries(old,new,'query')
 controls,rebuilt=x.pop('negative_source_controls'),y.pop('negative_source_controls');compare_queries(controls,rebuilt,'satisfiable_violation_query')
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert len(old)==126 and len({q['semantic_contract']for q in old})==6
 for name in {p['semantic_contract']for p in old}:
  qs=[p for p in old if p['semantic_contract']==name];assert [p['counterexample_partition']for p in qs]==list(range(1,len(qs)+1))and all(p['counterexample_partitions']==len(qs)and p['result']=='unsat'and p['premises_nonvacuous']for p in qs)
 assert len(a['rechecked_prior_source_proofs'])==14 and all(q['result']=='unsat'for q in a['rechecked_prior_source_proofs'])
 assert [p['mutated_PC']for p in controls]==['0xfffffe000a6650c4','0xfffffe000a660a84','0xfffffe000a656b58']and all(p['normal_oracle_rejected']and not p['native_target_executed']for p in controls)
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for q in e['source']['branch_pointers']:assert int(q['target'],16)==qword(TABLE+8*q['index'])
 for q in e['source']['literal_pointers']:assert int(q['original_pointer']['target'],16)==qword(int(q['slot'],16))
 for q in e['bank_rules']:
  left,right=(bytes.fromhex(e['banks'][q[k]])for k in ['left','right']);assert all(j^right[left[j]^int(q['key'],16)]==int(q['constant'],16)for j in range(256))
 for d,expected in zip(e['retirement_descriptors'],[('site.FPMessage','1122222222222222',0x64,128),('site.FPMessageAttr','',0x6c,112)]):assert(d['name'],d['signature'],d['flags32'],d['size_bytes'])==expected
 assert len(e['prefix_cells'])==30 and all(len(p['source_defined_cells'])==3 and sum(c['size_bytes']for c in p['source_defined_cells'])==16 for p in e['prefix_cells'])
 for calls in a['retirement_interfaces'].values():assert [c['kind']for c in calls]==['message','attribute']and all(not c['native_target_executed']and not c['retired_object_storage_preservation_assumed']for c in calls)
 report=read(BASE/'userclient_message_failure_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**'in report and '| MF-A'+str(j)+':'in report
 for j in range(1,9):assert '| MF'+str(j)+' |'in report
 assert CHECKS_SHA in report and AUDIT_SHA in report and 'ordinary-return premises'in report and 'Fourteen'in report and '126'in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_message_failure_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_message_failure_unwind_established']is True
  for key in R.FALSE:assert obj[key]is False
 for p in OWNED-{q+'.zst'for q in ARCHIVES}:
  if(BASE/p).exists():path_hygiene((BASE/p).read_bytes())
 print(json.dumps({'source_queries_rebuilt':126,'semantic_contracts':6,'prior_queries_rechecked':14,'source_words':413,'source_mutation_controls':3,'input_bytes_supplied':0,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9751 and len(after)==9757 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',126),('prior_source_queries_unsat',14),('negative_source_controls',3)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==658 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':658,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
