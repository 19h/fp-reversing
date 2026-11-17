#!/usr/bin/env python3
"""Rebuild parser-epoch proofs, qualified cuts and exact publication custody.
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
import recover_userclient_message_parser as R
import audit_userclient_message_parser as A
PREVIOUS='1d2722a120f1f1e0a31777c109f61b7429a04be7'
BASELINE_SHA='3ee0a7f552c52dc8f458b28188dd528982022974eaefa8c99674fa8c3f2c7cb2'
CHECKS_SHA='565b2803433729d335ac4535e01be67c5e340e9dd889c3884ce12dc9aee3b6af'
AUDIT_SHA='fbec01eac93c22b1ef2c6ca299ea7a5544e05ff75d0627e6179e16eb920b1ffb'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','userclient_message_initialization_report.md','userclient_fpttlv_entry_report.md','secure_tunnel_allocation_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_message_parser_report.md','triage_evidence/recover_userclient_message_parser.py','triage_evidence/audit_userclient_message_parser.py','triage_evidence/verify_userclient_message_parser_delivery.py','triage_evidence/userclient_message_parser_checks.json','triage_evidence/userclient_message_parser_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_message_parser_checks.json','triage_evidence/userclient_message_parser_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'source_spans':14,'captured_words':436,'bank_rules':11,'certified_bank_inputs':2816,'original_literal_pointers':19,'original_branch_pointers':13,'parent_profiles':2,'container_extent_bytes':16,'input_content_bytes_supplied':0}
TOTALS={'new_source_queries_unsat': 209, 'new_semantic_contracts': 17, 'prior_source_queries_unsat': 217, 'new_source_words_covered': 436, 'lifted_instruction_instances': 1452887, 'composed_header_profiles': 4, 'negative_source_controls': 3, 'new_controller_reads_per_request': 2, 'new_controller_reads_per_return': 4, 'new_certified_bank_applications_per_return': 11, 'native_target_calls': 0, 'input_content_bytes_supplied': 0}
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
 assert len(old)==209 and len({q['semantic_contract']for q in old})==17
 for name in {p['semantic_contract']for p in old}:
  qs=[p for p in old if p['semantic_contract']==name];assert [p['counterexample_partition']for p in qs]==list(range(1,len(qs)+1))and all(p['counterexample_partitions']==len(qs)and p['result']=='unsat'and p['premises_nonvacuous']for p in qs)
 assert len(a['rechecked_prior_source_proofs'])==217 and all(q['result']=='unsat'for q in a['rechecked_prior_source_proofs'])
 assert [p['mutated_PC']for p in controls]==['0xfffffe000a636348','0xfffffe000a660b70','0xfffffe000a661160']and all(p['normal_oracle_rejected']and not p['native_target_executed']for p in controls)
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for q in e['source']['branch_pointers']:assert int(q['target'],16)==qword(TABLE+8*q['index'])
 for q in e['source']['literal_pointers']:assert int(q['original_pointer']['target'],16)==qword(int(q['slot'],16))
 for q in e['bank_rules']:
  left,right=(bytes.fromhex(e['banks'][q[k]])for k in ['left','right']);assert all(j^right[left[j]^int(q['key'],16)]==int(q['constant'],16)for j in range(256))
 d=e['container_descriptor'];assert(d['name'],d['signature'],d['flags32'],d['size_bytes'])==('site.FPTTLV','11',0xe4,16)
 cut=e['completion_cut_premises'];assert not cut['cursor_exhaustion_executed']and cut['input_bytes_supplied']==0 and e['composition_boundary']=='0xfffffe000a654ae4'
 report=read(BASE/'userclient_message_parser_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**'in report and '| MP-A'+str(j)+':'in report
 for j in range(1,11):assert '| MP'+str(j)+' |'in report
 assert CHECKS_SHA in report and AUDIT_SHA in report and 'separate completion cuts'in report and '217'in report and '209'in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_message_parser_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_message_parser_interfaces_established']is True
  for key in R.FALSE:assert obj[key]is False
 for p in OWNED-{q+'.zst'for q in ARCHIVES}:
  if(BASE/p).exists():path_hygiene((BASE/p).read_bytes())
 print(json.dumps({'source_queries_rebuilt':209,'semantic_contracts':17,'prior_queries_rechecked':217,'source_words':436,'source_mutation_controls':3,'input_bytes_supplied':0,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9745 and len(after)==9751 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',209),('prior_source_queries_unsat',217),('negative_source_controls',3)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==657 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':657,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
