#!/usr/bin/env python3
"""Fresh refill-publication receipts and exact owned publication custody.
O(owned bytes + source + query DAG + visits + RAM) construction/space;
SMT search separate. No native physical mappings or history scan.
"""
import json,re
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
import recover_kernel_refill_publication as R
import audit_kernel_refill_publication as A

PREVIOUS='3fbb30436dcf82d45bcbad380c7726361ed0fc03'
BASELINE_SHA='402876ad0e3783c019f7505ac2e8c3c286cec60391e8623c970ad26d835ede5e'
CHECKS_SHA='29b3379693daa4bbe4d6c0d82f3e1ead4f58edb2eeb5ff123ea1de50d81da73f'
AUDIT_SHA='3d217a84d328af55b8532bd150d01c401e23ab529894b8031037f2e8d6c8150a'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md','foundational_triage_report.md','interface_investigation_status.md',
 'mach_ports_report.md','interface_abi_report.md','kernel_permanent_storage_report.md','kernel_physical_zero_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_refill_publication_report.md','triage_evidence/recover_kernel_refill_publication.py',
 'triage_evidence/probe_kernel_refill_publication.py','triage_evidence/replay_kernel_refill_publication.py',
 'triage_evidence/audit_kernel_refill_publication.py','triage_evidence/verify_kernel_refill_publication_delivery.py',
 'triage_evidence/kernel_refill_publication_checks.json','triage_evidence/kernel_refill_publication_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_refill_publication_checks.json','triage_evidence/kernel_refill_publication_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions': 11, 'captured_instructions': 3720, 'captured_bytes': 14880, 'matched_prior_functions': 7, 'source_blocks': 16, 'block_instructions': 92}
TOTALS={'source_queries_unsat': 18, 'prior_source_queries_rechecked': 10, 'rechecked_separation_lemmas_unsat': 2, 'components': 15, 'continuous_refill_components': 9, 'consumer_epoch_pairs': 3, 'component_source_visits': 37461, 'executed_captured_source_PCs': 845, 'all_executed_source_PCs': 845, 'proved_source_PCs': 97, 'proof_instruction_instances': 97, 'linked_edge_obligations': 79, 'checked_read_store_rewrites': 0, 'independent_oracle_checks': 129, 'changed_source_controls': 3, 'zero_to_mapping_request_links': 18}
REPLAY={'source_visits_checked': 37461, 'declared_model_semantic_contracts_checked': 183, 'declared_API_models_checked': 183, 'writes_checked': 36177, 'write_bytes_checked': 287850, 'reads_checked': 1659, 'read_bytes_checked': 10639, 'logical_PAC_steps_checked': 180, 'final_boundaries_checked': 15, 'whole_RAM_bytes_checked': 15728640, 'global_bytes_checked': 751500, 'original_publication_entries_reconstructed': 61, 'original_clear_entries_reconstructed': 17, 'permanent_events_reconstructed_and_checked': 12, 'logical_envelopes_checked': 3}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,n in [('source_proofs',18),('rechecked_prior_source_proofs',10),('rechecked_separation_lemmas',2)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==n
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
   assert x==y and x.get('premises_nonvacuous',True) and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for address in R.FUNCTIONS:
  if address!=R.Z.MEMSET:assert not e['exact_symbols'][hex(address)]
 rows=e['exact_symbols'][hex(R.Z.MEMSET)]
 assert rows==[{'name':'_memset','entry':'com.apple.kernel','n_type':15,'n_section':19}]
 report=read(BASE/'kernel_refill_publication_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report
 for j in range(1,8):assert '| RP'+str(j)+' |' in report and '| RP-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'129 independent','0xf8001f40','0xf402','0xe402','18 exact','37461','0x40']:assert item in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_refill_publication_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);nested_hygiene(receipt);assert receipt['conditional_kernel_refill_publication_contract_established']
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_and_audit_match':True,'source_queries_reconstructed_and_resolved':18,'prior_source_queries_rechecked':10,
  'separation_lemmas_rechecked':2,'private_components_rebuilt':15,'changed_source_controls_rejected':3,
  'zero_to_mapping_request_links_checked':18,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9422 and len(after)==9430 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('independent_replay_checks',REPLAY),('new_source_queries_unsat',18),('prior_source_queries_rechecked',10),
  ('rechecked_separation_lemmas_unsat',2),('conditional_kernel_refill_publication_contract_established',True)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==614
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':614,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
