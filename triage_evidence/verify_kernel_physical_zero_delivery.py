#!/usr/bin/env python3
"""Fresh physical-zero receipts and exact owned publication custody.
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
import recover_kernel_physical_zero as R
import audit_kernel_physical_zero as A

PREVIOUS='9d28ad8d03e8da5b6b08b4f926ae8f05db37bbc1'
BASELINE_SHA='61b07e68c1b7c439a8070bf66df51b9d8ddfe81144f9da29ee6b6d89df5017b4'
CHECKS_SHA='b834c970a2369dab217e58a9fd0f362705734eb64649a75e4b0bfe5cf9061b0e'
AUDIT_SHA='17138aec0731058064e32bbd1f3a22064e0bad62b384e393e9fa0c8920a1da33'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md','foundational_triage_report.md','interface_investigation_status.md',
 'mach_ports_report.md','interface_abi_report.md','kernel_permanent_storage_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_physical_zero_report.md','triage_evidence/recover_kernel_physical_zero.py',
 'triage_evidence/probe_kernel_physical_zero.py','triage_evidence/replay_kernel_physical_zero.py',
 'triage_evidence/audit_kernel_physical_zero.py','triage_evidence/verify_kernel_physical_zero_delivery.py',
 'triage_evidence/kernel_physical_zero_checks.json','triage_evidence/kernel_physical_zero_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_physical_zero_checks.json','triage_evidence/kernel_physical_zero_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions': 6, 'captured_instructions': 1873, 'captured_bytes': 7492, 'matched_prior_functions': 1, 'source_blocks': 9, 'block_instructions': 41, 'sections_rehashed': 725, 'aligned_words_scanned': 15490987, 'direct_zero_branch_sites': 28}
TOTALS={'source_queries_unsat': 10, 'rechecked_separation_lemmas_unsat': 2, 'components': 80, 'component_source_visits': 16254, 'executed_source_PCs': 337, 'proved_source_PCs': 181, 'proof_instruction_instances': 589, 'linked_edge_obligations': 579, 'checked_read_store_rewrites': 0, 'independent_oracle_checks': 425, 'changed_source_controls': 3, 'logical_DC_ZVA_effects': 1157}
REPLAY={'source_visits_checked': 16254, 'logical_PAC_steps_checked': 245, 'writes_checked': 10268, 'write_bytes_checked': 81361, 'reads_checked': 899, 'read_bytes_checked': 7021, 'final_boundaries_checked': 80, 'whole_RAM_bytes_checked': 83886080, 'global_bytes_checked': 393920, 'original_clear_entries_reconstructed': 79, 'declared_model_semantic_contracts_checked': 107, 'declared_API_models_checked': 107, 'logical_DC_ZVA_steps_checked': 1157, 'logical_DC_bytes_checked': 74048}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,n in [('source_proofs',10),('rechecked_separation_lemmas',2)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==n
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
   assert x==y and x.get('premises_nonvacuous',True) and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for address in R.FUNCTIONS[:4]:assert not e['exact_symbols'][hex(address)]
 for address,names in [(R.ATTR,['_pmap_cache_attributes']),(R.BZERO,['___bzero','_bzero']),(R.MEMSET,['_memset'])]:
  rows=e['exact_symbols'][hex(address)];assert sorted(r['name'] for r in rows)==sorted(names)
  assert all(r['entry']=='com.apple.kernel' and r['n_type']==15 and r['n_section']==(18 if address==R.ATTR else 19) for r in rows)
 report=read(BASE/'kernel_physical_zero_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report
 for j in range(1,7):assert '| PZ'+str(j)+' |' in report and '| PZ-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'425 independent','256','16483','64 B logical','allocation-to-zero identity','28 direct']:assert item in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_physical_zero_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);nested_hygiene(receipt);assert receipt['conditional_kernel_physical_zero_contract_established']
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_and_audit_match':True,'source_queries_reconstructed_and_resolved':10,
  'separation_lemmas_rechecked':2,'private_components_rebuilt':80,'changed_source_controls_rejected':3,
  'logical_DC_steps_replayed':1157,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9414 and len(after)==9422 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('independent_replay_checks',REPLAY),('new_source_queries_unsat',10),
  ('rechecked_separation_lemmas_unsat',2),('conditional_kernel_physical_zero_contract_established',True)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==613
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':613,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
