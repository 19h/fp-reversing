#!/usr/bin/env python3
"""Rebuild kernel retirement magazine obligations and verify exact publication custody.
O(owned bytes+query DAG) wrapper time/space; separate SMT search.
No target calls, IDB mutations or history rewrite.
"""
import json
import re
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_kernel_retirement_magazines as R
import audit_kernel_retirement_magazines as A

PREVIOUS='40e998a24310bf8ec3fec673414b156bd5457f60'
BASELINE_SHA='adda585ad03649d941f11c6a67c09b87fc0c8b3970b82acd431a46a6ef90db28'
CHECKS_SHA='23222833dc8d0af1cf2ace9c02a13cd2c2eaea204b11e3fef72a8062137514bb'
AUDIT_SHA='620ace6bb019692829a4d497f5f897d98bb83126ea5ee378aec044a16a8f6157'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md','foundational_triage_report.md','interface_investigation_status.md',
 'mach_ports_report.md','interface_abi_report.md','kernel_allocator_boundary_report.md','kernel_retirement_query_report.md',
 'kernel_retirement_dispatch_report.md','mixed_data_retirement_report.md','kernel_zone_retirement_report.md',
 'kernel_zone_refill_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_retirement_magazines_report.md','triage_evidence/recover_kernel_retirement_magazines.py',
 'triage_evidence/audit_kernel_retirement_magazines.py','triage_evidence/probe_kernel_retirement_magazines.py',
 'triage_evidence/verify_kernel_retirement_magazines_delivery.py','triage_evidence/kernel_retirement_magazines_checks.json',
 'triage_evidence/kernel_retirement_magazines_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_retirement_magazines_checks.json','triage_evidence/kernel_retirement_magazines_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'complete_helper_instructions': 350, 'complete_helper_bytes': 1400, 'source_blocks': 16, 'block_instructions': 79, 'call_sites': 14, 'call_targets': 8, 'original_function_matches': 2}
TOTALS={'source_queries_unsat': 19, 'composition_queries_unsat': 2, 'separation_lemmas_unsat': 2, 'checked_separation_instantiations': 5, 'prior_queries_unsat': 4, 'source_block_PCs': 79, 'proof_instruction_instances': 96, 'linked_edge_obligations': 77, 'checked_read_store_rewrites': 1392, 'CFG_source_nodes': 350, 'CFG_edges': 392, 'CFG_abstract_states': 366, 'components': 27, 'returning_components': 25, 'deeper_release_requests': 2, 'component_source_visits': 5186, 'component_distinct_helper_PCs': 347, 'independent_oracle_checks': 653, 'changed_source_CFG_controls': 2}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit();old,new=a.pop('source_proofs'),fresh.pop('source_proofs')
 compositions,new_compositions=a.pop('composition_proofs'),fresh.pop('composition_proofs')
 separations,new_separations=a.pop('separation_lemmas'),fresh.pop('separation_lemmas')
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert len(old)==len(new)==19 and len(compositions)==len(new_compositions)==2 and len(separations)==len(new_separations)==2
 for x,y in [*zip(old,new),*zip(compositions,new_compositions),*zip(separations,new_separations)]:
  x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
  assert x==y and x.get('premises_nonvacuous',True) and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  # A.audit() has just solved the freshly reconstructed obligations.
  # Canonical equivalence binds those results to the retained formulas.
 a['source_proofs']=old;a['composition_proofs']=compositions;a['separation_lemmas']=separations
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 report=read(BASE/'kernel_retirement_magazines_report.md')
 for j in range(1,8):
  assert '| RM'+str(j)+' |' in report and '| RM-A'+str(j)+':' in report and '**QG'+str(j)+'**' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000bd75180','0xfffffe000bd753d8','350','392','366','RM-A7','0xa5a5a5a5a5a5a5a5']:assert word in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_retirement_magazines_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_kernel_retirement_magazines_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':19,'composition_queries_reconstructed_and_resolved':2,'separation_lemmas_reconstructed_and_resolved':2,
  'prior_source_queries_rechecked':4,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9342 and len(after)==9349 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',19),('new_composition_queries_unsat',2),('separation_lemmas_unsat',2),('prior_source_queries_rechecked',4),('conditional_kernel_retirement_magazines_contract_established',True)]:
  assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==603
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':603,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
