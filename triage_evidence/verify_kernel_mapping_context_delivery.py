#!/usr/bin/env python3
"""Fresh initialization contracts, private state joins and owned publication.
O(owned bytes + source + query DAG + visits + RAM) construction/space;
solver search separate. No native transport, history rewrite or IDB mutation.
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
import recover_kernel_mapping_context as R
import audit_kernel_mapping_context as A
PREVIOUS='0692a04b917e8ab550c3ce7e9ea3c8b5f60c02d0'
BASELINE_SHA='de484a784966ddc37ce8c706499f370f38cc5e4ceaf3678c571b4ceffa5cdc8e'
CHECKS_SHA='f781001a80ec324375b7a2b2b083a98cc7db484f4b6795db264f7977dd6caba2'
AUDIT_SHA='2115d8cd2fb82edc3a7466a41a2d35c40728c5089399c5deed63f693ddbc9a03'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md','foundational_triage_report.md','interface_investigation_status.md',
 'mach_ports_report.md','interface_abi_report.md','kernel_mapping_transport_report.md','kernel_zone_boot_inputs_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_mapping_context_report.md','triage_evidence/recover_kernel_mapping_context.py',
 'triage_evidence/probe_kernel_mapping_context.py','triage_evidence/replay_kernel_mapping_context.py',
 'triage_evidence/audit_kernel_mapping_context.py','triage_evidence/verify_kernel_mapping_context_delivery.py',
 'triage_evidence/kernel_mapping_context_checks.json','triage_evidence/kernel_mapping_context_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_mapping_context_checks.json','triage_evidence/kernel_mapping_context_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions':15,'captured_words':3826,'captured_bytes':15304,'matched_prior_functions':9,
 'undecoded_words_preserved':4,'geometry_rows':4,'geometry_fixups':2,'direct_call_scan_sections':3,
 'aligned_branch_words_scanned':2558561,'initializer_call_sites':2}
TOTALS={'source_queries_unsat':23,'prior_source_queries_rechecked':2,'configurations':10,'components':42,
 'component_source_visits':19585,'executed_source_PCs':715,'proved_source_PCs':102,'proof_instruction_instances':102,
 'linked_edge_obligations':79,'independent_oracle_checks':216,'changed_source_controls':3,'exact_state_joins':32,
 'complete_five_component_chains':7}
REPLAY={'source_visits_checked':19585,'reads_checked':1849,'read_bytes_checked':12560,'writes_checked':1572,
 'write_bytes_checked':11546,'final_boundaries_checked':42,'whole_RAM_bytes_checked':44040192,
 'global_bytes_checked':2078623,'transport_entries_reconstructed':21,'original_clear_entries_reconstructed':10,
 'original_conversion_entries_reconstructed':73,'logical_PAC_steps_checked':172,
 'declared_model_semantic_contracts_checked':95,'declared_API_models_checked':95,'logical_DC_ZVA_steps_checked':2540}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,n in [('source_proofs',23),('rechecked_prior_source_proofs',2)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==n
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
   assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert e['file_initial_state']=={'context128_hex':bytes(128).hex(),'CPU_blocks49152_zero':True,'root_pair16_hex':bytes(16).hex()}
 assert e['exact_symbols'][hex(R.Z.BZERO)]==[{'name':name,'entry':'com.apple.kernel','n_type':15,'n_section':19} for name in ['___bzero','_bzero']]
 assert all(not rows for address,rows in e['exact_symbols'].items() if address!=hex(R.Z.BZERO))
 assert {d['text'] for d in e['diagnostics']} >= {'pmap','pmap_bootstrap','kvtophys_nofail','pmap_asid_plru'}
 opaque={r['pc'] for r in e['undecoded_words']};assert len(opaque)==4 and not opaque&{v['pc'] for c in a['components'] for v in c['source_visits']}
 assert e['geometry']['rows'][3]['u64_fields']==['0x4000','0x3fff','0xe','0x1ffc000','0x3','0x2','0x2']
 report=read(BASE/'kernel_mapping_context_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| MC'+str(j)+' |' in report and '| MC-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'216 independent','44040192','0xfffffe000c6211f0','0xfffffe000c621234',
  '0x0460000000400403','0x123400000001','0x00201420','0xd4e00000','N=0','32 exact state joins']:assert item in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_mapping_context_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);nested_hygiene(receipt);assert receipt['conditional_kernel_mapping_context_contract_established']
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_and_audit_match':True,'source_queries_reconstructed_and_resolved':23,
  'prior_source_queries_rechecked':2,'private_components_rebuilt':42,'exact_state_joins_checked':32,
  'changed_source_controls_rejected':3,'opaque_transport_words_executed':False,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9438 and len(after)==9446 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('independent_replay_checks',REPLAY),('new_source_queries_unsat',23),('prior_source_queries_rechecked',2),
  ('conditional_kernel_mapping_context_contract_established',True)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==616
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':616,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
