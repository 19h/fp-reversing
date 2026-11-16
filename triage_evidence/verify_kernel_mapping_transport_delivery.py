#!/usr/bin/env python3
"""Fresh mapping/transport receipts and exact owned publication custody.
O(owned bytes + source + query DAG + visits + RAM) construction/space;
SMT search separate. No native transport or historical scan.
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
import recover_kernel_mapping_transport as R
import audit_kernel_mapping_transport as A
PREVIOUS='d6c00cdb11c6b83552be7edea881681c9cca56de'
BASELINE_SHA='1e7f3773db909d132c1448649ff87e82ca562d42f693b3c54751c3b82c7c28af'
CHECKS_SHA='7e06d78a53ee5254a411b7cf20e9286add73c8a08ba0e152f2d9f13cb0f15840'
AUDIT_SHA='f0485639b36f9c23510855c8525b87bfb75034bb98767dda38871760993608aa'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md','foundational_triage_report.md','interface_investigation_status.md',
 'mach_ports_report.md','interface_abi_report.md','kernel_refill_publication_report.md','kernel_physical_zero_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_mapping_transport_report.md','triage_evidence/recover_kernel_mapping_transport.py',
 'triage_evidence/probe_kernel_mapping_transport.py','triage_evidence/replay_kernel_mapping_transport.py',
 'triage_evidence/audit_kernel_mapping_transport.py','triage_evidence/verify_kernel_mapping_transport_delivery.py',
 'triage_evidence/kernel_mapping_transport_checks.json','triage_evidence/kernel_mapping_transport_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_mapping_transport_checks.json','triage_evidence/kernel_mapping_transport_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions':11,'captured_words':2120,'captured_bytes':8480,'undecoded_words_preserved':6,'direct_call_sites':116,'original_diagnostics':8}
TOTALS={'source_queries_unsat':22,'prior_source_queries_rechecked':2,'components':70,'component_source_visits':4422,
 'executed_source_PCs':467,'proved_source_PCs':97,'proof_instruction_instances':97,'linked_edge_obligations':75,
 'independent_oracle_checks':338,'changed_source_controls':3,'descriptor_value_links':18}
REPLAY={'source_visits_checked':4422,'logical_PAC_steps_checked':189,'writes_checked':1116,'write_bytes_checked':7901,
 'reads_checked':1145,'read_bytes_checked':7803,'declared_model_semantic_contracts_checked':44,'declared_API_models_checked':44,
 'final_boundaries_checked':70,'whole_RAM_bytes_checked':73400320,'global_bytes_checked':105186,
 'transport_request_entries_reconstructed':20,'logical_system_reads_checked':13}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,n in [('source_proofs',22),('rechecked_prior_source_proofs',2)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==n
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
   assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert e['context_file_bytes_hex']==bytes(128).hex()
 for address in R.FUNCTIONS:
  rows=e['exact_symbols'][hex(address)]
  assert rows==([{'name':'_sptm_retype','entry':'com.apple.kernel','n_type':15,'n_section':18}] if address==R.WRAPPERS[0] else [])
 assert {d['text'] for d in e['diagnostics']} >= {'pmap.c','invalid mapping type: %d @%s:%d'}
 opaque={r['pc'] for r in e['undecoded_words']}
 assert len(opaque)==6 and not opaque&{v['pc'] for c in a['components'] for v in c['source_visits']}
 report=read(BASE/'kernel_mapping_transport_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| MT'+str(j)+' |' in report and '| MT-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'338 independent','73400320','0xfffffe000c620bd8','0xfffffe000c620be0','0x00201420','0xd4e00000','1048576 B']:assert item in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_mapping_transport_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);nested_hygiene(receipt);assert receipt['conditional_kernel_mapping_transport_contract_established']
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_and_audit_match':True,'source_queries_reconstructed_and_resolved':22,
  'prior_source_queries_rechecked':2,'private_components_rebuilt':70,'changed_source_controls_rejected':3,
  'opaque_transport_words_executed':False,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9430 and len(after)==9438 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('independent_replay_checks',REPLAY),('new_source_queries_unsat',22),('prior_source_queries_rechecked',2),
  ('conditional_kernel_mapping_transport_contract_established',True)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==615
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':615,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
