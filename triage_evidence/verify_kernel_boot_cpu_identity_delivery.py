#!/usr/bin/env python3
"""Fresh original-source contracts, private byte witnesses and publication.
O(owned bytes + source + formula DAG + journals + mapped bytes) construction/
space; SMT search separate. No native execution, IDB or history mutation.
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
import recover_kernel_boot_cpu_identity as R
import audit_kernel_boot_cpu_identity as A
PREVIOUS='a648d82c026755ed7cb0aaf74bfb9f9f43007420'
BASELINE_SHA='2263c0307699d67def1a459526b4c38255f3e36d823bbfbb309cbd9bd72d3e6d'
CHECKS_SHA='0be41bdc2408ffec19951dcf7bd475fd640a35a1633fbffb9625a308fa7c4b81'
AUDIT_SHA='7254143093c9dbbe31972461211b0ac2834973c4c97473d0354cce54ec537ecd'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','foundational_triage_report.md','obfuscated_routines_report.md',
 'interface_investigation_status.md','kernel_boot_header_handoff_report.md','kernel_mapping_context_report.md',
 'kernel_sptm_boot_inputs_report.md','kernel_mapping_transport_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_boot_cpu_identity_report.md','triage_evidence/recover_kernel_boot_cpu_identity.py',
 'triage_evidence/probe_kernel_boot_cpu_identity.py','triage_evidence/replay_kernel_boot_cpu_identity.py',
 'triage_evidence/audit_kernel_boot_cpu_identity.py','triage_evidence/verify_kernel_boot_cpu_identity_delivery.py',
 'triage_evidence/kernel_boot_cpu_identity_checks.json','triage_evidence/kernel_boot_cpu_identity_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_boot_cpu_identity_checks.json','triage_evidence/kernel_boot_cpu_identity_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions':10,'captured_words':2459,'captured_bytes':9836,'matched_prior_functions':4,
 'captured_strings':25,'direct_calls':119,'logical_data_blocks':10,'original_pointer_fixups':3,'opaque_words_preserved':3}
TOTALS={'source_queries_unsat':19,'proved_source_PCs':97,'proof_instruction_instances':97,'linked_edge_obligations':78,
 'components':21,'executed_source_PCs':287,'source_visits':2804,'independent_oracle_checks':954,
 'independent_nonstack_bytes_checked':3522560,'changed_source_controls':4,'original1472_byte_copies':4,'same_RAM_explicit_caller_epochs':4}
REPLAY={'source_visits_checked':2804,'reads_checked':959,'writes_checked':1067,'declared_models_checked':26,
 'logical_effects_checked':99,'same_RAM_epochs_checked':4,'whole_mapped_bytes_checked':3608576}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit();oldproofs,newproofs=a.pop('source_proofs'),fresh.pop('source_proofs');assert len(oldproofs)==len(newproofs)==19
 for x,y in zip(oldproofs,newproofs):
  x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'));assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert e['runtime_boot_pointer_original_zero_and_not_fixup']
 assert [p['target'] for p in e['pointer_fixups']]==list(map(hex,[R.ARRAY,R.CLUSTERS,R.SLOT]))
 assert {r['name'] for r in e['exact_symbols'][hex(R.COPY)]}=={'_memcpy','_memmove'}
 assert all(not names for address,names in e['exact_symbols'].items() if address!=hex(R.COPY))
 assert not {p['PC'] for p in e['opaque_words']}&{p['PC'] for c in a['components'] for p in c['source_visits']}
 report=read(BASE/'kernel_boot_cpu_identity_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| BC'+str(j)+' |' in report and '| BC-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'954 independent','3608576','3522560','0xfffffe000be833ac','0xfffffe000c639dc8','0xfffffe000bc9c80c','0xfffffe000be78164','four complete-RAM']:assert item in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_boot_cpu_identity_report.md' in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_kernel_boot_cpu_identity_contract_established']
  for name in R.FALSE:assert obj[name] is False
 print(json.dumps({'fresh_source_and_audit_match':True,'nonvacuous_queries_rebuilt_and_resolved':19,
  'private_components_rebuilt':21,'independent_semantic_checks':954,'changed_source_controls_rejected':4,
  'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9462 and len(after)==9470 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for name,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('independent_replay_checks',REPLAY),
  ('new_source_queries_unsat',19),('conditional_kernel_boot_cpu_identity_contract_established',True)]:assert new['validation'][R.P+'_'+name]==value
 assert new['validation']['reports']==old['validation']['reports']+1==619
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references'] and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':619,
  'original_inputs_preserved':3,'analyst_paths_absent':True,**COUNTS,**TOTALS,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
