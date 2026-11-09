#!/usr/bin/env python3
"""Seal the bounded operation-dispatch increment and preserve prior artifacts.
O(prior artifact bytes + report links) time, O(manifest + largest JSON) space.
Only six owned existing index/publisher paths may change. No native target use.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_operation_heads_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['capture_daemon_operation_heads.py','daemon_operation_heads_symbolic.py','prove_daemon_operation_heads.py','validate_daemon_operation_heads.py','seal_daemon_operation_heads.py','verify_daemon_operation_heads_publication.py']
EVIDENCE=['daemon_operation_heads_source.json','daemon_operation_heads_symbolic.json','daemon_operation_heads_proofs.json','daemon_operation_heads_checks.json']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'daemon_operation_heads_prior_manifest.json';assert sha(prior)=='09f356727f11e2cf2c4f2d58c0168fc7d438a2972e3e413de1461b077c50b032';m=json.loads(prior.read_text());assert len(m['files'])==4898;changed=[];unchanged=0
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==4892
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects=[json.loads((ROOT/n).read_text())for n in EVIDENCE];source,symbolic,proofs,checks=objects
 for obj,script in zip(objects,SCRIPTS[:4],strict=True):
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
 assert len(source['handlers'])==4 and source['function_starts_source']['entry_count']==1005
 assert source['text_census']['aligned_pairs_checked']==3712489
 constructors=[c for h in source['handlers']for c in h['literal_candidates']if 'record_constructor'in c]
 links=[m for c in constructors for m in c['MIG_links']]
 assert len(constructors)==7 and len(links)==6 and {m['request_ID']for m in links}=={1000,1001,1002,1200,1201,1202}
 for link in links:
  word=int.from_bytes(bytes.fromhex(link['original_descriptor_word_hex']),'little');assert word>>63==1 and(word>>62)&1==0 and(word&0xffffffff)+0x100000000==int(link['stub'],16)
 assert len(symbolic['cases'])==5 and len(proofs['proofs'])==28 and len(proofs['full_FP_domain_probes'])==7
 assert sum(r['result']=='sat'for r in proofs['full_FP_domain_probes'])==6
 assert checks['all_checks_pass']and checks['symbolic_heads_use_Z3_scalar_semantics']and checks['CPU_replay_uses_Unicorn']
 for flag in ['native_target_executed','host_API_executed','new_port_emission_established','idb_mutated','native_input_extent_known','upstream_nested_phase_proved','later_auxiliary_epoch_join_proved','full_goal_complete']:assert checks[flag]is False
 assert checks['verified_counts']=={'operation_heads':4,'symbolic_classes':5,'MIG_wrapper_constructor_links':6,'source_constructor_sites':7,'source_constructor_projection_instructions':129,'source_obligations_rebuilt':28,'accepted_SMT_files':56,'full_FP_domain_probe_files':7,'rejected_full_FP_counterexamples_replayed':6,'constructor_store_cases':56,'constructor_A64_instructions':1205,'fresh_continuous_A64_cases':40}
 assert checks['independent_A64_totals']['source_visits']==68888 and len(checks['fresh_replay_cases'])==40
 smt={r[k]for r in proofs['proofs']for k in ['file','original_file']}|{r['file']for r in proofs['full_FP_domain_probes']};assert len(smt)==63 and smt=={p.name for p in ROOT.glob('daemon_operation_heads_*.smt2')}
 for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 for r in proofs['full_FP_domain_probes']:assert r['result']in ['sat','unsat']and sha(ROOT/r['file'])==r['sha256']
 for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| OH'+str(j)+' |'in report for j in range(1,11))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['daemon_operation_heads_delivery.json','daemon_operation_heads_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':4898,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'accepted_SMT_files':56,'full_FP_domain_probe_files':7,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_operation_heads_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Six MIG constructor links, four borrowed-record heads, source-local codec composition and three overwritten frame slots. Native admission, ownership, nested incoming phase and later driver epochs unproved.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in EVIDENCE},'native_target_executed':False,'host_API_executed':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'new_port_emission_established':False,'all_native_setup_states_covered':False,'later_emitter_epoch_join_established':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', OH1-OH10, original bytes/fixups, rebuilt SMT, continuous private CPU witnesses and prior artifact preservation'}
 (ROOT/'daemon_operation_heads_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':4898,'unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
