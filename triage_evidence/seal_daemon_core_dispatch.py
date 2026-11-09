#!/usr/bin/env python3
"""Seal the bounded operation-dispatch increment and preserve prior artifacts.
O(prior artifact bytes + report links) time, O(manifest + largest JSON) space.
Only six owned existing index/publisher paths may change. No native target use.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_core_dispatch_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['capture_daemon_core_dispatch.py','daemon_core_dispatch_symbolic.py','prove_daemon_core_dispatch.py','validate_daemon_core_dispatch.py','seal_daemon_core_dispatch.py','verify_daemon_core_dispatch_publication.py']
EVIDENCE=['daemon_core_dispatch_source.json','daemon_core_dispatch_symbolic.json','daemon_core_dispatch_proofs.json','daemon_core_dispatch_checks.json']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'daemon_core_dispatch_prior_manifest.json';assert sha(prior)=='c18fcabbd533678c4eef37c5648189c7255f9eefd090695cc2b575109fd01ebf';m=json.loads(prior.read_text());assert len(m['files'])==4856;changed=[];unchanged=0
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==4850
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects=[json.loads((ROOT/n).read_text())for n in EVIDENCE];source,symbolic,proofs,checks=objects
 for obj,script in zip(objects,SCRIPTS[:4],strict=True):
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
 assert source['operation_unread_prefix_source_visits']==447 and source['earlier_operation_reads']==source['earlier_operation_writes']==0 and len(source['known_bytes'])==479
 assert len(symbolic['paths'])==13 and len(symbolic['export_variables'])==3 and len(proofs['proofs'])==14
 meta=proofs['metadata'];assert len(meta['routes'])==7 and meta['default_cardinality']==2734142884 and sum(r['cardinality']for r in meta['routes'])+meta['default_cardinality']==2**32
 assert checks['all_checks_pass']and checks['checkpoint_and_replay_share_Unicorn']and checks['symbolic_dispatch_uses_separate_Z3_scalar_semantics']
 for flag in ['native_import_contents_assigned','native_target_executed','host_API_executed','new_port_emission_established','idb_mutated','full_goal_complete']:assert checks[flag]is False
 assert checks['verified_counts']=={'symbolic_paths':13,'operation_values':33,'fresh_continuous_A64_cases':132,'rebuilt_obligations':14,'accepted_SMT_files':28,'opaque_export_variables':3,'logging_call_bindings_checked':2,'registration_constructor_instructions_checked':4}
 assert checks['independent_A64_totals']['source_visits']==220848 and len(checks['fresh_replay_cases'])==132
 smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert len(smt)==28 and smt=={p.name for p in ROOT.glob('daemon_core_dispatch_*.smt2')}
 for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| CD'+str(j)+' |'in report for j in range(1,11))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['daemon_core_dispatch_delivery.json','daemon_core_dispatch_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':4856,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'accepted_SMT_files':28,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_core_dispatch_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Exact operation partition under captured tag6CF4/private setup context; imported addresses, input/output/call frontiers. Native global-state invariance, admission and downstream epochs unproved.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in EVIDENCE},'native_target_executed':False,'host_API_executed':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'new_port_emission_established':False,'all_native_setup_states_covered':False,'later_emitter_epoch_join_established':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', CD1-CD10, original bytes/fixups, rebuilt SMT, continuous private CPU witnesses and prior artifact preservation'}
 (ROOT/'daemon_core_dispatch_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':4856,'unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
