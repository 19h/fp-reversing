#!/usr/bin/env python3
"""Seal the reply-ABI increment with six explicitly owned existing changes.
O(prior bytes+links) time; O(manifest+largest JSON) space. No native effects.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['rpc502_reply_bridge_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={'rpc502_reply_bridge_source.json':'recover_rpc502_reply_bridge.py','rpc502_reply_bridge_profiles.json':'probe_rpc502_reply_bridge.py','rpc502_reply_bridge_checks.json':'validate_rpc502_reply_bridge.py'}
SCRIPTS=list(GENS.values())+['seal_rpc502_reply_bridge.py','verify_rpc502_reply_bridge_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'rpc502_reply_bridge_prior_manifest.json';assert sha(prior)=='895a9e47460488b1a0c8a76bbdde9b3f69f16435ee42d80064be7fe0489dc118';m=json.loads(prior.read_text());assert len(m['files'])==5650;unchanged=0;changed=[]
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==5644
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  obj=objects[n];assert obj['generator_sha256']==sha(ROOT/script)
  for d,h in obj['dependencies'].items():assert sha(ROOT/d)==h,(n,d)
 checks=objects['rpc502_reply_bridge_checks.json'];src=objects['rpc502_reply_bridge_source.json'];prof=objects['rpc502_reply_bridge_profiles.json']
 assert checks['all_checks_pass']and checks['source_recapture_match']and len(prof['cases'])==36 and len(prof['declared_transfers'])==7
 assert len(src['spans'])==5 and sum(len(x['instructions'])for x in src['spans'].values())==332 and len(src['exact_instruction_roles'])==14
 assert checks['verified_counts']=={'demux_prefix':1,'daemon_completion':7,'complex_emissions':4,'kext_reply':28,'accepted':7,'simple_errors':3,'outputs_unchanged':21,'destroy_requests':15,'declared_transfers':7}
 assert checks['independent_A64_replay']=={'source_visits_checked':1071,'reads_checked':502,'read_bytes_checked':3349,'writes_checked':337,'write_bytes_checked':2524,'final_boundaries_checked':36,'declared_API_models_checked':21}
 for key in ['native_target_executed','native_IPC_executed','native_application_execution_established','native_descriptor_conversion_established','native_OOL_cleanup_executed','complete_FairPlay_round_trip_established','idb_mutated','full_goal_complete']:assert checks[key]is False
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/n).read_text(),filename=n)
 text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| RP'+str(j)+' |'in text for j in range(1,9))and all('QG'+str(j)+':'in text for j in range(1,8));links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['rpc502_reply_bridge_delivery.json','rpc502_reply_bridge_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5650,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':len(SCRIPTS)+1,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'rpc502_reply_bridge_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original RPC502 response continuation, matching kext parser and six output handoffs. Declared application outputs and transfer; native effects unresolved.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_replay':checks['independent_A64_replay'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in GENS},'native_target_executed':False,'native_IPC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', RP1-RP8, original source capture, independent CPU/byte oracle and prior preservation'}
 (ROOT/'rpc502_reply_bridge_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
