#!/usr/bin/env python3
"""Final source, dependency, packet, preservation and link readback.

Only new ownership-increment identity/quality records are written.
O(total source/artifact bytes+links) work, O(largest artifact) working space.
No native target/API/IDB action; complete interface goal remains active.
"""
import hashlib,json,re,struct,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def main():
 prior=json.loads((ROOT/'rpc502_cleanup_prior_manifest.json').read_text());assert sha(ROOT/'rpc502_cleanup_prior_manifest.json')=='a414f8110273af3cae35da752be0e4490db75d6a84402991026550c5f0fa290e'
 identity=json.loads((ROOT/'rpc502_ownership_source_identity.json').read_text());thin=Path(identity['thin_path']);univ=Path(identity['universal_path']);raw=thin.read_bytes();fat=univ.read_bytes();assert sha(thin)==identity['thin_sha256']and sha(univ)==identity['universal_sha256'];assert len(raw)==17668912 and fat[3407872:3407872+len(raw)]==raw
 magic,cpu,subtype,kind,ncmds,sizeofcmds,flags,reserved=struct.unpack_from('<8I',raw);assert magic==0xfeedfacf and cpu==0x100000c and subtype==0x80000002;cursor=32;uid=None
 for _ in range(ncmds):
  cmd,size=struct.unpack_from('<II',raw,cursor);assert size>=8
  if cmd==0x1b:uid=str(uuid.UUID(bytes=raw[cursor+8:cursor+24]))
  cursor+=size
 assert cursor==32+sizeofcmds and uid==identity['thin_uuid']=='204741e9-b89f-32b4-9321-51f3975c7cac'
 src={'scope':'Fresh original thin/universal/header/UUID readback;not live IDB/native process attestation.','generator_sha256':sha(Path(__file__)),'thin_path':str(thin),'thin_sha256':sha(thin),'thin_size_bytes':len(raw),'thin_uuid':uid,'universal_path':str(univ),'universal_sha256':sha(univ),'arm64e_offset_bytes':3407872,'entire_slice_equal':True,'live_IDB_bytes_verified':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_cleanup_source_identity.json').write_text(json.dumps(src,indent=2)+'\n')
 checks=json.loads((ROOT/'rpc502_cleanup_checks.json').read_text());preservation=json.loads((ROOT/'rpc502_cleanup_preservation.json').read_text())
 for obj,producer in[(checks,'validate_rpc502_cleanup.py'),(preservation,'validate_rpc502_cleanup_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/producer)and obj['all_checks_pass']and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert checks['source_sha256']==sha(thin)and checks['new_whole_worker_executions']==0 and not checks['native_target_executed']and not checks['full_mapping_lifetime_proved']
 assert sha(ROOT/'rpc502_cleanup_replays.json')==checks['fresh_replays_sha256'];p=json.loads((ROOT/'rpc502_cleanup_profiles.json').read_text());f=json.loads((ROOT/'rpc502_cleanup_replays.json').read_text());c=json.loads((ROOT/'rpc502_cleanup_contracts.json').read_text());assert len(p['cases'])==len(f['cases'])==24 and p['cases']==f['cases'];assert p['generator_sha256']==sha(ROOT/'probe_rpc502_cleanup.py')and f['generator_sha256']==sha(ROOT/'validate_rpc502_cleanup.py')and c['generator_sha256']==sha(ROOT/'recover_rpc502_cleanup.py');assert not p['native_target_executed']and not f['native_target_executed']and not c['native_target_executed']
 from daemon_receive_tools import IMAGE
 for e in p['source_instructions']:assert IMAGE.read(int(e['ea'],16),4).hex()==e['bytes']
 for row in p['cases']:
  assert not row['native_target_executed']and not row['full_worker_executed']and row['stop_reason']=='returned_to_fixture';assert row['source_record_stores']==[{'pc':'0x1001f19cc','address':'0x5a00000000','size_bytes':4,'after_hex':'ffffffff'}]
 allowed={e['path']:e for e in preservation['allowed_existing_changes']};assert len(prior['files'])==1147 and len(allowed)==6 and preservation['unchanged_prior_artifacts']==1141
 for e in prior['files']:assert sha(BASE/e['path'])==(allowed[e['path']]['current_sha256']if e['path']in allowed else e['sha256']),e['path']
 for e in prior['inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 links=0
 for name in['rpc502_cleanup_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   pth=Path(target.split('#',1)[0]);pth=pth if pth.is_absolute()else BASE/pth;assert pth.exists()or pth==ROOT/'rpc502_cleanup_quality_gates.json',(name,target);links+=1
 counts=checks['verified_counts'];assert counts['proofs_unsat']==5 and counts['fresh_helper_runs']==24 and counts['source_built_cleanup_calls']==4 and counts['descriptor_invalidations']==24 and counts['alignment_counterexamples']==1
 evidence=['Factual technical analysis.','C1-C8 assumptions,dependent results and falsification probes.','Source-built argument/mode/index contracts and24 retained/fresh helpers;full interface goal remains active.','Byte/u32/u64 domains,alignment,record extents,formulas and complexity.','Close-only versus unmap/close,descriptor invalidation versus resource retirement,local helper versus whole worker/native effects distinguished.','Original source/fixups,ordered caller journals,fresh local SMT queries and distinct fresh helper replays.','Impact-labeled bounded continuation table.']
 quality={'scope':'Shared cleanup helper/constructor ABI only;complete native mapping lifetime and broad interface goal remain unresolved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':counts,'prior_artifacts_checked':1147,'unchanged_prior_artifacts':1141,'inputs_preserved':prior['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in['rpc502_cleanup_checks.json','rpc502_cleanup_preservation.json','rpc502_cleanup_profiles.json','rpc502_cleanup_replays.json','rpc502_cleanup_contracts.json']},'source_identity_sha256':sha(ROOT/'rpc502_cleanup_source_identity.json'),'new_whole_worker_executions':0,'native_target_executed':False,'native_resource_effects_verified':False,'full_mapping_lifetime_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'rpc502_cleanup_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_helper_runs':24,'proofs_unsat':5,'prior_artifacts_checked':1147,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
