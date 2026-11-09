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
 prior=json.loads((ROOT/'rpc502_ownership_prior_manifest.json').read_text());assert sha(ROOT/'rpc502_ownership_prior_manifest.json')=='6ff969fd46c599a714988f928aed529bd4e5fc63cc9181c671f6f5c7c8748f2b'
 identity=json.loads((ROOT/'rpc502_padding_source_identity.json').read_text());thin=Path(identity['thin_path']);univ=Path(identity['universal_path']);raw=thin.read_bytes();fat=univ.read_bytes();assert sha(thin)==identity['thin_sha256']and sha(univ)==identity['universal_sha256'];assert len(raw)==17668912 and fat[3407872:3407872+len(raw)]==raw
 magic,cpu,subtype,kind,ncmds,sizeofcmds,flags,reserved=struct.unpack_from('<8I',raw);assert magic==0xfeedfacf and cpu==0x100000c and subtype==0x80000002;cursor=32;uid=None
 for _ in range(ncmds):
  cmd,size=struct.unpack_from('<II',raw,cursor);assert size>=8
  if cmd==0x1b:uid=str(uuid.UUID(bytes=raw[cursor+8:cursor+24]))
  cursor+=size
 assert cursor==32+sizeofcmds and uid==identity['thin_uuid']=='204741e9-b89f-32b4-9321-51f3975c7cac'
 src={'scope':'Fresh original thin/universal/header/UUID readback;not live IDB/native process attestation.','generator_sha256':sha(Path(__file__)),'thin_path':str(thin),'thin_sha256':sha(thin),'thin_size_bytes':len(raw),'thin_uuid':uid,'universal_path':str(univ),'universal_sha256':sha(univ),'arm64e_offset_bytes':3407872,'entire_slice_equal':True,'live_IDB_bytes_verified':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_ownership_source_identity.json').write_text(json.dumps(src,indent=2)+'\n')
 checks=json.loads((ROOT/'rpc502_ownership_checks.json').read_text());preservation=json.loads((ROOT/'rpc502_ownership_preservation.json').read_text())
 for obj,producer in[(checks,'audit_rpc502_ownership.py'),(preservation,'validate_rpc502_ownership_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/producer)and obj['all_checks_pass']and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert checks['source_sha256']==sha(thin)and checks['new_worker_executions']==0 and not checks['native_target_executed']and not checks['native_leak_established']
 assert sha(ROOT/'rpc502_error_delivery_replays.json')==checks['fresh_callback_replays_sha256']
 p=json.loads((ROOT/'rpc502_error_delivery_profiles.json').read_text());f=json.loads((ROOT/'rpc502_error_delivery_replays.json').read_text());assert len(p['cases'])==len(f['cases'])==8 and p['cases']==f['cases'];assert p['generator_sha256']==sha(ROOT/'probe_rpc502_error_delivery.py')and f['generator_sha256']==sha(ROOT/'audit_rpc502_ownership.py');assert not p['application_body_executed']and not p['native_target_executed']and not f['native_target_executed']
 from daemon_receive_tools import IMAGE
 for e in p['source_instructions']:assert IMAGE.read(int(e['ea'],16),4).hex()==e['bytes']
 for e in checks['resource_call_site_bytes']:assert IMAGE.read(int(e['address'],16),4).hex()==e['bytes']
 for c in p['cases']:
  assert not c['native_target_executed']and c['stop_reason']=='returned_to_fixture'
  for e in c['events']:
   if e['kind']=='send_request':
    wire=bytes.fromhex(e['wire_hex']);assert len(wire)==36 and struct.unpack_from('<I',wire,20)[0]==602 and struct.unpack_from('<I',wire,32)[0]==0xffff5bd9 and struct.unpack_from('<I',wire,0)[0]&0x80000000==0
 allowed={e['path']:e for e in preservation['allowed_existing_changes']};assert len(prior['files'])==1135 and len(allowed)==6 and preservation['unchanged_prior_artifacts']==1129
 for e in prior['files']:assert sha(BASE/e['path'])==(allowed[e['path']]['current_sha256']if e['path']in allowed else e['sha256']),e['path']
 for e in prior['inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 links=0
 for name in['rpc502_ownership_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   pth=Path(target.split('#',1)[0]);pth=pth if pth.is_absolute()else BASE/pth;assert pth.exists()or pth==ROOT/'rpc502_ownership_quality_gates.json',(name,target);links+=1
 counts=checks['verified_counts'];assert counts['retained_fresh_worker_pairs']==2 and counts['resource_import_edges']==58 and counts['fresh_callback_runs']==8 and counts['send_requests']==6 and counts['request_destroy_requests']==8 and counts['reply_destroy_requests']==4
 evidence=['Factual technical analysis.','O1-O8 assumptions,dependent results and falsification probes.','Complete finite resource ledgers and eight original/fresh callback fixtures;broader interface goal active.','Independent resource arithmetic,byte/u32 extents,event order and complexity.','Mapping epochs,retained/fresh worker reuse versus new callbacks,and composed versus native effects distinguished.','Original source/fixup/journal/packet readback,canonical worker equality and distinct fresh callback replay.','Impact-labeled bounded continuation table.']
 quality={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':counts,'prior_artifacts_checked':1135,'unchanged_prior_artifacts':1129,'inputs_preserved':prior['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in['rpc502_ownership_checks.json','rpc502_ownership_preservation.json','rpc502_error_delivery_profiles.json','rpc502_error_delivery_replays.json']},'source_identity_sha256':sha(ROOT/'rpc502_ownership_source_identity.json'),'new_worker_executions':0,'application_abstracted_in_callback_fixtures':True,'native_target_executed':False,'native_resource_effects_verified':False,'native_leak_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'rpc502_ownership_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_callback_runs':8,'prior_artifacts_checked':1135,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
