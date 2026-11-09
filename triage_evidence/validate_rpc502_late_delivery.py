#!/usr/bin/env python3
"""Final source/input/report/preservation readback for the late-data increment.

Writes only new source identity and scoped quality records. The separately
owned aggregator refreshes the manifest. O(artifact/source bytes+links) time;
O(largest loaded JSON/report) retained space. No native target/API/IDB action.
"""
import hashlib,json,re,struct,subprocess,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def main():
 identity=json.loads((ROOT/'rpc502_parser_source_identity.json').read_text());thin=Path(identity['thin_path']);univ=Path(identity['universal_path']);raw=thin.read_bytes();fat=univ.read_bytes();assert sha(thin)==identity['thin_sha256']and sha(univ)==identity['universal_sha256'];assert len(raw)==17668912 and fat[3407872:3407872+len(raw)]==raw;magic,cpu,subtype,kind,ncmds,sizeofcmds,flags,reserved=struct.unpack_from('<8I',raw);assert magic==0xfeedfacf and cpu==0x100000c and subtype==0x80000002;cursor=32;actual_uuid=None
 for _ in range(ncmds):
  cmd,size=struct.unpack_from('<II',raw,cursor);assert size>=8
  if cmd==0x1b:actual_uuid=str(uuid.UUID(bytes=raw[cursor+8:cursor+24]))
  cursor+=size
 assert cursor==32+sizeofcmds and actual_uuid==identity['thin_uuid']=='204741e9-b89f-32b4-9321-51f3975c7cac'
 src={'scope':'Fresh original file/slice/header/UUID identity;not live IDB or native process attestation.','generator_sha256':sha(Path(__file__)),'thin_path':str(thin),'thin_sha256':sha(thin),'thin_size_bytes':len(raw),'thin_uuid':actual_uuid,'universal_path':str(univ),'universal_sha256':sha(univ),'arm64e_offset_bytes':3407872,'entire_slice_equal':True,'live_IDB_bytes_verified':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_late_source_identity.json').write_text(json.dumps(src,indent=2)+'\n')
 names=['rpc502_late_checks.json','rpc502_late_signature_checks.json','rpc502_late_reuse_checks.json','rpc502_late_preservation.json'];objects={n:json.loads((ROOT/n).read_text())for n in names};producers=dict(zip(names,['validate_rpc502_late.py','validate_rpc502_late_signature.py','validate_rpc502_late_reuse.py','validate_rpc502_late_preservation.py']))
 for n,o in objects.items():
  assert o['all_checks_pass']and not o['full_goal_complete']and o['generator_sha256']==sha(ROOT/producers[n]),n
  for dep,h in o.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 old=json.loads((ROOT/'rpc502_late_prior_manifest.json').read_text());allowed={e['path']:e for e in objects['rpc502_late_preservation.json']['allowed_existing_changes']};assert len(old['files'])==1081
 for e in old['files']:assert sha(BASE/e['path'])==(allowed[e['path']]['current_sha256']if e['path']in allowed else e['sha256']),e['path']
 for e in old['inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 # Recheck the explicitly bounded source-root filename inventory;no broad scan.
 inventory=json.loads((ROOT/'rpc502_late_sidecar_inventory.json').read_text());r=subprocess.run(inventory['command'],capture_output=True,text=True);assert r.returncode==inventory['exit_code']and r.stdout==inventory['stdout']and r.stderr==inventory['stderr'];assert inventory['matching_paths']==[]
 context=json.loads((ROOT/'rpc502_late_ida_context.json').read_text());assert context['isError']and not context['live_IDB_bytes_verified']and not context['idb_mutated'];links=0
 for name in['rpc502_late_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  content=(BASE/name).read_text()
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',content):
   raw=raw.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',raw)or raw.startswith('#'):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p==ROOT/'rpc502_late_quality_gates.json',(name,raw);links+=1
 a=objects['rpc502_late_checks.json']['verified_counts'];b=objects['rpc502_late_signature_checks.json']['verified_counts'];reuse=objects['rpc502_late_reuse_checks.json']['verified_counts'];assert a['fresh_runs']==6 and b['fresh_runs']==1 and reuse['common_width_gate_uses']==21
 quality={'scope':'Late signed-prefix/signature/public-operation interfaces only;full goal remains active and incomplete.','generator_sha256':sha(Path(__file__)),'QG1':{'status':'pass','evidence':'Factual original-source technical analysis.'},'QG2':{'status':'pass','evidence':'L1-L9 assumptions,dependent results,falsification probes and boundaries.'},'QG3':{'status':'pass_for_increment','evidence':'Exact prefix/hash/signature spans,local width/pointer predicates,80-byte selected ABI,zero/nonzero public outputs and seven fresh complete workers;full goal incomplete.'},'QG4':{'status':'pass','evidence':'u32/u64/signed comparison,byte/bit/limb sizes,two proofs,modular scalar counterexample,SDK compile and complexity explicit.'},'QG5':{'status':'pass','evidence':'Width versus later rejection,zero versus nonzero outputs,partial types and native/trust/padding gaps distinguished.'},'QG6':{'status':'pass','evidence':'Original file/slice/UUID,opcode/fixup/compiler,raw mapping byte,source epoch,independent SHA256/modular exponentiation and fresh replay provenance;live IDB unavailable.'},'QG7':{'status':'pass','evidence':'Impact-labeled bounded continuation table;source-root metadata filename search explicitly bounded.'},'verified_counts':a,'nonzero_verified_counts':b,'reuse_verified_counts':reuse,'prior_artifacts_checked':1081,'unchanged_prior_artifacts':1075,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in names},'source_identity_sha256':sha(ROOT/'rpc502_late_source_identity.json'),'IDA_context_sha256':sha(ROOT/'rpc502_late_ida_context.json'),'sidecar_inventory_sha256':sha(ROOT/'rpc502_late_sidecar_inventory.json'),'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'rpc502_late_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_workers':7,'report_links':links,'prior_artifacts':1081,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
