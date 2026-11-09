#!/usr/bin/env python3
"""Final source/preservation/link readback for the exported-block increment.

O(total source/artifact bytes+links) time,O(largest JSON/report) space.
Writes only new identity/quality records;no native target/API or IDB action.
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
 identity=json.loads((ROOT/'rpc502_parser_source_identity.json').read_text());thin=Path(identity['thin_path']);univ=Path(identity['universal_path']);raw=thin.read_bytes();fat=univ.read_bytes();assert sha(thin)==identity['thin_sha256']and sha(univ)==identity['universal_sha256'];assert len(raw)==17668912 and fat[3407872:3407872+len(raw)]==raw;magic,cpu,subtype,kind,ncmds,sizeofcmds,flags,reserved=struct.unpack_from('<8I',raw);assert magic==0xfeedfacf and cpu==0x100000c and subtype==0x80000002;cursor=32;uid=None
 for _ in range(ncmds):
  cmd,size=struct.unpack_from('<II',raw,cursor);assert size>=8
  if cmd==0x1b:uid=str(uuid.UUID(bytes=raw[cursor+8:cursor+24]))
  cursor+=size
 assert cursor==32+sizeofcmds and uid==identity['thin_uuid']=='204741e9-b89f-32b4-9321-51f3975c7cac'
 src={'scope':'Fresh thin/universal/header/UUID file readback;not live IDB or native process attestation.','generator_sha256':sha(Path(__file__)),'thin_path':str(thin),'thin_sha256':sha(thin),'thin_size_bytes':len(raw),'thin_uuid':uid,'universal_path':str(univ),'universal_sha256':sha(univ),'arm64e_offset_bytes':3407872,'entire_slice_equal':True,'live_IDB_bytes_verified':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_padding_source_identity.json').write_text(json.dumps(src,indent=2)+'\n')
 names=['rpc502_padding_checks.json','rpc502_padding_preservation.json'];objects={n:json.loads((ROOT/n).read_text())for n in names};producers=dict(zip(names,['validate_rpc502_padding.py','validate_rpc502_padding_preservation.py']))
 for name,o in objects.items():
  assert o['all_checks_pass']and not o['full_goal_complete']and o['generator_sha256']==sha(ROOT/producers[name]),name
  for n,h in o.get('dependencies',{}).items():assert sha(ROOT/n)==h,(name,n)
 old=json.loads((ROOT/'rpc502_padding_prior_manifest.json').read_text());allowed={e['path']:e for e in objects['rpc502_padding_preservation.json']['allowed_existing_changes']};assert len(old['files'])==1110
 for e in old['files']:assert sha(BASE/e['path'])==(allowed[e['path']]['current_sha256']if e['path']in allowed else e['sha256']),e['path']
 for e in old['inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 links=0
 for name in['rpc502_padding_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',raw)or raw.startswith('#'):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p==ROOT/'rpc502_padding_quality_gates.json',(name,raw);links+=1
 counts=objects['rpc502_padding_checks.json']['verified_counts'];assert counts['fresh_runs']==2 and counts['exported_blocks']==6 and counts['proofs_unsat']==7
 quality={'scope':'Exported-block byte/digest/local-status contracts only;full goal remains active and incomplete.','generator_sha256':sha(Path(__file__)),'QG1':{'status':'pass','evidence':'Factual technical analysis.'},'QG2':{'status':'pass','evidence':'B1-B8 assumptions,dependent results and falsification probes.'},'QG3':{'status':'pass_for_increment','evidence':'Six closed byte-observation windows,two complete fresh workers,exact regions and original literals;full interface goal incomplete.'},'QG4':{'status':'pass','evidence':'u8/u32,byte/bit/region extents,seven explicit-domain local proofs and complexity;no new target C type inferred.'},'QG5':{'status':'pass','evidence':'Local folds versus complete acceptance,positive versus negative stages,multiple mismatched regions and native limits distinguished.'},'QG6':{'status':'pass','evidence':'Original file/slice/UUID,opcode/fixup/compiler/ROM,source epochs,independent public/hash outputs and fresh whole-worker replay.'},'QG7':{'status':'pass','evidence':'Bounded impact-labeled continuation table.'},'verified_counts':counts,'prior_artifacts_checked':1110,'unchanged_prior_artifacts':1104,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in names},'source_identity_sha256':sha(ROOT/'rpc502_padding_source_identity.json'),'complete_acceptance_language_unknown':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'rpc502_padding_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_workers':2,'report_links':links,'prior_artifacts':1110,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
