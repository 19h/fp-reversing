#!/usr/bin/env python3
"""Read-only supplemental delivery gates;write only this increment's gate JSON.

O(total new artifact bytes+report bytes+baseline metadata) time/space,with
streamed hashing of large files. No prior producers/native APIs/IDB mutation.
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
 c=json.loads((ROOT/'rpc502_supp_checks.json').read_text());p=json.loads((ROOT/'rpc502_supp_preservation.json').read_text());contracts=json.loads((ROOT/'rpc502_supp_contracts.json').read_text());assert c['all_checks_pass']and p['all_checks_pass'];assert c['generator_sha256']==sha(ROOT/'validate_rpc502_supp.py')and p['generator_sha256']==sha(ROOT/'validate_rpc502_supp_preservation.py')
 for obj in [c,contracts]:
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,n
 assert p['prior_artifacts_checked']==953 and p['unchanged_prior_artifacts']==947 and len(p['allowed_existing_changes'])==6
 for e in p['allowed_existing_changes']:assert sha(BASE/e['path'])==e['current_sha256'],e['path']
 for e in p['original_inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 body=json.loads((ROOT/'rpc502_supp_bodies_checks.json').read_text());assert body['all_checks_pass']and body['generator_sha256']==sha(ROOT/'validate_rpc502_supp_bodies.py')
 for n,h in body['dependencies'].items():assert sha(ROOT/n)==h,n
 counts=c['verified_counts'];assert counts['cases']==counts['fresh_worker_runs']==348 and counts['core_records']==53 and counts['header_byte_domain']==256 and counts['local_proofs_unsat']==5;assert counts['retained_original_visits']==counts['fresh_original_visits']==13217516
 text=(BASE/'rpc502_supplemental_report.md').read_text();assert 'PENDING'not in text
 for j in range(1,10):assert '| S'+str(j)+' |'in text
 for j in range(1,8):assert '| QG'+str(j)+' |'in text
 links=0
 for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',text):
  raw=raw.strip('<>')
  if re.match(r'^[a-zA-Z][\w+.-]*://',raw)or raw.startswith('#'):continue
  name=raw.split('#',1)[0];target=Path(name)if name.startswith('/')else BASE/name;assert target.exists()or target==ROOT/'rpc502_supp_quality_gates.json',name;links+=1
 # Fresh LC_UUID check,independent of the retained prior identity description.
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e');data=source.read_bytes();assert hashlib.sha256(data).hexdigest()==c['source_sha256'];ncmds=struct.unpack_from('<I',data,16)[0];off=32;uuids=[]
 for _ in range(ncmds):
  cmd,size=struct.unpack_from('<II',data,off);assert size>=8
  if cmd==0x1b:uuids.append(str(uuid.UUID(bytes=data[off+8:off+24])))
  off+=size
 assert uuids==['204741e9-b89f-32b4-9321-51f3975c7cac']
 out={'generator_sha256':sha(Path(__file__)),'scope':'Supplemental-file/internal-carrier increment only;broader interface objective remains active.','source_sha256':c['source_sha256'],'source_uuid_fresh':uuids[0],'QG1':{'status':'pass','evidence':'Descriptive source analysis;no normative premise.'},'QG2':{'status':'pass','evidence':'S1-S9 with dependencies and falsification probes.'},'QG3':{'status':'pass_for_increment','evidence':'Cursor layouts,partial carrier ABI,fallback,ownership and finite failures;full goal incomplete.'},'QG4':{'status':'pass','evidence':'Byte extents,32/64-bit arithmetic,SDK analytical view,modulo bounds and complexity explicit.'},'QG5':{'status':'pass','evidence':'Local proof/fixed-context sweep/native/partial-record and lifetime limits separated.'},'QG6':{'status':'pass','evidence':'Current original thin/universal bytes,LC_UUID,opcodes,fixups,compiler metadata,byte journals,five formulas and all348 fresh original worker replays.'},'QG7':{'status':'pass','evidence':'Impact-labeled source continuation table.'},'verified_counts':counts,'candidate_body_verified_counts':body['verified_counts'],'preserved_prior_artifacts':953,'unchanged_prior_artifacts':947,'allowed_existing_mutations':6,'report_local_links':links,'native_target_executed':False,'target_host_operations_executed':False,'IDB_mutated':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_supp_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');assert (ROOT/'rpc502_supp_quality_gates.json').exists();print(json.dumps({'all_checks_pass':True,'verified_counts':counts}),flush=True)

if __name__=='__main__':main()
