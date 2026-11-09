#!/usr/bin/env python3
"""Final source/input/preservation/link/quality checks for this increment.

O(total artifact bytes+profiles+reports) time,streamed hashes and bounded JSON
space. Writes only the new quality-gate record;no old producers/native APIs.
"""
import base64,hashlib,json,re,struct,uuid,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()

def main():
 check=json.loads((ROOT/'rpc502_certificate_checks.json').read_text());contract=json.loads((ROOT/'rpc502_certificate_contracts.json').read_text());prior=json.loads((ROOT/'rpc502_certificate_preservation.json').read_text());assert check['all_checks_pass']and prior['all_checks_pass'];assert check['generator_sha256']==sha(ROOT/'validate_rpc502_certificate.py');assert contract['generator_sha256']==sha(ROOT/'recover_rpc502_certificate.py');assert prior['generator_sha256']==sha(ROOT/'validate_rpc502_certificate_preservation.py')
 for obj in[check,contract]:
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,n
 assert prior['prior_artifacts_checked']==977 and prior['unchanged_prior_artifacts']==971 and len(prior['allowed_existing_changes'])==6
 for e in prior['allowed_existing_changes']:assert sha(BASE/e['path'])==e['current_sha256'],e['path']
 for e in prior['original_inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 counts=check['verified_counts'];assert counts['fresh_worker_runs']==counts['cases']==44 and counts['assertions']==5931245 and counts['digest_oracles']==43 and counts['SHA1_outputs']==42 and counts['MD5_outputs']==1 and counts['CASAL_executions']==9 and counts['local_proofs_unsat']==6
 witness=contract['unaligned_counterexample'];p=int(witness['pointer32'],16);mask=0xffffffff;caller=((((2*(p&0x26d01f50)-p+0xd92fe0a8)&mask)^0x3e1d32ca)*0xba209ef7)&mask;callee=((p^0xe732d262)*0xba209ef7)&mask;assert p&7 and caller!=callee and hex(caller)==witness['caller_key']and hex(callee)==witness['callee_key']
 profiles=json.loads((ROOT/'rpc502_certificate_profiles.json').read_text());restorations=0
 for w in profiles['cases']:
  r=json.loads(zlib.decompress(base64.b64decode(w['payload_zlib_base64'])))
  assert all(not(e['offset_bytes']<32 and e['offset_bytes']+e['size_bytes']>28)for e in r['core_argument_reads'])
  if len(r['atomic_points'])!=2:continue
  events=[e for e in r['image_writes']if e['address']=='0x1010b5de0'];assert events==[{'pc':'0x100a04c58','address':'0x1010b5de0','size':4,'value':'0xa94ef'},{'pc':'0x1009757d0','address':'0x1010b5de0','size':4,'value':'0x5d96'}];restorations+=1
 assert restorations==9
 thin=Path('/Users/___/Downloads/zut/fairplayd.arm64e').read_bytes();univ=Path('/Users/___/Downloads/fpx/fairplayd').read_bytes();assert hashlib.sha256(thin).hexdigest()==check['source_sha256'];assert hashlib.sha256(univ).hexdigest()=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and univ[3407872:3407872+len(thin)]==thin
 off=32;ids=[]
 for _ in range(struct.unpack_from('<I',thin,16)[0]):
  cmd,n=struct.unpack_from('<II',thin,off)
  if cmd==0x1b:ids.append(str(uuid.UUID(bytes=thin[off+8:off+24])))
  off+=n
 assert ids==['204741e9-b89f-32b4-9321-51f3975c7cac']
 report=(BASE/'rpc502_certificate_report.md').read_text();assert 'PENDING'not in report
 for j in range(1,11):assert '| C'+str(j)+' |'in report
 for j in range(1,8):assert '| QG'+str(j)+' |'in report
 links=0
 for name in re.findall(r'\[[^\]]*\]\(([^)]+)\)',report):
  name=name.strip('<>')
  if re.match(r'^[a-zA-Z][\w+.-]*://',name)or name.startswith('#'):continue
  name=name.split('#',1)[0];p=Path(name)if name.startswith('/')else BASE/name;assert p.exists()or p==ROOT/'rpc502_certificate_quality_gates.json',name;links+=1
 out={'generator_sha256':sha(Path(__file__)),'scope':'Certificate/TLV/digest/atomic increment only;full interface goal remains active.','source_sha256':check['source_sha256'],'source_uuid_fresh':ids[0],'QG1':{'status':'pass','evidence':'Descriptive technical analysis.'},'QG2':{'status':'pass','evidence':'C1-C10 and explicit falsification probes.'},'QG3':{'status':'pass_for_increment','evidence':'Source schema/item/callback/hash/atomic interfaces;broader goal incomplete.'},'QG4':{'status':'pass','evidence':'Byte spans,u32/u64 arithmetic,alignment constraint,SDK views,standard digest oracles and complexity.'},'QG5':{'status':'pass','evidence':'Structural versus authenticated,nonminimal lengths,zero-size mode,context retirement and A72/MAX boundaries separated.'},'QG6':{'status':'pass','evidence':'Current thin/universal/UUID,original opcodes/fixups/metadata,all44 fresh calls,source byte epochs,43 digest outputs,six local proofs and standards links.'},'QG7':{'status':'pass','evidence':'Impact-labeled bounded continuation table.'},'verified_counts':counts,'prior_artifacts_checked':977,'unchanged_prior_artifacts':971,'allowed_existing_mutations':6,'outer_parameter28_overlapping_reads':0,'source_gate_restorations_checked':restorations,'unaligned_counterexample_independently_checked':True,'report_local_links':links,'native_target_executed':False,'IDB_mutated':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_certificate_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');assert(ROOT/'rpc502_certificate_quality_gates.json').exists();print(json.dumps({'all_checks_pass':True,'verified_counts':counts,'gate_restorations':restorations}),flush=True)

if __name__=='__main__':main()
