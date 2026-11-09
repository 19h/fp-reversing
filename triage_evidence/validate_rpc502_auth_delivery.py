#!/usr/bin/env python3
"""Final original-source/input/preservation/cross-certificate/report checks.

Writes only new scoped quality evidence. O(total artifact bytes+report links)
work with streamed hashes,bounded JSON and two integer RSA/hash checks.
No original inputs,binaries,IDBs or published producers are written.
"""
import hashlib,json,re,struct,uuid
from pathlib import Path
from recover_rpc502_auth_cross_certificates import build
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()

def main():
 checks=json.loads((ROOT/'rpc502_auth_checks.json').read_text());contract=json.loads((ROOT/'rpc502_auth_contracts.json').read_text());pres=json.loads((ROOT/'rpc502_auth_preservation.json').read_text());profiles=json.loads((ROOT/'rpc502_auth_profiles.json').read_text());cross=json.loads((ROOT/'rpc502_auth_cross_component_certificates.json').read_text());inv=json.loads((ROOT/'rpc502_auth_certificate_inventory.json').read_text())
 for obj,producer in[(checks,'validate_rpc502_auth.py'),(contract,'recover_rpc502_auth.py'),(profiles,'probe_rpc502_auth_cases.py'),(cross,'recover_rpc502_auth_cross_certificates.py'),(inv,'scan_rpc502_auth_certificates.py')]:
  assert obj['generator_sha256']==sha(ROOT/producer)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,n
 assert checks['all_checks_pass']and pres['all_checks_pass'];assert pres['generator_sha256']==sha(ROOT/'validate_rpc502_auth_preservation.py');assert pres['prior_artifacts_checked']==1022 and pres['unchanged_prior_artifacts']==1016 and len(pres['allowed_existing_changes'])==6
 for e in pres['allowed_existing_changes']:assert sha(BASE/e['path'])==e['current_sha256']
 for e in pres['original_inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 assert build()==cross and cross['all_mathematical_relations_match']and len(cross['cross_component_relations'])==2
 k=checks['verified_counts'];assert k['assertions']==57525170 and k['cases']==k['fresh_runs']==k['complete_worker_returns']==6 and k['retained_source_visits']==k['fresh_source_visits']==57461975 and k['original_instructions']==59504 and k['source_ranges']==19 and k['compiler_ranges']==12 and k['pointer_records']==1513 and k['proofs_unsat']==4 and k['comparison_bytes']==230 and k['comparison_next_index_guards']==227 and k['verification_tail_records']==6 and k['source_tail_bytes']==1320 and k['source_stack_read_bytes']==952 and k['outer_parameter28_reads']==0 and k['successful_local_combiners']==k['failed_local_combiners']==3 and k['classified_certificates']==41 and k['unique_DER']==40 and k['unique_RSA_keys']==39 and k['inventory_signature_relations']==k['matching_inventory_relations']==47
 expected=contract['fixed_issuer_DN']['decoded_ascii_including_NUL'].rstrip('\0')
 from rpc502_auth_models import name_text
 assert not any(name_text(e['certificate'],'issuer').decode()==expected for e in inv['records'])
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e').read_bytes();univ=Path('/Users/___/Downloads/fpx/fairplayd').read_bytes();assert hashlib.sha256(source).hexdigest()==checks['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';assert hashlib.sha256(univ).hexdigest()=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and univ[3407872:3407872+len(source)]==source
 off=32;ids=[]
 for _ in range(struct.unpack_from('<I',source,16)[0]):
  cmd,n=struct.unpack_from('<II',source,off)
  if cmd==0x1b:ids.append(str(uuid.UUID(bytes=source[off+8:off+24])))
  off+=n
 assert ids==['204741e9-b89f-32b4-9321-51f3975c7cac']
 report=BASE/'rpc502_auth_report.md';text=report.read_text();assert 'PENDING'not in text
 for j in range(1,11):assert '| V'+str(j)+' |'in text
 for j in range(1,8):assert '| QG'+str(j)+' |'in text
 links=0
 for n in re.findall(r'\[[^\]]*\]\(([^)]+)\)',text):
  n=n.strip('<>')
  if re.match(r'^[a-zA-Z][\w+.-]*://',n)or n.startswith('#'):continue
  n=n.split('#',1)[0];p=Path(n)if n.startswith('/')else BASE/n;assert p.exists()or p==ROOT/'rpc502_auth_quality_gates.json',n;links+=1
 out={'generator_sha256':sha(Path(__file__)),'scope':'Issuer/verification-record/certificate-hierarchy increment;full interface goal remains active.','source_sha256':checks['source_sha256'],'source_uuid_fresh':ids[0],'report_sha256':sha(report),'report_local_links':links,'QG1':{'status':'pass','evidence':'Descriptive source,ABI,arithmetic and public-certificate analysis.'},'QG2':{'status':'pass','evidence':'V1-V10 with dependent results and falsification probes.'},'QG3':{'status':'pass_for_increment','evidence':'Issuer extent/bytes,status predicates,partial signature/digest view,inventory and cross-component hierarchy;broader goal incomplete.'},'QG4':{'status':'pass','evidence':'u8/u32/u64,signed LDRSB,unsigned wrap comparisons,source epochs,SDK offsets and bounded algorithms.'},'QG5':{'status':'pass','evidence':'Empty caller path versus successor loop,prefix match versus signature validity,raw signature versus encoded digest,low-byte versus whole-word status,scan classifier and prior-extract freshness distinguished.'},'QG6':{'status':'pass','evidence':'Fresh thin/universal/UUID,all six fresh original runs,ordered source-byte digests,source-defined stack bytes,DER/signature/TBS oracles,four scalar proofs,41 fresh OpenSSL Name parses,47 internal and two cross-component RSA/hash relations.'},'QG7':{'status':'pass','evidence':'Impact-labeled bounded continuation table.'},'verified_counts':{**k,'cross_component_signature_relations':2},'prior_artifacts_checked':1022,'unchanged_prior_artifacts':1016,'allowed_existing_mutations':6,'native_target_executed':False,'IDB_mutated':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_auth_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':out['verified_counts']}),flush=True)

if __name__=='__main__':main()
