#!/usr/bin/env python3
"""Final read-only source/input/dependency/report checks;new scoped gate record.

O(total checked bytes+report links) time,streamed hashes and bounded JSON.
Published old producers,source binaries,input files and IDBs are never written.
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
 checks=json.loads((ROOT/'rpc502_startup_checks.json').read_text());contracts=json.loads((ROOT/'rpc502_startup_contracts.json').read_text());pres=json.loads((ROOT/'rpc502_startup_preservation.json').read_text());profiles=json.loads((ROOT/'rpc502_startup_profiles.json').read_text())
 for obj,producer in[(checks,'validate_rpc502_startup.py'),(contracts,'recover_rpc502_startup.py'),(profiles,'probe_rpc502_startup_cases.py')]:
  assert obj['generator_sha256']==sha(ROOT/producer)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,n
 assert checks['all_checks_pass']and pres['all_checks_pass'];assert pres['generator_sha256']==sha(ROOT/'validate_rpc502_startup_preservation.py');assert pres['prior_artifacts_checked']==1000 and pres['unchanged_prior_artifacts']==994 and len(pres['allowed_existing_changes'])==6
 for e in pres['allowed_existing_changes']:assert sha(BASE/e['path'])==e['current_sha256']
 for e in pres['original_inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 k=checks['verified_counts'];assert k['assertions']==27841267;assert k['cases']==k['fresh_runs']==8 and k['retained_source_visits']==k['fresh_source_visits']==27574672 and k['original_instructions']==59399 and k['local_proofs_unsat']==4 and k['embedded_certificates']==k['independent_RSA_SHA1_relations']==2 and k['outer_parameter28_reads']==0 and k['source_built_certificate_bytes']==2254 and k['source_certificate_shift_bytes']==2246 and k['source_ranges']==23 and k['compiler_ranges']==10 and k['pointer_records']==1507 and k['completed_original_startup_callbacks']==3 and k['complete_worker_returns']==2;assert checks['quantum_subdivision_source_prefix_equal']
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e').read_bytes();univ=Path('/Users/___/Downloads/fpx/fairplayd').read_bytes();assert hashlib.sha256(source).hexdigest()==checks['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';assert hashlib.sha256(univ).hexdigest()=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and univ[3407872:3407872+len(source)]==source
 off=32;ids=[]
 for _ in range(struct.unpack_from('<I',source,16)[0]):
  cmd,n=struct.unpack_from('<II',source,off)
  if cmd==0x1b:ids.append(str(uuid.UUID(bytes=source[off+8:off+24])))
  off+=n
 assert ids==['204741e9-b89f-32b4-9321-51f3975c7cac']
 report=BASE/'rpc502_startup_report.md';text=report.read_text();assert 'PENDING'not in text
 for j in range(1,11):assert '| U'+str(j)+' |'in text
 for j in range(1,8):assert '| QG'+str(j)+' |'in text
 links=0
 for n in re.findall(r'\[[^\]]*\]\(([^)]+)\)',text):
  n=n.strip('<>')
  if re.match(r'^[a-zA-Z][\w+.-]*://',n)or n.startswith('#'):continue
  n=n.split('#',1)[0];p=Path(n)if n.startswith('/')else BASE/n;assert p.exists()or p==ROOT/'rpc502_startup_quality_gates.json',n;links+=1
 out={'generator_sha256':sha(Path(__file__)),'scope':'Startup/readiness/arena/environment and embedded certificate increment only;full interface goal active.','source_sha256':checks['source_sha256'],'source_uuid_fresh':ids[0],'report_sha256':sha(report),'report_local_links':links,'QG1':{'status':'pass','evidence':'Descriptive source/state/byte analysis.'},'QG2':{'status':'pass','evidence':'U1-U10 with dependent results and falsification probes.'},'QG3':{'status':'pass_for_increment','evidence':'Original callback predecessor,early readiness,arena,environment/lock ABI and embedded records;broader goal incomplete.'},'QG4':{'status':'pass','evidence':'u8/u32/u64,signed pointer bias,SDK sizeof/offset checks,timeval units,source-store reconstruction and bounded complexity.'},'QG5':{'status':'pass','evidence':'Early flag versus callback completion,callback versus process startup,NULL result versus certificate error,opaque lock paths,unknown outputs and budgets versus returns distinguished.'},'QG6':{'status':'pass','evidence':'Fresh thin/universal/UUID,original opcodes/fixups/metadata/arrays,all eight fresh calls,every ordered source visit,arena/certificate source epochs,independent DER/OpenSSL/RSA/hash and four local proofs.'},'QG7':{'status':'pass','evidence':'Impact-labeled bounded continuation table.'},'verified_counts':k,'prior_artifacts_checked':1000,'unchanged_prior_artifacts':994,'allowed_existing_mutations':6,'native_target_executed':False,'IDB_mutated':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_startup_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':k}),flush=True)

if __name__=='__main__':main()
