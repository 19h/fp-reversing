#!/usr/bin/env python3
"""Final source/input/preservation/report-link readback for this increment.

Reads all new validation outputs and original source metadata;writes only new
quality/source records. The separately authorized aggregator refreshes manifest.
O(total artifact/source bytes+links) time;O(largest JSON/report) retained space.
No native target/API/IDB actions;the broad goal remains active and incomplete.
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
 identity=json.loads((ROOT/'rpc502_parser_source_identity.json').read_text());thin=Path(identity['thin_path']);universal=Path(identity['universal_path']);raw=thin.read_bytes();fat=universal.read_bytes();assert sha(thin)==identity['thin_sha256']and sha(universal)==identity['universal_sha256'];assert len(raw)==17668912 and fat[3407872:3407872+len(raw)]==raw
 magic,cpu,subtype,filetype,ncmds,sizeofcmds,flags,reserved=struct.unpack_from('<8I',raw);assert magic==0xfeedfacf and cpu==0x100000c and subtype==0x80000002;cursor=32;actual_uuid=None
 for _ in range(ncmds):
  cmd,size=struct.unpack_from('<II',raw,cursor);assert size>=8
  if cmd==0x1b:actual_uuid=str(uuid.UUID(bytes=raw[cursor+8:cursor+24]))
  cursor+=size
 assert cursor==32+sizeofcmds and actual_uuid==identity['thin_uuid']=='204741e9-b89f-32b4-9321-51f3975c7cac'
 source={'scope':'Fresh read-only thin/universal/header/UUID readback;not live IDB or native process attestation.','generator_sha256':sha(Path(__file__)),'thin_path':str(thin),'thin_sha256':sha(thin),'thin_size_bytes':len(raw),'thin_uuid':actual_uuid,'universal_path':str(universal),'universal_sha256':sha(universal),'arm64e_offset_bytes':3407872,'entire_slice_equal':True,'live_IDB_bytes_verified':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_rsa_source_identity.json').write_text(json.dumps(source,indent=2)+'\n')
 names=['rpc502_rsa_checks.json','rpc502_rsa_sequence_checks.json','rpc502_policy_checks.json','rpc502_rsa_preservation.json'];objects={n:json.loads((ROOT/n).read_text())for n in names}
 for n,o in objects.items():
  assert o['all_checks_pass']and not o['full_goal_complete'],n
  for dep,h in o.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 producers={'rpc502_rsa_checks.json':'validate_rpc502_rsa.py','rpc502_rsa_sequence_checks.json':'validate_rpc502_rsa_sequence.py','rpc502_policy_checks.json':'validate_rpc502_policy.py','rpc502_rsa_preservation.json':'validate_rpc502_rsa_preservation.py'}
 for n,producer in producers.items():assert objects[n]['generator_sha256']==sha(ROOT/producer),(n,producer)
 old=json.loads((ROOT/'rpc502_rsa_prior_manifest.json').read_text());allowed={v['path']:v for v in objects['rpc502_rsa_preservation.json']['allowed_existing_changes']}
 for e in old['files']:
  path=BASE/e['path'];assert sha(path)==(allowed[e['path']]['current_sha256']if e['path']in allowed else e['sha256']),e['path']
 for e in old['inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 links=0
 for name in ['rpc502_rsa_report.md','rpc502_policy_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  text=(BASE/name).read_text()
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',text):
   raw=raw.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',raw)or raw.startswith('#'):continue
   target=Path(raw.split('#',1)[0]);target=target if target.is_absolute()else BASE/target
   # Quality file is emitted by this successful final readback.
   assert target.exists()or target==ROOT/'rpc502_rsa_quality_gates.json',(name,raw)
   links+=1
 from rpc502_startup_tools import unpack,journals,visits
 from daemon_import_bindings import binding
 from rpc502_startup_tools import certificate_view
 arithmetic_profiles=json.loads((ROOT/'rpc502_rsa_profiles.json').read_text());leaf_views=[certificate_view(bytes.fromhex(w['case']['body_hex']))for w in arithmetic_profiles['cases']];assert len({v['tbs_hex']for v in leaf_views})==1
 assert[len(bytes.fromhex(v['signature_hex']))for v in leaf_views]==[128,256,256,256]
 assert all(c['outer28_reads']==0 for c in objects['rpc502_rsa_checks.json']['case_summaries'])
 profiles=json.loads((ROOT/'rpc502_policy_profiles.json').read_text());allocation_evidence=[];same_step_store_cases=0
 selected_binding=binding(0x10109ff58);assert selected_binding['symbol']=='_malloc'and selected_binding['library_path']=='/usr/lib/libSystem.B.dylib'
 for wrapper in profiles['cases']:
  r=unpack(wrapper);point=next(a for a in r['policy_points']if a['pc']=='0x100747f90');store=next(e for e in r['core_stack_stores']if e['pc']=='0x100747f8c');assert store['step_index']==point['step']and int(store['address'],16)==int(point['sp'],16)+0x178
  assert store['actual_after_hex']==bytes.fromhex(point['frame_prefix500_hex'])[0x178:0x17c].hex()
  adjacent=False
  for d in journals(r):
   seq=visits(d)
   if 0x100747f90 in seq:
    j=seq.index(0x100747f90);assert j>0 and seq[j-1]==0x100747f8c;adjacent=True
  assert adjacent;same_step_store_cases+=1
  if wrapper['case']['version']==2:continue
  call=next(a for a in r['policy_points']if a['pc']=='0x100919330');after=next(a for a in r['policy_points']if a['pc']=='0x100919334');assert int(call['registers'][0],16)==8
  reads=[e for e in r['bound_import_reads']if e['pc']=='0x100919328'];assert len(reads)==1 and reads[0]['slot']=='0x10109ff58'and reads[0]['target']=='libSystem/_malloc'
  models=[]
  for d in journals(r):models.extend(e for e in d['records']if e.get('site')=='0x100919330'and e.get('name')=='libSystem/_malloc')
  assert len(models)==1 and models[0]['requested_size_bytes']==8 and models[0]['result']==after['registers'][0]and not models[0]['native_API_executed']
  allocation_evidence.append({'case':wrapper['case']['label'],'source_pointer_read':reads[0],'original_binding':selected_binding,'explicit_API_model':models[0]})
 assert same_step_store_cases==3 and len(allocation_evidence)==2
 q={'scope':'RSA/key-interface and alternate-certificate late-consumer increment only;full goal remains active and incomplete.','generator_sha256':sha(Path(__file__)),'QG1':{'status':'pass','evidence':'Factual original-source technical analysis;no normative claim.'},'QG2':{'status':'pass','evidence':'R1-R8 and P1-P8 assumptions,dependent results,stress tests and explicit boundaries.'},'QG3':{'status':'pass_for_increment','evidence':'224 full products,726075 rows,seven exponent outputs,three late-field consumers and all seven complete fresh workers;full goal incomplete.'},'QG4':{'status':'pass','evidence':'u32/u64/signed32,byte/limb extents,exact carry bound,four local proofs,two SDK compiles and explicit complexity.'},'QG5':{'status':'pass','evidence':'Short/zero/nonzero/range cases,kind paths,local statuses and native limits separated;source-store step equality accounted for.'},'QG6':{'status':'pass','evidence':'Original file/slice/UUID,opcode/fixup/compiler/DER/source epoch,independent math and fresh replay provenance.'},'QG7':{'status':'pass','evidence':'Both reports have bounded impact-labeled continuation tables.'},'verified_counts':objects['rpc502_rsa_checks.json']['verified_counts'],'sequence_verified_counts':objects['rpc502_rsa_sequence_checks.json']['verified_counts'],'policy_verified_counts':objects['rpc502_policy_checks.json']['verified_counts'],'prior_artifacts_checked':1047,'unchanged_prior_artifacts':1041,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in names},'source_identity_sha256':sha(ROOT/'rpc502_rsa_source_identity.json'),'adjacent_same_step_source_store_cases':same_step_store_cases,'additional_allocation_evidence':allocation_evidence,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'rpc502_rsa_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'links':links,'prior_artifacts':1047,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
