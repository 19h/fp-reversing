#!/usr/bin/env python3
"""Final source, fresh evidence, prior-artifact and reporting readback.

Writes only new identity/quality records. O(total prior/source bytes + links)
time and bounded JSON/source space. No native target or IDB operation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='efa00b51848596d9cce97895786ccc5d1e1f866067efb73ba35e576cb5387d67'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as stream:
  while b:=stream.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 oldpath=ROOT/'sample_caller_prior_manifest.json';assert sha(oldpath)==BASELINE_SHA;old=read(oldpath.name);checks=read('sample_caller_checks.json');preserve=read('sample_caller_preservation.json');c=read('sample_caller_contracts.json');p=read('sample_caller_profiles.json');bp=read('sample_caller_builder_profiles.json');proof=read('sample_caller_proofs.json');fresh=read('sample_caller_replays.json')
 for obj,name in[(checks,'validate_sample_caller.py'),(preserve,'validate_sample_caller_preservation.py'),(c,'recover_sample_caller.py'),(p,'probe_sample_caller.py'),(bp,'probe_sample_builders.py'),(proof,'prove_sample_caller.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert fresh['generator_sha256']==sha(ROOT/'validate_sample_caller.py')and fresh['caller_cases']==p['cases']and fresh['builder_cases']==bp['cases'];assert sha(ROOT/'sample_caller_replays.json')==checks['fresh_replays_sha256'];assert proof['contracts_sha256']==sha(ROOT/'sample_caller_contracts.json')
 for row in proof['proofs']:assert sha(ROOT/row['file'])==row['sha256']and row['result']=='unsat'
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 k=Kernel();fp=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert sha(SOURCE)==checks['source_sha256']==c['source_sha256']==p['source_sha256']==bp['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';assert k.sha256==checks['kernel_collection_sha256']==c['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';assert function(k,fp,0xfffffe000a6247a4)==c['function'];assert pointer(k,0xfffffe000847aa38)==c['entry_pointer']
 for row in c['builder_contexts']:
  f=function(k,fp,int(row['parent_compiler_start'],16));assert f['end']==row['parent_compiler_end']and f['sha256']==row['parent_sha256']
  for s in[row['fragment'],row['entry_prefix']]:
   a,z=int(s['start'],16),int(s['end'],16);assert k.read(a,z-a)==IMAGE.read(a,z-a)==bytes.fromhex(s['bytes_hex'])
 for row in c['bank_rules']:assert pointer(k,int(row['slot'],16))==row['original_pointer']
 counts=checks['verified_counts'];expected={'original_caller_functions':1,'original_builder_parent_functions':2,'original_builder_spans':4,'caller_source_facts':25,'literal_frame_store_records':9,'exhaustive_bank_rules':11,'bank_byte_inputs':2816,'builder_bank_rules':2,'builder_bank_byte_inputs':512,'proofs_unsat':12,'fresh_caller_runs':113,'fresh_caller_source_visits':39019,'fresh_builder_runs':48,'fresh_builder_source_visits':4512,'task_stack_epochs':119,'builder_source_record_bytes':3840,'source_output_status_bytes':224,'guard_trap_boundaries':2,'completion_requests':19,'release_requests':35}
 for n,v in expected.items():assert counts[n]==v,(n,counts[n],v)
 assert len(fresh['caller_cases'])==113 and len(fresh['builder_cases'])==48 and len(proof['proofs'])==12;assert sum(len(r['source_visits'])for r in fresh['caller_cases'])==39019 and sum(len(r['source_visits'])for r in fresh['builder_cases'])==4512;assert all(not r['undefined_private_reads']and not r['native_API_executed']for r in fresh['caller_cases']);assert all(r['stop_reason']=='before_coordinator_call'and not r['native_API_executed']for r in fresh['builder_cases'])
 identity={'scope':'Original coordinator/builders/chained slots and source record/task-width readback. Native task identity, lifetime and entry reachability unproved.','generator_sha256':sha(Path(__file__)),'kext_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'fileset_uuid':fp['uuid'],'coordinator':{n:c['function'][n]for n in['start','end','sha256']},'builder_contexts':[{n:r[n]for n in['name','parent_compiler_start','parent_compiler_end','parent_sha256']}for r in c['builder_contexts']],'entry_pointer':c['entry_pointer'],'contracts_sha256':sha(ROOT/'sample_caller_contracts.json'),'new_live_IDB_ranges':0,'native_target_executed':False,'native_task_identity_proved':False,'complete_lifecycle_proved':False,'frame_reachability_proved':False,'full_goal_complete':False};(ROOT/'sample_caller_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={e['path']:e for e in preserve['allowed_existing_changes']};assert len(old['files'])==1307 and len(allowed)==6 and preserve['unchanged_prior_artifacts']==1301
 for row in old['files']:assert sha(BASE/row['path'])==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
 for row in old['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 links=0
 for name in['sample_caller_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   pth=Path(target.split('#',1)[0]);pth=pth if pth.is_absolute()else BASE/pth;assert pth.exists()or pth==ROOT/'sample_caller_quality_gates.json',(name,target);links+=1
 report=(BASE/'sample_caller_report.md').read_text()
 for phrase in['SR8','QG7','0x0f6f4af997099bc0','17179869180','0x31ae0066','3840','119','void','reaching definition','unknown']:assert phrase in report,phrase
 evidence=['Factual technical analysis.','SR1-SR8 with dependent results and falsification probes.','Internal record, source call/target sites, two task-carrier routes, width/status/unwind contracts; full goal remains active.','Exact byte extents, modular widths, original source epochs and explicit complexity.','Full64/low32 key, stored status/void-release X0, partial/full lifecycle and fixture/native reachability separated.','Original compiler/source/chained slots, 12 local proofs, 161 fresh cases and source-written records.','Impact-labeled bounded continuation table.'];outputs=['sample_caller_checks.json','sample_caller_contracts.json','sample_caller_profiles.json','sample_caller_builder_profiles.json','sample_caller_replays.json','sample_caller_proofs.json','sample_caller_preservation.json']
 out={'scope':'Descriptor-setup caller and two builder slices; native task identity, complete lifecycle and frame reachability remain unproved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':counts,'prior_artifacts_checked':1307,'unchanged_prior_artifacts':1301,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'sample_caller_source_identity.json'),'native_target_executed':False,'native_lifetime_proved':False,'complete_lifecycle_proved':False,'frame_reachability_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'sample_caller_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':161,'proofs_unsat':12,'prior_artifacts_checked':1307,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
