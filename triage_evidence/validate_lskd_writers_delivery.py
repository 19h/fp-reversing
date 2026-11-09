#!/usr/bin/env python3
"""Seal selector18/core ingress and conditional writer-root evidence.

O(pinned bytes+I+256R) time/space plus solver cost30 s/query. No target executes;
no actual table-entry writer, complete core operation or daemon IPC is claimed.
"""
import hashlib,json,re
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from lskd_writers_symbolic import queries
BASE=ROOT.parent;BASELINE_SHA='5e921ae8e4ce3a394c594ccb856cc26f53cd721f3334989c4c2a1d82aab71c5f'
EXPECTED={'bounded_source_windows':10,'original_pointer_slots':8,'selector18_descriptor_bytes_checked':48,'exhaustive_bank_rules':5,'bank_byte_input_checks':1280,'source_proof_pairs_unsat':13,'fresh_entry_prefix_cases':36,'entry_prefix_instruction_visits':4968,'source_instruction_byte_checks':73120,'source_write_epochs':2176,'source_read_epochs':5104,'discarded_stack_probe_reads':72,'byte_reconstructed_cases':1060,'original_stack_probe_calls':36,'original_bank_pointer_frame_stores':72,'source_argument_to_frame_stores':216,'source_provider_to_core_prefixes':18,'fresh_conditional_bank_cases':1024,'conditional_bank_instruction_visits':13312}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 assert sha(ROOT/'lskd_writers_prior_manifest.json')==BASELINE_SHA;baseline=read('lskd_writers_prior_manifest.json');assert len(baseline['files'])==2079
 c=read('lskd_writers_contracts.json');checks=read('lskd_writers_checks.json');proof=read('lskd_writers_proofs.json');preserve=read('lskd_writers_preservation.json')
 for obj,name in[(c,'recover_lskd_writers.py'),(checks,'validate_lskd_writers.py'),(proof,'prove_lskd_writers.py'),(preserve,'validate_lskd_writers_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and checks['verified_counts']==EXPECTED and preserve['all_checks_pass']and sha(ROOT/'lskd_writers_replays.json')==checks['fresh_replays_sha256']
 for flag in['native_allocator_executed','complete_core_operation_executed','same_frame_reaching_definition_proved','actual_tag_table_writer_proved','native_target_executed','external_IPC_emission_proved']:assert not checks[flag]
 assert checks['model_memory_writes']==0
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert sha(SOURCE)==c['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 for ptr in c['original_pointer_slots']:assert pointer(k,int(ptr['slot'],16))==ptr
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 desc=c['selector18'];assert k.read(int(desc['descriptor'],16),48).hex()==desc['original48_hex']and IMAGE.read(int(desc['descriptor'],16),48).hex()==desc['normalized48_hex']and desc['input_count_bytes']==desc['output_count_bytes']==3096
 assert desc['selector']==18 and int(desc['lookup_mask64'],16)&(1<<17)and not c['conditional_writer_root']['same_frame_reaching_definition_proved']and not c['conditional_writer_root']['actual_tag_table_writer_proved']
 assert c['first_allocator']=={'call_PC':'0xfffffe000a5304c8','target':'0xfffffe000c4b9a08','size_bytes':16384,'alignment_bytes':64,'executed':False}
 for b in c['bank_rules']:
  l,r=int(b['left'],16),int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer']
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==13 and lifts==proof['source_lift_counts']==checks['source_lift_counts']and sum(lifts.values())==39
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
 fresh=read('lskd_writers_replays.json');assert fresh['generator_sha256']==sha(ROOT/'validate_lskd_writers.py')and fresh['dependencies']==checks['dependencies']and len(fresh['entry_cases'])==36 and len(fresh['conditional_bank_cases'])==1024 and not fresh['full_goal_complete']
 assert sum(r['input']['entry_kind']=='provider'for r in fresh['entry_cases'])==18
 for r in fresh['entry_cases']:assert not r['native_allocator_executed']and not r['native_target_executed']and not r['API_models']and r['model_memory_writes']==0 and r['boundary']['pc']=='0xfffffe000a5304c8'
 coverage=set()
 for r in fresh['conditional_bank_cases']:
  assert not r['original_parent_path_executed']and not r['tag_table_modified']and not r['native_target_executed']and r['model_memory_writes']==0;x=r['input'];coverage.add((x['placement'],x['input32']&~255,x['input32']&255))
 assert coverage=={(p,h,b)for p in[0,0x100]for h in[0,0xa5f0c300]for b in range(256)};del fresh
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['prior_artifacts_checked']==2079 and preserve['unchanged_prior_artifacts']==2073
 for row in baseline['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  p=BASE/row['path'];assert p.stat().st_size==row['size_bytes']and sha(p)==row['sha256']
 links=0
 for name in['lskd_writers_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p in[ROOT/'lskd_writers_source_identity.json',ROOT/'lskd_writers_quality_gates.json'],(name,target);links+=1
 report=(BASE/'lskd_writers_report.md').read_text()
 for term in['WR11','QG7','unknown','36','1024','73120','2079','2073','3096','3072','16384','5056','5216','Mach','_zgcqcxw1qve0CY','0xfffffe000ccc7b08','0xC14','same-frame']:assert term in report,term
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'source_spans':[{n:s[n]for n in['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'selector18':desc,'vtables':c['vtables'],'original_pointer_slots':c['original_pointer_slots'],'first_allocator':c['first_allocator'],'bank_pointer_outputs':c['bank_pointer_outputs'],'conditional_writer_root':c['conditional_writer_root'],'core_entry_prefix_executed':True,'provider_entry_prefix_executed':True,'native_mapper_executed':False,'native_allocator_executed':False,'actual_tag_table_writer_proved':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_writers_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 evidence=['Factual source/interface analysis.','WR1-WR11 list dependencies and falsification probes.','Selector18/core ingress, source bank publications, conditional producer and status channels covered; full objective remains active.','Explicit widths/extents, source counts and reproduction.','Actual prefix/local/native execution, conditional/actual writer, allocation preparation/effects and outer/embedded status separated.','Original names/bytes/fixups,36 fresh entry prefixes,1024 local cases,13 source proof pairs and five exhaustive banks.','Impact-labeled continuation table.'];outputs=['lskd_writers_contracts.json','lskd_writers_profiles.json','lskd_writers_bank_profiles.json','lskd_writers_replays.json','lskd_writers_checks.json','lskd_writers_proofs.json','lskd_writers_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':lifts,'prior_artifacts_checked':2079,'unchanged_prior_artifacts':2073,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_writers_source_identity.json'),'model_memory_writes':0,'actual_tag_table_writer_proved':False,'complete_core_operation_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_writers_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'fresh_prefix_cases':36,'fresh_conditional_cases':1024,'source_proof_pairs':13,'prior_artifacts_checked':2079,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
