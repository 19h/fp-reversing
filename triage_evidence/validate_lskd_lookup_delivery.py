#!/usr/bin/env python3
"""Seal source lookup-table delivery, independently decode W13 kill and pin evidence.

O(pinned bytes+I+256R) time, O(largest JSON) space, plus solver cost30 s/query.
Original single instructions execute only in private guests; no native target.
"""
import hashlib,json,re
from pathlib import Path
import z3,unicorn
from unicorn import arm64_const as ar
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from lskd_lookup_symbolic import queries
BASE=ROOT.parent;BASELINE_SHA='62d8a5d922c1e3e2c9395fdcbfee9a6ef9f71c1270d9621b240b9d3afc0649bc'
EXPECTED={'bounded_source_spans':12,'aligned_text_words_examined':422089,'decoded_text_instructions':422038,'undecoded_text_words':51,'indexed_store_candidates':41,'original_table_bytes_checked':4096,'exhaustive_table_root_banks':2,'bank_input_checks':512,'source_proof_pairs_unsat':15,'fresh_cases':40,'source_visits':228037,'source_lookup_error_wrapper_returns':40,'FP64_contexts_preserved':40,'register_only_models':280,'source_byte_checks':912148,'source_write_epochs':20841,'read_epochs':45048,'discarded_probe_read_epochs':40,'discarded_unknown_load_epochs':38,'byte_reconstructed_cases':40,'preceding_complete_prefixes_equal':24,'source_table_pointer_stores':40,'source_pointer_store_to_lookup_pairs':38,'original_table_u32_read_epochs':42,'source_dead_window_instructions':2584,'source_dead_load_windows':38,'source_zero_context_rejections':2,'zero_key_second_stage_rejections':4}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 assert sha(ROOT/'lskd_lookup_prior_manifest.json')==BASELINE_SHA;baseline=read('lskd_lookup_prior_manifest.json');assert len(baseline['files'])==1982
 c=read('lskd_lookup_contracts.json');checks=read('lskd_lookup_checks.json');proof=read('lskd_lookup_proofs.json');preserve=read('lskd_lookup_preservation.json');state=read('lskd_state_contracts.json')
 for obj,name in[(c,'recover_lskd_lookup.py'),(checks,'validate_lskd_lookup.py'),(proof,'prove_lskd_lookup.py'),(preserve,'validate_lskd_lookup_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and checks['verified_counts']==EXPECTED and preserve['all_checks_pass']and sha(ROOT/'lskd_lookup_replays.json')==checks['fresh_replays_sha256']
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert sha(SOURCE)==c['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 table=c['table'];assert k.read(int(table['address'],16),4096).hex()==table['original4096_hex']==bytes(4096).hex()and table['file_backed']and not table['native_runtime_contents_known']and not table['allocation_object_extent_proved']
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for b in c['bank_rules']:
  l,r=int(b['left'],16),int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer']
 for ptr in c['secondary_dispatch_slots']+c['bank_input_slots']+[x['pointer']for x in c['bounded_pointer_aliases']]:assert pointer(k,int(ptr['slot'],16))==ptr
 qs,lifts=queries(c,state);assert len(qs)==len(proof['proofs'])==15 and lifts==proof['source_lift_counts']==checks['source_lift_counts']and sum(lifts.values())==99
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
 a=0xfffffe000a531164;raw=k.read(a,4);w=int.from_bytes(raw,'little');assert w==0x1200256d
 # Decode the logical-immediate AND independently of Capstone and the source lift.
 assert(w>>31)&1==0 and(w>>29)&3==0 and(w>>23)&0x3f==0x24 and(w>>22)&1==0 and(w>>16)&63==0 and(w>>10)&63==9 and(w>>5)&31==11 and w&31==13
 imms=(w>>10)&63;N=(w>>22)&1;length=((N<<6)|((~imms)&63)).bit_length()-1;levels=(1<<length)-1;S=imms&levels;R=((w>>16)&63)&levels;esize=1<<length;ones=(1<<(S+1))-1;mask=((ones>>R)|(ones<<(esize-R)))&((1<<esize)-1);assert length==5 and esize==32 and mask==0x3ff
 kills=[]
 for old,key in[(0,0),(1,1),(1<<63,0xffffffff),((1<<64)-1,0x400),(0xa5a5a5a5a5a5a5a5,0x87654321),(0x1234567887654321,0x3ff)]:
  u=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);u.mem_map(a&~4095,4096);u.mem_write(a,raw);u.reg_write(ar.UC_ARM64_REG_X13,old);u.reg_write(ar.UC_ARM64_REG_X11,key);u.reg_write(ar.UC_ARM64_REG_NZCV,0xa0000000);u.emu_start(a,a+4,count=1);out=u.reg_read(ar.UC_ARM64_REG_X13);assert out==key&mask and u.reg_read(ar.UC_ARM64_REG_X11)==key and u.reg_read(ar.UC_ARM64_REG_NZCV)==0xa0000000;kills.append({'old_X13':hex(old),'W11':hex(key),'new_X13':hex(out),'NZCV':'0xa0000000'})
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['prior_artifacts_checked']==1982 and preserve['unchanged_prior_artifacts']==1976
 for row in baseline['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  p=BASE/row['path'];assert p.stat().st_size==row['size_bytes']and sha(p)==row['sha256']
 links=0
 for name in['lskd_lookup_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p in[ROOT/'lskd_lookup_source_identity.json',ROOT/'lskd_lookup_quality_gates.json'],(name,target);links+=1
 report=(BASE/'lskd_lookup_report.md').read_text()
 for term in['LT11','QG7','unknown','40','228037','2584','1982','1976','Mach','0xfffffe000ccc7b08','0xfffffe000ccc78d0','0xfffffe000ccc78a8','concurrent','Static only']:assert term in report,term
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'source_spans':[{n:s[n]for n in['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'table':table,'bounded_pointer_aliases':c['bounded_pointer_aliases'],'secondary_dispatch_slots':c['secondary_dispatch_slots'],'allowed_kill_decoding':{'pc':hex(a),'original_word':hex(w),'datasize_bits':32,'source_register':11,'destination_register':13,'logical_immediate':hex(mask),'write_zero_extends_to_X13':True,'six_original_instruction_cases':kills},'indexed_store_inventory_sha256':hashlib.sha256(json.dumps(c['indexed_store_inventory'],sort_keys=True).encode()).hexdigest(),'complete_table_writer_inventory_proved':False,'native_runtime_contents_known':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_lookup_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 evidence=['Factual source/interface analysis.','LT1-LT11 list dependencies and falsification probes.','Saved-pointer lineage, initialized-cache errors, second gate and bounded writer candidates covered; full objective remains active.','Exact widths, byte extents, source counts and reproduction.','Native/file contents, indexed/allocation extents, local/native contexts, concurrent reads and writer candidates separated.','Original source/chains,40 fresh epoch audits,24 preceding prefixes,2584 def/use rows,15 re-lifted proof pairs and independent logical-immediate decoding.','Impact-labeled continuation table.']
 outputs=['lskd_lookup_contracts.json','lskd_lookup_profiles.json','lskd_lookup_replays.json','lskd_lookup_checks.json','lskd_lookup_proofs.json','lskd_lookup_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':lifts,'independent_original_W13_kill_cases':len(kills),'prior_artifacts_checked':1982,'unchanged_prior_artifacts':1976,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_lookup_source_identity.json'),'model_memory_writes':0,'uninitialized_values_consumed':0,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_lookup_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'fresh_cases':40,'source_proof_pairs':15,'independent_original_W13_kill_cases':6,'prior_artifacts_checked':1982,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
