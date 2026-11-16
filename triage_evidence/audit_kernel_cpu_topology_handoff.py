#!/usr/bin/env python3
"""Original topology/iterator/property contracts and source-produced joins.
O(source + formula DAG + visits + journals + mapped bytes) construction/space;
SMT search separate,30 s/query. No native parser, SPTM or startup claim.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_boot_cpu_identity import Model as Parent
from audit_kernel_mapping_context import DEC
from lskd_values_symbolic import resize
import recover_kernel_cpu_topology_handoff as R
import probe_kernel_cpu_topology_handoff as CPU
from replay_kernel_cpu_topology_handoff import oracle,Replay
B=R.B
class Model(Parent):
 def condition(self,name):
  if name=='gt':return self.cmp_left>self.cmp_right
  return super().condition(name)
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   post=i.mnemonic=='ldrb' and i.writeback
   if post:
    assert len(i.operands)==3;name=i.reg_name(i.operands[1].mem.base);before=self.read(name)
   if i.mnemonic=='umull':
    if self.next is not None:self.edge_checks.append(self.next==i.address)
    self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
    self.write(i.reg_name(i.operands[0].reg),z3.ZeroExt(32,self.read(i.reg_name(i.operands[1].reg)))*z3.ZeroExt(32,self.read(i.reg_name(i.operands[2].reg))));continue
   old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c
   if post:self.write(name,before+i.operands[2].imm)
   if i.mnemonic=='ccmp':self.arithmetic_flags=None # Subsequent branches consume CCMP, not the preceding SUBS flags.
  return self

def source_proofs(e):
 proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,a,b,linked=False):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));offset=a-int(f['start'],16)
  v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[offset:offset+b-a].hex()}]};return v.run('cut') if linked else v.enter('cut')
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000)
  s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks)});print(label,flush=True)
 mask,result=z3.BitVecs('TH_input_mask64 TH_state_compare64',64);v=local();v.seed('x0',result);v.setmem(v.sp0+0x20,8,mask);cut(v,0xfffffe000be832b4,0xfffffe000be832c8)
 prove('each_compared_node_saves_full_result_consumes_one_mask_bit_and_shifts_mask64',v,z3.Or(v.read('x28')!=result,v.read('x8')!=(mask&1),v.load(v.sp0+0x20,8)!=z3.LShR(mask,1)))
 state=z3.BitVec('TH_state_compare32',32);v=local();v.seed('w28',state);cut(v,0xfffffe000be83398,0xfffffe000be8339c)
 prove('zero_state_compare_admits_running_path_independently_of_mask_bit',v,v.next!=z3.If(state==0,resize(0xfffffe000be832d4,64),resize(0xfffffe000be8339c,64)))
 bit=z3.BitVec('TH_mask_bit64',64);v=local();v.seed('x8',bit);cut(v,0xfffffe000be8339c,0xfffffe000be833a0)
 prove('nonrunning_node_zero_mask_bit_selects_next_iterator',v,v.next!=z3.If(bit==0,resize(0xfffffe000be83260,64),resize(0xfffffe000be833a0,64)))
 v=local();v.regions=[(B.ARRAY-4,1)];v.seed('x21',0xfffffe0007ef8000);cut(v,0xfffffe000be832d0,0xfffffe000be832d4)
 prove('masked_running_path_clears_original_byte825c',v,v.load(B.ARRAY-4,1)!=0)
 count,limit=z3.BitVecs('TH_admitted_count32 TH_CPU_limit32',32);v=local();v.regions=[(B.GLOBALS,4)];v.setmem(B.GLOBALS,4,count);v.setmem(v.sp0+0x2c,4,limit);v.seed('x24',B.GLOBALS);v.seed('w28',state);cut(v,0xfffffe000be832d4,0xfffffe000be832e0)
 prove('running_path_bypasses_reserved_slot_test_but_loads_count_and_limit',v,z3.Or(v.read('w8')!=count,v.read('w9')!=limit,v.next!=z3.If(state==0,resize(0xfffffe000be832f4,64),resize(0xfffffe000be832e0,64))))
 v=local();v.seed('w8',count);v.seed('w9',limit);cut(v,0xfffffe000be832e0,0xfffffe000be832ec)
 prove('reserved_slot_threshold_is_unsigned_count_below_modular_limit_minus1',v,v.next!=z3.If(z3.ULT(count,limit-1),resize(0xfffffe000be832f4,64),resize(0xfffffe000be832ec,64)))
 pointer=z3.BitVec('TH_existing_boot_record64',64);v=local();v.regions=[(B.RECORD_PTR,8)];v.setmem(B.RECORD_PTR,8,pointer);v.seed('x24',B.GLOBALS);cut(v,0xfffffe000be832ec,0xfffffe000be832f4)
 prove('reserved_slot_without_published_boot_record_skips_nonrunning_node',v,v.next!=z3.If(pointer==0,resize(0xfffffe000be83260,64),resize(0xfffffe000be832f4,64)))
 v=local();v.seed('w8',count);v.seed('w9',limit);cut(v,0xfffffe000be832f4,0xfffffe000be832fc)
 prove('unsigned_count_at_least_limit_finishes_enumeration_before_new_record',v,v.next!=z3.If(z3.UGE(count,limit),resize(0xfffffe000be83b9c,64),resize(0xfffffe000be832fc,64)))
 node=CPU.P+0x1000;cluster=CPU.P+0x2000;value=z3.BitVec('TH_property_value64',64);v=local();v.regions=[(node,136)];v.seed('x26',node);v.seed('x0',value);cut(v,0xfffffe000be834b8,0xfffffe000be834bc)
 prove('mandatory_reg_value_is_stored_low32_separately_from_ordinal',v,v.load(node+4,4)!=z3.Extract(31,0,value))
 v=local();v.regions=[(node,136)];physical=v.load(node+4,4);v.seed('x26',node);cut(v,0xfffffe000be8324c,0xfffffe000be83254)
 prove('completed_CPU_record_passes_zeroextended_reg32_to_selector0e_wrapper',v,z3.Or(v.read('x0')!=z3.ZeroExt(32,physical),v.next!=R.WRAPPER))
 index=z3.BitVec('TH_cluster_index32',32);base=z3.BitVec('TH_cluster_array64',64);v=local();v.regions=[(B.GLOBALS+0x24,8)];v.setmem(B.GLOBALS+0x24,8,base);v.seed('x25',B.GLOBALS+8);v.seed('w8',index);cut(v,0xfffffe000be839d0,0xfffffe000be839f0)
 offset=z3.ZeroExt(32,index)*88;signed=z3.SignExt(32,z3.Extract(31,0,offset))
 prove('cluster_stride88_and_signed32_pointer_poison_gate',v,v.read('x23')!=z3.If(offset==signed,base+signed,((base+offset)&0xffffffffffff)|0x2bad000000000000))
 ordinal=z3.BitVec('TH_CPU_ordinal32',32);v=local();v.regions=[(node,136),(cluster,88)];oldcount=v.load(cluster+8,4);oldmask=v.load(cluster+0x10,8);v.setmem(node,4,ordinal);v.seed('x23',cluster);v.seed('x26',node);cut(v,0xfffffe000be83224,0xfffffe000be83248)
 prove('cluster_count32_increments_and_membership64_sets_ordinal_mod64_bit',v,z3.Or(v.load(cluster+8,4)!=oldcount+1,v.load(cluster+0x10,8)!=(oldmask|(resize(1,64)<<(z3.ZeroExt(32,ordinal)&63)))))
 v=local();v.regions=[(node,136),(B.GLOBALS+8,8)];old=v.load(B.GLOBALS+8,4);maximum=v.load(B.GLOBALS+12,4);v.setmem(node+8,4,index);v.seed('x25',B.GLOBALS+8);v.seed('x26',node);cut(v,0xfffffe000be83a50,0xfffffe000be83a6c)
 prove('new_cluster_increments_global_count_and_unsigned_maximum',v,z3.Or(v.load(B.GLOBALS+8,4)!=old+1,v.load(B.GLOBALS+12,4)!=z3.If(z3.UGT(maximum,index),maximum,index)))
 reg=z3.BitVec('TH_reg32',32);old=z3.BitVec('TH_old_affinity_core_bound64',64);v=local();v.regions=[(node,136),(v.sp0+0x80,8)];v.setmem(node+4,4,reg);v.setmem(v.sp0+0x80,8,old);v.seed('x26',node);v.seed('x21',0);cut(v,0xfffffe000be831cc,0xfffffe000be831e8)
 core=z3.ZeroExt(56,z3.Extract(7,0,reg))
 prove('physical_affinity_core_bound_uses_signed_maximum_not_minimum',v,v.load(v.sp0+0x80,8)!=z3.If(old>core,old,core))
 size=z3.BitVec('TH_pair_size32',32);v=local();v.setmem(v.sp0+0x68,4,size);cut(v,0xfffffe000be83740,0xfffffe000be8374c)
 prove('present_CPU_pair_property_accepts_exactly16_bytes',v,v.next!=z3.If(size==16,resize(0xfffffe000be8374c,64),resize(0xfffffe000be83dcc,64)))
 payload=CPU.P+0x4000;v=local();v.regions=[(payload,16),(node,136)];first=v.load(payload,8);second=v.load(payload+8,8);v.setmem(v.sp0+0x78,8,payload);v.seed('x26',node);cut(v,0xfffffe000be8374c,0xfffffe000be83760)
 prove('CPU_pair_property_copies_both_full64_words_in_order',v,z3.Or(v.load(node+0x50,8)!=first,v.load(node+0x58,8)!=second))
 v=local();v.regions=[(0xfffffe0007ef8c28,4)];v.seed('x8',value);cut(v,0xfffffe000be83c9c,0xfffffe000be83ca8)
 prove('chip_revision_publication_is_low32',v,v.load(0xfffffe0007ef8c28,4)!=z3.Extract(31,0,value))
 v=local();v.regions=[(0xfffffe0007f8b6e8,8)];v.seed('x19',0xfffffe0007f8b000);args=v.load(0xfffffe0007f8b6e8,8);cut(v,0xfffffe000be83d00,0xfffffe000be83d28)
 prove('final_cluster_power_parser_ABI_can_write_global_c58_directly',v,z3.Or(v.read('x0')!=args+0x6c,v.read('x1')!=0xfffffe0007064355,v.read('x2')!=0xfffffe0007ef8c58,v.read('x3')!=4,v.read('x4')!=0,v.next!=R.PARSE))
 v=local();v.regions=[(0xfffffe0007f8b6e8,8)];args=v.load(0xfffffe0007f8b6e8,8);cut(v,R.POST+20,R.POST+64)
 prove('original_post_enumeration_helper_parser_ABI_targets_control_e98',v,z3.Or(v.read('x0')!=args+0x6c,v.read('x1')!=R.OPTION,v.read('x2')!=R.CONTROL,v.read('x3')!=4,v.read('x4')!=0,v.next!=R.PARSE))
 v=local();v.regions=[(R.CONTROL,4)];mode=v.load(R.CONTROL,4);v.seed('x19',R.CONTROL);cut(v,R.POST+64,R.POST+76)
 prove('post_enumeration_control_unsigned_at_least4_selects_original_diagnostic',v,v.next!=z3.If(z3.UGE(mode,4),resize(R.POST+96,64),resize(R.POST+76,64)))
 v=local();cut(v,R.POST+76,R.POST+80)
 prove('admitted_post_enumeration_mode_clears_implementation_defined_system_register',v,v.system['s3_4_c15_c10_4']!=0)
 v=local();v.regions=[(0xfffffe0007f8c7c8,1)];flag=v.load(0xfffffe0007f8c7c8,1);cut(v,R.WRAPPER+16,R.WRAPPER+32)
 prove('reg_wrapper_selects_selector0e_and_exact_original_opaque_word',v,z3.Or(v.read('x16')!=14,v.next!=z3.If(flag!=0,resize(R.WRAPPER+40,64),resize(R.WRAPPER+32,64))))
 length=z3.BitVec('TH_compare_length64',64);v=local();v.seed('x2',length);cut(v,R.COMPARE+12,R.COMPARE+20)
 prove('bounded_compare_zero_length_selects_zero_result_without_byte_load',v,z3.Or(v.read('x3')!=0,v.next!=z3.If(length==0,resize(R.COMPARE+56,64),resize(R.COMPARE+20,64))))
 left,right=CPU.P+0x6000,CPU.P+0x7000;v=local();v.regions=[(left,1),(right,1)];a=v.load(left,1);b=v.load(right,1);v.seed('x0',left);v.seed('x1',right);cut(v,R.COMPARE+0x164,R.COMPARE+0x178)
 prove('bounded_compare_byte_step_advances_both_pointers_and_stops_on_difference_or_NUL',v,z3.Or(v.read('x0')!=left+1,v.read('x1')!=right+1,v.read('x3')!=z3.ZeroExt(56,a)-z3.ZeroExt(56,b),v.next!=z3.If(z3.Or(a!=b,a==0),resize(R.COMPARE+0x180,64),resize(R.COMPARE+0x178,64))))
 return proofs,coverage

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);prior=[]
 labels={'bootstrap_thread_field_zeroextends_CPU_low16_and_binds_fixed_CPU_pointer','thread_setter_writes_system_registers_backpointer_and_preserves_TPIDR0_high16','actual_boot_thread_field_selects_zero_ASR16_SPTM_block_offset','fixed_boot_CPU_data_address_skips_direct_SPTM_initialization_call'}
 for p in json.loads(read(ROOT/(B.P+'_audit.json')))['source_proofs']:
  if p['label'] not in labels:continue
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat;prior.append({**p,'source_artifact_sha256':sha(ROOT/(B.P+'_audit.json'))})
 assert len(prior)==4;image=Image();components=[];replays=[];totals=Counter()
 for c in CPU.cases():
  row=CPU.Probe(image,c).run();row['independent_oracle']=oracle(row);replay=Replay(image,row).run();components.append(row);replays.append(replay);totals.update(replay);print('case',c['label'],len(row['source_visits']),flush=True)
 cases=CPU.cases();controls=[]
 for c,pc in [(cases[0],0xfffffe000be834b8),(cases[0],0xfffffe000be833ac),(cases[2],0xfffffe000be832f0),(cases[0],0xfffffe000be83244),(cases[0],R.POST+76)]:
  row=CPU.Probe(image,c,pc).run()
  try:oracle(row)
  except AssertionError as error:controls.append({'component':row,'oracle_rejection':{'kind':error.args[0][0],'label':error.args[0][1]}})
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
 source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={v['PC'] for c in components for v in c['source_visits']};assert visited<=source and not visited&{p['PC'] for p in e['opaque_words']}
 stats={'source_queries_unsat':len(proofs),'prior_source_queries_rechecked':len(prior),'proved_source_PCs':len({pc for c in coverage for pc in c['PCs']}),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),
  'components':len(components),'source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(visited),'changed_source_controls':len(controls),
  'independent_topology_and_post_helper_checks':sum(len(c['independent_oracle']['checks']) for c in components),'independent_thread_handoff_checks':sum(len(c['independent_oracle']['thread_handoff_oracle']['checks']) for c in components if c['independent_oracle']['thread_handoff_oracle']),
  'completed_admitted_CPU_records':sum(len(c['independent_oracle']['completed_admitted_records']) for c in components),'source_boot_record_handoffs':sum(len(c['source_boot_record_snapshots']) for c in components),'same_RAM_explicit_caller_epochs':sum(len(c['epochs']) for c in components),
  'original_comparison_entries':sum(len(c['original_comparison_entries']) for c in components),'declared_selector0e_calls':sum(len(c['declared_selector0e_calls']) for c in components),
  'original_post_helper_returns':sum(len(c['source_main_continuation_checkpoints']) for c in components),
  'independent_topology_nonstack_bytes_checked':sum(c['independent_oracle']['independent_topology_nonstack_bytes_checked'] for c in components),'independent_post_helper_nonstack_bytes_checked':sum(c['independent_oracle']['independent_post_helper_nonstack_bytes_checked'] for c in components),
  'independent_thread_nonstack_bytes_checked':sum(c['independent_oracle']['thread_handoff_oracle']['independent_nonstack_bytes_checked'] for c in components if c['independent_oracle']['thread_handoff_oracle'])}
 function_coverage=[{'start':f['start'],'captured_words':len(f['instructions']),'executed_unique_PCs':len({i['ea'] for i in f['instructions']}&visited)} for f in e['functions']]
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_cpu_topology_handoff.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'coverage':coverage,'components':components,'independent_replays':replays,'negative_controls':controls,'independent_totals':stats,'independent_replay_totals':dict(totals),
  'executed_function_coverage':function_coverage,'unexecuted_source_PCs':sorted(source-visited),'conditional_kernel_cpu_topology_handoff_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
