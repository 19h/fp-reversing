#!/usr/bin/env python3
"""Original-source contracts and producer-to-consumer private state joins.
O(source + query DAG + visits + journals + RAM) construction/space; solver
search separate,30 s/query. Native boot, range ownership and SPTM unknown.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_mapping_transport import Model as Parent,DEC
from lskd_values_symbolic import resize
import recover_kernel_mapping_context as R
import probe_kernel_mapping_context as CPU
from replay_kernel_mapping_context import Replay

class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   vector=i.mnemonic in ['ldr','str'] and i.reg_name(i.operands[0].reg)[0] in 'qds'
   if not vector and i.mnemonic!='sturh':
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
   if i.mnemonic=='sturh':self.store(self.address(i,i.operands[1]),2,self.read(i.reg_name(i.operands[0].reg)),i.address);continue
   name=i.reg_name(i.operands[0].reg);n={'q':16,'d':8,'s':4}[name[0]];key='v'+name[1:];at=self.address(i,i.operands[1])
   if i.mnemonic=='ldr':self.vectors[key]=resize(self.load(at,n),128)
   else:self.store(at,n,resize(self.vectors[key],n*8),i.address)
  return self

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,label,a,b):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16)
  v.e=v.c={'spans':[{'label':label,'start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.enter(label)
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks),
   'checked_read_store_rewrites':list(v.separation_rewrites.values())});print(label,flush=True)
 v=local();v.regions=[(R.BOOTROOT,8),(R.ROOTPAIR,16)];root=v.load(R.BOOTROOT,8)
 cut(v,'root_copy',0xfffffe000be74108,0xfffffe000be74124)
 prove('ARM_root_pair_physical_word_and_original_P2V_call_share_exact_boot_root',v,z3.Or(v.load(R.ROOTPAIR,8)!=root,v.read('x0')!=root,v.read('x1')!=v.sp0+0x48,v.next!=R.P2V))
 v=local();v.regions=[(R.ROOTPAIR,16)];converted=z3.BitVec('MC_root_alias64',64);status=z3.BitVec('MC_root_status32',32);v.setmem(v.sp0+0x48,8,converted);v.seed('w0',status)
 cut(v,'root_publish',0xfffffe000be74124,0xfffffe000be74138)
 prove('ARM_root_alias_publication_is_conversion_output_on_zero_status_else_zero',v,v.load(R.ROOTPAIR+8,8)!=z3.If(status==0,converted,resize(0,64)))
 v=local();request=z3.BitVec('MC_ARM_request64',64);v.setmem(v.sp0+0x30,8,request)
 cut(v,'caller_request',0xfffffe000be75444,0xfffffe000be7545c)
 prove('context_initializer_receives_modular_32MiB_rounded_ARM_request',v,z3.Or(v.next!=R.INIT,v.read('x0')!=((request+0x1ffffff)&0xfffffffffe000000)))
 v=local();v.regions=[(R.T.CTX,128)]
 cut(v,'geometry_pointer',0xfffffe000be60934,0xfffffe000be60948)
 prove('initializer_publishes_original_geometry_object_at_context_offset20',v,v.load(R.T.CTX+0x20,8)!=R.GEOM)
 v=local();v.regions=[(R.T.CTX,128),(R.ROOTPAIR,16)];physical=v.load(R.ROOTPAIR,8);alias=v.load(R.ROOTPAIR+8,8);v.seed('x24',R.T.CTX)
 cut(v,'context_roots',0xfffffe000be6094c,0xfffffe000be60960)
 prove('context_words0_and1_receive_virtual_and_raw_physical_root_pair',v,z3.Or(v.load(R.T.CTX,8)!=alias,v.load(R.T.CTX+8,8)!=physical))
 v=local();v.regions=[(R.T.CTX,128),(0xfffffe000700f340,16)];bounds=int.from_bytes(bytes.fromhex(e['bounds_literal']['bytes_hex']),'little');v.setmem(0xfffffe000700f340,16,resize(bounds,128));v.seed('x24',R.T.CTX)
 cut(v,'context_bounds',0xfffffe000be60960,0xfffffe000be6096c)
 prove('original_Q_literal_sets_lower_ffff800000000000_upper_ffffffffffffffff',v,z3.Or(v.load(R.T.CTX+0x10,8)!=0xffff800000000000,v.load(R.T.CTX+0x18,8)!=0xffffffffffffffff))
 v=local();v.regions=[(R.T.CTX,128)];v.seed('x24',R.T.CTX)
 cut(v,'context_kind',0xfffffe000be6096c,0xfffffe000be60980)
 prove('context_kind1_and_byte76_value1_are_source_stores',v,z3.Or(v.load(R.T.CTX+0x68,4)!=1,v.load(R.T.CTX+0x6e,1)!=0,v.load(R.T.CTX+0x75,2)!=0x100))
 v=local();count=z3.BitVec('MC_count32',32);v.seed('w8',count)
 cut(v,'bitmap_budget',0xfffffe000be609ac,0xfffffe000be609b8)
 prove('bitmap_byte_budget_uses_u32_add63_wrap_shift3_and_mask1ffffff8',v,v.read('w25')!=(z3.LShR(count+63,3)&0x1ffffff8))
 v=local();v.regions=[(R.BUMP,8)];bump=v.load(R.BUMP,8);v.seed('x21',0xfffffe0007e6d000)
 cut(v,'bump_align8',0xfffffe000be609c0,0xfffffe000be609d0)
 prove('bump_first_alignment_is_modular_add7_and_clear_low3',v,z3.Or(v.read('x20')!=((bump+7)&0xfffffffffffffff8),v.load(R.BUMP,8)!=((bump+7)&0xfffffffffffffff8)))
 v=local();v.regions=[(R.BUMP,8)];bump=v.load(R.BUMP,8);budget=z3.BitVec('MC_budget64',64);v.seed('x21',0xfffffe0007e6d000);v.seed('x25',budget)
 cut(v,'bump_carry',0xfffffe000be609f4,0xfffffe000be60a08);partial=bump+budget;carry=z3.ULT(partial+16383,partial)
 prove('bump_roundup_diagnostic_tests_only_second_add_carry',v,v.next!=z3.If(carry,resize(0xfffffe000be60d20,64),resize(0xfffffe000be60a08,64)))
 v=local();v.regions=[(R.BUMP,8)];value=z3.BitVec('MC_bump_sum64',64);v.seed('x8',value);v.seed('x21',0xfffffe0007e6d000)
 cut(v,'bump_round16k',0xfffffe000be60a08,0xfffffe000be60a10)
 prove('bump_published_after_roundup_has_low14_bits_clear',v,v.load(R.BUMP,8)!=(value&0xffffffffffffc000))
 v=local();head=0xfffffe000cb0c028;v.regions=[(head,16),(R.T.CTX,128)];v.seed('x24',R.T.CTX)
 cut(v,'context_queue',0xfffffe000be60a38,0xfffffe000be60a4c)
 prove('queue_head_points_to_context_and_context_pair_points_to_head',v,z3.Or(v.load(head,8)!=R.T.CTX,v.load(head+8,8)!=R.T.CTX,v.load(R.T.CTX+0x30,8)!=head,v.load(R.T.CTX+0x38,8)!=head))
 v=local();v.regions=[(R.ASID_COUNT,8)];count=v.load(R.ASID_COUNT,4);v.seed('x22',0xfffffe0007e6c000)
 cut(v,'normalized_count',0xfffffe000be60b68,0xfffffe000be60b78)
 prove('count_publishes_u32_floor64_then_diagnoses_zero',v,z3.Or(v.load(R.ASID_COUNT,4)!=(count&0xffffffc0),v.next!=z3.If((count&0xffffffc0)==0,resize(0xfffffe000be60cf4,64),resize(0xfffffe000be60b78,64))))
 v=local();count=z3.BitVec('MC_normalized_count32',32);v.regions=[(R.ASID_COUNT+4,4)];v.seed('w8',count)
 cut(v,'default_policy',0xfffffe000be60b78,0xfffffe000be60b8c)
 prove('default_policy_word_is_unsigned_normalized_count_greater_than256',v,v.load(R.ASID_COUNT+4,4)!=z3.If(z3.UGT(count,256),resize(1,32),resize(0,32)))
 v=local();thread=CPU.THREAD;data=CPU.CPUDATA;v.thread=resize(thread,64);v.regions=[(thread,0x280),(data,4096)];v.setmem(thread+0x1c0,8,data);threadfield=z3.BitVec('MC_thread_field64',64);cpu=z3.BitVec('MC_cpu32',32);v.setmem(thread+0x1b8,8,threadfield);v.seed('w0',cpu)
 cut(v,'CPU_block',0xfffffe000be7350c,0xfffffe000be73528)
 prove('CPU_data_index_store_and_signed_thread_field_ASR16_block_address',v,z3.Or(v.load(data+0x8e8,4)!=cpu,v.read('x21')!=resize(R.T.CPU_BASE,64)+(threadfield>>16)))
 v=local();ident=z3.BitVec('MC_transport_identifier64',64);v.regions=[(R.SHARED,8),(CPU.P,8192)];shared=v.load(R.SHARED,8);v.seed('x21',CPU.P);v.seed('x0',ident)
 cut(v,'identifier_widths',0xfffffe000be735f8,0xfffffe000be73610)
 prove('identifier_saved_full64_stored_low16_and_shared_indexed_by_zero_extended_low32_shift15',v,z3.Or(v.read('x19')!=ident,v.load(CPU.P+0x1d78,2)!=z3.Extract(15,0,ident),v.read('x0')!=shared+(z3.ZeroExt(32,z3.Extract(31,0,ident))<<15)))
 v=local();v.regions=[(CPU.P,16)];status=z3.BitVec('MC_shared_status32',32);alias=z3.BitVec('MC_shared_alias64',64);v.setmem(v.sp0+0x28,8,alias);v.seed('w0',status);v.seed('x21',CPU.P)
 cut(v,'shared_alias',0xfffffe000be7361c,0xfffffe000be7362c)
 prove('CPU_shared_alias_stored_only_on_zero_conversion_status',v,v.load(CPU.P+8,8)!=z3.If(status==0,alias,resize(0,64)))
 v=local();v.regions=[(CPU.P,8)];returned=z3.BitVec('MC_returned_result_pointer64',64);v.seed('x21',CPU.P);v.seed('x0',returned)
 cut(v,'result_pointer',0xfffffe000be73634,0xfffffe000be73638)
 prove('CPU_result_pointer_producer_stores_full_raw_SPTM_return',v,v.load(CPU.P,8)!=returned)
 v=local();v.regions=[(CPU.TABLE,24),(CPU.OUTPUT,8)];base=v.load(CPU.TABLE+8,8);delta=z3.BitVec('MC_P2V_delta64',64);v.seed('x11',CPU.TABLE+16);v.seed('x12',delta);v.seed('x1',CPU.OUTPUT)
 cut(v,'P2V_success',0xfffffe000c62023c,0xfffffe000c620250)
 prove('selected_P2V_record_publishes_virtual_base_plus_offset_and_status0',v,z3.Or(v.load(CPU.OUTPUT,8)!=base+delta,v.read('w0')!=0),[base+delta!=0])
 v=local();v.regions=[(CPU.TABLE,24)];base=v.load(CPU.TABLE,8);delta=z3.BitVec('MC_V2P_delta64',64);v.seed('x11',CPU.TABLE);v.seed('x12',delta)
 cut(v,'V2P_selected',0xfffffe000c6455a0,0xfffffe000c6455ac)
 prove('selected_V2P_record_returns_physical_base_plus_offset_to_common_success',v,z3.Or(v.read('x8')!=base+delta,v.next!=0xfffffe000c645354))
 for address,selector in [(R.IDENT,0x13),(R.RESULT,0x32)]:
  v=local();v.regions=[(R.T.TRANSPORT_FLAG,1)];flag=v.load(R.T.TRANSPORT_FLAG,1)
  cut(v,'wrapper'+str(selector),address+16,address+32)
  prove('SPTM_wrapper_selector_'+hex(selector)+'_and_opaque_word_branch',v,z3.Or(v.read('x16')!=selector,v.next!=z3.If(flag!=0,resize(address+40,64),resize(address+32,64))))
 v=local();v.regions=[(R.ASID_COUNT,4)];v.setmem(R.ASID_COUNT,4,0);v.seed('x22',0xfffffe0007e6c000)
 cut(v,'zero_count',0xfffffe000be60a64,0xfffffe000be60a74)
 prove('zero_count_underflows_u32_minus1_and_enters_bulk_bitmap_path',v,z3.Or(v.read('w11')!=0xffffffff,v.next!=0xfffffe000be60a80))
 prior=[]
 for p in json.loads(read(ROOT/(R.T.P+'_audit.json')))['source_proofs']:
  if p['label'] not in ['selected_transport_receives_root_VA_descriptor_and_zero','result_record_word0_copies_to_argument5_word1_to_argument2']:continue
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat;prior.append({**p,'source_artifact_sha256':sha(ROOT/(R.T.P+'_audit.json'))})
 assert len(prior)==2
 image=Image();components=[];replays=[];totals=Counter();joins=[]
 for c in CPU.configurations():
  parent=None;previous=None
  for phase in ['root','context','cpu','gate','backend']:
   row=CPU.Probe(image,c,phase,parent).run();row['independent_oracle_checks']=CPU.oracle(row);index=len(components)
   if parent is not None:joins.append({'parent_component':previous,'child_component':index,'scope':'Exact previous private RAM and all tracked globals transferred; new declared call registers/stack and documented failure input remain explicit'})
   components.append(row);r=Replay(image,row,parent).run();replays.append(r);totals.update(r);parent=row;previous=index
   if row['boundary']['kind']!='source_component_complete':break
  print('configuration',c,'complete',flush=True)
 negative=[];base=CPU.configurations()[0]
 for phase,pc,parent in [('root',0xfffffe000be74114,None),('context',0xfffffe000be60944,components[0]),('cpu',0xfffffe000be73634,components[1])]:
  row=CPU.Probe(image,base,phase,parent,pc).run()
  try:CPU.oracle(row)
  except AssertionError as error:negative.append({'component':row,'oracle_rejection':error.args[0][0]})
  else:raise AssertionError('changed source accepted')
 source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={i['pc'] for c in components for i in c['source_visits']}
 stats={'source_queries_unsat':len(proofs),'prior_source_queries_rechecked':len(prior),'configurations':len(CPU.configurations()),'components':len(components),
  'component_source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(source&visited),
  'proved_source_PCs':len({pc for c in coverage for pc in c['PCs']}),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),
  'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'independent_oracle_checks':sum(len(c['independent_oracle_checks']) for c in components),
  'changed_source_controls':len(negative),'exact_state_joins':len(joins),'complete_five_component_chains':sum(c['phase']=='backend' for c in components)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_mapping_context.py'),
  'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],
  'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'coverage':coverage,'components':components,'independent_replays':replays,'exact_state_joins':joins,
  'independent_replay_totals':dict(totals),'negative_controls':negative,'unexecuted_source_PCs':sorted(source-visited),'independent_totals':stats,
  'conditional_kernel_mapping_context_contract_established':True,**{k:False for k in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
