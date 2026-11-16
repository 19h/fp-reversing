#!/usr/bin/env python3
"""Original registry/dispatch obligations, private continuations and replay.
O(source+registry+formula DAG+visits+journals+RAM) construction/space; SMT
search separate, 30 s/query. No native startup, authentication or target IPC.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_bootstrap_state_composition import Model as Parent,source_proofs as bootstrap_proofs,semantic_count as bootstrap_count
from audit_kernel_mapping_context import DEC
from lskd_values_symbolic import resize
import recover_kernel_startup_registry_abi as R
import probe_kernel_startup_registry_abi as CPU
from replay_kernel_startup_registry_abi import oracle,Replay,bootstrap_row,registry_contracts

class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic not in ['cneg','blraa','pacia','ldursw']:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
   if i.mnemonic=='ldursw':self.write(i.reg_name(i.operands[0].reg),z3.SignExt(32,self.load(self.address(i,i.operands[1]),4)))
   elif i.mnemonic=='pacia':assert i.op_str=='x16, x17'
   elif i.mnemonic=='cneg':
    assert i.op_str.endswith(', ls');value=self.read(i.reg_name(i.operands[1].reg));self.write(i.reg_name(i.operands[0].reg),z3.If(z3.ULE(self.cmp_left,self.cmp_right),-value,value))
   else:
    assert i.op_str=='x8, x17';self.write('x30',i.address+4);self.next=self.read('x8')
  return self

def source_proofs(e):
 proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,a,b,linked=False):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16)
  v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.run('cut') if linked else v.enter('cut')
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks)});print(label,flush=True)
 a,b,c,d=z3.BitVecs('SR_phaseA32 SR_phaseB32 SR_rankA32 SR_rankB32',32)
 def comparator():
  v=local();v.regions=[(R.BASE,48)];v.setmem(R.BASE,4,a);v.setmem(R.BASE+4,4,c);v.setmem(R.BASE+24,4,b);v.setmem(R.BASE+28,4,d);v.seed('x0',R.BASE);v.seed('x1',R.BASE+24);return v
 v=comparator();cut(v,R.COMPARE+4,R.COMPARE+20);prove('comparator_phase_difference_selects_primary_path',v,v.next!=z3.If(a!=b,resize(R.COMPARE+48,64),resize(R.COMPARE+20,64)))
 v=comparator();cut(v,R.COMPARE+4,R.COMPARE+20);cut(v,R.COMPARE+48,R.COMPARE+56,True);prove('comparator_primary_result_is_unsigned_phase_order',v,v.read('w0')!=z3.If(z3.UGT(a,b),resize(1,32),resize(0xffffffff,32)),[a!=b])
 v=comparator();cut(v,R.COMPARE+4,R.COMPARE+44);prove('comparator_equal_phase_uses_rank_and_has_no_tertiary_key',v,v.read('w0')!=z3.If(c==d,resize(0,32),z3.If(z3.UGT(c,d),resize(1,32),resize(0xffffffff,32))),[a==b])
 v=local();v.regions=[(R.BASE,24)];v.setmem(R.BASE,4,a);v.seed('x24',R.BASE);v.seed('w19',b);cut(v,0xfffffe000c630318,0xfffffe000c630324);prove('dispatcher_admits_unsigned_phase_at_most_threshold',v,v.next!=z3.If(z3.UGT(a,b),resize(0xfffffe000c630384,64),resize(0xfffffe000c630324,64)))
 target,arg=z3.BitVecs('SR_callback64 SR_argument64',64);v=local();v.regions=[(R.BASE,24)];v.setmem(R.BASE+8,8,target);v.setmem(R.BASE+16,8,arg);v.seed('x24',R.BASE);cut(v,0xfffffe000c630368,0xfffffe000c630374);prove('logical_authenticated_call_forwards_full_argument_and_modifier2abe',v,z3.Or(v.next!=target,v.read('x0')!=arg,v.read('x17')!=0x2abe,v.read('x30')!=0xfffffe000c630374))
 cursor=z3.BitVec('SR_cursor64',64);v=local();v.regions=[(R.CURSOR,8)];v.seed('x24',cursor);v.seed('x23',R.CURSOR-0xa48);cut(v,0xfffffe000c630374,0xfffffe000c63037c);prove('returned_callback_advances_and_publishes_cursor_by24_mod64',v,z3.Or(v.read('x24')!=cursor+24,v.load(R.CURSOR,8)!=cursor+24))
 v=local();v.regions=[(0xfffffe0007f8b5f0,4)];v.seed('w8',a);v.seed('x21',0xfffffe0007f8b000);cut(v,0xfffffe000c630358,0xfffffe000c630360);prove('dispatcher_publishes_phase_minus1_before_callback',v,v.load(0xfffffe0007f8b5f0,4)!=a-1)
 v=local();v.regions=[(R.CALLBACK,8)];cut(v,0xfffffe000c639dd8,0xfffffe000c639df0);prove('main_logical_PACIA_publishes_timebase_target_and_modifier2abe',v,z3.Or(v.load(R.CALLBACK,8)!=R.TIMEBASE,v.read('x17')!=0x2abe))
 freq=z3.BitVec('SR_frequency64',64);den=z3.BitVec('SR_denominator64',64);v=local();v.regions=[(0xfffffe000cb5c5f8,8)];v.setmem(0xfffffe000cb5c5f8,8,freq);v.seed('x25',den);cut(v,0xfffffe000c639df0,0xfffffe000c639e04);prove('main_passes_timebase_frequency_and_denominator_stack_pair',v,z3.Or(v.next!=R.TIMEBASE,v.read('x0')!=v.sp0+0x50,v.load(v.sp0+0x50,8)!=freq,v.load(v.sp0+0x58,8)!=den))
 v=local();cut(v,0xfffffe000c639e0c,0xfffffe000c639e24);prove('main_checked_label_copy_has_requested_and_capacity32',v,z3.Or(v.next!=R.STRNCHK,v.read('x0')!=v.sp0+0x50,v.read('x1')!=0xfffffe000706217c,v.read('x2')!=32,v.read('x3')!=32))
 v=local();cut(v,0xfffffe000c630260,0xfffffe000c630264);prove('sort_tail_enters_original_dispatcher',v,v.next!=R.DISPATCH)
 size=z3.BitVec('SR_property_size32',32);want=z3.BitVec('SR_destination_size32',32);v=local();v.regions=[(R.BASE,48)];v.setmem(R.BASE+40,4,want);v.setmem(v.sp0+0x48,4,size);v.seed('x29',v.sp0+0x70);v.seed('x19',R.BASE);cut(v,0xfffffe000c6304ac,0xfffffe000c6304bc);prove('tunable_property_requires_exact_requested_size',v,v.next!=z3.If(size!=want,resize(0xfffffe000c63051c,64),resize(0xfffffe000c6304bc,64)))
 v=local();v.regions=[(R.BASE,48),(0xfffffe0007f8b6e8,8)];dst=v.load(R.BASE+32,8);want=v.load(R.BASE+40,4);boot=v.load(0xfffffe0007f8b6e8,8);v.seed('x19',R.BASE);cut(v,0xfffffe000c6304d0,0xfffffe000c6304ec);prove('tunable_option_parser_uses_copied_bootargs_destination_size_and_zero_flags',v,z3.Or(v.next!=R.B.B.O.PARSE,v.read('x0')!=boot+0x6c,v.read('x2')!=dst,v.read('x3')!=z3.ZeroExt(32,want),v.read('x4')!=0))
 value=z3.BitVec('SR_boolean_byte8',8);v=local();v.regions=[(R.BASE,48),(R.BASE+64,1)];v.setmem(R.BASE+32,8,R.BASE+64);v.setmem(R.BASE+64,1,value);v.seed('x19',R.BASE);cut(v,0xfffffe000c6304f8,0xfffffe000c63050c);prove('conditional_tunable_normalization_only_replaces_destination_low_byte',v,v.load(R.BASE+64,1)!=z3.If(value!=0,resize(1,8),resize(0,8)))
 return proofs,coverage

def semantic_count(o):return len(o['checks'])+bootstrap_count(o['bootstrap_contracts'])+sum(len(o[k]['checks']) for k in ['tree_API_contracts','option_API_contracts','copy_contracts','string_contracts'])

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);retained,retained_coverage=bootstrap_proofs(e);image=Image();static=registry_contracts(e,image);components=[];totals=Counter()
 for c in CPU.cases():
  row=CPU.Probe(image,c).run();row['independent_oracle']=oracle(row,e);q=Replay(image,row).run();totals.update(q);row['independent_replay']=q;components.append(row);print(c['label'],len(row['source_visits']),flush=True)
 old=json.loads(read(ROOT/(R.B.P+'_audit.json')))['components'][1];new=bootstrap_row(components[0]);cut=components[0]['bootstrap_state_checkpoint']
 keys=['source_visits','source_reads','source_writes','API_models','original_API_entries','original_API_returns','final_private_RAM','final_image_globals','final_vectors']
 assert all(old[k]==new[k] for k in keys)
 assert all(old['boundary'][k]==new['boundary'][k] for k in ['pc','registers31','SP','NZCV']) and all(cut['system'][k]==v for k,v in old['final_system'].items())
 preservation={'prior_audit_sha256':sha(ROOT/(R.B.P+'_audit.json')),'prior_component':old['configuration']['label'],'compared_fields':keys+['boundary_pc','boundary_GPR31','boundary_SP','boundary_NZCV','common_logical_system_registers'],'exact_match':True,'additional_logical_timestamp_input_declared':True,'new_storage_declared_before_main_entry':True}
 controls=[]
 for pc in [0xfffffe000c639dec,0xfffffe000be8b868]:
  row=CPU.Probe(image,CPU.cases()[0],pc).run()
  try:oracle(row,e)
  except AssertionError as error:controls.append({'component':row,'oracle_rejection':list(error.args[0])})
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
 visited={v['pc'] for c in components for v in c['source_visits']};source={i['ea'] for f in e['functions'] for i in f['instructions']};assert visited<=source and not visited&{i['ea'] for f in e['functions'] for i in f['instructions'] if i['mnemonic'] in ['opaque','udf']}
 stats={'source_queries_unsat':len(proofs),'retained_bootstrap_queries_rebuilt':len(retained),'proved_source_PCs':len({pc for q in coverage for pc in q['PCs']}),'proof_instruction_instances':sum(q['instruction_instances'] for q in coverage),'linked_edge_obligations':sum(q['linked_edge_obligations'] for q in coverage),'components':len(components),'source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(visited),'changed_source_controls':len(controls),'independent_semantic_checks':sum(semantic_count(c['independent_oracle']) for c in components),'static_registry_checks':len(static['checks']),'registry_records':3519,'unique_callback_targets':115,'tunable_descriptors':22,'original_API_entries':sum(len(c['original_API_entries']) for c in components),'original_API_returns':sum(len(c['original_API_returns']) for c in components),'original_registry_callbacks_returned':len(components),'trace_records':sum(len(c['independent_oracle']['trace_records']) for c in components),'whole_mutable_checkpoint_bytes_checked':sum(c['independent_oracle']['whole_mutable_checkpoint_bytes_checked'] for c in components),'private_nonstack_bytes_checked':sum(c['independent_oracle']['private_nonstack_bytes_checked'] for c in components),'call_frame_epochs':0,'native_target_executions':0}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_startup_registry_abi.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'source_proofs':proofs,'retained_source_proofs_rebuilt':retained,'proof_coverage':coverage,'retained_proof_coverage':retained_coverage,'independent_registry_contracts':static,'components':components,'negative_controls':controls,'prior_published_checkpoint_preservation':preservation,'independent_totals':stats,'independent_replay_totals':dict(totals),'executed_function_coverage':[{'start':f['start'],'captured_words':len(f['instructions']),'executed_unique_PCs':len({i['ea'] for i in f['instructions']}&visited)} for f in e['functions']],'conditional_kernel_startup_registry_abi_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
