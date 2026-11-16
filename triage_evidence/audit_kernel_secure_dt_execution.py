#!/usr/bin/env python3
"""Local original-source contracts and independently decoded tree witnesses.
O(source + formula DAG + visits + journals + mapped bytes) space/construction;
SMT search separate, 30 s/query. No native boot, parser or receiver claim.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_cpu_topology_handoff import Model as Parent
from audit_kernel_mapping_context import DEC
from lskd_values_symbolic import resize
import recover_kernel_secure_dt_execution as R
import probe_kernel_secure_dt_execution as CPU
from replay_kernel_secure_dt_execution import oracle,Replay
B=R.B
class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic!='sxtb':
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
   self.write(i.reg_name(i.operands[0].reg),z3.SignExt(24,z3.Extract(7,0,self.read(i.reg_name(i.operands[1].reg)))))
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
 base,extent=z3.BitVecs('DT_base64 DT_extent64',64);v=local();v.seed('x0',base);v.seed('x1',extent);cut(v,R.INIT+4,R.INIT+12)
 prove('initializer_addition_carry_selects_diagnostic_before_publication',v,v.next!=z3.If(z3.ULT(base+extent,base),resize(R.INIT+60,64),resize(R.INIT+12,64)))
 v=local();v.regions=[(R.GLOBALS,32)];v.seed('x0',base);v.seed('x1',extent);cut(v,R.INIT+12,R.INIT+56)
 prove('initializer_publishes_base_size_modular_end_and_nonnull_flag',v,z3.Or(v.load(R.GLOBALS,8)!=base,v.load(R.GLOBALS+8,8)!=extent,v.load(R.GLOBALS+16,8)!=base+extent,v.load(R.GLOBALS+24,4)!=z3.If(base!=0,resize(1,32),resize(0,32))))
 pointer=z3.BitVec('DT_node64',64);v=local();v.seed('x0',pointer);cut(v,B.PROPERTY+36,B.PROPERTY+40)
 prove('null_property_node_selects_failure_without_node_read',v,v.next!=z3.If(pointer==0,resize(B.PROPERTY+240,64),resize(B.PROPERTY+40,64)))
 v=local();cut(v,B.PROPERTY+240,B.PROPERTY+244);prove('property_miss_returns_zeroextended_ffffffff',v,v.read('x0')!=0xffffffff)
 out=CPU.WORK;record=CPU.TREE+0x100;data=z3.BitVec('DT_property_data64',64);length=z3.BitVec('DT_property_length32',32)
 v=local();v.regions=[(out,16),(record+32,4)];v.setmem(record+32,4,length);v.seed('x19',record);v.seed('x21',out);v.seed('x20',out+8);v.seed('x27',data);cut(v,B.PROPERTY+276,B.PROPERTY+292)
 prove('property_hit_publishes_full_pointer_u32_length_and_status1',v,z3.Or(v.load(out,8)!=data,v.load(out+8,4)!=length,v.read('x0')!=1))
 v=local();v.regions=[(record+32,4)];v.setmem(record+32,4,length);v.seed('x19',record);cut(v,B.PROPERTY+192,B.PROPERTY+224)
 prove('property_advance_rounds_header36_plus_length_to_four_bytes',v,z3.Or(v.read('x19')!=((record+z3.ZeroExt(32,length)+39)&~resize(3,64)),v.next!=B.PROPERTY+224))
 iterator=out+0x40;root=CPU.TREE;ordinal=z3.BitVec('DT_iterator_ordinal64',64);count=z3.BitVec('DT_child_count32',32)
 v=local();v.regions=[(iterator,40),(root,8)];v.setmem(iterator+32,8,ordinal);v.setmem(iterator+8,8,root);v.setmem(root+4,4,count);v.seed('x0',iterator);cut(v,B.ITERATE+20,B.ITERATE+40)
 prove('iterator_compares_u64_index_with_zeroextended_child_count',v,v.next!=z3.If(z3.UGE(ordinal,z3.ZeroExt(32,count)),resize(B.ITERATE+100,64),resize(B.ITERATE+40,64)))
 v=local();v.regions=[(iterator+32,8)];v.seed('x0',iterator);v.seed('x8',ordinal);cut(v,B.ITERATE+40,B.ITERATE+48)
 prove('iterator_increments_index_before_first_or_next_child_path',v,v.load(iterator+32,8)!=ordinal+1)
 v=local();cut(v,B.ITERATE+100,B.ITERATE+112);prove('iterator_exhaustion_sets_null_pointer_and_status0',v,z3.Or(v.read('x0')!=0,v.read('w8')!=0,v.next!=B.ITERATE+252))
 result=z3.BitVec('DT_iterator_result64',64);status=z3.BitVec('DT_iterator_status32',32);v=local();v.regions=[(out,8)];v.seed('x0',result);v.seed('w8',status);v.seed('x1',out);cut(v,B.ITERATE+252,B.ITERATE+260)
 prove('iterator_always_stores_output_and_zeroextends_status',v,z3.Or(v.load(out,8)!=result,v.read('x0')!=z3.ZeroExt(32,status)))
 v=local();v.regions=[(R.GLOBALS,8)];rootvalue=v.load(R.GLOBALS,8);v.seed('x0',pointer);cut(v,B.LOOKUP+72,B.LOOKUP+88)
 prove('lookup_null_start_selects_global_root_otherwise_given_node',v,v.read('x23')!=z3.If(pointer==0,rootvalue,pointer))
 v=local();v.regions=[(out,8)];v.seed('x19',out);v.seed('x23',pointer);cut(v,B.LOOKUP+516,B.LOOKUP+528)
 prove('lookup_success_writes_selected_node_and_status1',v,z3.Or(v.load(out,8)!=pointer,v.read('x0')!=1,v.next!=B.LOOKUP+464))
 v=local();cut(v,B.LOOKUP+460,B.LOOKUP+464);prove('lookup_miss_returns_zeroextended_ffffffff',v,v.read('x0')!=0xffffffff)
 v=local();v.regions=[(record+32,4)];v.setmem(record+32,4,length);v.seed('x0',record);cut(v,R.SKIP+84,R.SKIP+116)
 prove('subtree_skip_property_step_uses_four_byte_record_alignment',v,z3.Or(v.read('x0')!=((record+z3.ZeroExt(32,length)+39)&~resize(3,64)),v.next!=R.SKIP+116))
 left,right=CPU.TREE+0x800,CPU.TREE+0x900;v=local();v.regions=[(left,1),(right,1)];a=v.load(left,1);b=v.load(right,1);v.seed('x0',left);v.seed('x1',right);cut(v,R.STRCMP+4,R.STRCMP+16)
 prove('strcmp_reads_unsigned_bytes_advances_pointers_and_signextends_left8',v,z3.Or(v.read('x0')!=left+1,v.read('x1')!=right+1,v.read('w10')!=z3.ZeroExt(24,a),v.read('w8')!=z3.SignExt(24,a),v.read('w9')!=z3.ZeroExt(24,b)))
 v=local();v.seed('w8',z3.SignExt(24,a));v.seed('w9',z3.ZeroExt(24,b));cut(v,R.STRCMP+36,R.STRCMP+44)
 prove('strcmp_difference_subtracts_signed8_values_modulo32',v,v.read('w0')!=z3.SignExt(24,a)-z3.SignExt(24,b))
 v=local();cut(v,R.STRCMP+28,R.STRCMP+32);prove('strcmp_equal_NUL_path_returns_zero',v,v.read('x0')!=0)
 v=local();v.regions=[(R.CURSOR,8)];v.seed('w11',length);v.seed('x0',record);v.seed('x27',R.CURSOR-0xe8);cut(v,B.FIND+200,B.FIND+228);cut(v,B.FIND+232,B.FIND+236,True)
 prove('named_scan_advances_shared_cursor_before_comparing_property',v,v.load(R.CURSOR,8)!=record+36+z3.ZeroExt(32,(length+3)&~resize(3,32)),[z3.ULE(length,CPU.TREE_SIZE)])
 v=local();v.regions=[(out,8)];v.seed('x19',out);v.seed('x24',pointer);cut(v,B.FIND+268,B.FIND+272);prove('named_scan_success_publishes_containing_node',v,v.load(out,8)!=pointer)
 v=local();cut(v,B.LOOKUP+144,B.LOOKUP+152);prove('lookup_component_buffer_budget_starts_at63',v,z3.Or(v.read('x8')!=v.sp0+0x30,v.read('x9')!=63))
 return proofs,coverage

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);prior=[]
 for p in json.loads(read(ROOT/(B.P+'_audit.json')))['rechecked_prior_source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat;prior.append({**p,'topology_audit_sha256':sha(ROOT/(B.P+'_audit.json'))})
 image=Image();components=[];replays=[];totals=Counter()
 for c in CPU.cases():
  row=CPU.Probe(image,c).run();row['independent_oracle']=oracle(row);q=Replay(image,row).run();components.append(row);replays.append(q);totals.update(q);print('case',c['label'],len(row['source_visits']),flush=True)
 controls=[]
 for c,pc in [(CPU.cases()[0],R.INIT+36),(CPU.cases()[0],B.PROPERTY+284),(CPU.cases()[0],B.ITERATE+252),(CPU.cases()[1],B.FIND+268)]:
  row=CPU.Probe(image,c,pc).run()
  try:oracle(row)
  except AssertionError as error:controls.append({'component':row,'oracle_rejection':{'kind':error.args[0][0],'label':error.args[0][1]}})
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
 source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={v['PC'] for c in components for v in c['source_visits']};assert visited<=source and not visited&{p['PC'] for p in e['opaque_words']}
 stats={'source_queries_unsat':len(proofs),'prior_source_queries_rechecked':len(prior),'proved_source_PCs':len({pc for q in coverage for pc in q['PCs']}),'proof_instruction_instances':sum(q['instruction_instances'] for q in coverage),'linked_edge_obligations':sum(q['linked_edge_obligations'] for q in coverage),'components':len(components),'source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(visited),'changed_source_controls':len(controls),
  'independent_semantic_checks':sum(len(c['independent_oracle']['checks'])+len(c['independent_oracle']['original_API_contracts']['checks'])+len(c['independent_oracle']['topology']['thread_handoff_oracle']['checks']) if c['independent_oracle']['topology'] and c['independent_oracle']['topology']['thread_handoff_oracle'] else len(c['independent_oracle']['checks'])+len(c['independent_oracle']['original_API_contracts']['checks']) for c in components),
  'original_tree_API_calls':sum(len(c['original_tree_API_entries']) for c in components),'original_tree_API_returns':sum(len(c['original_tree_call_returns']) for c in components),'dedicated_API_calls':sum(len(c['tree_API_returns']) for c in components),'original1472_byte_copies':sum(len(c['original_copy_entries']) for c in components),'tree_initializer_returns':len(components),
  'source_boot_record_handoffs':sum(len(c['source_boot_record_snapshots']) for c in components),'original_post_helper_returns':sum(len(c['source_main_continuation_checkpoints']) for c in components)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_secure_dt_execution.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],
  'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'coverage':coverage,'components':components,'independent_replays':replays,'negative_controls':controls,'independent_totals':stats,'independent_replay_totals':dict(totals),'executed_function_coverage':[{'start':f['start'],'captured_words':len(f['instructions']),'executed_unique_PCs':len({i['ea'] for i in f['instructions']}&visited)} for f in e['functions']],
  'conditional_kernel_secure_dt_execution_contract_established':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
