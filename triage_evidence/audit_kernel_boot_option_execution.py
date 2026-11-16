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
from audit_kernel_secure_dt_execution import Model as Parent
from audit_kernel_mapping_context import DEC
from lskd_values_symbolic import resize
import recover_kernel_boot_option_execution as R
import probe_kernel_boot_option_execution as CPU
from replay_kernel_boot_option_execution import oracle,Replay
B=R.B
class Model(Parent):
 def condition(self,name):
  if name in ['lt','le','ge']:return self.cmp_left<self.cmp_right if name=='lt' else self.cmp_left<=self.cmp_right if name=='le' else self.cmp_left>=self.cmp_right
  return super().condition(name)
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic!='sxtw':
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1;self.write(i.reg_name(i.operands[0].reg),z3.SignExt(32,self.read(i.reg_name(i.operands[1].reg))))
  return self

def source_proofs(e):
 proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,a,b):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16);v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.enter('cut')
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown());proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks)});print(label,flush=True)
 width=z3.BitVec('BO_width32',32);v=local();v.seed('w3',width);cut(v,0xfffffe000c5e48d0,0xfffffe000c5e48d8)
 prove('reserved_width_allones_selects_return_before_input_load',v,v.next!=z3.If(width==0xffffffff,resize(0xfffffe000c5e4ba4,64),resize(0xfffffe000c5e48d8,64)))
 at=CPU.WORK;v=local();v.regions=[(at,1)];ch=v.load(at,1);v.seed('x0',at);cut(v,0xfffffe000c5e48d8,0xfffffe000c5e48e4)
 prove('first_input_NUL_selects_early_return_path',v,v.next!=z3.If(ch!=0,resize(0xfffffe000c5e48ec,64),resize(0xfffffe000c5e48e4,64)))
 v=local();cut(v,0xfffffe000c5e4920,0xfffffe000c5e4934);prove('scanner_masks_encode_NUL_TAB_SPACE_and_equals',v,z3.Or(v.read('x22')!=sum(1<<n for n in [0,9,32,61]),v.read('x19')!=sum(1<<n for n in [0,9,32])))
 token,requested=z3.BitVecs('BO_token_length64 BO_requested_length64',64);v=local();v.seed('x26',token);v.seed('x0',requested);cut(v,0xfffffe000c5e4988,0xfffffe000c5e4990)
 prove('matched_prefix_requires_equal_requested_name_length',v,v.next!=z3.If(token!=requested,resize(0xfffffe000c5e4a44,64),resize(0xfffffe000c5e4990,64)))
 v=local();cut(v,0xfffffe000c5e49d0,0xfffffe000c5e49dc);prove('scanner_constructs_delimiter_callback_and_discriminator_ba5',v,z3.Or(v.read('x16')!=R.SPACE,v.read('x17')!=0xba5))
 pointer=z3.BitVec('BO_numeric_input64',64);v=local();v.seed('x16',R.SPACE);v.seed('x25',pointer);cut(v,0xfffffe000c5e49e0,0xfffffe000c5e49f4)
 prove('numeric_decoder_ABI_uses_local64_output_and_mode0',v,z3.Or(v.read('x0')!=pointer,v.read('x1')!=v.sp0+0x28,v.read('x2')!=R.SPACE,v.read('x3')!=0,v.next!=R.NUMBER))
 value=z3.BitVec('BO_converted_value64',64);out=CPU.WORK+0x100
 for n,a,b in [(8,0xfffffe000c5e4ae0,0xfffffe000c5e4aec),(2,0xfffffe000c5e4b24,0xfffffe000c5e4b30),(4,0xfffffe000c5e4b34,0xfffffe000c5e4b40),(1,0xfffffe000c5e4b5c,0xfffffe000c5e4b68)]:
  v=local();v.regions=[(out,8)];v.setmem(v.sp0+0x10,8,out);v.seed('x8',value);cut(v,a,b);prove('scanner_numeric_store_'+str(n)+'_bytes',v,z3.Or(v.load(out,n)!=resize(value,n*8),v.read('w24')!=1))
 v=local();v.regions=[(out,4)];old=v.load(out+3,1);v.setmem(v.sp0+0x10,8,out);v.seed('w8',z3.Extract(31,0,value));cut(v,0xfffffe000c5e4b44,0xfffffe000c5e4b58)
 prove('three_byte_numeric_output_preserves_adjacent_fourth_byte',v,z3.Or(v.load(out,3)!=z3.Extract(23,0,value),v.load(out+3,1)!=old,v.read('w24')!=1))
 v=local();v.regions=[(out,8)];v.seed('x23',out);v.seed('x8',value);cut(v,0xfffffe000c5e4e9c,0xfffffe000c5e4ea8);prove('numeric_success_returns0_and_publishes_full64_value',v,z3.Or(v.read('x0')!=0,v.load(out,8)!=value))
 v=local();cut(v,0xfffffe000c5e4d94,0xfffffe000c5e4d9c);prove('numeric_failure_returns1_without_output_store',v,z3.Or(v.read('x0')!=1,z3.BoolVal(bool(v.stores)),v.next!=0xfffffe000c5e4ea8))
 accumulator,radix,digit=z3.BitVecs('BO_accumulator64 BO_radix64 BO_digit64',64);v=local();v.seed('x24',accumulator);v.seed('x26',radix);v.seed('x8',digit);cut(v,0xfffffe000c5e4e50,0xfffffe000c5e4e60)
 prove('valid_digit_accumulates_modulo64_after_radix_gate',v,z3.Or(v.read('x24')!=accumulator*radix+(digit&255),v.next!=0xfffffe000c5e4e60),[z3.ULT(digit&255,radix)])
 scale=z3.BitVec('BO_signed_scale32',32);v=local();v.seed('w21',scale);v.seed('x24',accumulator);cut(v,0xfffffe000c5e4e94,0xfffffe000c5e4e9c);prove('numeric_final_scale_is_signextended32_before_modular64_multiply',v,v.read('x8')!=accumulator*z3.SignExt(32,scale))
 for shift,a in [(10,0xfffffe000c5e4f38),(20,0xfffffe000c5e4f40),(30,0xfffffe000c5e4f48)]:
  v=local();v.seed('w21',scale);cut(v,a,a+4);prove('suffix_scale_shift_'+str(shift)+'_is_modulo32',v,v.read('w21')!=scale<<shift)
 c=z3.BitVec('BO_callback_character32',32);v=local();v.seed('w0',c);cut(v,R.SPACE+4,R.SPACE+12);prove('delimiter_callback_unsigned_greater_than_SPACE_returns_false_path',v,v.next!=z3.If(z3.UGT(c,32),resize(R.SPACE+48,64),resize(R.SPACE+12,64)))
 v=local();v.seed('w0',c);cut(v,R.SPACE+12,R.SPACE+40);yes=z3.Or(c==0,c==9,c==32);prove('delimiter_callback_bounded_bitmap_accepts_only_NUL_TAB_SPACE',v,v.next!=z3.If(yes,resize(R.SPACE+40,64),resize(R.SPACE+48,64)),[z3.ULE(c,32)])
 for expected,a in [(1,R.SPACE+40),(0,R.SPACE+48)]:
  v=local();cut(v,a,a+4);prove('delimiter_callback_return_'+str(expected),v,v.read('x0')!=expected)
 v=local();v.regions=[(out,4)];old=v.load(out+3,1);v.seed('x0',out);cut(v,0xfffffe000c5e4d00,0xfffffe000c5e4d10);prove('three_byte_flag_output_sets_one_and_preserves_fourth_byte',v,z3.Or(v.load(out,3)!=1,v.load(out+3,1)!=old))
 for n,a,b in [(4,0xfffffe000c5e4cf4,0xfffffe000c5e4cfc),(8,0xfffffe000c5e4ccc,0xfffffe000c5e4cd4)]:
  v=local();v.regions=[(out,8)];v.seed('x0',out);cut(v,a,b);prove('flag_writer_sets_one_in_'+str(n)+'_bytes',v,v.load(out,n)!=1)
 oldstatus=z3.BitVec('BO_previous_status32',32);v=local();v.seed('w9',width);v.seed('w24',oldstatus);cut(v,0xfffffe000c5e4af8,0xfffffe000c5e4b00);prove('zero_width_presence_sets_status1_without_output_store',v,z3.Or(v.read('w24')!=z3.If(width==0,resize(1,32),oldstatus),z3.BoolVal(bool(v.stores))))
 return proofs,coverage
def semantic_count(o):
 n=len(o['checks'])+len(o['option_contracts']['checks']);tree=o['tree_and_topology']
 if tree:
  n+=len(tree['checks'])+len(tree['original_API_contracts']['checks']);top=tree['topology']
  if top and top['thread_handoff_oracle']:n+=len(top['thread_handoff_oracle']['checks'])
 else:n+=len(o['initializer_contracts']['checks'])
 return n

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);prior=[]
 for p in json.loads(read(ROOT/(B.P+'_audit.json')))['rechecked_prior_source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat;prior.append({**p,'tree_audit_sha256':sha(ROOT/(B.P+'_audit.json'))})
 image=Image();components=[];replays=[];totals=Counter()
 for c in CPU.cases():
  row=CPU.Probe(image,c).run();row['independent_oracle']=oracle(row);q=Replay(image,row).run();components.append(row);replays.append(q);totals.update(q);print('case',c['label'],len(row['source_visits']),flush=True)
 controls=[]
 for c,pc in [(CPU.cases()[1],0xfffffe000c5e4b38),(CPU.cases()[10],0xfffffe000c5e4e5c),(CPU.cases()[12],0xfffffe000c5e4cf8),(CPU.cases()[11],0xfffffe000c5e498c)]:
  row=CPU.Probe(image,c,pc).run()
  try:oracle(row)
  except AssertionError as error:controls.append({'component':row,'oracle_rejection':{'kind':error.args[0][0],'label':error.args[0][1]}})
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
 source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={v['PC'] for c in components for v in c['source_visits']};assert visited<=source and not visited&{p['PC'] for p in e['opaque_words']}
 stats={'source_queries_unsat':len(proofs),'prior_source_queries_rechecked':len(prior),'proved_source_PCs':len({pc for q in coverage for pc in q['PCs']}),'proof_instruction_instances':sum(q['instruction_instances'] for q in coverage),'linked_edge_obligations':sum(q['linked_edge_obligations'] for q in coverage),'components':len(components),'source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(visited),'changed_source_controls':len(controls),
  'independent_semantic_checks':sum(semantic_count(c['independent_oracle']) for c in components),'original_option_API_calls':sum(len(c['original_option_API_entries']) for c in components),'original_option_API_returns':sum(len(c['original_option_call_returns']) for c in components),
  'original_tree_API_calls':sum(len(c['original_tree_API_entries']) for c in components),'original_tree_API_returns':sum(len(c['original_tree_call_returns']) for c in components),'dedicated_option_API_calls':sum(len(c['dedicated_option_API_returns']) for c in components),
  'original1472_byte_copies':sum(len(c['original_copy_entries']) for c in components),'tree_initializer_returns':len(components),'source_boot_record_handoffs':sum(len(c['source_boot_record_snapshots']) for c in components),'original_post_helper_returns':sum(len(c['source_main_continuation_checkpoints']) for c in components),
  'logical_authenticated_callback_calls':sum(sum(e['kind']=='logical_authenticated_call' for e in c['logical_effects']) for c in components),'explicit_vector_register_checks':len(components)*32}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_boot_option_execution.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],
  'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'coverage':coverage,'components':components,'independent_replays':replays,'negative_controls':controls,'independent_totals':stats,'independent_replay_totals':dict(totals),'executed_function_coverage':[{'start':f['start'],'captured_words':len(f['instructions']),'executed_unique_PCs':len({i['ea'] for i in f['instructions']}&visited)} for f in e['functions']],
  'conditional_kernel_boot_option_execution_contract_established':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
