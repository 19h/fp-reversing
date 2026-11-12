#!/usr/bin/env python3
"""Source-only 104 B parameter allocation return and immediate consumers.

Pinned reaching prefixes; declared fresh distinct or counterfactual null return.
No allocator initialization, native API, guest, hardware or IDA mutation.
O(receipt+C*V+I) time/space; 10000 new source steps per case, 30 s/query.
"""
import json
from collections import Counter
import z3
from capstone.arm64 import ARM64_OP_IMM
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_carrier_control import span
from lskd_values_symbolic import resize,part,mem,cell
import recover_versioned_inner_entry as Parent

P='versioned_aes_parameters';ROOT=Parent.ROOT
PIN='9337520390e93eb413f513e495bd85b65fc9601656abb495304ddaf4fa4aae4c'
FILL=0xfffffe000a687d64;FILL_CALL=0xfffffe000a69d9c0
LOCK_CELL=0xfffffe000cccda78;LOCK_READ=0xfffffe000a69da98
Frontier=Parent.Parent.Parent.Parent.Frontier

class Parameters(Parent.Inner):
 def __init__(self,*a):self.extended=False;self.allow_lock=False;super().__init__(*a)
 def load(self,a,n):
  if self.extended and self.allow_lock and self.pc==LOCK_READ:
   assert self.concrete(a)==LOCK_CELL and n==8
   v=z3.BitVec('startup_lock_cell64',64);self.loads.append({'visit':len(self.trace),'pc':hex(self.pc),'address':hex(LOCK_CELL),'size_bytes':8,**Parent.value(v),'origin_contract':'arbitrary runtime startup lock-cell word; no image or pointer premise'});return v
  try:return super().load(a,n)
  except ValueError:
   if not self.extended:raise
   at=self.concrete(a);self.boundary={'kind':'before_unbacked_external_read','pc':hex(self.pc),'address':hex(at),'size_bytes':n,'instruction_executed':False};raise Frontier()
 def store(self,a,n,v,pc):
  if not self.extended or not self.allow_lock or pc!=0xfffffe000a69dafc:return super().store(a,n,v,pc)
  at=self.concrete(a);v=z3.simplify(resize(v,n*8));assert at==self.lock_record and n==8 and z3.eq(v,z3.BitVec('startup_lock_cell64',64))
  self.writes.append({'visit':len(self.trace),'pc':hex(pc),'address':hex(at),'size_bytes':n,**Parent.value(v)})
  for j in range(n):self.state[at+j]=z3.Extract(8*j+7,8*j,v);self.known.add(at+j)
 def step(self,pc):
  if not self.extended:return super().step(pc)
  raw=self.k.read(pc,4);assert raw==Parent.Parent.IMAGE.read(pc,4);i=next(Parent.DC.disasm(raw,pc));m=i.mnemonic;ops=i.operands;self.pc=pc;special=False;nxt=pc+4
  if i.writeback and m in ['str','strb']:
   a=self.address(i,ops[1]);base=i.reg_name(ops[1].mem.base);old=self.read(base);n=1 if m=='strb'else self.width(i.reg_name(ops[0].reg))//8
   self.store(a,n,self.read(i.reg_name(ops[0].reg)),pc);self.write(base,old+ops[-1].imm if ops[-1].type==ARM64_OP_IMM else a);special=True
  elif m in ['cbz','cbnz']:
   test=self.read(i.reg_name(ops[0].reg))==0;test=z3.Not(test)if m=='cbnz'else test;take=self.concrete(z3.If(test,z3.BitVecVal(1,8),z3.BitVecVal(0,8)));nxt=ops[1].imm&((1<<64)-1)if take else nxt;self.decisions.append({'pc':hex(pc),'target':hex(nxt),'taken':bool(take),'visit':len(self.trace)});special=True
  elif m=='ubfx':
   n=self.width(i.reg_name(ops[0].reg));self.write(i.reg_name(ops[0].reg),resize(z3.Extract(ops[2].imm+ops[3].imm-1,ops[2].imm,self.read(i.reg_name(ops[1].reg))),n));special=True
  elif m=='ldurb':self.write(i.reg_name(ops[0].reg),self.load(self.address(i,ops[1]),1));special=True
  elif m=='subs':
   n=self.width(i.reg_name(ops[0].reg));a=self.operand(i,ops[1],n);b=self.operand(i,ops[2],n);self.write(i.reg_name(ops[0].reg),a-b);self.equal=a-b==0;self.cmp_left=a;self.cmp_right=b;special=True
  if special:
   assert any(a<=pc<z for a,z in self.ranges);self.trace.append({'pc':hex(pc),'bytes_hex':raw.hex(),'mnemonic':m,'operands':i.op_str});return nxt
  try:return super().step(pc)
  except Frontier:
   if pc!=FILL_CALL:raise
   e=self.boundary;assert e['target']==hex(FILL)and e['kind']=='before_pending_native_allocation_or_free';e={k:v for k,v in e.items()if k not in ['kind','instruction_executed']};e['X2']=Parent.value(self.read('x2'));self.edges.append(e);self.call_stack.append(e);self.write('x30',pc+4);self.boundary=None
   self.trace.append({'pc':hex(pc),'bytes_hex':raw.hex(),'mnemonic':m,'operands':i.op_str});return FILL
 def parameters(self,allocation):
  assert self.boundary['pc']==hex(Parent.ALLOC);gate={r:Parent.value(self.read(r))for r in ['w19','w22']};self.parameters_object=self.heap+0x400;assert not any(j in self.known for j in range(self.parameters_object,self.parameters_object+104));self.extended=True;self.reset_journal()
  for j in range(1,19):self.seed('x'+str(j),z3.BitVec('parameter_allocator_clobber_x'+str(j),64))
  self.seed('x0',self.parameters_object if allocation=='fresh_distinct_object'else 0);self.seed('x30',Parent.ALLOC+4);pc=Parent.ALLOC+4
  for _ in range(10000):
   try:pc=self.step(pc)
   except Frontier:break
  assert self.boundary is not None
  self.boundary['kind']='before_startup_lock_cell_read'if allocation=='fresh_distinct_object'else 'before_output_stream_free_after_null_parameter_allocation'
  row=self.receipt();row.update(allocation_gate_phase=gate,allocation_return_fixture=allocation,allocation_result=hex(self.parameters_object if allocation=='fresh_distinct_object'else 0),declared_distinct_object=hex(self.parameters_object),allocator_clobbers_declared=list(range(1,19)),parameters_at_boundary=self.snapshot(self.parameters_object,104),retained_parameter_register=Parent.value(self.read('x28')),local_constant_at_boundary=self.snapshot(Parent.GUEST+0x4118,32))
  return row
 def lock_continuation(self):
  assert self.boundary=={'kind':'before_startup_lock_cell_read','pc':hex(LOCK_READ),'address':hex(LOCK_CELL),'size_bytes':8,'instruction_executed':False}
  at=self.concrete(self.read('sp'))+0x3b8;assert all(at+j in self.known for j in range(8));self.lock_record=self.concrete(z3.Concat(*[resize(self.state[at+j],8)for j in reversed(range(8))]));self.allow_lock=True;self.reset_journal();pc=LOCK_READ
  for _ in range(10000):
   try:pc=self.step(pc)
   except Frontier:break
  assert self.boundary is not None and self.boundary['pc']=='0xfffffe000a69db54'and self.boundary['target']=='0xfffffe000a5b403c';self.boundary['kind']='before_private_lock_operation_wrapper'
  row=self.receipt();row.update(parameters_at_boundary=self.snapshot(self.parameters_object,104),lock_record_at_boundary=self.snapshot(self.lock_record,16),retained_parameter_register=Parent.value(self.read('x28')),lock_pack_phase=Parent.value(self.read('w22')));return row

def proofs(inner,fill,decoder):
 c={'spans':[inner,fill,decoder]};qs=[];counts={};F=0x51010000
 def run(label,a,z,seeds=(),memory=()):
  v=Parent.Flags(part(c,label,a,z))
  for r,x in seeds:v.seed(r,x)
  for a,n,x in memory:mem(v,a,n,x)
  v.run(label);counts[label]=v.count;return v
 def claim(label,q):
  s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat,label;qs.append({'label':label,'query':s.to_smt2(),'result':'unsat'})
 H,Q,L,C=z3.BitVecs('parameter_object64 parameter_return64 startup_lock_word64 lock_record64',64);N=z3.BitVec('lock_phase32',32)
 v=run('allocation_null_gate',0xfffffe000a69d92c,0xfffffe000a69d948,[('x0',Q),('w19',0x34e),('w22',0xd71)])
 claim('allocation_null_gate',z3.Or(v.read('x28')!=0,v.read('w8')!=z3.If(Q==0,z3.BitVecVal(0xd80,32),z3.BitVecVal(0xd71,32))))
 v=run('parameter_control_stores',0xfffffe000a69d958,0xfffffe000a69d978,[('x0',H)])
 claim('parameter_control_stores',z3.Or(v.read('x28')!=H,cell(v,H,1)!=1,cell(v,H+1,1)!=1,cell(v,H+0x38,1)!=0,cell(v,H+0x24,4)!=0,cell(v,H+0x28,4)!=0x1000,cell(v,H+0x2c,4)!=0))
 SZ=z3.BitVec('fill_count64',64)
 v=run('fill_alignment_head',FILL+4,FILL+0x14,[('x0',H),('x2',SZ)])
 HEAD=resize((-resize(H,32))&7,64)
 claim('fill_alignment_head',v.read('x8')!=z3.If(z3.ULT(SZ,HEAD),SZ,HEAD))
 v=run('lock_record_pack',0xfffffe000a69da9c,0xfffffe000a69db00,[('sp',F),('x9',L),('w22',N)],[(F+0x3b8,8,C)])
 K=(resize(C,32)^0x6133a0c8)*0x84d77373;encoded=cell(v,C+8,4)
 claim('lock_record_pack',z3.Or(cell(v,C,8)!=L,encoded+K!=N-0x63))
 v=run('lock_record_decode',0xfffffe000a5b412c,0xfffffe000a5b414c,[('x0',C)],[(C,8,L),(C+8,4,encoded)])
 claim('matching_lock_record_decode',z3.Or(v.read('x0')!=L,v.read('w17')!=N-0x63))
 v=run('null_parameter_status',0xfffffe000a69b258,0xfffffe000a69b264)
 claim('null_parameter_status',v.read('w25')!=0xce515a38)
 J=z3.BitVec('constant_index64',64);B=z3.BitVec('constant_raw_byte32',32);D=z3.BitVec('constant_destination64',64)
 v=run('local_constant_byte',0xfffffe000a69da4c,0xfffffe000a69da64,[('x8',J),('x25',D),('w13',B),('w22',N),('w10',-19),('w11',25)])
 claim('local_constant_byte',cell(v,D+J,1)!=resize(B^N^(-19*resize(J,32))^25,8))
 return qs,counts

def build():
 assert sha(ROOT/'versioned_inner_entry_checks.json')==PIN
 old=json.loads(read(ROOT/'versioned_inner_entry_checks.json'));assert old['generator_sha256']==sha(Parent.__file__)
 output=json.loads(read(ROOT/'versioned_output_stream_checks.json'));words=json.loads(read(ROOT/'versioned_stream_words_checks.json'));strict=json.loads(read(ROOT/'versioned_stream_initialization_checks.json'));prep=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));dispatcher=json.loads(read(ROOT/'versioned_dispatcher_frame_checks.json'));k=Parent.Parent.Kernel()
 fill=dict(span(k,FILL,0xfffffe000a687ecc),label='pure_fill_source');decoder=dict(span(k,0xfffffe000a5b412c,0xfffffe000a5b414c),label='lock_record_decoder');qs,lifts=proofs(old['inner_source'],fill,decoder);ranges=[(int(s['start'],16),int(s['end'],16))for s in [dispatcher['source_function'],output['adapter_source'],old['inner_source'],old['probe_source'],old['bounds_source'],fill]];rows=[];counts=Counter()
 for case in old['cases']:
  ix=case['parent_case_index'];word=next(r for r in words['cases']if r['parent_case_index']==ix);st=next(r for r in strict['cases']if r['parent_case_index']==ix and r['boundary']['pc']=='0xfffffe000a5a731c');expected=next(r for r in output['cases']if r['parent_case_index']==ix and r['allocation_return_fixture']=='fresh_distinct_object')
  for allocation in ['fresh_distinct_object','null_return']:
   v=Parameters(k,prep['cases'][ix]);assert v.prefix(word,st,expected,ranges)==case['strict_prefix'];assert v.continuation(0)==case['continuations'][0];row=v.parameters(allocation);row.update(parent_case_index=ix,configuration=case['configuration'],operand_profile=case['operand_profile']);rows.append(row)
   branches=[row]
   if allocation=='fresh_distinct_object':row['lock_origin_continuation']=v.lock_continuation();branches.append(row['lock_origin_continuation'])
   print(json.dumps({'parent':ix,'allocation':allocation,'visits':[len(b['source_trace'])for b in branches],'boundaries':[b['boundary']for b in branches]}),flush=True)
   for b in branches:
    for key,events in [('source_visits','source_trace'),('authenticated_transfers','source_transfers'),('source_returns','source_returns')]:counts[key]+=len(b[events])
    counts['source_read_bytes']+=sum(x['size_bytes']for x in b['source_reads']);counts['source_write_bytes']+=sum(x['size_bytes']for x in b['source_writes'])
 deps=['recover_versioned_inner_entry.py','recover_versioned_output_stream.py','recover_versioned_stream_words.py','recover_versioned_stream_initialization.py','recover_versioned_dispatcher_frame.py','lskd_values_symbolic.py','kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py','recover_carrier_control.py']
 bank=Parent.Parent.selected(0xfffffe0007941f60,0xfffffe000794a0d0,0x6d,0x1ae,Parent.Parent.POOL);bank.update(original_pointer=Parent.Parent.pointer(k,int(bank['slot'],16)),left256_hex=k.read(0xfffffe0007941f60,256).hex(),right256_hex=k.read(0xfffffe000794a0d0,256).hex());assert bank['original_pointer']['target']=='0xfffffe0007949dab';raw=k.read(0xfffffe0007949da7,32);assert raw==Parent.Parent.IMAGE.read(0xfffffe0007949da7,32)
 assert all(k.read(a,256)==Parent.Parent.IMAGE.read(a,256)for a in [0xfffffe0007941f60,0xfffffe000794a0d0])
 section=next(s for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit'for s in e['sections']if s['address']<=LOCK_CELL<LOCK_CELL+8<=s['address']+s['size'])
 context={'references':{n:sha(ROOT/n)for n in ['kext_provider_initialize_checks.json','kext_startup_hardware_bridge_checks.json']},'startup_store_source':span(k,0xfffffe000a607210,0xfffffe000a607240),'lock_cell_section':{key:hex(val)if key in ['address']else val for key,val in section.items()},'native_epoch_join_established':False}
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'parent_checks_sha256':PIN,'kernel_collection_sha256':k.sha256,'startup_context':context,'fill_source':fill,'lock_decoder_source':decoder,'source_proofs':qs,'source_lift_counts':lifts,'constant_bank':bank,'constant_source':{'address':'0xfffffe0007949da7','bytes_hex':raw.hex(),'length_bytes':32},'cases':rows,'verified_counts':{'parent_cases':len(old['cases']),'allocation_continuations':len(rows),'separate_lock_origin_continuations':8,'source_queries_unsat':len(qs),'source_lift_instructions':sum(lifts.values()),'constant_bank_inputs':256,**counts},'allocator_model_memory_writes':0,'output_B_bytes_written':0,'new_guest_executed':False,'native_target_executed':False,'full_goal_complete':False}

if __name__=='__main__':
 obj=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(obj['verified_counts']),flush=True)
