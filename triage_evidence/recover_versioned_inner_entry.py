#!/usr/bin/env python3
"""Source-only adapter/inner continuation with strict and symbolic boundaries.

Parent return premises are unchanged. Original probe and bounds instructions
are lifted; PAC/fault behavior is not native execution. External stack guard
is arbitrary and coherent. The strict prefix stops before undefined A+0x270;
separate continuations retain its arbitrary u64 and declare flag-byte fixtures.
No allocation/free API runs. O(receipt+C*V+I) time/space; 10000 steps/case.
"""
import json
from collections import Counter
import z3
from capstone.arm64 import ARM64_OP_MEM,ARM64_OP_IMM
from lskd_values_symbolic import Lift,resize,part,mem,cell
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_kext_aes_handoff import function
from recover_carrier_control import span
import recover_versioned_output_stream as Parent

P='versioned_inner_entry';PIN='be9917579a29d521f1608f69db5ee89823d24bab35006af9e80bcb4f4754ec54'
GUEST=Parent.GUEST;ROOT=Parent.ROOT;DC=Parent.Parent.Parent.Parent.DC
GUARD=0xfffffe000cacb000;FLAG=0xfffffe000ccca078;AUX=GUEST+0xc000
SLOT=0xfffffe000a68a080;ALLOC=0xfffffe000a69d8f0;FREE=0xfffffe000a5a92e4
CONTROLLERS=[0xfffffe000ccc30d8,0xfffffe000ccc32f8,0xfffffe000ccc32f0,0xfffffe000ccc3618]
CALLS={Parent.CALL:Parent.ADAPTER,0xfffffe000a69ef94:0xfffffe000a5a1cc4,0xfffffe000a69f03c:Parent.INNER,0xfffffe000a689308:0xfffffe000a687ecc,0xfffffe000a689378:0xfffffe000a687ecc}

def value(v):return Parent.Parent.Parent.value(v)

class Inner(Parent.Output):
 def __init__(self,*a):self.active=False;super().__init__(*a)
 def load(self,a,n):
  if not self.active:return super().load(a,n)
  at=self.concrete(a);origin=None
  if at==GUARD:assert n==8;v=z3.BitVec('kernel_stack_guard64',64);origin='external_runtime_guard; no image-zero premise'
  elif at==AUX+0x270 and self.allow_aux and not all(j in self.known for j in range(at,at+n)):
   assert n==8 and not any(j in self.known for j in range(at,at+n));v=z3.BitVec('aux270_word64',64);origin='unspecified auxiliary bytes; no concrete fill'
  elif at==FLAG and self.environment is not None:
   assert n==1;v=z3.BitVecVal(self.environment,8);origin='declared stable environment-byte fixture'
  else:return super().load(a,n)
  self.loads.append({'visit':len(self.trace),'pc':hex(self.pc),'address':hex(at),'size_bytes':n,**value(v),'origin_contract':origin});return v
 def store(self,a,n,v,pc):
  if not self.active:return super().store(a,n,v,pc)
  at=self.concrete(a);v=z3.simplify(resize(v,n*8));assert GUEST<=at<at+n<=GUEST+0x20000 or any(g<=at<at+n<=g+8 for g in CONTROLLERS),('write escape',hex(pc),hex(at),n)
  preserved_auxiliary_origin=at==AUX+0x270 and n==8 and z3.eq(v,z3.BitVec('aux270_word64',64))
  assert z3.is_bv_value(v)or self.stack_lo<=at<at+n<=self.stack_hi or preserved_auxiliary_origin,('symbolic non-frame store',hex(pc),hex(at),n,v.sexpr())
  self.writes.append({'visit':len(self.trace),'pc':hex(pc),'address':hex(at),'size_bytes':n,**value(v)})
  for j in range(n):self.state[at+j]=z3.simplify(z3.Extract(j*8+7,j*8,v));self.known.add(at+j)
 def flag_condition(self,c):
  return self.equal if c=='eq'else z3.Not(self.equal)if c=='ne'else z3.ULT(self.cmp_left,self.cmp_right)if c=='lo'else z3.UGT(self.cmp_left,self.cmp_right)if c=='hi'else z3.ULE(self.cmp_left,self.cmp_right)if c=='ls'else self.cmp_left<=self.cmp_right if c=='le'else self.cmp_left>self.cmp_right if c=='gt'else self.cmp_left>=self.cmp_right if c=='ge'else self.cmp_left<self.cmp_right if c=='lt'else None
 def transfer_pointer(self,target,modifier,pc):
  if pc==Parent.CALL:p=self.parent_boundary['original_pointer']
  else:
   candidates=[r for r in self.loads if r['size_bytes']==8 and 'bytes_hex'in r and int.from_bytes(bytes.fromhex(r['bytes_hex']),'little')==target and Parent.POOL<=int(r['address'],16)<Parent.POOL+0x10000];assert candidates,('missing pointer',hex(pc),hex(target));p=Parent.pointer(self.k,int(candidates[-1]['address'],16))
  assert p['authenticated']and p['target']==hex(target)
  assert int(p['diversity'],16)==modifier or pc==0xfffffe000a69ef94 and int(p['diversity'],16)==0 and modifier==int(p['slot'],16)
  return p
 def step(self,pc):
  if not self.active:return super().step(pc)
  assert any(a<=pc<z for a,z in self.ranges),('instruction escape',hex(pc));raw=self.k.read(pc,4);assert raw==Parent.IMAGE.read(pc,4);i=next(DC.disasm(raw,pc));self.pc=pc;m=i.mnemonic;ops=i.operands;dest=i.reg_name(ops[0].reg)if ops else '';nxt=pc+4
  if m in ['bti','pacibsp']:pass
  elif m in ['ret','retab']:
   nxt=self.concrete(self.read('x30'));assert self.call_stack and self.call_stack[-1]['return_pc']==hex(nxt)
   entry=self.call_stack.pop();self.returns.append({'pc':hex(pc),'target':hex(nxt),'entry_call_pc':entry['pc'],'SP':hex(self.concrete(self.read('sp'))),'entry_SP':entry['SP'],'visit':len(self.trace)})
   assert self.returns[-1]['SP']==entry['SP']
  elif m=='adrp'or m=='adr':self.write(dest,ops[1].imm&((1<<64)-1))
  elif m in ['blraa','braa']:
   target=self.concrete(self.read(i.op_str.split(',')[0]));modifier=self.concrete(self.read('x17'));p=self.transfer_pointer(target,modifier,pc)
   event={'pc':hex(pc),'target':hex(target),'modifier':hex(modifier),'original_pointer':p,'visit':len(self.trace),'call':m=='blraa'}
   if m=='blraa':
    event.update(X0=value(self.read('x0')),X1=value(self.read('x1')),SP=hex(self.concrete(self.read('sp'))),return_pc=hex(pc+4))
    if pc not in CALLS:
     self.boundary={**event,'kind':'before_pending_native_allocation_or_free','instruction_executed':False};raise Parent.Parent.Parent.Frontier()
    assert target==CALLS[pc];self.call_stack.append(event);self.write('x30',pc+4)
   self.edges.append(event);nxt=target
  elif m=='b':nxt=ops[0].imm&((1<<64)-1)
  elif m.startswith('b.'):
   c=self.flag_condition(m[2:]);assert c is not None;take=self.concrete(z3.If(c,z3.BitVecVal(1,8),z3.BitVecVal(0,8)));nxt=ops[0].imm&((1<<64)-1)if take else nxt;self.decisions.append({'pc':hex(pc),'target':hex(nxt),'taken':bool(take),'visit':len(self.trace)})
  elif i.writeback and m in ['stp','ldp','ldr']:
   o=next(o for o in ops if o.type==ARM64_OP_MEM);base=i.reg_name(o.mem.base);a=self.address(i,o);sz=self.width(dest)//8;oldbase=self.read(base)
   if m in ['stp','ldp']:
    for j in range(2):
     r=i.reg_name(ops[j].reg)
     if m=='stp':self.store(a+j*sz,sz,self.read(r),pc)
     else:self.write(r,self.load(a+j*sz,sz))
   else:self.write(dest,self.load(a,sz))
   self.write(base,oldbase+ops[-1].imm if ops[-1].type==ARM64_OP_IMM else a)
  elif m=='ldrb'and dest=='wzr':
   a=self.concrete(self.address(i,ops[1]));assert pc==0xfffffe000a5a1cf0 and GUEST<=a<GUEST+0x20000
   self.discarded.append({'pc':hex(pc),'address':hex(a),'size_bytes':1,'visit':len(self.trace),'source_defined':a in self.known,'architectural_destination':'WZR','readability_assumed':True})
  elif m=='cset':
   c=self.flag_condition(i.op_str.rsplit(',',1)[1].strip());assert c is not None;self.write(dest,z3.If(c,z3.BitVecVal(1,32),z3.BitVecVal(0,32)))
  elif m=='csel':
   c=self.flag_condition(i.op_str.rsplit(',',1)[1].strip());assert c is not None;self.write(dest,z3.If(c,self.read(i.reg_name(ops[1].reg)),self.read(i.reg_name(ops[2].reg))))
  elif m=='ldrsw':
   a=self.concrete(self.address(i,ops[1]));assert pc==0xfffffe000a69decc and 0xfffffe000a69ecf8<=a<0xfffffe000a69ed38 and a%4==0
   self.relative_load={'address':hex(a),'index':(a-0xfffffe000a69ecf8)//4};self.write(dest,z3.SignExt(32,self.load(z3.BitVecVal(a,64),4)))
  elif m=='br':
   nxt=self.concrete(self.read(dest));assert pc==0xfffffe000a69ded8 and self.relative_load is not None;self.relative_load.update(target=hex(nxt),base='0xfffffe000a69ded0',branch_pc=hex(pc),visit=len(self.trace));self.relative_edges.append(self.relative_load);self.relative_load=None
  elif m=='movi':assert i.op_str=='v0.2d, #0000000000000000';self.vector_zero=True
  elif m=='str'and dest=='q0':assert self.vector_zero;self.store(self.address(i,ops[1]),16,z3.BitVecVal(0,128),pc)
  elif m in ['lsl','lsr']and ops[2].type==Parent.ARM64_OP_REG:Parent.shift(self,i)
  else:self.c={'spans':[{'label':'one','start':hex(pc),'bytes_hex':raw.hex()}]};Lift.run(self,'one')
  self.trace.append({'pc':hex(pc),'bytes_hex':raw.hex(),'mnemonic':m,'operands':i.op_str});return nxt

 def reset_journal(self):
  self.trace=[];self.loads=[];self.writes=[];self.edges=[];self.observables=[];self.returns=[];self.decisions=[];self.discarded=[];self.relative_edges=[];self.relative_load=None;self.boundary=None
 def receipt(self):
  assert not any(int(w['address'],16)<GUEST+0x1800 and int(w['address'],16)+w['size_bytes']>GUEST+0x1600 for w in self.writes)
  return {'source_trace':self.trace,'source_reads':self.loads,'source_writes':self.writes,'source_transfers':self.edges,'source_returns':self.returns,'direct_decisions':self.decisions,'discarded_probe_reads':self.discarded,'relative_table_transfers':self.relative_edges,'boundary':self.boundary,'input_stream_at_boundary':self.snapshot(self.heap,32),'output_stream_at_boundary':self.snapshot(self.heap+0x200,32),'record_at_boundary':self.snapshot(GUEST+0x4060,0x50),'caller_delta_cell':self.snapshot(self.entry_SP+0x1e8,8),'private_header':self.snapshot(self.header,8),'all_selected_observables_concrete':all(z3.is_bv_value(z3.simplify(v))for v in self.observables),'output_B_bytes_written':0,'allocator_model_memory_writes':0,'new_guest_executed':False,'native_target_executed':False}
 def prefix(self,words,strict,expected,ranges):
  parent=self.run_output(words,strict,'fresh_distinct_object');assert parent==expected;self.parent_boundary=parent['boundary'];self.entry_SP=self.concrete(self.read('sp'));self.stack_hi=self.entry_SP;self.stack_lo=self.entry_SP-0x1000;self.ranges=ranges;self.active=True;self.allow_aux=False;self.environment=None;self.call_stack=[];self.vector_zero=False;self.reset_journal();pc=Parent.CALL
  for _ in range(10000):
   try:pc=self.step(pc)
   except Parent.Parent.Parent.Frontier:break
  assert self.boundary is not None and self.boundary['pc']==hex(SLOT)and self.boundary['address']==hex(AUX+0x270)and self.boundary['known_bytes']==0
  self.header=int.from_bytes(bytes.fromhex(next(e for e in self.edges if e['pc']=='0xfffffe000a69f03c')['X1']['bytes_hex']),'little')
  return self.receipt()
 def continuation(self,environment):
  assert self.boundary['pc']==hex(SLOT);self.allow_aux=True;self.environment=environment;self.reset_journal();pc=SLOT
  for _ in range(10000):
   try:pc=self.step(pc)
   except Parent.Parent.Parent.Frontier:break
  assert self.boundary is not None and self.boundary['pc']==hex(ALLOC if environment==0 else FREE)
  self.boundary['kind']='before_FPAESParameters_allocation'if environment==0 else 'before_output_stream_free'
  row=self.receipt();row.update(environment_byte=environment,environment_address=hex(FLAG),environment_stable_read_fixture=True,auxiliary_origin={'address':hex(AUX+0x270),'size_bytes':8,'expression':'aux270_word64','source_initialization_established':False},new_allocator_return_supplied=False)
  return row

class Flags(Parent.A64):
 flag_condition=Inner.flag_condition
 def run(self,label):
  original=self.c;row=next(s for s in self.c['spans']if s['label']==label)
  for i in DC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address;dest=i.reg_name(i.operands[0].reg)
   if i.mnemonic in ['csel','cset']:
    cond=self.flag_condition(i.op_str.rsplit(',',1)[1].strip());assert cond is not None
    self.write(dest,z3.If(cond,self.read(i.reg_name(i.operands[1].reg)),self.read(i.reg_name(i.operands[2].reg))))if i.mnemonic=='csel'else self.write(dest,z3.If(cond,z3.BitVecVal(1,32),z3.BitVecVal(0,32)));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
  self.c=original;return self

def proofs(source,probe):
 c={'spans':[source,probe]};qs=[];counts={};F=0x51010000
 def run(label,a,z,seeds=(),memory=()):
  v=Flags(part(c,label,a,z))
  for r,x in seeds:v.seed(r,x)
  for a,n,x in memory:mem(v,a,n,x)
  v.run(label);counts[label]=v.count;return v
 def claim(n,q):
  s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat,n;qs.append({'label':n,'query':s.to_smt2(),'result':'unsat'})
 C,W,A,H1,H2,T=z3.BitVecs('inner_record64 inner_workspace64 inner_aux64 inner_input_stream64 inner_output_stream64 inner_task64',64)
 v=run('first_bounds_arguments',0xfffffe000a6892d4,0xfffffe000a689308,[('sp',F),('x20',W+0x100),('x2',C)],[(C+0x28,8,W+0x4000),(C,8,H2),(C+8,8,A),(C+0x40,8,A+0x1000),(C+0x48,8,T),(C+0x38,8,H1)])
 claim('first_bounds_arguments',z3.Or(v.read('x0')!=W+0x4c0,v.read('x1')!=W+0x4000,cell(v,F+0x2d8,8)!=T,cell(v,F+0x420,8)!=H2,cell(v,F+0x3e0,8)!=H1))
 claim('first_bounds_nonwrapping_extent',z3.And(z3.ULE(W,0xffffffffffffbfff),z3.UGT(v.read('x0'),v.read('x1'))))
 v=run('second_bounds_arguments',0xfffffe000a689364,0xfffffe000a689374,[('sp',F),('x23',A+0x280),('x21',A+0x1000)])
 claim('second_bounds_arguments',z3.Or(v.read('x0')!=A+0x280,v.read('x1')!=A+0x1000))
 claim('second_bounds_nonwrapping_extent',z3.And(z3.ULE(A,0xffffffffffffefff),z3.UGT(v.read('x0'),v.read('x1'))))
 SZ=z3.BitVec('inner_probe_bytes64',64)
 v=run('probe_loop_guard',0xfffffe000a5a1ccc,0xfffffe000a5a1cd0,[('x9',SZ)])
 claim('probe_small_size_skips_page_loop',z3.And(z3.UGE(SZ,16),z3.ULE(SZ,256),z3.Not(z3.ULT(v.cmp_left,v.cmp_right))))
 B=z3.BitVec('inner_flag32',32)
 v=run('flag_bit_index',0xfffffe000a68a0d8,0xfffffe000a68a0f8,[('sp',F),('w5',0xfaf7bb03),('w7',0x050847a6),('w30',0xfaf7b915),('w8',0x050847a6+0xfaf7bb03),('w9',B)])
 claim('flag_bit_index',v.read('w8')!=z3.If(B&1==0,z3.BitVecVal(0x31a,32),z3.BitVecVal(0x359,32)))
 CUR,LIM=z3.BitVecs('inner_cursor32 inner_limit32',32)
 v=run('eight_byte_extent',0xfffffe000a69b6cc,0xfffffe000a69b730,[('x9',H1),('w20',0xb8),('w10',0x4fe),('w11',CUR+0x0c69aa47),('w12',0x96c)],[(H1+12,4,LIM+0x13496211)])
 claim('modular_eight_byte_extent',v.read('w11')!=(z3.BitVecVal(0x96c,32)^z3.If(z3.ULE(CUR+8,LIM),z3.BitVecVal(0xbc,32),z3.BitVecVal(0,32))))
 STATUS=z3.BitVec('inner_stream_status_cell64',64);X=z3.BitVec('inner_phase32',32)
 v=run('stream_extent_error',0xfffffe000a69b808,0xfffffe000a69b830,[('x8',STATUS),('w10',X)])
 claim('stream_extent_error',cell(v,STATUS,4)!=0xce515b53)
 v=run('inner_result_store',0xfffffe000a69d830,0xfffffe000a69d838,[('sp',F),('w25',X)],[(F+0x368,8,C)])
 claim('inner_result_store',cell(v,C+0x20,4)!=X)
 GUARDWORD=z3.BitVec('inner_guard64',64)
 v=run('guard_compare',0xfffffe000a69d838,0xfffffe000a69d84c,[('x29',F+0x650)],[(F+0x5f0,8,GUARDWORD),(0xfffffe000847c5f8,8,GUARD),(GUARD,8,GUARDWORD)])
 claim('stable_guard_passes_comparison',z3.Not(v.equal))
 return qs,counts

def build():
 assert sha(ROOT/'versioned_output_stream_checks.json')==PIN
 old=json.loads(read(ROOT/'versioned_output_stream_checks.json'));assert old['generator_sha256']==sha(Parent.__file__)
 for name,key in [('versioned_stream_words_checks.json','parent_checks_sha256'),('versioned_core_preparation_checks.json','preparation_checks_sha256'),('versioned_stream_initialization_checks.json','strict_checks_sha256'),('versioned_dispatcher_frame_checks.json','dispatcher_checks_sha256')]:assert sha(ROOT/name)==old[key]
 words=json.loads(read(ROOT/'versioned_stream_words_checks.json'));strict=json.loads(read(ROOT/'versioned_stream_initialization_checks.json'));prep=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));dispatcher=json.loads(read(ROOT/'versioned_dispatcher_frame_checks.json'));k=Parent.Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');inner=function(k,entry,Parent.INNER);assert inner['end']=='0xfffffe000a69ecf8'and bytes.fromhex(inner['bytes_hex'])==Parent.IMAGE.read(Parent.INNER,int(inner['end'],16)-Parent.INNER)
 probe=dict(span(k,0xfffffe000a5a1cc4,0xfffffe000a5a1cf8),label='probe');bounds=dict(span(k,0xfffffe000a687ecc,0xfffffe000a687ee0),label='bounds')
 ranges=[(int(s['start'],16),int(s['end'],16))for s in [dispatcher['source_function'],old['adapter_source'],inner,probe,bounds]];rows=[];counts=Counter()
 for expected in old['cases']:
  if expected['allocation_return_fixture']!='fresh_distinct_object':continue
  ix=expected['parent_case_index'];word=next(r for r in words['cases']if r['parent_case_index']==ix);st=next(r for r in strict['cases']if r['parent_case_index']==ix and r['boundary']['pc']=='0xfffffe000a5a731c');v=Inner(k,prep['cases'][ix]);prefix=v.prefix(word,st,expected,ranges);branches=[]
  for environment in [0,1]:
   v=Inner(k,prep['cases'][ix]);assert v.prefix(word,st,expected,ranges)==prefix;branches.append(v.continuation(environment))
  row={'parent_case_index':ix,'configuration':expected['configuration'],'operand_profile':expected['operand_profile'],'strict_prefix':prefix,'continuations':branches};rows.append(row)
  for r in [prefix,*branches]:
   counts['source_visits']+=len(r['source_trace']);counts['source_read_bytes']+=sum(e['size_bytes']for e in r['source_reads']);counts['source_write_bytes']+=sum(e['size_bytes']for e in r['source_writes']);counts['authenticated_transfers']+=len(r['source_transfers']);counts['returns']+=len(r['source_returns']);counts['relative_table_transfers']+=len(r['relative_table_transfers']);counts['discarded_probe_reads']+=len(r['discarded_probe_reads'])
  print(json.dumps({'parent':ix,'strict_visits':len(prefix['source_trace']),'branch_visits':[len(r['source_trace'])for r in branches]}),flush=True)
 qs,lift_counts=proofs(inner,probe);table=k.read(0xfffffe000a69ecf8,64);assert table==Parent.IMAGE.read(0xfffffe000a69ecf8,64);targets=[0xfffffe000a69ded0+int.from_bytes(table[j:j+4],'little',signed=True)for j in range(0,64,4)];assert all(Parent.INNER<=a<0xfffffe000a69ecf8 and k.read(a,4)==bytes.fromhex('9f2403d5')for a in targets)
 deps=['recover_versioned_output_stream.py','recover_versioned_stream_words.py','recover_versioned_stream_initialization.py','recover_versioned_dispatcher_frame.py','lskd_values_symbolic.py','kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py','recover_carrier_control.py']
 banks=[]
 for label,l,r,key,add,base,bias in [('inner_controller',0xfffffe0007949ed0,0xfffffe000792fec0,0x92,0x154,Parent.POOL,0),('shared_controller',Parent.qword(Parent.POOL+0xc08)-8,Parent.qword(Parent.POOL+0x158)-4,0x98,-0x79,Parent.POOL,-4),('first_bounds',Parent.qword(Parent.POOL+0xc08)-8,Parent.qword(Parent.POOL+0x158)-4,0x6d,0xf0e,Parent.TABLE,0),('second_bounds',Parent.qword(Parent.POOL+0xb70),Parent.qword(Parent.POOL+0xa10),0x92,0xe7f,Parent.TABLE,0),('flag_address',Parent.qword(Parent.POOL+0x840),Parent.qword(Parent.POOL+0xbb8),0xd8,0xf6,Parent.POOL,0)]:
  b=Parent.selected(l,r,key,add,base,bias);b.update(label=label,base=hex(base),left256_hex=k.read(l,256).hex(),right256_hex=k.read(r,256).hex(),original_pointer=Parent.pointer(k,int(b['slot'],16)));assert k.read(l,256)==Parent.IMAGE.read(l,256)and k.read(r,256)==Parent.IMAGE.read(r,256);banks.append(b)
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'parent_checks_sha256':PIN,'kernel_collection_sha256':k.sha256,'inner_source':inner,'probe_source':probe,'bounds_source':bounds,'source_proofs':qs,'source_lift_counts':lift_counts,'selected_bank_rules':banks,'guard_import_pointer':Parent.pointer(k,0xfffffe000847c5f8),'guard_symbols':k.symbols([GUARD]),'flag_pointer':Parent.pointer(k,Parent.POOL+8*0x116),'flag_original_byte_hex':k.read(FLAG,1).hex(),'relative_table':{'address':'0xfffffe000a69ecf8','base':'0xfffffe000a69ded0','bytes_hex':table.hex(),'signed_offsets':[int.from_bytes(table[j:j+4],'little',signed=True)for j in range(0,64,4)],'targets':[hex(a)for a in targets],'all_targets_within_inner_and_BTI_J':True,'entries':16,'data_not_decoded_as_instructions':True},'next_allocation_type_view':Parent.Parent.Parent.type_view(k,0xfffffe000847b460),'cases':rows,'verified_counts':{'parent_cases':len(rows),'strict_prefixes':len(rows),'symbolic_continuations':sum(len(r['continuations'])for r in rows),'source_queries_unsat':len(qs),'source_lift_instructions':sum(lift_counts.values()),'bank_inputs':1280,'relative_table_entries':16,'inner_instruction_words':len(inner['instructions']),**counts},'all_actual_native_deltas_proved_zero':False,'full_inner_semantics_proved':False,'output_B_bytes_written':0,'allocator_model_memory_writes':0,'new_guest_executed':False,'native_target_executed':False,'full_goal_complete':False}

if __name__=='__main__':
 obj=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(obj['verified_counts']),flush=True)
