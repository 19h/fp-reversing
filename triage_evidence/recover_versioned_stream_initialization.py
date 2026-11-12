#!/usr/bin/env python3
"""Source-only continuation after the pending 32 B stream allocation.

One declared fresh distinct object or null return; no allocator memory writes,
heap zeroing, native calls or guest execution. Unknown words retain symbolic
origins. O(receipt bytes+C*V+I+256R) time/space plus 30 s/query, 1000 steps/case.
"""
import json,struct
from collections import Counter
import z3
from capstone.arm64 import ARM64_OP_REG
from kext_port_tools import ROOT,IMAGE,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from lskd_values_symbolic import Lift,part,mem,cell,resize
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_versioned_dispatcher_frame as Parent

P='versioned_stream_initialization';PIN='f33cd61a5e74dc26f8f62af789a24d0d431b3ec50e23c364373e269efb1e0c80'
HEAP=Parent.Parent.Parent.P+0x1a000

class Frontier(Exception):pass

class Flags(Lift):
 def run(self,label):
  original=self.c;row=next(s for s in self.c['spans']if s['label']==label)
  for i in Parent.DC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='tst':self.equal=self.read(i.reg_name(i.operands[0].reg))&i.operands[1].imm==0;self.count+=1;continue
   if i.mnemonic=='csel':
    assert i.op_str.endswith(', eq');self.write(i.reg_name(i.operands[0].reg),z3.If(self.equal,self.read(i.reg_name(i.operands[1].reg)),self.read(i.reg_name(i.operands[2].reg))));self.count+=1;continue
   if i.mnemonic=='cset'and i.op_str.endswith(', hi'):
    self.write(i.reg_name(i.operands[0].reg),z3.If(z3.UGT(self.cmp_left,self.cmp_right),z3.BitVecVal(1,32),z3.BitVecVal(0,32)));self.count+=1;continue
   self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
  self.c=original;return self

def value(v):
 v=z3.simplify(v)
 return {'bytes_hex':v.as_long().to_bytes(v.size()//8,'little').hex()}if z3.is_bv_value(v)else {'expression':v.sexpr()}

class Stream(Parent.Slice):
 def __init__(self,k,row,allocation):
  super().__init__(k,row);self.preallocation=super().run_slice();self.trace=[];self.loads=[];self.edges=[];self.observables=[];self.writes=[];self.boundary=None;self.allocation=allocation;self.heap=HEAP+row['configuration']['epoch']*0x100;self.scan=[];self.symbolic_writes=0
  assert not any(j in self.known for j in range(self.heap,self.heap+32))
  for j in range(1,19):self.seed('x'+str(j),z3.BitVec('allocator_clobber_x'+str(j),64))
  self.seed('x0',self.heap if allocation=='fresh_distinct_object'else 0);self.seed('x30',Parent.CALL+4)
 def concrete(self,v):
  v=z3.simplify(v)
  if not z3.is_bv_value(v):
   self.boundary={'kind':'before_unknown_dependent_observable','pc':hex(self.pc),'expression':v.sexpr(),'instruction_executed':False};raise Frontier()
  self.observables.append(v);return v.as_long()
 def load(self,a,n):
  at=self.concrete(a);bs=[];fixup=None
  for j in range(at,at+n):
   if Parent.Parent.Parent.P<=j<Parent.Parent.Parent.P+0x20000 and j not in self.known:
    self.boundary={'kind':'before_unspecified_frame_or_heap_read','pc':hex(self.pc),'address':hex(at),'size_bytes':n,'known_bytes':sum(x in self.known for x in range(at,at+n)),'instruction_executed':False};raise Frontier()
   bs.append(resize(self.state[j],8)if j in self.state else z3.BitVecVal(IMAGE.read(j,1)[0],8))
  v=z3.simplify(z3.Concat(*reversed(bs))if n>1 else bs[0]);rec={'visit':len(self.trace),'pc':hex(self.pc),'address':hex(at),'size_bytes':n,**value(v)}
  if not any(j in self.state for j in range(at,at+n))and z3.is_bv_value(v):
   original=self.k.read(at,n);normalized=v.as_long().to_bytes(n,'little')
   if original!=normalized:assert n==8;fixup=pointer(self.k,at);assert int(fixup['target'],16)==v.as_long()
  rec['original_pointer_fixup']=fixup;self.loads.append(rec)
  if self.pc==0xfffffe000a5a7034:self.scan.append({'address':hex(at),'byte':self.concrete(v),'source_pc':hex(self.pc)})
  return v
 def store(self,a,n,v,pc):
  at=self.concrete(a);v=z3.simplify(resize(v,n*8));assert Parent.Parent.Parent.P<=at<at+n<=Parent.Parent.Parent.P+0x20000
  rec={'visit':len(self.trace),'pc':hex(pc),'address':hex(at),'size_bytes':n,**value(v)};self.writes.append(rec)
  if not z3.is_bv_value(v):self.symbolic_writes+=1
  for j in range(n):self.state[at+j]=z3.simplify(z3.Extract(j*8+7,j*8,v));self.known.add(at+j)
 def snapshot(self,a,n):
  return {'address':hex(a),'size_bytes':n,'known_mask_hex':bytes(int(j in self.known)for j in range(a,a+n)).hex(),'terms':[value(resize(self.state[j],8))if j in self.known else {'origin':'unspecified byte; no source definition in retained epoch'}for j in range(a,a+n)]}
 def step(self,pc):
  assert Parent.START<=pc<Parent.END;raw=self.k.read(pc,4);assert raw==IMAGE.read(pc,4);i=next(Parent.DC.disasm(raw,pc));self.pc=pc;m=i.mnemonic;nextpc=pc+4
  if m=='blraa':
   target=self.concrete(self.read(i.op_str.split(',')[0]));modifier=self.concrete(self.read('x17'))
   loads=[r for r in self.loads if r['size_bytes']==8 and 'bytes_hex'in r and int.from_bytes(bytes.fromhex(r['bytes_hex']),'little')==target];assert loads;p=pointer(self.k,int(loads[-1]['address'],16));assert p['target']==hex(target)and p['diversity']==hex(modifier)and p['authenticated']
   self.boundary={'kind':'before_pending_cleanup_call','pc':hex(pc),'target':hex(target),'modifier':hex(modifier),'X0':hex(self.concrete(self.read('x0'))),'X1':hex(self.concrete(self.read('x1'))),'original_pointer':p,'instruction_executed':False};raise Frontier()
  if m=='braa':
   target=self.concrete(self.read(i.op_str.split(',')[0]));modifier=self.concrete(self.read('x17'));loads=[r for r in self.loads if r['size_bytes']==8 and 'bytes_hex'in r and int.from_bytes(bytes.fromhex(r['bytes_hex']),'little')==target];assert loads
   p=pointer(self.k,int(loads[-1]['address'],16));assert p['authenticated']and p['target']==hex(target)and p['diversity']==hex(modifier);self.edges.append({'pc':hex(pc),'target':hex(target),'modifier':hex(modifier),'original_pointer':p});nextpc=target
  elif m=='b':nextpc=i.operands[0].imm&((1<<64)-1)
  elif m.startswith('b.'):
   assert m in ['b.eq','b.ne'];take=z3.simplify(self.equal if m=='b.eq'else z3.Not(self.equal));assert z3.is_true(take)or z3.is_false(take);nextpc=(i.operands[0].imm&((1<<64)-1))if z3.is_true(take)else nextpc
  elif m=='bti':pass
  elif m=='adrp':self.write(i.reg_name(i.operands[0].reg),i.operands[1].imm&((1<<64)-1))
  elif m=='cset'and i.op_str.endswith(', hi'):self.write(i.reg_name(i.operands[0].reg),z3.If(z3.UGT(self.cmp_left,self.cmp_right),z3.BitVecVal(1,32),z3.BitVecVal(0,32)))
  else:self.c={'spans':[{'label':'one','start':hex(pc),'bytes_hex':raw.hex()}]};Lift.run(self,'one')
  self.trace.append({'pc':hex(pc),'bytes_hex':raw.hex(),'mnemonic':m,'operands':i.op_str});return nextpc
 def run_stream(self):
  pc=Parent.CALL+4
  while len(self.trace)<1000:
   if pc==0xfffffe000a5a729c:self.boundary={'kind':'before_dispatcher_epilogue','pc':hex(pc),'instruction_executed':False};break
   try:pc=self.step(pc)
   except Frontier:break
  assert self.boundary is not None and z3.eq(z3.simplify(self.read('w24')),self.opaque)
  result_addr=Parent.Parent.Parent.W;result=self.snapshot(result_addr,4);heap=self.snapshot(self.heap,32)
  return {'allocation_return_fixture':self.allocation,'allocation_result':hex(self.heap if self.allocation=='fresh_distinct_object'else 0),'source_preallocation_slice':self.preallocation,'source_trace':self.trace,'source_reads':self.loads,'source_writes':self.writes,'source_transfers':self.edges,'scan':self.scan,'heap_at_boundary':heap,'dispatcher_result_at_boundary':result,'boundary':self.boundary,'symbolic_frame_writes':self.symbolic_writes,'carried_word_still_symbolic':True,'allocator_clobbers_declared':list(range(1,19)),'model_memory_writes':0,'new_guest_executed':False,'native_target_executed':False}

def proofs(regions):
 c={'spans':regions};qs=[];counts={};F=0x51010000;N,I=z3.BitVecs('stream_count32 stream_marker_index32',32);D,C=z3.BitVecs('stream_inputB64 stream_object64',64);BASE=0x13496211
 def run(label,a,z,seeds=(),memory=(),typ=Lift):
  v=typ(part(c,label,a,z))
  for r,x in seeds:v.seed(r,x)
  for a,n,x in memory:mem(v,a,n,x)
  v.run(label);counts[label]=v.count;return v
 v=run('scan_counter_encoding',0xfffffe000a5a6104,0xfffffe000a5a6138,[('sp',F),('x29',F+0x250),('w10',N)])
 qs.append(('scan_counter_encoding',z3.Or(cell(v,F+0xac,4)!=BASE+N,cell(v,F+0x1b8,4)!=N)))
 v=run('backward_scan_index',0xfffffe000a5a702c,0xfffffe000a5a7034,[('w11',BASE+I+1),('w10',0xecb69dee)])
 qs.append(('backward_scan_index',z3.Or(v.read('w8')!=I,v.read('w12')!=BASE+I)))
 v=run('scan_repeat_guard',0xfffffe000a5a7040,0xfffffe000a5a705c,[('w15',0xc25b55b9),('w16',0x3da4b356),('w12',BASE+I),('w1',BASE)])
 qs.append(('scan_repeat_guard',v.read('w8')!=z3.If(I==0,z3.BitVecVal(0xbe5,32),z3.BitVecVal(0xbd3,32))))
 v=run('stream_constructor',0xfffffe000a5a708c,0xfffffe000a5a70fc,[('sp',F),('x29',F+0x250),('w16',0x3da4b356),('w30',0xc25b517a),('w12',BASE+I),('x23',D)],[(F+0x160,8,C),(F+0x1b8,4,N)])
 qs.append(('stream_constructor_fields',z3.Or(cell(v,C,8)!=D,cell(v,C+8,4)!=N*0x13509fb7+0x4552bd62,cell(v,C+12,4)!=BASE+I,cell(v,C+16,4)!=0x0c69aa47,cell(v,C+20,4)!=0xbd904c36,cell(v,C+24,4)!=0x31ae0066)))
 qs.append(('length_encoding_reversible',((cell(v,C+8,4)-0x4552bd62)*0x472d6e07)!=N))
 M=z3.BitVec('stream_mode32',32)
 v=run('stream_mode_guard',0xfffffe000a5a70fc,0xfffffe000a5a7114,[('sp',F),('w8',0xe2c),('w13',0x783)],[(F+0x88,4,M)],Flags)
 qs.append(('stream_mode_guard',v.read('w12')!=z3.If(z3.UGT(M,1),z3.BitVecVal(0xe05,32),z3.BitVecVal(0x783,32))))
 v=run('stream_marker_position_guard',0xfffffe000a5a712c,0xfffffe000a5a7180,[('sp',F),('x29',F+0x250),('w8',0xe2c),('w11',BASE+I+1),('w10',0xecb69dee),('w30',0xc25b517a)],[(F+0x160,8,C)])
 # Derive both constants from the source phase before checking the full domain.
 expr=v.read('w10');zero=z3.simplify(z3.substitute(expr,(I,z3.BitVecVal(0,32)))).as_long();eight=z3.simplify(z3.substitute(expr,(I,z3.BitVecVal(8,32)))).as_long()
 qs.append(('stream_marker_position_guard',expr!=z3.If(z3.ULT(I,8),z3.BitVecVal(zero,32),z3.BitVecVal(eight,32))))
 Q=z3.BitVec('stream_allocation_pointer64',64)
 v=run('allocation_result_gate',0xfffffe000a5a6f84,0xfffffe000a5a6f9c,[('x0',Q),('w22',0xbd3),('w19',0x93d)])
 qs.append(('allocation_result_gate',v.read('w8')!=z3.If(Q==0,z3.BitVecVal(0x975,32),z3.BitVecVal(0x93d,32))))
 T=z3.BitVec('stream_type_flags32',32)
 v=run('kernel_allocator_flags',0xfffffe000c4ba158,0xfffffe000c4ba16c,[('x0',F)],[(F+40,4,T)],Flags)
 qs.append(('kernel_allocator_flags',v.read('w1')!=z3.If(T&0x10==0,z3.BitVecVal(0x8004,32),z3.BitVecVal(4,32))))
 v=run('cleanup_postreturn_status',0xfffffe000a5a7278,0xfffffe000a5a7288,[('x20',TABLE),('w19',0x13e)],[(TABLE+8*0x13e,8,0xfffffe000a5a7290)])
 qs.append(('cleanup_postreturn_status',z3.Or(v.read('x8')!=0xfffffe000a5a7290,v.read('w2')!=0xce515bbf)))
 S=z3.BitVec('stream_encoded_status32',32)
 v=run('wrapper_status_decode',0xfffffe000a5a3034,0xfffffe000a5a3040,[('w19',S)])
 qs.append(('wrapper_status_decode',v.read('w0')!=S^0x31ae0066))
 out=[]
 for label,q in qs:
  s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat,label;out.append({'label':label,'query':s.to_smt2(),'result':'unsat'})
 return out,counts

def type_view(k,a):
 raw=IMAGE.read(a,64);ps=[pointer(k,a+j)for j in [16,32]];flags,n=struct.unpack_from('<II',raw,40);name=k.read(int(ps[0]['target'],16),80).split(b'\0')[0].decode();return {'address':hex(a),'normalized64_hex':raw.hex(),'original64_hex':k.read(a,64).hex(),'pointer_fields':ps,'flags':hex(flags),'size_bytes':n,'name':name,'native_bookkeeping_fields_known':False}

def build():
 assert sha(ROOT/'versioned_dispatcher_frame_checks.json')==PIN
 previous=json.loads(read(ROOT/'versioned_dispatcher_frame_checks.json'));assert previous['generator_sha256']==sha(Parent.__file__)
 assert sha(ROOT/'versioned_core_preparation_checks.json')==Parent.PIN
 prior=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));k=Kernel();kernel=[]
 for a in [0xfffffe000c4ba154,0xfffffe000bcfeb8c,0xfffffe000c4ba368,0xfffffe000bcff010]:
  f=k.function(a);f['bytes_hex']=f.pop('bytes');f['label']=hex(a);kernel.append(f)
 from recover_carrier_control import span
 wrapper=dict(span(k,0xfffffe000a5a3034,0xfffffe000a5a3040),label='wrapper_status_decode')
 qs,counts=proofs([previous['source_function'],wrapper,*kernel]);rows=[];totals=Counter()
 for ix,row in enumerate(prior['cases']):
  if row['configuration']['mode32']!=2:continue
  for allocation in ['fresh_distinct_object','null_return']:
   v=Stream(k,row,allocation);r=v.run_stream();r.update(parent_case_index=ix,configuration=row['configuration'],operand_profile=row['source_payload']['operand_profile']);rows.append(r)
   totals['symbolic_instruction_visits']+=len(r['source_trace']);totals['source_read_bytes']+=sum(e['size_bytes']for e in r['source_reads']);totals['source_write_bytes']+=sum(e['size_bytes']for e in r['source_writes']);totals['authenticated_transfers']+=len(r['source_transfers']);totals['symbolic_frame_writes']+=r['symbolic_frame_writes'];totals[r['boundary']['kind']]+=1
 views=[type_view(k,a)for a in [0xfffffe000847b320,0xfffffe000847b720]]
 assert all(v['name']=='site.FPByteArrayStreamInternal'and v['flags']=='0x64'and v['size_bytes']==32 for v in views)
 assert views[0]['pointer_fields'][0]['target']==views[1]['pointer_fields'][0]['target']and views[0]['pointer_fields'][1]['target']==views[1]['pointer_fields'][1]['target']
 rules=[]
 probe=next(r for r in rows if r['boundary']['kind']=='before_pending_cleanup_call');rd=probe['source_reads']
 def loaded(pc):return int.from_bytes(bytes.fromhex(next(r for r in rd if r['pc']==hex(pc))['bytes_hex']),'little')
 for label,l,r,key,add,base,bias in [('typed_free',loaded(0xfffffe000a5a7208),loaded(0xfffffe000a5a721c),0x47,0xeb0,TABLE,0),('free_type_view',loaded(0xfffffe000a5a7238),loaded(0xfffffe000a5a7014),0x16,-0x45,POOL,-4)]:
  rule=selected(l,r,key,add,base,bias);rule.update(label=label,base=hex(base),left256_hex=k.read(l,256).hex(),right256_hex=k.read(r,256).hex(),original_pointer=pointer(k,int(rule['slot'],16)));assert k.read(l,256)==IMAGE.read(l,256)and k.read(r,256)==IMAGE.read(r,256);assert(int(rule['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(rule['target'],16);rules.append(rule)
 controls=[]
 for ix,mod in [(0x783,0xbe01),(0xe05,0xbe01),(0xd54,0x592d),(0xd36,0x592d),(0x975,0x4696),(0x93d,0x4696),(0xbd3,0x95c9),(0xbe5,0x95c9),(0x13e,0xbe01)]:
  p=pointer(k,TABLE+8*ix);assert p['target']==hex(qword(TABLE+8*ix))and p['authenticated']and int(p['diversity'],16)==mod;controls.append({'index':hex(ix),'original_pointer':p})
 dependencies=['recover_versioned_dispatcher_frame.py','recover_versioned_core_preparation.py','probe_versioned_core_entry.py','lskd_values_symbolic.py','kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','recover_carrier_control.py']
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in dependencies},'parent_checks_sha256':PIN,'preparation_checks_sha256':Parent.PIN,'kernel_collection_sha256':k.sha256,'kernel_functions':kernel,'kernel_symbols':k.symbols([0xfffffe000c4ba154,0xfffffe000bcfeb8c,0xfffffe000c4ba368,0xfffffe000bcff010]),'wrapper_decode_source':wrapper,'source_proofs':qs,'source_lift_counts':counts,'cases':rows,'allocation_and_free_type_views':views,'cleanup_bank_rules':rules,'control_pointer_records':controls,'verified_counts':{'cases':len(rows),'source_queries_unsat':len(qs),'source_lift_instructions':sum(counts.values()),'kernel_function_instruction_words':sum(len(f['instructions'])for f in kernel),'cleanup_bank_inputs':512,'control_pointer_records':len(controls),'pending_cleanup_pointers_checked':sum(r['boundary']['kind']=='before_pending_cleanup_call'for r in rows),**totals},'allocator_flags_raw':{'type_flags':'0x64','IOMallocTypeImpl_W1':'0x8004','kalloc_type_impl_low3':'0x4','native_allocator_success_established':False,'native_zeroing_established':False},'model_memory_writes':0,'new_guest_executed':False,'native_target_executed':False,'full_goal_complete':False}

if __name__=='__main__':
 obj=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(obj['verified_counts']),flush=True)
