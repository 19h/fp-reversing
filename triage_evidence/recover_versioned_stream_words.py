#!/usr/bin/env python3
"""Source-only reader slice with coherent arbitrary frame-byte origins.

Missing private frame bytes stay unspecified in the retained fixtures. This
separate symbolic model preserves their correlations without selecting values;
unknown heap/external reads and unknown observables remain forbidden. One prior
fresh-object return is inherited; no second allocator, native API or guest runs.
O(receipt bytes+C*V+I+256R) time/space plus 30 s/query; 2000 steps/case.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT,IMAGE,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from lskd_values_symbolic import Lift,part,mem,cell,resize
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_versioned_stream_initialization as Parent

P='versioned_stream_words';PIN='be35ea79704879200c95fb057b0d7a8cb4809c55405238b5affa4fde6fc9efff'
DECODER=0xfffffe000a5a7450;AFTER=0xfffffe000a5a7498;CALL=0xfffffe000a5a8218

class Reader(Parent.Stream):
 def __init__(self,k,row):
  self.allow_origins=False;self.origins={};self.origin_sites={};self.words=[];self.word_before=None;self.output_view=None;super().__init__(k,row,'fresh_distinct_object')
 def load(self,a,n):
  try:return super().load(a,n)
  except Parent.Frontier:
   b=self.boundary;sp=z3.simplify(self.read('sp')).as_long()
   if not self.allow_origins or b['kind']!='before_unspecified_frame_or_heap_read'or not sp<=int(b['address'],16)<int(b['address'],16)+n<=sp+0x200:raise
   at=int(b['address'],16);bs=[]
   for j in range(at,at+n):
    if j in self.known:bs.append(resize(self.state[j],8))
    else:
     if j not in self.origins:self.origins[j]=z3.BitVec('frame_'+hex(j-sp)[2:]+'_byte',8);self.origin_sites[j]=hex(self.pc)
     bs.append(self.origins[j])
   v=z3.simplify(z3.Concat(*reversed(bs))if n>1 else bs[0]);self.loads.append({'visit':len(self.trace),'pc':hex(self.pc),'address':hex(at),'size_bytes':n,**Parent.value(v),'source_defined_mask_hex':bytes(int(j in self.known)for j in range(at,at+n)).hex()});self.boundary=None;return v
 def store(self,a,n,v,pc):
  at=self.concrete(a);sp=z3.simplify(self.read('sp')).as_long();v=z3.simplify(v)
  if not z3.is_bv_value(v):assert sp<=at<at+n<=sp+0x200,('symbolic value outside frame',hex(pc),hex(at))
  return super().store(a,n,v,pc)
 def step(self,pc):
  raw=self.k.read(pc,4);assert raw==IMAGE.read(pc,4);i=next(Parent.Parent.DC.disasm(raw,pc));self.pc=pc
  if pc==DECODER:self.word_before={'read_visit_start':len(self.loads),'pointer':hex(self.concrete(self.read('x10'))),'index':self.concrete(self.read('w11')+self.read('w26')),'registers':{r:Parent.value(self.read(r))for r in ['w5','w6','w7','w26','w30']}}
  if pc==AFTER:
   assert self.word_before is not None;w=self.concrete(self.read('w11'));r=self.word_before;r.update(after_visit=len(self.trace),encoded_word32=hex(w),canonical_word32=hex(w^0x31ae0066),source_read_indices=[j for j in range(r['read_visit_start'],len(self.loads))if self.loads[j]['pc']in [hex(DECODER),hex(0xfffffe000a5a7460),hex(0xfffffe000a5a746c),hex(0xfffffe000a5a7480)]]);self.words.append(r);self.word_before=None
  if pc==0xfffffe000a5a80f8:self.output_view={'read_PC':'0xfffffe000a5a80f0','pointer':hex(self.concrete(self.read('x11'))),'capacity_bytes':self.concrete(self.read('w12'))}
  if i.mnemonic=='tst':
   w=self.width(i.reg_name(i.operands[0].reg));self.equal=z3.simplify((self.operand(i,i.operands[0],w)&self.operand(i,i.operands[1],w))==0)
  elif i.mnemonic=='csel':
   cond=i.op_str.rsplit(',',1)[1].strip();assert cond in ['eq','ne'];self.write(i.reg_name(i.operands[0].reg),z3.If(self.equal if cond=='eq'else z3.Not(self.equal),self.read(i.reg_name(i.operands[1].reg)),self.read(i.reg_name(i.operands[2].reg))))
  else:return super().step(pc)
  self.trace.append({'pc':hex(pc),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str});return pc+4
 def run_reader(self,expected):
  strict=super().run_stream()
  for key in strict:assert strict[key]==expected[key],key
  assert strict['boundary']['pc']=='0xfffffe000a5a731c';cut=len(self.trace);self.allow_origins=True;pc=int(self.boundary['pc'],16);self.boundary=None
  while len(self.trace)-cut<2000:
   try:pc=self.step(pc)
   except Parent.Frontier:break
  assert self.boundary is not None and self.boundary['pc']==hex(CALL)and self.boundary['target']=='0xfffffe000c4ba154'
  self.boundary['kind']='before_second_stream_allocation';self.boundary['captured_X1_not_allocator_argument']=self.boundary.pop('X1')
  assert self.boundary['X0']=='0xfffffe000847b8e0'and self.output_view=={'read_PC':'0xfffffe000a5a80f0','pointer':hex(Parent.Parent.Parent.Parent.P+0x1600),'capacity_bytes':512}
  assert len(self.origins)==24 and [w['canonical_word32']for w in self.words]==['0xfb1958','0x4','0x1']
  sp=z3.simplify(self.read('sp')).as_long();origins=[{'address':hex(a),'body_SP_offset':hex(a-sp),'symbol':str(v),'first_read_pc':self.origin_sites[a],'source_initialization_established':False}for a,v in sorted(self.origins.items())]
  # All selected control/address/call observations already passed concrete().
  assert all(z3.is_bv_value(z3.simplify(v))for v in self.observables)
  return {'source_preallocation_slice':self.preallocation,'strict_parent_prefix_visits':cut,'new_reader_visits':len(self.trace)-cut,'source_trace':self.trace,'source_reads':self.loads,'source_writes':self.writes,'source_transfers':self.edges,'frame_byte_origins':origins,'original_W24_origin':'unresolved_frame_word32','unconstrained_origin_bits':224,'decoded_words':self.words,'output_B_view':self.output_view,'input_stream_at_boundary':self.snapshot(self.heap,32),'boundary':self.boundary,'all_selected_observables_concrete':True,'observable_count':len(self.observables),'frame_initialization_claimed':False,'model_memory_writes':0,'new_guest_executed':False,'native_target_executed':False}

class Flags(Lift):
 def run(self,label):
  original=self.c;row=next(s for s in self.c['spans']if s['label']==label)
  for i in Parent.Parent.DC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='tst':
    w=self.width(i.reg_name(i.operands[0].reg));self.equal=(self.operand(i,i.operands[0],w)&self.operand(i,i.operands[1],w))==0;self.count+=1;continue
   self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
  self.c=original;return self

def proofs(source):
 c={'spans':[source]};qs=[];counts={};F=0x51010000;D=z3.BitVec('word_input64',64);I,V,L=z3.BitVecs('word_index32 word_header32 word_length32',32);bs=[z3.BitVec('word_byte'+str(j),8)for j in range(4)]
 def run(label,a,z,seeds=(),memory=(),typ=Lift):
  v=typ(part(c,label,a,z))
  for r,x in seeds:v.seed(r,x)
  for a,n,x in memory:mem(v,a,n,x)
  v.run(label);counts[label]=v.count;return v
 v=run('four_byte_decoder',0xfffffe000a5a7454,0xfffffe000a5a7498,[('x10',D),('w8',0),('w11',resize(bs[0],32)),('w5',0xcd),('w6',0x9c6d3bf2),('w7',0x6392c400),('w30',0xadc33b59)],[(D+j,1,bs[j])for j in range(1,4)])
 canonical=z3.Concat(*[b^0xcd for b in bs]);qs.append(('four_byte_decoder',v.read('w11')!=canonical^0x31ae0066))
 v=run('word_read_index',0xfffffe000a5a744c,0xfffffe000a5a7450,[('w11',I+0x7a6fa13d),('w26',0x85905ec3)])
 qs.append(('word_read_index',v.read('w8')!=I))
 v=run('header_low24_guard',0xfffffe000a5a7814,0xfffffe000a5a7858,[('sp',F),('w22',0x3da4b356)],[(F+0x34,4,V^0x31ae0066)])
 qs.append(('header_low24_guard',z3.Or(v.condition!=((V&0xffffff)==0xfb1958),v.read('w9')!=z3.If((V&0xffffff)==0xfb1958,z3.BitVecVal(0xcc1,32),z3.BitVecVal(0xc87,32)))))
 v=run('header_bit30_guard',0xfffffe000a5a7868,0xfffffe000a5a789c,[('w8',0xe2c),('w13',V^0x31ae0066)],typ=Flags)
 qs.append(('header_bit30_guard',z3.Or(v.equal!=((V&0x40000000)==0),v.read('w8')!=z3.If(V&0x40000000==0,z3.BitVecVal(0xe58,32),z3.BitVecVal(0xe2c,32)))))
 v=run('second_word_complement_projection',0xfffffe000a5a78c0,0xfffffe000a5a7958,[('w9',0x9ac),('w10',L^0x9c6d3b3f)])
 qs.append(('second_word_complement_projection',z3.Or(v.cmp_left!=~L,v.cmp_right!=7)))
 A,Q=z3.BitVecs('word_argument_record64 word_outputB64',64);N=z3.BitVec('word_output_capacity32',32)
 v=run('output_B_record_fields',0xfffffe000a5a80ec,0xfffffe000a5a80f8,[('x29',F+0x250)],[(F+0x180,8,A),(A+0x38,8,Q),(A+0x40,4,N)])
 qs.append(('output_B_record_fields',z3.Or(v.read('x11')!=Q,v.read('w12')!=N)))
 out=[]
 for label,q in qs:
  s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat,label;out.append({'label':label,'query':s.to_smt2(),'result':'unsat'})
 return out,counts

def build():
 assert sha(ROOT/'versioned_stream_initialization_checks.json')==PIN
 previous=json.loads(read(ROOT/'versioned_stream_initialization_checks.json'));assert previous['generator_sha256']==sha(Parent.__file__)
 assert sha(ROOT/'versioned_core_preparation_checks.json')==Parent.Parent.PIN
 prior=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));dispatch=json.loads(read(ROOT/'versioned_dispatcher_frame_checks.json'));assert sha(ROOT/'versioned_dispatcher_frame_checks.json')==Parent.PIN
 k=Kernel();qs,counts=proofs(dispatch['source_function']);rows=[];totals=Counter()
 for old in previous['cases']:
  if old['boundary']['pc']!='0xfffffe000a5a731c':continue
  row=prior['cases'][old['parent_case_index']];v=Reader(k,row);r=v.run_reader(old);r.update(parent_case_index=old['parent_case_index'],configuration=old['configuration'],operand_profile=old['operand_profile']);rows.append(r)
  totals['strict_prefix_visits']+=r['strict_parent_prefix_visits'];totals['new_reader_visits']+=r['new_reader_visits'];totals['source_read_bytes']+=sum(e['size_bytes']for e in r['source_reads']);totals['source_write_bytes']+=sum(e['size_bytes']for e in r['source_writes']);totals['authenticated_transfers']+=len(r['source_transfers']);totals['origin_bytes']+=len(r['frame_byte_origins']);totals['decoded_words']+=len(r['decoded_words'])
 probe=rows[0]['source_reads']
 def loaded(pc,j=0):return int.from_bytes(bytes.fromhex([r for r in probe if r['pc']==hex(pc)][j]['bytes_hex']),'little')
 banks=[]
 for label,l,r,key,add,base in [('second_stream_allocator',loaded(0xfffffe000a5a819c,1),loaded(0xfffffe000a5a819c,0),0xef,0xeb2,TABLE),('second_stream_type_view',loaded(0xfffffe000a5a81d8),loaded(0xfffffe000a5a81ec),0x73,0x11c,POOL)]:
  bank=selected(l,r,key,add,base);bank.update(label=label,base=hex(base),left256_hex=k.read(l,256).hex(),right256_hex=k.read(r,256).hex(),original_pointer=pointer(k,int(bank['slot'],16)));assert k.read(l,256)==IMAGE.read(l,256)and k.read(r,256)==IMAGE.read(r,256)and bank['original_pointer']['target']==bank['target'];banks.append(bank)
 assert banks[0]['target']=='0xfffffe000c4ba154'and banks[1]['target']=='0xfffffe000847b8e0'
 controls=[]
 for ix,mod in [(0xcc1,0xb26e),(0xc87,0xb26e),(0xe58,0x30c5),(0xe2c,0x30c5)]:
  p=pointer(k,TABLE+8*ix);assert p['target']==hex(qword(TABLE+8*ix))and p['authenticated']and int(p['diversity'],16)==mod;controls.append({'index':hex(ix),'original_pointer':p})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'parent_checks_sha256':PIN,'preparation_checks_sha256':Parent.Parent.PIN,'dispatcher_checks_sha256':Parent.PIN,'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in ['recover_versioned_stream_initialization.py','recover_versioned_dispatcher_frame.py','lskd_values_symbolic.py','kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py']},'source_proofs':qs,'source_lift_counts':counts,'cases':rows,'second_allocation_bank_rules':banks,'second_allocation_type_view':Parent.type_view(k,0xfffffe000847b8e0),'header_control_pointer_records':controls,'verified_counts':{'cases':len(rows),'source_queries_unsat':len(qs),'source_lift_instructions':sum(counts.values()),'bank_inputs':512,'header_control_pointer_records':len(controls),'pending_allocator_pointers_checked':len(rows),**totals},'native_frame_initialization_established':False,'new_guest_executed':False,'model_memory_writes':0,'native_target_executed':False,'full_goal_complete':False}

if __name__=='__main__':
 obj=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(obj['verified_counts']),flush=True)
