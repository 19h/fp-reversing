#!/usr/bin/env python3
"""Source-only second-stream construction and private stack-adapter contract.

Hash-pinned parent prefixes; distinct fresh 32 B or counterfactual null return.
No allocator, stack probe, inner body, native API or guest executes. Arbitrary
frame origins remain coherent; no allocator memory initialization is assumed.
O(receipt bytes+C*V+I+256R) time/space plus 30 s/query; 2000 steps/new case.
"""
import json
from collections import Counter
import z3
from capstone.arm64 import ARM64_OP_REG,ARM64_EXT_UXTB,ARM64_EXT_SXTW
from kext_port_tools import ROOT,IMAGE,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import starts
from recover_carrier_control import span
from lskd_values_symbolic import Lift,part,mem,cell,resize
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_versioned_stream_words as Parent

P='versioned_output_stream';PIN='6d716dcc1ffc8a2d2d19f078a433f130b3e387198894c5fce291ae825c46b9ed'
ADAPTER=0xfffffe000a69ee38;END=0xfffffe000a69f064;INNER=0xfffffe000a6890dc
CALL=0xfffffe000a5a8508;PENDING_FREE=0xfffffe000a5a92e4
GUEST=Parent.Parent.Parent.Parent.Parent.P

def shift(obj,i):
 w=obj.width(i.reg_name(i.operands[0].reg));a=obj.operand(i,i.operands[1],w);b=obj.operand(i,i.operands[2],w)&(w-1)
 obj.write(i.reg_name(i.operands[0].reg),a<<b if i.mnemonic=='lsl'else z3.LShR(a,b))

class A64(Lift):
 def operand(self,i,o,n):
  if o.ext in [ARM64_EXT_UXTB,ARM64_EXT_SXTW]:
   v=self.read(i.reg_name(o.reg));v=z3.ZeroExt(n-8,resize(v,8))if o.ext==ARM64_EXT_UXTB else z3.SignExt(n-32,resize(v,32));return v<<o.shift.value
  return super().operand(i,o,n)
 address=Parent.Parent.Parent.Slice.address
 def run(self,label):
  original=self.c;row=next(s for s in self.c['spans']if s['label']==label)
  for i in Parent.Parent.Parent.DC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='adrp':self.write(i.reg_name(i.operands[0].reg),i.operands[1].imm&((1<<64)-1));self.count+=1
   elif i.mnemonic in ['lsl','lsr']and i.operands[2].type==ARM64_OP_REG:shift(self,i);self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
  self.c=original;return self

class Output(Parent.Reader):
 def step(self,pc):
  raw=self.k.read(pc,4);assert raw==IMAGE.read(pc,4);i=next(Parent.Parent.Parent.DC.disasm(raw,pc))
  if i.mnemonic in ['lsl','lsr']and i.operands[2].type==ARM64_OP_REG:
   self.pc=pc;shift(self,i);self.trace.append({'pc':hex(pc),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str});return pc+4
  return super().step(pc)
 def run_output(self,expected,strict,allocation):
  parent=self.run_reader(strict);parent.update(parent_case_index=expected['parent_case_index'],configuration=expected['configuration'],operand_profile=expected['operand_profile']);assert parent==expected
  H2=self.heap+0x200;assert not any(j in self.known for j in range(H2,H2+32));before_origins=dict(self.origins)
  self.trace=[];self.loads=[];self.writes=[];self.edges=[];self.observables=[];self.allow_origins=False;self.boundary=None
  for j in range(1,19):self.seed('x'+str(j),z3.BitVec('second_allocator_clobber_x'+str(j),64))
  self.seed('x0',H2 if allocation=='fresh_distinct_object'else 0);self.seed('x30',Parent.CALL+4);pc=Parent.CALL+4
  for _ in range(2000):
   try:pc=self.step(pc)
   except Parent.Parent.Frontier:break
  assert self.boundary is not None and self.origins==before_origins
  success=allocation=='fresh_distinct_object';assert self.boundary['pc']==hex(CALL if success else PENDING_FREE)
  self.boundary['kind']='before_private_stack_adapter'if success else 'before_input_stream_free_after_null_second_allocation'
  C=self.concrete(self.read('x0'))if success else GUEST+0x4060
  if success:
   assert C==GUEST+0x4060 and self.boundary['target']==hex(ADAPTER)
   assert self.boundary['X1']==hex(self.concrete(self.read('x29'))-0x68)
  else:assert self.boundary['target']=='0xfffffe000c4ba368'and self.boundary['X0']=='0xfffffe000847bba0'and self.boundary['X1']==hex(self.heap)
  assert not any(GUEST+0x1600<=int(e['address'],16)<GUEST+0x1800 for e in self.writes)
  return {'parent_case_index':expected['parent_case_index'],'configuration':expected['configuration'],'operand_profile':expected['operand_profile'],'allocation_return_fixture':allocation,'allocation_result':hex(H2 if success else 0),'declared_distinct_object':hex(H2),'allocator_clobbers_declared':list(range(1,19)),'source_trace':self.trace,'source_reads':self.loads,'source_writes':self.writes,'source_transfers':self.edges,'input_stream_at_boundary':self.snapshot(self.heap,32),'output_stream_at_boundary':self.snapshot(H2,32),'reused_record_at_boundary':self.snapshot(C,0x50),'boundary':self.boundary,'new_origin_bytes':0,'output_B_bytes_written':0,'all_selected_observables_concrete':all(z3.is_bv_value(z3.simplify(v))for v in self.observables),'model_memory_writes':0,'new_guest_executed':False,'native_target_executed':False}

def proofs(regions,k):
 c={'spans':regions};qs=[];counts={};F=0x51010000
 def run(label,a,z,seeds=(),memory=(),typ=A64):
  v=typ(part(c,label,a,z))
  for r,x in seeds:v.seed(r,x)
  for a,n,x in memory:mem(v,a,n,x)
  v.run(label);counts[label]=v.count;return v
 def claim(n,q):
  s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat,n;qs.append({'label':n,'query':s.to_smt2(),'result':'unsat'})
 D,H=z3.BitVecs('output_data64 output_object64',64);N=z3.BitVec('output_capacity32',32)
 v=run('output_constructor',0xfffffe000a5a82a4,0xfffffe000a5a8320,[('sp',F),('x29',F+0x250),('x11',D),('w12',N),('w28',0x3da4b356),('w9',0x692)],[(F+0x190,8,H)])
 claim('output_constructor',z3.Or(cell(v,H,8)!=D,cell(v,H+8,4)!=N*0x13509fb7+0x4552bd62,cell(v,H+12,4)!=N+0x13496211,cell(v,H+16,4)!=0x0c69aa47,cell(v,H+20,4)!=0xbd904c34,cell(v,H+24,4)!=0x31ae0066,cell(v,F+0x134,4)!=1))
 SHIFT=z3.BitVec('output_shift_count32',32)
 v=run('register_shift_mask',0xfffffe000a5a82c4,0xfffffe000a5a82c8,[('w12',N),('w9',SHIFT)])
 claim('register_shift_mask',v.read('x9')!=resize(N<<(SHIFT&31),64))
 C,R,A,B,E,TASK,IN=z3.BitVecs('output_record64 output_arguments64 output_aux64 output_workspace10064 output_auxend64 output_task64 output_input_stream64',64)
 M,J,T,PH=z3.BitVecs('output_mode32 output_marker32 output_prior_word32 output_phase32',32);K=(resize(C,32)^0x6133a0c8)*0x84d77373
 class Pack(A64):
  def write(self,name,value):
   if self.pc==0xfffffe000a5a83bc and name=='w12':self.raw_key=value;value=K
   return super().write(name,value)
 v=run('output_record_pack',0xfffffe000a5a8320,0xfffffe000a5a8450,[('sp',F),('x29',F+0x250),('x16',H),('w24',PH)],[(F+0x180,8,R),(R+8,4,M),(R+12,4,J),(R,8,TASK),(F+0x16c,4,T),(F+0xd8,8,C),(F+0xe8,8,A),(F+0xf0,8,B),(F+0xe0,8,E),(F+0x150,8,IN),(F+0xf8,8,C+0x3fa0)],typ=Pack)
 f=((T^0x2ef3cd08)+0xd10c32f8)^((T^0xfab34999)+0x054cb667)^((T^0xe5ee84f7)+0x1a117b09)
 claim('record_address_key',v.raw_key!=K)
 claim('output_record_fields',z3.Or(cell(v,C,8)!=H,cell(v,C+8,8)!=A,cell(v,C+16,8)!=B,cell(v,C+0x38,8)!=IN,cell(v,C+0x40,8)!=E,cell(v,C+0x48,8)!=TASK,cell(v,C+0x28,8)!=C+0x3fa0,cell(v,C+0x18,4)+K!=M+0x10289de0,cell(v,C+0x1c,4)+K!=J*0x59c51537+0x4f301f03,cell(v,C+0x30,4)-K!=f+0x492f18ff,(cell(v,C+0x34,4)^K)!=PH+0xfaf7b49c))
 packed=v
 v=run('inner_record_decoder',0xfffffe000a68920c,0xfffffe000a689244,[('sp',F),('x0',C),('x2',C),('w14',0x84d77373)],[(C+off,4,cell(packed,C+off,4))for off in [0x18,0x1c,0x30,0x34]])
 claim('inner_record_decoder',z3.Or(cell(v,F+0x314,4)!=M+0x10289de0,cell(v,F+0x408,4)!=J*0x59c51537+0x4f301f03,cell(v,F+0x350,4)!=f+0x492f18ff,cell(v,F+0x45c,4)!=PH+0xfaf7b49c))
 S,CELL,HEAD=z3.BitVecs('adapter_seed64 adapter_cell64 adapter_header64',64);POST=z3.BitVec('adapter_final_header32',32)
 v=run('adapter_seed_update',0xfffffe000a69ef2c,0xfffffe000a69ef3c,[('x19',CELL)],[(CELL,8,S)])
 PWORD=S*0x2e95+1;claim('adapter_seed_capture_and_update',z3.Or(v.read('x21')!=S,v.read('x8')!=PWORD))
 v=run('adapter_private_size',0xfffffe000a69ef78,0xfffffe000a69ef88,[('x8',PWORD)])
 SZ=(z3.LShR(PWORD,56)&0xf0)+16;claim('adapter_private_size',z3.Or(v.read('x8')!=SZ,v.read('x9')!=SZ,z3.ULT(v.read('x8'),16),z3.UGT(v.read('x8'),256),(v.read('x8')&15)!=0))
 v=run('adapter_header_initialization',0xfffffe000a69efa4,0xfffffe000a69efac,[('x20',HEAD),('x21',S)])
 claim('adapter_header_initialization',cell(v,HEAD,8)!=S-0xb0)
 v=run('inner_header_restoration',0xfffffe000a689200,0xfffffe000a68920c,[('x1',HEAD)],[(HEAD,8,S-0xb0)])
 claim('inner_header_restoration',cell(v,HEAD,8)!=S)
 v=run('adapter_delta_output',0xfffffe000a69f040,0xfffffe000a69f050,[('x20',HEAD),('x21',S),('x19',CELL)],[(HEAD,4,POST)])
 DELTA=z3.ZeroExt(48,z3.Extract(15,0,POST-resize(S,32)))<<4;OUT=cell(v,CELL,8)
 claim('adapter_delta_output',OUT!=DELTA)
 claim('adapter_delta_domain',z3.Or(z3.UGT(OUT,0xffff0),(OUT&15)!=0,(OUT==0)!=(z3.Extract(15,0,POST)==z3.Extract(15,0,S))))
 v=run('caller_delta_and_status',0xfffffe000a5a8514,0xfffffe000a5a8528,[('sp',F),('x29',F+0x250),('x19',C)],[(F+0x1e8,8,DELTA),(C+0x20,4,POST)])
 claim('caller_delta_and_status',z3.Or(v.read('sp')!=F+DELTA,v.read('w14')!=POST))
 # Every bank cut retains its original addressing and index arithmetic. The
 # two byte results are arbitrary here; exhaustive original-table identities
 # below bind them for every low-byte input, independently of controller epochs.
 rules=[]
 specs=[('controller_a',0xfffffe000a69ee88,0xfffffe000a69eeb8,'w8',0xfffffe0007949ed0,0xfffffe000792fec0,0x92,0xbf,POOL,[( 'w11',0x92)],0xfffffe000a69ee94,0xfffffe000a69eea8),('controller_b',0xfffffe000a69eed4,0xfffffe000a69ef04,'w9',0xfffffe0007949dd0,0xfffffe000792fbc0,0xd8,-4,POOL,[],0xfffffe000a69eee0,0xfffffe000a69eef4),('published_seed',0xfffffe000a69ef4c,0xfffffe000a69ef70,'w9',qword(POOL+0xb70),qword(POOL+0xa10),0x92,0x9f,POOL,[('x1',POOL),('w11',0x92)],0xfffffe000a69ef54,0xfffffe000a69ef60),('inner_target',0xfffffe000a69efc0,0xfffffe000a69efe4,'w8',qword(POOL+0x840),qword(POOL+0xbb8),0x3e,0xed9,TABLE,[('x1',POOL)],0xfffffe000a69efc8,0xfffffe000a69efd4),('inner_table',0xfffffe000a69eff8,0xfffffe000a69f028,'w9',0xfffffe0007941f60,0xfffffe000794a0d0,5,6,POOL,[],0xfffffe000a69f004,0xfffffe000a69f018)]
 for label,a,z,reg,left,right,key,add,base,seeds,pc1,pc2 in specs:
  B32=z3.BitVec(label+'_selector32',32);L,RR=z3.BitVecs(label+'_left8 '+label+'_right8',8)
  class Bank(A64):
   def load(self,at,n):
    if self.pc in [pc1,pc2]:
     expected=left+resize(resize(B32,8),64)if self.pc==pc1 else right+resize(L^key,64);claim(label+'_address_'+hex(self.pc),at!=expected);assert n==1;return L if self.pc==pc1 else RR
    at=z3.simplify(at);assert n==8 and z3.is_bv_value(at);return z3.BitVecVal(qword(at.as_long()),64)
  v=run(label,a,z,[(reg,B32),*seeds],typ=Bank);claim(label+'_index',v.read(reg)!=resize(resize(B32,8)^RR,32)+add)
  b=selected(left,right,key,add,base);b.update(label=label,left256_hex=k.read(left,256).hex(),right256_hex=k.read(right,256).hex(),base=hex(base),original_pointer=pointer(k,int(b['slot'],16)));assert k.read(left,256)==IMAGE.read(left,256)and k.read(right,256)==IMAGE.read(right,256);rules.append(b)
 return qs,counts,rules

def build():
 assert sha(ROOT/'versioned_stream_words_checks.json')==PIN
 old=json.loads(read(ROOT/'versioned_stream_words_checks.json'));assert old['generator_sha256']==sha(Parent.__file__)
 assert sha(ROOT/'versioned_stream_initialization_checks.json')==old['parent_checks_sha256']and sha(ROOT/'versioned_core_preparation_checks.json')==old['preparation_checks_sha256']and sha(ROOT/'versioned_dispatcher_frame_checks.json')==old['dispatcher_checks_sha256']
 strict=json.loads(read(ROOT/'versioned_stream_initialization_checks.json'));prior=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));dispatcher=json.loads(read(ROOT/'versioned_dispatcher_frame_checks.json'))
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e);text=next(s for s in e['sections']if s['section']=='__text');assert catalog[-1]==ADAPTER and text['address']+text['size']==END
 adapter=dict(span(k,ADAPTER,END),label='last_text_function');assert adapter['instructions'][-1]['mnemonic']=='retab'
 inner=dict(span(k,INNER,0xfffffe000a689244),label='inner_entry_and_decode');regions=[dispatcher['source_function'],adapter,inner];qs,counts,rules=proofs(regions,k);rows=[];totals=Counter()
 for expected in old['cases']:
  previous=next(r for r in strict['cases']if r['parent_case_index']==expected['parent_case_index']and r['boundary']['pc']=='0xfffffe000a5a731c')
  for allocation in ['fresh_distinct_object','null_return']:
   v=Output(k,prior['cases'][expected['parent_case_index']]);r=v.run_output(expected,previous,allocation);rows.append(r)
   totals['new_source_visits']+=len(r['source_trace']);totals['source_read_bytes']+=sum(x['size_bytes']for x in r['source_reads']);totals['source_write_bytes']+=sum(x['size_bytes']for x in r['source_writes']);totals['authenticated_transfers']+=len(r['source_transfers']);totals[r['boundary']['kind']]+=1
   print(json.dumps({'case':len(rows),'allocation':allocation,'visits':len(r['source_trace'])}),flush=True)
 deps=['recover_versioned_stream_words.py','recover_versioned_stream_initialization.py','recover_versioned_dispatcher_frame.py','lskd_values_symbolic.py','kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py','recover_carrier_control.py']
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'parent_checks_sha256':PIN,'preparation_checks_sha256':sha(ROOT/'versioned_core_preparation_checks.json'),'strict_checks_sha256':sha(ROOT/'versioned_stream_initialization_checks.json'),'dispatcher_checks_sha256':sha(ROOT/'versioned_dispatcher_frame_checks.json'),'kernel_collection_sha256':k.sha256,'adapter_source':adapter,'last_function_boundary':{'last_LC_FUNCTION_STARTS_entry':hex(catalog[-1]),'text_end':hex(END),'auth_stubs_start':hex(next(s for s in e['sections']if s['section']=='__auth_stubs')['address'])},'inner_prefix_source':inner,'source_proofs':qs,'source_lift_counts':counts,'adapter_bank_rules':rules,'probe_import_pointer':pointer(k,0xfffffe000847c618),'inner_call_pointer':pointer(k,0xfffffe000847a888),'null_cleanup_type_view':Parent.Parent.type_view(k,0xfffffe000847bba0),'cases':rows,'verified_counts':{'cases':len(rows),'source_queries_unsat':len(qs),'source_lift_instructions':sum(counts.values()),'adapter_instruction_words':len(adapter['instructions']),'inner_prefix_instruction_words':len(inner['instructions']),'adapter_bank_inputs':256*len(rules),**totals},'full_inner_header_preservation_proved':False,'actual_adapter_delta_proved_zero':False,'output_B_bytes_written':0,'model_memory_writes':0,'new_guest_executed':False,'native_target_executed':False,'full_goal_complete':False}

if __name__=='__main__':
 obj=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(obj['verified_counts']),flush=True)
