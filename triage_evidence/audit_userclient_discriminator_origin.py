#!/usr/bin/env python3
"""Source obligations, integer reduction certificate and separate integer replay.
O(I+L+query DAG) construction/space; SMT cost separate, 30 s/query.
No native target or IDB changes. Valid input/frame epochs remain premises.
"""
import copy
import json
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_IMM,ARM64_EXT_SXTW
from kext_port_tools import ROOT,IMAGE,TABLE,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_discriminator_origin as R

TOKEN=0x886a1ca3
PHASE=0x7795e642
SUCCESS=0x31ae0066
A=0xfffeffd7bf3f5bfb
B=0x0001002840c0a405
MODULUS=2**32-1
MAGIC=0x8000000080000001
DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True

class Model(Base):
 def __init__(self,e):
  super().__init__(e)
  self.pointer,self.h,self.i=z3.BitVecs('DO_pointer64 DO_hash64 DO_index64',64)
  self.byte,self.next_byte=z3.BitVecs('DO_byte8 DO_next_byte8',8)
 def owned(self):
  spans=[(self.sp,0x1120),(self.ctx,2048),(self.src,4096)];out=[(self.sp&15)==0]
  for j,(a,n) in enumerate(spans):
   out.extend([a!=0,z3.ULE(a,resize(2**64-1-n,64))])
   for b,m in spans[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,m in IMAGE_REGIONS:out.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  return out
 def load(self,a,n):
  if self.pc in R.BRANCHES:
   js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  if self.pc in [0xfffffe000a657184,0xfffffe000a657234]:
   assert n==1;self.address_checks.append(a==(self.pointer if self.pc==0xfffffe000a657184 else self.pointer+self.i+1))
   return self.byte if self.pc==0xfffffe000a657184 else self.next_byte
  return super().load(a,n)
 def run(self,label,end=None):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if end is not None and i.address>=end:break
   if i.mnemonic=='umulh':
    self.pc=i.address;self.count+=1;self.visited.add(i.address)
    self.write(i.reg_name(i.operands[0].reg),z3.Extract(127,64,z3.ZeroExt(64,self.read(i.reg_name(i.operands[1].reg)))*z3.ZeroExt(64,self.read(i.reg_name(i.operands[2].reg)))))
   else:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.e,self.c=old_e,old_c
  return self

def setup(e):
 v=Model(e)
 for reg,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('w1',PHASE),('w3',TOKEN),('w23',v.status)]:v.seed(reg,x)
 mem(v,v.sp+0x478,8,v.ctx+0x128);mem(v,v.ctx+0x128,8,v.pointer)
 return v

class IntegerReplay:
 """Independent unsigned integer instruction interpreter; no symbolic lift used."""
 def __init__(self,e,data,status=SUCCESS):
  self.reg={};self.memory={};self.reads=[];self.steps=0;self.e=e
  for j in range(31):self.reg['x'+str(j)]=0
  self.reg.update(sp=0x70000000,x2=0x71000000,x4=0x72000000,x7=TABLE,x1=PHASE,x3=TOKEN,x23=status)
  p=0 if data is None else 0x73000000
  self.memory[(0x70000478,8)]=0x71000128;self.memory[(0x71000128,8)]=p
  if data is not None:
   for j,b in enumerate(data+b'\0'):self.memory[(p+j,1)]=b
 def read(self,r):return 0 if r in ['wzr','xzr'] else self.reg['x'+r[1:] if r.startswith('w') else r]&((1<<(32 if r.startswith('w') else 64))-1)
 def write(self,r,x):self.reg['x'+r[1:] if r.startswith('w') else r]=x&((1<<(32 if r.startswith('w') else 64))-1)
 def operand(self,i,o):
  x=self.read(i.reg_name(o.reg)) if o.type==ARM64_OP_REG else o.imm if o.type==ARM64_OP_IMM else None
  assert x is not None
  return x<<o.shift.value if o.shift.type else x
 def address(self,i,o):
  x=self.read(i.reg_name(o.mem.base))+o.mem.disp
  if o.mem.index:
   v=self.read(i.reg_name(o.mem.index))
   if o.ext:assert o.ext==ARM64_EXT_SXTW;v=v-(1<<32) if v&(1<<31) else v
   x+=v<<o.shift.value
  return x&((1<<64)-1)
 def run(self):
  starts={int(s['start'],16)-4:s for s in self.e['spans'] if s['label'] in ['status_gate','pointer_gate','hash_entry','empty_default','hash_step','reduction','store_gate']}
  pc=0xfffffe000a6570c4
  while pc in starts:
   row=starts[pc]
   for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
    self.steps+=1;assert self.steps<200000;m=i.mnemonic;o=i.operands;dest=i.reg_name(o[0].reg)
    if m in ['ldr','ldrb']:
     n=1 if m=='ldrb' else 4 if dest.startswith('w') else 8;a=self.address(i,o[1])
     if n==1:self.reads.append(a)
     x=self.memory[(a,n)] if (a,n) in self.memory else int.from_bytes(IMAGE.read(a,n),'little')
    elif m=='str':self.memory[(self.address(i,o[1]),4 if dest.startswith('w') else 8)]=self.read(dest);continue
    elif m=='cmp':self.equal=self.operand(i,o[0])==self.operand(i,o[1]);continue
    elif m=='cset':assert i.op_str.endswith(', eq');x=int(self.equal)
    elif m=='mov':x=self.operand(i,o[1])
    elif m=='movk':x=(self.read(dest)&~(0xffff<<o[1].shift.value))|(o[1].imm<<o[1].shift.value)
    else:
     a,b=(self.operand(i,o[j]) for j in [1,2])
     if m=='add':x=a+b
     elif m=='sub':x=a-b
     elif m=='and':x=a&b
     elif m=='orr':x=a|b
     elif m=='eor':x=a^b
     elif m=='mul':x=a*b
     elif m=='umulh':x=(a*b)>>64
     elif m=='lsl':x=a<<b
     elif m=='lsr':x=a>>b
     else:raise AssertionError((hex(i.address),m))
    self.write(dest,x)
   terminal=next(t for t in self.e['transfers'] if int(t['ea'],16)==int(row['end_exclusive'],16))
   ti=next(DEC.disasm(bytes.fromhex(terminal['bytes_hex']),int(terminal['ea'],16)));assert ti.mnemonic=='braa'
   pc=self.read(ti.reg_name(ti.operands[0].reg))
  return {'target':hex(pc),'stored_discriminator':self.memory.get((0x72000c90,4)),'byte_reads':len(self.reads),'instruction_instances':self.steps}

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=(),rewrites=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*premises);assert s.check()==z3.sat,label
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),'certified_rewrites':list(rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count});visited.update(v.visited)
 v=setup(e);v.run('input_cell_root');prove('saved_input_cell_address_is_scratch128',v,cell(v,v.sp+0x478,8)!=v.ctx+0x128)
 v.run('input_cell_clear');prove('source_initializes_scratch_input_pointer_to_null',v,cell(v,v.ctx+0x128,8)!=0)
 v=setup(e);v.run('status_gate');prove('all_status32_success_enters_pointer_gate_other_rejects',v,z3.Or(v.read('x9')!=z3.If(v.status==SUCCESS,resize(0xfffffe000a657110,64),resize(0xfffffe000a65ef14,64)),v.read('w11')!=0xa08))
 v.run('pointer_gate');prove('all_pointer64_null_to_zero_store_nonnull_to_first_byte',v,z3.Or(v.read('x9')!=v.pointer,v.read('x10')!=0,v.read('w19')!=TOKEN,
  v.read('x11')!=z3.If(v.pointer==0,resize(0xfffffe000a657294,64),resize(0xfffffe000a657164,64))),[v.status==SUCCESS])
 null=copy.deepcopy(v);null.run('store_gate');prove('null_input_stores_zero_and_rejects',null,z3.Or(cell(null,null.src+0xc90,4)!=0,null.read('x8')!=0xfffffe000a65ef14),[null.status==SUCCESS,null.pointer==0])
 v.run('hash_entry');prove('all_first_byte8_empty_or_loop_seed_and_constants',v,z3.Or(v.read('x14')!=z3.If(v.byte==0,resize(0xfffffe000a6571e4,64),resize(0xfffffe000a657208,64)),v.read('x11')!=5381,v.read('x10')!=0,
  v.read('x15')!=A,v.read('x16')!=B,v.read('x20')!=0x1f6,v.read('w1')!=0x886a1e84,v.read('w22')!=PHASE,v.read('w8')!=0x580),[v.status==SUCCESS,v.pointer!=0])
 empty=copy.deepcopy(v);empty.run('empty_default');prove('empty_input_stores_5381_and_accepts_without_reduction',empty,z3.Or(cell(empty,empty.src+0xc90,4)!=5381,empty.read('x8')!=0xfffffe000a6572d0),[empty.status==SUCCESS,empty.pointer!=0,empty.byte==0])
 v=setup(e)
 for reg,x in [('x9',v.pointer),('x10',v.i),('x11',v.h),('w12',v.byte),('x15',A),('x16',B),('x20',0x1f6),('w8',0x580),('w22',PHASE),('w1',0x886a1e84)]:v.seed(reg,x)
 v.run('hash_step')
 prove('all_hash64_byte8_exact_33h_plus_unsigned_byte_recurrence',v,z3.Or(v.read('x11')!=33*v.h+z3.ZeroExt(56,v.byte),v.read('x10')!=v.i+1,v.read('w19')!=TOKEN,
  v.read('x13')!=z3.If(v.next_byte==0,resize(0xfffffe000a65725c,64),resize(0xfffffe000a657208,64)),v.read('x12')!=z3.ZeroExt(56,v.next_byte),
  v.read('x9')!=v.pointer,v.read('x15')!=A,v.read('x16')!=B,v.read('x20')!=0x1f6,v.read('w8')!=0x580,v.read('w22')!=PHASE,v.read('w1')!=0x886a1e84),
  [v.pointer!=0,z3.ULT(v.i,resize(2**64-1,64)),z3.ULE(v.pointer,resize(2**64-2,64)-v.i)])
 v=setup(e);v.seed('w22',PHASE);v.seed('w19',TOKEN);v.seed('x11',v.h);v.run('reduction')
 product=z3.ZeroExt(64,v.h)*resize(MAGIC,128);q=z3.ZeroExt(31,z3.Extract(127,95,product))
 prove('reduction_source_exact_high_multiply_shift_and_remainder_form',v,z3.Or(v.values[(0xfffffe000a657274,'x9')]!=q,v.read('x10')!=v.h-q*MODULUS,v.read('x8')!=0xfffffe000a657294,v.read('w1')!=PHASE),
  rewrites=[{'lemma':'unsigned_magic_quotient_integer_certificate','transport':'UMULH then LSR31 equals floor(h*MAGIC/2^95); h*MAGIC fits unsigned128.'}])
 h,q0,r=z3.Ints('DO_h_unsigned DO_quotient DO_remainder');d=2**95;error=MAGIC*MODULUS-d
 s=z3.SolverFor('QF_LIA');s.set(timeout=30000);s.add(h>=0,h<2**64,q0>=0,q0<=2**32+1,r>=0,r<MODULUS,h==MODULUS*q0+r);assert s.check()==z3.sat
 s.add(z3.Or(q0*error+r*MAGIC<0,q0*error+r*MAGIC>=d,h*MAGIC>=2**128,h*MAGIC<q0*d,h*MAGIC>=(q0+1)*d,r>2**32-2));assert s.check()==z3.unsat
 qs.append({'label':'unsigned_magic_quotient_integer_certificate','result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
  'certified_rewrites':[{'euclidean_representation':'Every u64 h has h=(2^32-1)*q+r, 0<=r<2^32-1 and q<=2^32+1; the proved interval fixes floor(h*MAGIC/2^95)=q.'}]})
 coverage.append({'label':'unsigned_magic_quotient_integer_certificate','source_instruction_instances':0})
 v=setup(e);v.seed('x10',v.h);v.seed('w19',TOKEN);v.seed('w0',0x7795e3ce);v.run('store_gate')
 prove('all_result64_low32_store_full64_zero_gate_and_local_status',v,z3.Or(cell(v,v.src+0xc90,4)!=z3.Extract(31,0,v.h),
  v.read('x8')!=z3.If(v.h==0,resize(0xfffffe000a65ef14,64),resize(0xfffffe000a6572d0,64)),v.read('w23')!=0xce515bbf))
 v=setup(e);v.run('saved_status_default');prove('direct_saved_status32_initial_default_is_ce515bb2',v,cell(v,v.sp+0x9ec,4)!=0xce515bb2)
 v=setup(e);mem(v,v.ctx+0x200,8,v.header);mem(v,v.ctx+0x5d8,8,v.payload);mem(v,v.src+0x20,4,v.raw_marker);v.run('insertion_inputs')
 prove('insertion_marker_is_independent_source20_u32_input',v,z3.Or(v.read('x24')!=v.header,v.read('w22')!=v.raw_marker,v.read('x28')!=v.payload,cell(v,v.src+0xcb4,4)!=0))
 pp=[]
 specs={'userclient_uidlist_publication_audit.json':['all_discriminator32_exact_node0_search_gate','complete_16_byte_node_then_context_head_publication','published_marker_reconstructs_insertion_cleanup_key'],
  'secure_tunnel_table_insertion_audit.json':['all_source_marker32_key_basis','post_writer_raw_marker_into_source_and_tunnel'],
  'userclient_replacement_bootstrap_audit.json':['null_allocation_null_reloaded_holder_all_saved_status32_update_or_failure_gate','rollback_null_reloaded_holder_all_saved_status32_update_or_failure_gate']}
 for name,labels in specs.items():
  old=json.loads(read(ROOT/name))
  for label in labels:
   q=next(q for q in old['source_proofs'] if q['label']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
   pp.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/name)})
 replay=[];samples=[None,b'']+[bytes([j]) for j in range(256)]+[bytes((j%255)+1 for j in range(n)) for n in [2,7,8,15,16,17,31,64,127,256,1024]]+[b'alpha\0ignored',b'\0ignored']
 for j,data in enumerate(samples):
  got=IntegerReplay(e,data).run();chars=None if data is None else data.split(b'\0',1)[0];h=5381
  if chars:
   for b in chars:h=(33*h+b)&(2**64-1)
   expected=h%MODULUS
  else:expected=0 if chars is None else 5381
  target=0xfffffe000a6572d0 if expected else 0xfffffe000a65ef14
  assert got['stored_discriminator']==expected and int(got['target'],16)==target and got['byte_reads']==(0 if chars is None else len(chars)+1)
  replay.append({'case':j,'input_hex':None if data is None else data.hex(),**got})
 bad_status=IntegerReplay(e,b'alpha',SUCCESS^1).run();assert bad_status['stored_discriminator'] is None and bad_status['byte_reads']==0 and int(bad_status['target'],16)==0xfffffe000a65ef14
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};assert selected==visited
 assert e['inventory_totals']['saved_status']=={'reads':47,'writes':1}
 assert e['inventory_totals']['insertion_marker']=={'reads':1,'writes':0}
 altered=[]
 for name in ['instruction_byte','modulus_claim','inventory_write_claim','native_input_identity_claim']:
  bad=copy.deepcopy(e)
  if name=='instruction_byte':b=bytearray.fromhex(bad['spans'][0]['bytes_hex']);b[0]^=1;bad['spans'][0]['bytes_hex']=b.hex()
  elif name=='modulus_claim':bad['verified_counts']['modulus']-=1
  elif name=='inventory_write_claim':bad['inventory_totals']['saved_status']['writes']=0
  else:bad['native_input_identity_established']=True
  assert bad!=R.build();altered.append({'alteration':name,'rejected_by_fresh_evidence_comparison':True})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'scope':R.SCOPE,
  'source_proofs':qs,'coverage':coverage,'proved_source_PCs':sorted(map(hex,visited)),'rechecked_prior_source_proofs':pp,
  'integer_replays':replay,'failed_status_replay':bad_status,'altered_evidence_controls':altered,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(pp),'distinct_proved_instructions':len(visited),
   'proof_instruction_instances':sum(x['source_instruction_instances'] for x in coverage),'independent_integer_replays':len(replay)+1,
   'altered_evidence_rejections':len(altered)},'conditional_discriminator_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
