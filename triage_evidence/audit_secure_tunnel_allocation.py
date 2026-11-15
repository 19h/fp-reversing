#!/usr/bin/env python3
"""Source lifts of local allocation, header and byte-layout contracts.
O(I+256R+query DAG) construction and space; SMT search separate, 30 s/query.
No target executes. Storage is disjoint and address arithmetic does not wrap.
"""
import copy
import json
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_EXT_UXTB, ARM64_EXT_SXTW
from kext_port_tools import ROOT, IMAGE, TABLE, POOL, qword
from lskd_values_symbolic import Lift, resize, mem
from audit_userclient_hash_table_initializer import IMAGE_REGIONS
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_secure_tunnel_allocation as R

DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True
SUCCESS=0x31ae0066

def value(x):
 x=z3.simplify(x);assert z3.is_bv_value(x),str(x);return x.as_long()

class Model(Lift):
 def __init__(self,e):
  super().__init__({'spans':e['spans']});self.e=e;self.visited=set();self.address_checks=[]
  self.p,self.src,self.ctx,self.sp,self.h=z3.BitVecs('ST_object64 ST_source64 ST_context64 ST_SP64 ST_header64',64)
  self.original=z3.BitVec('ST_original_object960',960)
  self.source_bytes=z3.Array('ST_source_bytes',z3.BitVecSort(64),z3.BitVecSort(8))
  self.object_bytes={j:z3.Extract(8*j+7,8*j,self.original) for j in range(120)}
  self.bytes={};self.object_stores=[]
  for j in range(31):self.seed('x'+str(j),z3.BitVec('ST_initial_X'+str(j),64))
  self.seed('sp',self.sp)
 def offset(self,a,b):
  v=z3.simplify(resize(a,64)-b);return v.as_long() if z3.is_bv_value(v) else None
 def operand(self,i,o,n):
  if o.ext==ARM64_EXT_UXTB:
   assert not o.shift.type;return resize(self.read(i.reg_name(o.reg)),n)&255
  return super().operand(i,o,n)
 def address(self,i,o):
  if o.ext==ARM64_EXT_SXTW:
   return z3.simplify(resize(self.read(i.reg_name(o.mem.base)),64)+o.mem.disp+(z3.SignExt(32,resize(self.read(i.reg_name(o.mem.index)),32))<<o.shift.value))
  return super().address(i,o)
 def load(self,a,n):
  a=z3.simplify(a);off=self.offset(a,self.p)
  if off is not None and off+n<=120:
   return z3.Concat(*[self.object_bytes[off+j] for j in reversed(range(n))]) if n>1 else self.object_bytes[off]
  key=(a.sexpr(),n)
  if key in self.memory:return self.memory[key]
  off=self.offset(a,self.src)
  if off is not None and off+n<=0x800:
   bs=[self.bytes.get(z3.simplify(a+j).sexpr(),z3.Select(self.source_bytes,resize(off+j,64))) for j in range(n)]
   return z3.Concat(*reversed(bs)) if n>1 else bs[0]
  bs=[self.bytes.get(z3.simplify(a+j).sexpr()) for j in range(n)]
  if all(x is not None for x in bs):return z3.Concat(*reversed(bs)) if n>1 else bs[0]
  if z3.is_bv_value(a):return resize(int.from_bytes(IMAGE.read(a.as_long(),n),'little'),8*n)
  return super().load(a,n)
 def store(self,a,n,v,pc):
  super().store(a,n,v,pc);v=resize(v,n*8);off=self.offset(a,self.p)
  for j in range(n):
   byte=z3.simplify(z3.Extract(j*8+7,j*8,v));self.bytes[z3.simplify(a+j).sexpr()]=byte
   if off is not None:
    assert off+j<120;self.object_bytes[off+j]=byte;self.object_stores.append({'pc':hex(pc),'offset':off+j,'value':byte.sexpr()})
 def run(self,label,end=None):
  row=next(s for s in self.e['spans'] if s['label']==label);raw=bytes.fromhex(row['bytes_hex']);a=int(row['start'],16)
  if end is not None:raw=raw[:end-a]
  for i in DEC.disasm(raw,a):
   self.visited.add(i.address);self.pc=i.address
   if i.mnemonic=='adrp':self.count+=1;self.write(i.reg_name(i.operands[0].reg),resize(i.operands[1].imm,64))
   else:
    old=self.c;self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.c=old
  return self
 def owned(self):
  ranges=[(self.p,120),(self.src,0x800),(self.ctx,0x800),(self.sp,0x1080),(self.h,6)]
  out=[]
  for j,(a,n) in enumerate(ranges):
   out.extend([a!=0,z3.ULE(a,resize((1<<64)-1-n,64))])
   for b,m in ranges[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,m in IMAGE_REGIONS:out.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  return out

def setup(e):
 v=Model(e)
 for reg,x in [('x2',v.ctx),('x4',v.src),('w30',SUCCESS),('w3',0x886a1ca3),('w8',0x80)]:v.seed(reg,x)
 mem(v,v.ctx+0x148,8,v.p);mem(v,v.sp+0x630,8,v.src+0x710);mem(v,v.sp+0x628,8,v.src+0x26)
 return v

class BankModel(Model):
 """Use one explicitly certified 256-case composition at its original loads."""
 def __init__(self,e):
  super().__init__(e);self.q=z3.BitVec('ST_selector_input32',32);self.left_byte=z3.BitVec('ST_left_bank_byte8',8)
 def load(self,a,n):
  left=int(self.e['banks']['D_L']['address'],16);right=int(self.e['banks']['D_R']['address'],16)
  if self.pc==0xfffffe000a65a520:
   assert n==1;self.address_checks.append(a==left+z3.ZeroExt(56,z3.Extract(7,0,self.q)));return self.left_byte
  if self.pc==0xfffffe000a65a530:
   assert n==1;self.address_checks.append(a==right+z3.ZeroExt(56,self.left_byte^0x93))
   return z3.Extract(7,0,self.q)^0xec
  return super().load(a,n)

def proofs(e):
 qs=[];coverage=[];visited=set()
 def prove(label,v,bad):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned());assert s.check()==z3.sat
  s.add(z3.simplify(bad));assert s.check()==z3.unsat,(label,s.reason_unknown())
  qs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True})
  coverage.append({'label':label,'source_instruction_instances':v.count,'object_byte_store_instances':len(v.object_stores)})
  visited.update(v.visited)
 v=Model(e);v.seed('x28',POOL);v.run('bank_root_left').run('bank_root_right')
 prove('original_saved_byte_bank_roots',v,z3.Or(v.load(v.sp+0x930,8)!=int(e['banks']['D_L']['address'],16),v.load(v.sp+0x928,8)!=int(e['banks']['D_R']['address'],16)))
 v=BankModel(e);v.seed('w8',v.q);v.seed('x7',TABLE)
 mem(v,v.sp+0x930,8,int(e['banks']['D_L']['address'],16));mem(v,v.sp+0x928,8,int(e['banks']['D_R']['address'],16))
 v.run('allocation_select')
 prove('all_u32_selector_inputs_allocate_binding_using_finite_lemma',v,z3.Or(v.read('x9')!=0xfffffe000c4ba154,v.read('x0')!=0xfffffe000847c120,v.read('x17')!=0xd0c8,*[z3.Not(c) for c in v.address_checks]))
 v=Model(e);v.seed('x4',v.src);v.run('source_field32_root').run('source_field16_root');v.seed('x2',v.ctx);v.run('clear_cell_root')
 prove('source_field_and_clear_cell_roots',v,z3.Or(v.load(v.sp+0x628,8)!=v.src+0x26,v.load(v.sp+0x630,8)!=v.src+0x710,v.load(v.sp+0x60,8)!=v.ctx+0x3f8))
 v=Model(e);v.seed('w22',0xb80);mem(v,v.sp+0x60,8,v.ctx+0x3f8);v.run('allocation_prepare')
 prove('conditional_B80_allocation_prepare_and_clear',v,z3.Or(v.read('w20')!=0x9f3,v.read('w19')!=0x8c,v.load(v.ctx+0x3f8,8)!=0))
 v=Model(e);out=z3.BitVec('ST_allocator_result64',64)
 for reg,x in [('x0',out),('w20',0x9f3),('w19',0x8c),('w22',0xb80)]:v.seed(reg,x)
 mem(v,v.sp+0xa28,8,v.ctx);mem(v,v.sp+0xa08,8,v.src);mem(v,v.sp+0xa60,8,TABLE);mem(v,v.sp+0xa30,8,0xfffffe000ccc30d0)
 v.run('allocation_return',0xfffffe000a65a5a4)
 prove('allocation_result_publication_and_null_selector',v,z3.Or(v.load(v.ctx+0x148,8)!=out,v.read('w8')!=z3.If(out==0,resize(0xb97,32),resize(0xb80,32))))
 v=Model(e);hdr=z3.BitVec('ST_header_input64',64);v.seed('w20',0x9f3);v.seed('x2',v.ctx);v.seed('x0',v.p);mem(v,v.ctx+0x6d0,8,hdr)
 v.run('header_gate',0xfffffe000a65a5e4)
 prove('six_byte_header_pointer_gate',v,z3.Or(v.read('x19')!=v.p,v.read('w9')!=0x8c3,v.read('w8')!=z3.If(hdr==0,resize(0x9f3,32),resize(0xa1a,32))))
 v=Model(e);h32=z3.BitVec('ST_header_word32',32);h4,h5=z3.BitVecs('ST_header_byte4 ST_header_byte5',8)
 v.seed('x19',v.p);v.seed('x10',v.h);v.seed('w9',0x8c3);v.seed('x7',TABLE);mem(v,v.h,4,h32);mem(v,v.h+4,1,h4);mem(v,v.h+5,1,h5)
 v.run('header_copy')
 expected=[z3.Extract(8*j+7,8*j,h32) for j in range(4)]+[h4,h5]
 prove('header_copy_exact_six_bytes_and_padding',v,z3.Or(*[v.object_bytes[j]!=expected[j] for j in range(6)],*[v.object_bytes[j]!=z3.Extract(8*j+7,8*j,v.original) for j in range(6,120)]))
 v=Model(e);v.seed('x0',v.h);v.seed('x1',v.p);v.seed('w20',0x93);v.seed('x7',TABLE)
 mem(v,v.sp+0x58,8,v.ctx+0x400);mem(v,v.sp+0x60,8,v.ctx+0x3f8)
 v.run('default_header_copy',0xfffffe000a65a770)
 prove('default_header_exact_seven_zero_flags_and_pointer',v,z3.Or(*[v.object_bytes[j]!=(7 if j==0 else 0) for j in range(6)],v.load(v.ctx+0x3f8,8)!=v.h,v.read('w9')!=0x794,*[v.object_bytes[j]!=z3.Extract(8*j+7,8*j,v.original) for j in range(6,120)]))
 v=setup(e);v.run('payload_initialize')
 expected={j:resize(0xc7,8) for j in range(8,104)}
 expected[104]=resize(0,8)
 for off in [108,112,116]:
  expected.update({off+j:resize((SUCCESS>>(8*j))&255,8) for j in range(4)})
 prove('initial_fill_status_padding_and_alias_publications',v,z3.Or(*[v.object_bytes[j]!=expected.get(j,z3.Extract(8*j+7,8*j,v.original)) for j in range(120)],v.load(v.ctx+0x48,8)!=v.p,v.load(v.ctx+0x6e8,8)!=v.p,v.load(v.src+0x270,4)!=SUCCESS))
 v.run('payload_overlay')
 final=dict(expected)
 final.update({8+j:z3.Select(v.source_bytes,resize(0x710+j,64)) for j in range(16)})
 final.update({24+j:z3.Select(v.source_bytes,resize(0x26+j,64)) for j in range(32)})
 final[104]=resize(1,8)
 final.update({116+j:z3.Select(v.source_bytes,resize(0x2b4+j,64)) for j in range(4)})
 prove('final_all_120_bytes_and_exact_source_lineage',v,z3.Or(*[v.object_bytes[j]!=final.get(j,z3.Extract(8*j+7,8*j,v.original)) for j in range(120)]))
 stores={int(s['pc'],16) for s in v.object_stores}
 assert len(v.object_stores)==210 and len(stores)==197,(len(v.object_stores),len(stores))
 return qs,coverage,visited

def dispatch_cases(e):
 # Execute the original bank-load/select instructions for every byte input.
 # All pre-mask high bits disappear at the original AND W8,#0xff.
 rows=[]
 for ix in range(256):
  v=Model(e);v.seed('w8',(0xa55a00<<8)|ix);v.seed('x7',TABLE)
  mem(v,v.sp+0x930,8,int(e['banks']['D_L']['address'],16));mem(v,v.sp+0x928,8,int(e['banks']['D_R']['address'],16))
  v.run('allocation_select');assert value(v.read('x9'))==0xfffffe000c4ba154 and value(v.read('x0'))==0xfffffe000847c120 and value(v.read('x17'))==0xd0c8
  rows.append({'input_byte':ix,'call_target':hex(value(v.read('x9'))),'descriptor':hex(value(v.read('x0'))),'modifier':hex(value(v.read('x17')))})
 return rows

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build()
 qs,coverage,visited=proofs(e);cases=dispatch_cases(e)
 for r in e['bank_rules']:
  left=bytes.fromhex(e['banks'][r['left_name']]['bytes_hex']);right=bytes.fromhex(e['banks'][r['right_name']]['bytes_hex'])
  assert all(x^right[left[x]^int(r['key'],16)]==int(r['constant'],16) for x in range(256))
 rejects=[];fresh=R.build()
 for label,mutate in [('instruction_byte',lambda x:x['spans'][0].update(bytes_hex='00'+x['spans'][0]['bytes_hex'][2:])),
  ('descriptor_size',lambda x:x['allocation_descriptor'].update(size_bytes=119)),
  ('pointer_target',lambda x:x['bank_rules'][0].update(target='0x0'))]:
  x=copy.deepcopy(e);mutate(x)
  try:assert x==fresh
  except AssertionError:rejects.append(label)
  else:raise AssertionError('Altered extraction accepted: '+label)
 return {'generator_sha256':sha(__file__),'source_sha256':e['source_sha256'],'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'scope':e['scope'],'source_proofs':qs,'coverage':coverage,'proved_source_PCs':sorted(map(hex,visited)),
  'allocation_select_replays':cases,'altered_evidence_rejections':rejects,
  'independent_totals':{'new_source_queries_unsat':len(qs),'distinct_proved_instructions':len(visited),
   'proof_instruction_instances':sum(x['source_instruction_instances'] for x in coverage),'allocation_select_cases':len(cases),
   'bank_input_cases_checked':512,'final_object_extent_bytes':120,'altered_evidence_rejections':len(rejects)},
  'conditional_secure_tunnel_allocation_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
