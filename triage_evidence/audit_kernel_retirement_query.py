#!/usr/bin/env python3
"""Instruction-derived retirement metadata and caller ABI obligations.
O(I+byte-array/query DAG) construction/space; SMT search separate, 30 s/query.
"""
import copy
import json
import z3
from capstone.arm64 import ARM64_EXT_SXTW
from kext_port_tools import ROOT
from lskd_values_symbolic import resize
from audit_kernel_allocator_boundary import Model as ParentModel,DEC
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_retirement_query as R

ZONE_BASE=0xfffffe000caeb480

class Model(ParentModel):
 def __init__(self,e):
  merged=copy.deepcopy(e);merged['spans']+=e['reused_caller_spans'];super().__init__(merged)
  self.bytes=z3.Array('KQ_initial_memory',z3.BitVecSort(64),z3.BitVecSort(8));self.initial_bytes=self.bytes
  self.load_cache={};self.load_bindings=[]
  self.lo,self.hi,self.root=z3.BitVecs('KQ_range_low64 KQ_range_high64 KQ_metadata_root64',64)
  self.out_zone,self.out_offset=z3.BitVecs('KQ_zone_output64 KQ_offset_output64',64)
  self.discriminator=z3.BitVec('KQ_discriminator32',32);self.with_metadata=False
  self.zone_present=True;self.offset_present=True;self.inline_outputs=False;self.allow_output_alias=False
  self.extra_regions=[]
  self.plain_returns=0
  self.setmem(0xfffffe0007e66e50,8,self.lo);self.setmem(0xfffffe0007e66e58,8,self.hi);self.setmem(0xfffffe0007e66f00,8,self.root)
 def load(self,a,n):
  a=z3.simplify(resize(a,64));value=z3.simplify(z3.Concat(*[z3.Select(self.bytes,z3.simplify(a+j)) for j in reversed(range(n))]) if n>1 else z3.Select(self.bytes,a),blast_select_store=True)
  key=value.sexpr()
  if '(select ' not in key:return value
  if key not in self.load_cache:
   fresh=z3.BitVec('KQ_read_'+str(len(self.load_cache))+'_'+str(n*8),n*8)
   self.load_cache[key]=fresh;self.load_bindings.append(fresh==value)
  return self.load_cache[key]
 def setmem(self,a,n,value):
  a=z3.simplify(resize(a,64));v=z3.simplify(resize(value,n*8))
  for j in range(n):self.bytes=z3.Store(self.bytes,z3.simplify(a+j),z3.simplify(z3.Extract(8*j+7,8*j,v)))
 def store(self,a,n,value,pc):
  self.stores.append({'pc':pc,'address':a,'size_bytes':n,'value':resize(value,n*8)});self.setmem(a,n,value)
 def bindings_for(self,expressions):
  definitions={c.arg(0).get_id():c for c in self.load_bindings};needed=set();seen=set();todo=list(expressions)
  while todo:
   x=todo.pop();j=x.get_id()
   if j in seen:continue
   seen.add(j)
   if j in definitions and j not in needed:
    needed.add(j);todo.append(definitions[j].arg(1))
   todo.extend(x.children())
  return [c for c in self.load_bindings if c.arg(0).get_id() in needed]
 def operand(self,i,o,n):
  if o.ext==ARM64_EXT_SXTW:
   assert not o.shift.type;return resize(z3.SignExt(32,resize(self.read(i.reg_name(o.reg)),32)),n)
  return super().operand(i,o,n)
 def condition(self,name):
  return self.equal if name=='eq' else z3.Not(self.equal) if name=='ne' else self.carry if name=='hs' else z3.Not(self.carry) if name=='lo' else z3.And(self.carry,z3.Not(self.equal)) if name=='hi' else z3.Or(z3.Not(self.carry),self.equal) if name=='ls' else None
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   m=i.mnemonic;o=i.operands
   custom=m in ['adds','cmp','ccmp','asr','ret','tbz','tbnz','bl'] or m.startswith('b.')
   if not custom:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    ParentModel.run(self,'one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
   if m in ['cmp','ccmp','adds']:
    n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1] if m=='adds' else o[0],n);b=self.operand(i,o[2] if m=='adds' else o[1],n)
    if m=='adds':
     value=a+b;self.write(i.reg_name(o[0].reg),value);self.equal=value==0;self.carry=z3.ULT(value,a)
    elif m=='cmp':self.equal=a==b;self.carry=z3.UGE(a,b)
    else:
     pred=self.condition(i.op_str.rsplit(',',1)[1].strip());assert pred is not None
     self.equal=z3.If(pred,a==b,z3.BoolVal(bool(o[2].imm&4)));self.carry=z3.If(pred,z3.UGE(a,b),z3.BoolVal(bool(o[2].imm&2)))
    self.cmp_left,self.cmp_right=a,b
   elif m in ['tbz','tbnz']:
    pred=(self.read(i.reg_name(o[0].reg))&(1<<o[1].imm))==0
    if m=='tbnz':pred=z3.Not(pred)
    self.next=z3.If(pred,resize(o[2].imm,64),resize(i.address+4,64))
   elif m.startswith('b.'):
    pred=self.condition(m[2:]);assert pred is not None;self.next=z3.If(pred,resize(o[0].imm,64),resize(i.address+4,64))
   elif m=='asr':self.write(i.reg_name(o[0].reg),self.read(i.reg_name(o[1].reg))>>o[2].imm)
   elif m=='ret':self.next=self.read('x30');self.plain_returns+=1
   else:
    self.seed('x30',i.address+4);self.next=resize(o[0].imm,64);self.call_return=i.address+4
    self.calls.append({'pc':hex(i.address),'target':hex(o[0].imm&(2**64-1))})
  return self
 def owned(self):
  spans=[(self.sp0-0x80,0x100),(resize(0xfffffe0007e66e50,64),16),(resize(0xfffffe0007e66f00,64),8)]
  if self.with_metadata:spans.extend([(self.page,0x100020),(self.zone,64)])
  spans.extend(self.extra_regions)
  output_start=len(spans)
  if self.zone_present and not self.inline_outputs:spans.append((self.out_zone,8))
  if self.offset_present and not self.inline_outputs:spans.append((self.out_offset,8))
  out=[(self.sp0&15)==0,z3.UGE(self.sp0,0x100),z3.ULE(self.sp0,resize(2**64-1-0x100,64))]
  if self.with_metadata:out.append(z3.ULE(self.root,resize(2**64-1-0x100020,64)-self.page_index))
  for j,(a,n) in enumerate(spans):
   out.extend([a!=0,z3.ULE(a,resize(2**64-1-n,64))])
   for h,(b,m) in enumerate(spans[j+1:],j+1):
    if self.allow_output_alias and j>=output_start and h>=output_start:continue
    out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
  return out
 def snapshot(self):
  self.page_index=z3.LShR(self.pointer,10)&0xffffffff0;self.page=self.root+self.page_index
  self.header=self.load(self.page,2);self.zone=resize(ZONE_BASE,64)+192*z3.ZeroExt(48,self.header&0x3ff)
  self.element=self.load(self.zone+0x34,2);self.special=self.load(self.page+0x10,2)&0xf000
  self.special_offset=self.load(self.page+0x12,2)
  self.byte_index=self.load(self.page+3,1);self.half_index=self.load(self.zone+0x38,2)
  self.index=z3.If((self.header&0xf000)==0xe000,z3.ZeroExt(8,self.byte_index),self.half_index)
  self.indexed=self.page+(z3.ZeroExt(48,self.index)<<4);self.indexed_offset=self.load(self.indexed+2,2)
  self.end=self.pointer+z3.ZeroExt(48,self.element);self.cross=z3.UGE(self.end^self.pointer,0x4000)
  self.limit=((self.indexed-self.root)<<28)>>32;self.boundary=self.limit<<14
  return self

def setup(e,zp=True,op=True):
 v=Model(e);v.zone_present=zp;v.offset_present=op
 v.seed('x0',v.pointer);v.seed('x1',v.out_zone if zp else 0);v.seed('w2',v.discriminator);v.seed('x3',v.out_offset if op else 0)
 return v.snapshot()

def fit(v):return z3.And(z3.ULE(v.pointer,resize(2**64-9,64)),z3.UGE(v.pointer,v.lo),z3.ULE(v.pointer+8,v.hi))
def accepted(e,zp=True,op=True):
 v=setup(e,zp,op);v.with_metadata=True;return v.run('query_entry').run('query_range').run('query_metadata')
def done(v):
 v.run('query_zone_gate');return v.run('query_zone_store_return' if v.zone_present else 'query_plain_return')

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(c) for c in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label,s.reason_unknown())
  s.add(*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV','query':s.to_smt2()})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores),'linked_edge_obligations':len(v.edge_checks)})
  visited.update(v.visited);print(label,flush=True)
 def result(v,offset):
  bad=[v.read('x0')!=z3.ZeroExt(48,v.element),v.next!=v.initial[30]]
  if v.zone_present:bad.append(v.load(v.out_zone,8)!=v.zone)
  if v.offset_present:bad.append(v.load(v.out_offset,8)!=resize(offset,64))
  return z3.Or(*bad)
 v=setup(e).run('query_entry')
 prove('all_pointer64_add_eight_overflow_guard_exact',v,v.next!=z3.If(z3.UGT(v.pointer,resize(2**64-9,64)),resize(0xfffffe000bd79308,64),resize(0xfffffe000bd792e8,64)))
 v.run('query_range')
 prove('all_pointer_and_interval64_range_admission_is_exact_eight_byte_extent',v,
  v.next!=z3.If(fit(v),resize(0xfffffe000bd79318,64),resize(0xfffffe000bd79308,64)),[z3.ULE(v.pointer,resize(2**64-9,64))])
 for overflow in [False,True]:
  for zp in [False,True]:
   for op in [False,True]:
    v=setup(e,zp,op);before=v.bytes;v.run('query_entry')
    prem=[z3.UGT(v.pointer,resize(2**64-9,64))] if overflow else [z3.ULE(v.pointer,resize(2**64-9,64)),z3.Not(fit(v))]
    if not overflow:v.run('query_range')
    v.run('query_reject')
    if op:v.run('query_reject_write')
    v.run('query_plain_return')
    expected=before
    if op:
     for j in range(8):expected=z3.Store(expected,v.out_offset+j,resize(0,8))
    prove(('overflow' if overflow else 'range')+'_reject_zone'+str(int(zp))+'_offset'+str(int(op))+'_only_clears_optional_offset',v,
     z3.Or(v.read('x0')!=0,v.next!=v.initial[30],v.bytes!=expected),prem)
 for zp in [False,True]:
  v=accepted(e,zp,False)
  prove('accepted_zone'+str(int(zp))+'_no_offset_forms_original_zone_and_u16_extent',v,z3.Or(v.read('x9')!=v.zone,
   v.read('x0')!=z3.ZeroExt(48,v.element),v.next!=0xfffffe000bd79384),[fit(v)])
  v.run('query_zero_gate');done(v)
  prove('accepted_zone'+str(int(zp))+'_no_offset_returns_extent_and_optional_zone',v,result(v,0),[fit(v)])
 # Distinct reasons for a zero offset all run from the original entry.
 for reason in ['disabled','no_crossing','small_element']:
  v=accepted(e);prem=[fit(v)];v.run('query_offset_enabled')
  if reason=='disabled':prem.append((v.header&0x400)==0)
  else:
   prem.append((v.header&0x400)!=0);v.run('query_crossing')
   if reason=='no_crossing':prem.append(z3.Not(v.cross))
   else:
    prem.extend([v.cross,v.special!=0xb000,z3.ULE(v.element,0x4000)]);v.run('query_special').run('query_large')
  if reason=='small_element':v.run('query_large_zero')
  else:v.run('query_zero_gate').run('query_zero_value')
  v.run('query_offset_store');done(v)
  prove('accepted_'+reason+'_returns_zero_offset_and_exact_zone_extent',v,result(v,0),prem)
 for clear in [False,True]:
  v=accepted(e);prem=[fit(v),(v.header&0x400)!=0,v.cross,v.special==0xb000,
   v.discriminator!=0 if clear else v.discriminator==0]
  v.run('query_offset_enabled').run('query_crossing').run('query_special').run('query_special_read')
  if clear:v.run('query_special_clear')
  v.run('query_offset_return').run('query_offset_store');done(v)
  prove('special_layout_'+('destructive' if clear else 'nondestructive')+'_u16_offset_and_outputs',v,z3.Or(result(v,z3.ZeroExt(48,v.special_offset)),
   v.load(v.page+0x12,2)!=(resize(0,16) if clear else v.special_offset)),prem)
 # Modular large-layout certificates preserve the byte-array state. The
 # prefix proves every register required by the address block; the address
 # block proves the exact branch; the tails prove its memory/return effects.
 for byte_index in [False,True]:
  v=accepted(e);before=v.bytes
  prem=[fit(v),(v.header&0x400)!=0,v.cross,v.special!=0xb000,z3.UGT(v.element,0x4000),
   (v.header&0xf000)==0xe000 if byte_index else (v.header&0xf000)!=0xe000]
  v.run('query_offset_enabled').run('query_crossing').run('query_special').run('query_large').run('query_large_mode')
  v.run('query_large_byte' if byte_index else 'query_large_half')
  idx=z3.ZeroExt(56,v.byte_index) if byte_index else z3.ZeroExt(48,v.half_index)
  prove('large_'+('byte' if byte_index else 'half')+'_prefix_exact_address_block_state_without_writes',v,z3.Or(
   v.read('x8')!=idx,v.read('x10')!=v.page,v.read('x11')!=v.root,v.read('x13')!=v.end,
   v.read('x9')!=v.zone,v.read('x0')!=z3.ZeroExt(48,v.element),v.read('x1')!=v.out_zone,v.read('x3')!=v.out_offset,
   v.read('w2')!=v.discriminator,v.read('x30')!=v.initial[30],v.next!=0xfffffe000bd793b0,v.bytes!=before),prem)
  v=setup(e);v.with_metadata=True
  idx=z3.ZeroExt(56,v.byte_index) if byte_index else z3.ZeroExt(48,v.half_index)
  indexed=v.page+(idx<<4);boundary=(((indexed-v.root)<<28)>>32)<<14
  for reg,val in [('x8',idx),('x10',v.page),('x11',v.root),('x13',v.end),('x9',v.zone),('x0',z3.ZeroExt(48,v.element))]:v.seed(reg,val)
  before=v.bytes
  v.enter('query_large_address')
  prove('large_'+('byte' if byte_index else 'half')+'_address_block_exact_signed_boundary',v,z3.Or(v.read('x10')!=indexed,
   z3.ULT(indexed,v.page),z3.UGT(indexed+4,v.page+0x100020),v.bytes!=before,
   v.read('x9')!=v.zone,v.read('x0')!=z3.ZeroExt(48,v.element),v.read('x1')!=v.out_zone,v.read('x3')!=v.out_offset,
   v.read('w2')!=v.discriminator,v.read('x30')!=v.initial[30],
   v.next!=z3.If(z3.UGE(v.end,boundary),resize(0xfffffe000bd793dc,64),resize(0xfffffe000bd793c8,64))))
 for clear in [False,True]:
  v=Model(e);indexed=z3.BitVec('KQ_tail_metadata_record64',64);v.extra_regions=[(indexed+2,2)]
  v.zone=z3.BitVec('KQ_tail_zone64',64);v.element=z3.BitVec('KQ_tail_element16',16)
  v.seed('x1',v.out_zone);v.seed('x3',v.out_offset);v.seed('w2',v.discriminator)
  offset=v.load(indexed+2,2)
  for reg,val in [('x10',indexed),('x9',v.zone),('x0',z3.ZeroExt(48,v.element))]:v.seed(reg,val)
  v.enter('query_large_read')
  if clear:v.run('query_large_clear')
  v.run('query_offset_return').run('query_offset_store');done(v)
  prove('large_'+('clear' if clear else 'keep')+'_tail_all_valid_u16_fields_exact_offset_and_outputs',v,
   z3.Or(result(v,z3.ZeroExt(48,offset)),v.load(indexed+2,2)!=(resize(0,16) if clear else offset)),
   [v.discriminator!=0 if clear else v.discriminator==0])
 v=setup(e);v.with_metadata=True;v.seed('x9',v.zone);v.seed('x0',z3.ZeroExt(48,v.element))
 v.enter('query_large_zero').run('query_offset_store');done(v)
 prove('large_below_boundary_tail_returns_zero_offset_and_zone_extent',v,result(v,0))
 # Output aliases are modeled as bytes too: when both output pointers alias,
 # the later zone store wins on an accepted zero-offset route.
 v=setup(e);v.out_offset=v.out_zone;v.seed('x3',v.out_zone);v.allow_output_alias=True;v.with_metadata=True
 v.run('query_entry').run('query_range').run('query_metadata').run('query_offset_enabled').run('query_zero_gate').run('query_zero_value').run('query_offset_store');done(v)
 prove('aliased_output_slots_receive_final_zone_store_on_accepted_zero_offset_path',v,
  z3.Or(v.load(v.out_zone,8)!=v.zone,v.read('x0')!=z3.ZeroExt(48,v.element),v.next!=v.initial[30]),[fit(v),(v.header&0x400)==0])
 def caller(n):
  v=Model(e);v.inline_outputs=True;v.out_zone=v.sp0-56;v.out_offset=v.sp0-64
  v.heap=resize(0xfffffe0007f8bfb0 if n==14 else 0xfffffe0007f36938,64)
  v.seed('x0',v.heap);v.seed('x1',v.pointer);v.seed('x2',n)
  return v.run('size_free_enter').run('size_free_limit').run('size_free_small_gate').run('size_free_query')
 for n in [14,32]:
  # A post-query cut isolates the exact rejection/admission predicate. The
  # output widths are established by the complete query source above.
  v=caller(n);elem,off=z3.BitVecs('KQ_caller_element16 KQ_caller_offset16',16)
  zone=z3.BitVec('KQ_caller_zone64',64);v.setmem(v.out_zone,8,zone);v.setmem(v.out_offset,8,z3.ZeroExt(48,off))
  v.returned(z3.ZeroExt(48,elem)).run('caller_query_return')
  prove('caller'+str(n)+'_zero_extent_selects_original_error_frontier',v,
   v.next!=z3.If(elem==0,resize(0xfffffe000bcfed78,64),resize(0xfffffe000bcfecb0,64)),[v.pointer!=0])
  v.run('caller_extent')
  prove('caller'+str(n)+'_all_u16_offset_extent_exact_size_admission',v,
   v.next!=z3.If(z3.ULE(z3.ZeroExt(48,off)+n,z3.ZeroExt(48,elem)),resize(0xfffffe000bcfecbc,64),resize(0xfffffe000bcfed78,64)),[v.pointer!=0,elem!=0])
  v.run('caller_adjust_request')
  prove('caller'+str(n)+'_admitted_u16_offset_uses_regular_base_and_original_extent',v,z3.Or(v.read('x0')!=v.heap,
   v.read('x1')!=v.pointer-z3.ZeroExt(48,off),v.read('x2')!=n,v.read('x3')!=zone,
   v.read('x4')!=z3.ZeroExt(48,elem),v.next!=0xfffffe000bcfed8c),
   [v.pointer!=0,elem!=0,z3.ULE(z3.ZeroExt(48,off)+n,z3.ZeroExt(48,elem))])
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']}
 reused={int(i['ea'],16) for s in e['reused_caller_spans'] for i in s['instructions']}
 assert visited==selected|reused,sorted(map(hex,(selected|reused)-visited))
 # A zeroing store changed to NOP must leave a nonzero offset in place.
 changed=copy.deepcopy(e);row=next(s for s in changed['spans'] if s['label']=='query_special_clear');row['bytes_hex']='1f2003d5'
 v=accepted(changed);v.run('query_offset_enabled').run('query_crossing').run('query_special').run('query_special_read').run('query_special_clear')
 s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.load_bindings,*v.edge_checks,fit(v),(v.header&0x400)!=0,v.cross,
  v.special==0xb000,v.discriminator!=0,v.special_offset!=0,v.load(v.page+0x12,2)!=0);assert s.check()==z3.sat
 prior=[]
 old=json.loads(read(ROOT/'kernel_allocator_boundary_audit.json'))
 for label in ['nonnull_size14_free_requests_zone_query_with_two_frame_outputs','nonnull_size32_free_requests_zone_query_with_two_frame_outputs']:
  q=next(q for q in old['source_proofs'] if q['label']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
  prior.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/'kernel_allocator_boundary_audit.json')})
 old=json.loads(read(ROOT/'mixed_data_retirement_checks.json'))
 for label in ['lookup_admits_complete_first_eight_bytes_under_unsigned_bounds','metadata_zone_index_uses_same_192_byte_stride','published_u16_offset_and_retirement_size_recover_base']:
  q=next(q for q in old['proofs'] if q['name']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
  prior.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/'mixed_data_retirement_checks.json')})
 # Composition formulas are separate from instruction proofs. Their
 # premises map to the query outputs, preserved-register inventory and
 # universal caller gate/argument certificates above.
 composition=[]
 def compose(label,premises,bad):
  s=z3.Solver();s.set(timeout=30000);s.add(*premises);assert s.check()==z3.sat
  s.add(bad);assert s.check()==z3.unsat
  composition.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2()})
 p0,o0,e0=z3.BitVecs('KQ_comp_pointer64 KQ_comp_offset16 KQ_comp_element16',64)
 # o/e are constrained to the u16 output domains established by the source.
 for n in [14,32]:
  for special in [False,True]:
   prem=[z3.ULE(o0,65535),z3.ULE(e0,65535),e0!=0,z3.ULE(o0+n,e0),z3.UGE(p0,o0)]
   if not special:prem.append(o0==0)
   base=p0-o0
   compose('query'+str(n)+('_special' if special else '_zero')+'_outputs_and_caller_admission_recover_nonwrapping_base_extent',prem,
    z3.Or(z3.UGT(base,p0),base+o0!=p0,z3.ULT(e0,n),z3.UGT(o0+n,e0)))
 a,b,x,w,l=z3.Ints('KQ_region_start KQ_other_start KQ_field_record KQ_region_size KQ_other_size')
 compose('indexed_u16_field_inherits_metadata_region_validity_and_separation',
  [a>0,w>0,l>0,a+w<=2**64-1,b>0,b+l<=2**64-1,a<=x,x+4<=a+w,z3.Or(a+w<=b,b+l<=a)],
  z3.Or(x+2<=0,x+4>2**64-1,z3.Not(z3.Or(x+4<=b,b+l<=x+2))))
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,
  'proved_source_PCs':sorted(map(hex,visited)),'rechecked_prior_source_proofs':prior,'composition_proofs':composition,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(prior),
   'distinct_new_proved_instructions':len(selected),'distinct_reused_proved_instructions':len(reused),
   'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),
   'modular_query_caller_cases':4,'new_composition_queries_unsat':len(composition),'altered_clear_store_counterexample':True},
  'conditional_kernel_retirement_query_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
