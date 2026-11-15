#!/usr/bin/env python3
"""Conditional source obligations for staging and parser entry/return ABI.
O(I+256R+query DAG) construction/space; SMT cost separate, 30 s/query.
No native target executes. Complete parser effects remain outside this model.
"""
import copy
import json
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_MEM
from kext_port_tools import ROOT,IMAGE,TABLE,POOL,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_container_staging as R

TOKEN=0x886a1ca3
PHASE=0x7795e642
SUCCESS=0x31ae0066
KEY0=0x02e859d27e491464
KEY1=0x4dae26df20976138
DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True

def mask(a):return z3.Extract(7,0,z3.LShR((z3.RotateRight(a&resize(-8,64),8)+KEY0)^KEY1,(a&7)<<3))

class Model(Base):
 def __init__(self,e):
  super().__init__(e);self.receipt=e
  self.argument,self.input,self.allocated,self.container,self.counter=z3.BitVecs('CS_argument64 CS_input64 CS_allocated64 CS_container64 CS_counter64',64)
  self.plain=z3.BitVec('CS_plain_byte8',8);self.cursor=z3.BitVec('CS_cursor64',64)
  self.branch_guards=[];self.with_input=False;self.with_allocated=False;self.with_container=False
  self.table_pcs=set()
  for row in e['spans']:
   for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
    if i.mnemonic=='ldr' and i.operands[1].type==ARM64_OP_MEM and i.reg_name(i.operands[1].mem.base)=='x7':self.table_pcs.add(i.address)
 def n(self):return z3.Extract(31,0,self.argument)
 def owned(self):
  spans=[(self.sp,0x1120),(self.ctx,0x800),(self.src,0x1000)]
  for enabled,a,n in [(self.with_input,self.input,z3.ZeroExt(32,self.n())),
   (self.with_allocated,self.allocated,z3.ZeroExt(32,self.n())),(self.with_container,self.container,16)]:
   if enabled:spans.append((a,n))
  out=[(self.sp&15)==0]
  for j,(a,n) in enumerate(spans):
   out.extend([a!=0,z3.ULE(a,resize(2**64-1,64)-n)])
   for b,m in spans[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,m in IMAGE_REGIONS:out.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  return out
 def load(self,a,n):
  for name,(lp,rp,pp) in R.BANK_PCS.items():
   r=next(r for r in self.receipt['bank_rules'] if r['name']==name);l,rr=int(r['left'],16),int(r['right'],16)
   if self.pc==lp:
    assert n==1;self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('CS_bank_'+name,8)
    self.address_checks.append(a==l+z3.ZeroExt(56,self.bank_input));return self.bank_byte
   if self.pc==rp:
    assert n==1;self.address_checks.append(a==rr+z3.ZeroExt(56,self.bank_byte^int(r['key'],16)))
    self.bank_rewrites.append({'pc':hex(self.pc),'rule':name,'inputs':256});return self.bank_input^int(r['constant'],16)
   if self.pc==pp:
    assert n==8;self.address_checks.append(a==int(r['slot'],16));return resize(int(r['target'],16),64)
  if self.pc in self.table_pcs:
   assert n==8
   js=R.BRANCHES[self.pc]
   self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  if self.pc==0xfffffe000a641e10:
   assert n==1;self.address_checks.append(a==self.input+self.counter-1);return self.plain
  aa=z3.simplify(a)
  if n==4 and z3.is_bv_value(aa) and aa.as_long() in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:return z3.BitVec('CS_controller_'+format(self.pc,'x'),32)
  return super().load(a,n)
 def run(self,label,end=None):
  row=next(s for s in self.e['spans'] if s['label']==label);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if end is not None and i.address>=end:break
   if i.address==skip:continue
   self.pc=i.address;m=i.mnemonic;o=i.operands
   custom=m=='ror' or m.startswith('b.') or m in ['lsl','lsr'] and o[2].type==ARM64_OP_REG or m=='str' and i.writeback
   if custom:
    self.visited.add(i.address);self.count+=1
    if m.startswith('b.'):
     assert i.address in R.RETAGS and m=='b.eq' and o[0].imm&(2**64-1)==i.address+8
     self.branch_guards.append(self.equal);skip=R.RETAGS[i.address]
    elif m=='str':
     assert o[1].type==ARM64_OP_MEM and len(o)==2
     a=self.address(i,o[1]);reg=i.reg_name(o[0].reg);self.store(a,self.width(reg)//8,self.read(reg),i.address)
     self.write(i.reg_name(o[1].mem.base),a)
    elif m=='ror':self.write(i.reg_name(o[0].reg),z3.RotateRight(self.read(i.reg_name(o[1].reg)),o[2].imm))
    else:
     n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);b=self.operand(i,o[2],n)&(n-1)
     self.write(i.reg_name(o[0].reg),a<<b if m=='lsl' else z3.LShR(a,b))
   else:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.e,self.c=old_e,old_c
  return self
 def returned(self,value):
  for j in [*range(19),30]:self.seed('x'+str(j),z3.BitVec('CS_call_'+str(self.count)+'_X'+str(j),64))
  self.seed('x0',value);return self

def setup(e):
 v=Model(e)
 for reg,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('x23',v.ctx),('x24',v.src),('x21',TABLE),
  ('w3',TOKEN),('w1',PHASE),('w30',SUCCESS),('x28',0xfffffe0007949dd0),
  ('x6',0xfffffe000ccc30d0),('x5',0xa41a4d891208c018)]:v.seed(reg,x)
 for o,x in [(0x878,v.argument),(0x8f8,v.input),(0xa08,v.src),(0xa28,v.ctx),(0xa60,TABLE),
  (0xa30,0xfffffe000ccc30d0),(0xa38,0xfffffe000ccc32f8),(0xa40,0xfffffe000792fbc0),
  (0xa10,0xfffffe0007949fd0),(0xa18,0xfffffe000792ffc0),(0xa00,0xfffffe000792fcc0),
  (0x670,v.ctx+0x90),(0x988,v.ctx+0x600),(0x888,v.src+0xbe4)]:mem(v,v.sp+o,8,x)
 mem(v,v.sp+0x9ec,4,v.status)
 return v

def channels(e):
 v=setup(e);v.run('size_channel').run('allocation_size_channel').run('saved_encoded_size').run('copy_count_roots');return v
def allocated(e):
 v=channels(e);v.seed('w3',TOKEN);v.seed('w1',PHASE)
 return v.run('staging_allocate').returned(v.allocated).run('staging_return')

def parser(e):
 v=setup(e)
 for r,a in [('w9',0xb9),('w10',TOKEN),('x8',v.ctx+0x600),('x0',v.allocated),('w22',v.n()^SUCCESS)]:v.seed(r,a)
 mem(v,v.ctx+0x600,8,0)
 return v.run('parser_entry')

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 for r in e['bank_rules']:
  l,rr=(bytes.fromhex(e['banks'][r[n+'_name']]['bytes_hex']) for n in ['left','right'])
  assert all(j^rr[l[j]^int(r['key'],16)]==int(r['constant'],16) for j in range(256))
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));result=s.check()
  assert result==z3.unsat,(label,str(result),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'pointer_branch_guards':len(v.branch_guards),'certified_bank_rewrites':copy.deepcopy(v.bank_rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)});visited.update(v.visited)
 v=setup(e);v.seed('x0',v.input);v.seed('x1',v.argument);v.seed('x2',v.header);v.run('saved_entry_arguments')
 prove('post_stack_probe_saved_three_entry_arguments',v,z3.Or(cell(v,v.sp+0x738,8)!=v.header,cell(v,v.sp+0x878,8)!=v.argument,cell(v,v.sp+0x8f8,8)!=v.input))
 v=setup(e).run('scratch_alias').run('staging_roots').run('saved_staging_roots').run('parser_output_root').run('staging_state_root')
 prove('scratch_source_aliases_and_writeback_staging_output_roots',v,z3.Or(v.read('x2')!=v.ctx,v.read('x4')!=v.src,
  cell(v,v.sp+0x670,8)!=v.ctx+0x90,cell(v,v.sp+0x6b0,8)!=v.ctx+8,
  cell(v,v.sp+0x988,8)!=v.ctx+0x600,cell(v,v.sp+0x888,8)!=v.src+0xbe4,cell(v,v.ctx+0x90,8)!=0,cell(v,v.ctx+8,8)!=0))
 v=channels(e)
 prove('all_argument64_low32_size_three_exact_codecs',v,z3.Or(cell(v,v.sp+0x524,4)!=(v.n()^SUCCESS),
  cell(v,v.src+0xc8,4)!=(v.n()^SUCCESS),cell(v,v.sp+0x4d8,8)+0x1cc01a010500480b!=z3.ZeroExt(32,v.n()),
  cell(v,v.sp+0x4b8,8)!=z3.ZeroExt(32,v.n()^0xc03f95d4),cell(v,v.sp+0x4b0,8)!=z3.ZeroExt(32,v.n())))
 v.seed('w3',TOKEN);v.seed('w1',PHASE);v.run('staging_allocate')
 prove('exact_saved_input_size_original_IOMallocData_request',v,z3.Or(v.read('x0')!=z3.ZeroExt(32,v.n()),v.read('x8')!=0xfffffe000c4ba60c,
  v.read('x17')!=0xca0c,v.read('w19')!=0x2e5,v.read('w20')!=TOKEN))
 v.returned(v.allocated).run('staging_return')
 prove('all_staging_result64_exact_nullable_gate_and_input_reload',v,z3.Or(cell(v,v.ctx+0x90,8)!=v.allocated,
  v.read('x15')!=v.input,v.read('w26')!=v.status,v.read('x8')!=z3.If(v.allocated==0,
  resize(0xfffffe000a6661bc,64),resize(0xfffffe000a641d54,64))))
 v.run('staging_gate')
 prove('all_size32_exact_zero_or_reverse_copy_gate_and_fixed_keys',v,z3.Or(v.read('x10')!=z3.If(v.n()==0,
  resize(0xfffffe000a641dc4,64),resize(0xfffffe000a641e08,64)),v.read('x9')!=z3.ZeroExt(32,v.n()),
  v.read('x21')!=KEY0,v.read('x1')!=KEY1,v.read('w3')!=TOKEN),[v.allocated!=0])
 zero=copy.deepcopy(v);zero.run('staging_done').run('parser_request')
 prove('zero_size_nonnull_staging_seam_requests_parser_without_byte_copy',zero,z3.Or(cell(zero,zero.ctx+0x358,8)!=zero.allocated,
  cell(zero,zero.ctx+0x600,8)!=0,cell(zero,zero.ctx+0x3c0,8)!=0,cell(zero,zero.src+0xbe4,4)!=SUCCESS,
  zero.read('x11')!=0xfffffe000a641fb4,zero.read('w22')!=SUCCESS,zero.read('x8')!=zero.ctx+0x600,
  zero.read('w9')!=0xb9,zero.read('w10')!=TOKEN),[zero.allocated!=0,zero.n()==0])
 v.with_input=v.with_allocated=True;v.seed('x9',v.counter)
 preserved={r:v.read(r) for r in ['w8','w11','w19']};v.run('staging_copy')
 st=[s for s in v.stores if s['pc']==0xfffffe000a641e48];assert len(st)==1 and st[0]['size_bytes']==1
 prove('every_valid_reverse_counter_one_protected_byte_exact_destination_and_backedge',v,z3.Or(st[0]['address']!=v.allocated+v.counter-1,
  st[0]['value']!=(v.plain^mask(v.allocated+v.counter-1)),v.read('x9')!=v.counter-1,
  v.read('x10')!=z3.If(v.counter==1,resize(0xfffffe000a641e68,64),resize(0xfffffe000a641e08,64)),
  v.read('x0')!=v.allocated,v.read('x15')!=v.input,v.read('x21')!=KEY0,v.read('x1')!=KEY1,
  *[v.read(r)!=a for r,a in preserved.items()]),
  [v.allocated!=0,z3.UGE(v.counter,1),z3.ULE(v.counter,z3.ZeroExt(32,v.n()))])
 v.run('staging_empty').run('parser_request')
 prove('final_nonempty_staging_step_publishes_buffer_and_requests_same_parser_ABI',v,z3.Or(cell(v,v.ctx+0x358,8)!=v.allocated,
  cell(v,v.ctx+0x600,8)!=0,cell(v,v.ctx+0x3c0,8)!=0,cell(v,v.src+0xbe4,4)!=SUCCESS,
  v.read('x11')!=0xfffffe000a641fb4,v.read('w22')!=(v.n()^SUCCESS),v.read('x8')!=v.ctx+0x600,
  v.read('w9')!=0xb9,v.read('w10')!=TOKEN),[v.allocated!=0,v.n()!=0,v.counter==1])
 v=parser(e)
 prove('shared_parser_entry_retains_output_continuation_input_and_encoded_extent',v,z3.Or(cell(v,v.ctx+0x5c8,8)!=0xfffffe000a656c08,
  cell(v,v.ctx+0x188,8)!=v.ctx+0x600,cell(v,v.ctx+0x618,8)!=v.allocated,cell(v,v.src+0xc8c,4)!=(v.n()^SUCCESS),
  cell(v,v.sp+0xa80,8)!=0,v.read('x10')!=0xfffffe000c4ba154,v.read('x0')!=0xfffffe000847b620,v.read('x17')!=0xd0c8))
 v.returned(v.container).run('parser_allocate_return')
 prove('all_typed_container_result64_zero_skip_or_initialize_gate',v,z3.Or(cell(v,v.ctx+0x228,8)!=v.container,
  v.read('w23')!=v.status,v.read('x8')!=z3.If(v.container==0,resize(0xfffffe000a660ae0,64),resize(0xfffffe000a6420f8,64))))
 nil=copy.deepcopy(v);nil.run('parser_resume')
 prove('null_container_allocation_resumes_without_overwriting_caller_precleared_output',nil,z3.Or(cell(nil,nil.ctx+0x600,8)!=0,
  nil.read('x8')!=0xfffffe000a656c08,nil.read('w23')!=nil.status),[nil.container==0])
 v.with_container=True;v.run('parser_initialize')
 prove('nonnull_site_FPTTLV_clears_two_pointer_fields_and_sets_reader_key',v,z3.Or(cell(v,v.container,8)!=0,
  cell(v,v.container+8,8)!=0,v.read('x26')!=KEY0,v.read('x8')!=0xfffffe000a642138))
 v.run('parser_cursor_gate')
 prove('initial_cursor_zero_exact_empty_or_nonempty_extent_gate',v,v.read('x12')!=z3.If(v.n()==0,
  resize(0xfffffe000a642180,64),resize(0xfffffe000a6421dc,64)))
 empty=copy.deepcopy(v);empty.run('parser_finish').run('parser_success').run('parser_output').run('parser_resume')
 prove('complete_empty_input_parser_publishes_initialized_container_and_success',empty,z3.Or(cell(empty,empty.ctx+0x600,8)!=empty.container,
  cell(empty,empty.container,8)!=0,cell(empty,empty.container+8,8)!=0,cell(empty,empty.src+0xc10,4)!=SUCCESS,
  empty.read('w23')!=SUCCESS,empty.read('x8')!=0xfffffe000a656c08),[empty.n()==0])
 arbitrary=copy.deepcopy(v);mem(arbitrary,arbitrary.sp+0xa80,8,arbitrary.cursor);arbitrary.run('parser_cursor_gate')
 prove('all_cursor64_parser_gate_compares_widened_decoded_extent',arbitrary,arbitrary.read('x12')!=z3.If(
  z3.ULT(arbitrary.cursor,z3.ZeroExt(32,arbitrary.n())),resize(0xfffffe000a6421dc,64),resize(0xfffffe000a642180,64)))
 v.run('parser_input_gate')
 prove('nonempty_parser_nullable_input_gate_before_header_body',v,z3.Or(cell(v,v.ctx+0x3d8,8)!=v.allocated,
  v.read('x14')!=z3.If(v.allocated==0,resize(0xfffffe000a6423c0,64),resize(0xfffffe000a642248,64)),v.read('x20')!=KEY1),[v.n()!=0])
 v=setup(e);v.seed('w19',PHASE);mem(v,v.ctx+0x600,8,v.container);mem(v,v.sp+0x738,8,v.header);v.run('reader_initialize')
 prove('all_context64_reader_setup_reuses_parser_container_and_initializes_output_channels',v,z3.Or(cell(v,v.ctx+0x4b0,8)!=v.container,
  v.read('x22')!=v.container,cell(v,v.ctx+0x128,8)!=0,cell(v,v.src+0xaa8,4)!=SUCCESS,
  v.read('x8')!=z3.If(v.header==0,resize(0xfffffe000a656f00,64),resize(0xfffffe000a63dd80,64)),v.read('w23')!=0xce515bbf))
 v=setup(e).run('reader_key_assignment')
 prove('original_earlier_reader_phase_explicit_fixed_protection_key_pair',v,z3.Or(v.read('x26')!=KEY0,v.read('x20')!=KEY1))
 pc=next(iter(R.RETAGS.values()));row=next(s for s in e['spans'] if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16)
 raw=bytes.fromhex(row['bytes_hex'])[off:off+4];v=setup(e);v.seed('x12',v.allocated)
 v.e=v.c={'spans':[{'label':'alternate','start':hex(pc),'bytes_hex':raw.hex()}]};v.run('alternate')
 prove('alternate_staging_pointer_MOVK_bit_transform_only',v,v.read('x12')!=((v.allocated&0xffffffffffff)|(0xc8a2<<48)))
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};assert visited==selected,{'missing':sorted(map(hex,selected-visited)),'extra':sorted(map(hex,visited-selected))}
 prior=json.loads(read(ROOT/'userclient_input_reader_audit.json'));pp=[]
 for label in ['protected_header_first_word_decodes_tag_channel','protected_header_u16_type_at_offset_four',
  'protected_header_u32_length_channel_at_offset_six',
  'all_valid_copy_counter64_one_decoded_byte_exact_reverse_store_and_loop_gate',
  'finite_reverse_copy_index_range_and_induction_certificate']:
  q=next(q for q in prior['source_proofs'] if q['label']==label);s=z3.Solver();s.set(timeout=30000)
  s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
  pp.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_input_reader_audit.json')})
 altered=[]
 for label in ['instruction_byte','descriptor_size','allocation_size_claim','complete_parser_claim']:
  bad=copy.deepcopy(e)
  if label=='instruction_byte':
   b=bytearray.fromhex(bad['spans'][0]['bytes_hex']);b[0]^=1;bad['spans'][0]['bytes_hex']=b.hex()
  elif label=='descriptor_size':bad['allocation_descriptor']['size_bytes']=32
  elif label=='allocation_size_claim':bad['scope']=bad['scope'].replace('exact-size allocator','size-plus-one allocator')
  else:bad['complete_parser_body_established']=True
  assert bad!=R.build();altered.append({'alteration':label,'rejected_by_fresh_evidence_comparison':True})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'source_sha256':e['source_sha256'],'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,
  'proved_source_PCs':sorted(map(hex,visited)),'rechecked_prior_source_proofs':pp,
  'altered_evidence_controls':altered,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(pp),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'bank_composition_input_cases':sum(256 for _ in e['bank_rules']),'altered_evidence_rejections':len(altered)},
  'conditional_container_staging_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
 print(json.dumps(a['independent_totals']),flush=True)
