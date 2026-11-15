#!/usr/bin/env python3
"""Source-level tunnel/table handoff and caller-record composition audit.
O(I+256R+query DAG) construction/space; separate SMT cost, 30 s/query.
No target executes. Saved records, disjoint extents and ordinary calls are premises.
"""
import copy
import json
from types import SimpleNamespace
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_EXT_UXTB, ARM64_EXT_SXTW
from kext_port_tools import ROOT, SOURCE, IMAGE, POOL, TABLE, qword
from lskd_values_symbolic import Lift, resize, mem
from audit_userclient_hash_table_initializer import IMAGE_REGIONS
from audit_userclient_hash_table_reclamation import Model as WriterModel
from audit_userclient_hash_table_lookup import Model as LookupModel
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_secure_tunnel_table_insertion as R

DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True
SUCCESS=0x31ae0066
KEY0=0x1ee45f68039f9913
EMPTY=0x629f8775
OCCUPIED=0x629f8777
TOKEN=0x886a1ca3
TAG=0xffc0000000000000

def number(x):
 x=z3.simplify(x);assert z3.is_bv_value(x),str(x);return x.as_long()

class Model(Lift):
 def __init__(self,e):
  super().__init__({'spans':e['spans']});self.e=e;self.visited=set();self.address_checks=[];self.bank_rewrites=[]
  self.sp,self.ctx,self.src,self.header,self.buffer,self.payload=z3.BitVecs('TI_SP64 TI_context64 TI_source64 TI_header64 TI_buffer64 TI_payload64',64)
  self.raw_marker,self.capacity,self.index,self.status=z3.BitVecs('TI_marker32 TI_capacity32 TI_index32 TI_status32',32)
  self.record=self.src+0x968;self.u=self.raw_marker^SUCCESS;self.bank_input=None;self.bank_byte=None
  for j in range(31):self.seed('x'+str(j),z3.BitVec('TI_initial_X'+str(j),64))
  self.seed('sp',self.sp)
 def operand(self,i,o,n):
  if o.ext==ARM64_EXT_UXTB:
   assert not o.shift.type;return resize(self.read(i.reg_name(o.reg)),n)&255
  return super().operand(i,o,n)
 def address(self,i,o):
  if o.ext==ARM64_EXT_SXTW:
   return z3.simplify(resize(self.read(i.reg_name(o.mem.base)),64)+o.mem.disp+(z3.SignExt(32,resize(self.read(i.reg_name(o.mem.index)),32))<<o.shift.value))
  return super().address(i,o)
 def load(self,a,n):
  a=z3.simplify(a)
  bank_pcs={0xfffffe000a65c17c:('L','lookup'),0xfffffe000a65c18c:('R','lookup'),
   0xfffffe000a65c2ec:('L','writer'),0xfffffe000a65c2fc:('R','writer')}
  if self.pc in bank_pcs:
   side,name=bank_pcs[self.pc];r=next(r for r in self.e['bank_rules'] if r['name']==name)
   left,right=int(r['left'],16),int(r['right'],16);assert n==1
   if side=='L':
    self.bank_input=z3.Extract(7,0,a-left);self.bank_byte=z3.BitVec('TI_left_byte_'+name,8)
    self.address_checks.append(a==left+z3.ZeroExt(56,self.bank_input));return self.bank_byte
   self.address_checks.append(a==right+z3.ZeroExt(56,self.bank_byte^int(r['key'],16)))
   self.bank_rewrites.append({'pc':hex(self.pc),'rule':name,'inputs_checked':256})
   return self.bank_input^int(r['constant'],16)
  if self.pc==0xfffffe000a65c1e8:
   good=a==TABLE+8*0xda1;bad=a==TABLE+8*0x91e;self.address_checks.append(z3.Or(good,bad))
   return z3.If(good,resize(qword(TABLE+8*0xda1),64),resize(qword(TABLE+8*0x91e),64))
  if self.pc in [0xfffffe000a65c1a0,0xfffffe000a65c310]:
   r=next(r for r in self.e['bank_rules'] if r['name']==('lookup' if self.pc==0xfffffe000a65c1a0 else 'writer'))
   self.address_checks.append(a==int(r['slot'],16));return resize(int(r['target'],16),64)
  key=(a.sexpr(),n)
  if key in self.memory:return self.memory[key]
  if z3.is_bv_value(a):return resize(int.from_bytes(IMAGE.read(a.as_long(),n),'little'),8*n)
  return super().load(a,n)
 def run(self,label,end=None):
  row=next(s for s in self.e['spans'] if s['label']==label);a=int(row['start'],16);raw=bytes.fromhex(row['bytes_hex'])
  if end is not None:raw=raw[:end-a]
  for i in DEC.disasm(raw,a):
   self.pc=i.address;self.visited.add(i.address);o=i.operands
   if i.mnemonic in ['adrp','tst'] or i.mnemonic=='lsl' and o[2].type==ARM64_OP_REG:
    self.count+=1
    if i.mnemonic=='adrp':self.write(i.reg_name(o[0].reg),resize(o[1].imm,64))
    elif i.mnemonic=='tst':
     n=self.width(i.reg_name(o[0].reg));self.equal=(self.operand(i,o[0],n)&self.operand(i,o[1],n))==0
    else:
     n=self.width(i.reg_name(o[0].reg));self.write(i.reg_name(o[0].reg),self.operand(i,o[1],n)<<(self.operand(i,o[2],n)&(n-1)))
   else:
    old=self.c;self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.c=old
  return self
 def owned(self):
  extent=24*z3.ZeroExt(32,self.capacity)
  spans=[(self.sp-0x70,0x10f0),(self.src,0x1000),(self.ctx,0x800),(self.header,16),(self.payload,120),(self.buffer,extent)]
  out=[self.capacity!=0,z3.ULT(self.index,self.capacity),z3.UGE(self.sp,0x200),
   (self.sp&15)==0,(self.record&7)==0,(self.header&7)==0,(self.buffer&7)==0]
  for j,(a,n) in enumerate(spans):
   out.extend([a!=0,z3.ULE(a,resize((1<<64)-1,64)-n)])
   for b,m in spans[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,m in IMAGE_REGIONS:out.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  return out

def cells(v):
 for off,x in [(0xa08,v.src),(0xa28,v.ctx),(0x998,v.record),(0x430,v.src+0xcb4),(0xa60,TABLE),
  (0xa30,0xfffffe000ccc30d0),(0xa38,0xfffffe000ccc32f8),
  (0xa48,0xfffffe0007949dd0),(0xa40,0xfffffe000792fbc0)]:mem(v,v.sp+off,8,x)
 mem(v,v.header+4,4,v.capacity);mem(v,v.header+8,8,v.buffer)
 mem(v,v.ctx+0x48,8,v.payload);mem(v,v.ctx+0x200,8,v.header);mem(v,v.ctx+0x5d8,8,v.payload)
 mem(v,v.src+0x20,4,v.raw_marker);mem(v,v.src+0xcb4,4,v.index)
 for a in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:mem(v,a,4,z3.BitVec('TI_controller_'+format(a,'x'),32))

def key_inputs(e):
 v=Model(e);cells(v);v.seed('x2',v.ctx);v.seed('x4',v.src);v.run('insertion_inputs').run('key_basis')
 return v

def lookup_request(e):
 v=key_inputs(e)
 # The proved basis lemma is a congruence cut into the following mixer.
 v.seed('x27',z3.ZeroExt(32,v.u)-SUCCESS);v.seed('x25',z3.ZeroExt(32,v.u)-SUCCESS+0x68aa65787ec20240)
 for reg,x in [('w20',TOKEN),('w26',TOKEN),('w9',v.capacity),('w13',0x7795e642),
  ('x6',0xfffffe000ccc30d0),('x5',0xa41a4d891208c018),('x7',TABLE)]:v.seed(reg,x)
 v.run('lookup_prefix').run('lookup_key_mix').run('lookup_codec').run('lookup_record').run('lookup_call')
 return v

def insertion_request(e):
 v=Model(e);cells(v)
 for reg,x in [('x4',v.src),('x24',v.header),('x27',z3.ZeroExt(32,v.u)-SUCCESS),('x28',v.payload),
  ('x6',0xfffffe000ccc30d0),('x5',0xa41a4d891208c018),('x7',TABLE)]:v.seed(reg,x)
 mem(v,v.sp+0x9e0,4,0x5cc)
 v.run('insert_address')
 v.run('insert_codec').run('insert_record').run('insert_call');return v

def cell(v,a,n):return v.memory[(z3.simplify(resize(a,64)).sexpr(),n)]

def proofs(e):
 qs=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=(),rewrites=(),owner=None):
  s=z3.Solver();s.set(timeout=30000);s.add(*(v.owned() if owner is None else owner),*premises);assert s.check()==z3.sat,label
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)))
  result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'certified_rewrites':list(rewrites)+[{'lemma':'exhaustive_original_bank_composition','applications':copy.deepcopy(v.bank_rewrites)}]})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)})
  visited.update(v.visited)
 v=Model(e);v.seed('x4',v.src);v.seed('x2',v.ctx);v.run('record_root').run('record_root_save').run('saved_context_roots')
 prove('affine_private_record_and_saved_context_roots',v,z3.Or(cell(v,v.sp+0x998,8)!=v.record,cell(v,v.sp+0xa08,8)!=v.src,cell(v,v.sp+0xa28,8)!=v.ctx))
 v=Model(e);cells(v);v.seed('x2',v.ctx);v.seed('x22',v.header);v.run('payload_alias').run('header_alias').seed('x4',v.src)
 v.run('insertion_inputs')
 prove('tunnel_alias_and_source_marker_load',v,z3.Or(cell(v,v.ctx+0x218,8)!=v.payload,cell(v,v.ctx+0x5d8,8)!=v.payload,cell(v,v.ctx+0x200,8)!=v.header,v.read('x24')!=v.header,v.read('x28')!=v.payload,v.read('x22')!=z3.ZeroExt(32,v.raw_marker),cell(v,v.src+0xcb4,4)!=0))
 v.run('payload_save');v.seed('x28',z3.BitVec('TI_growth_temporary_X28',64));v.run('payload_restore')
 prove('payload_saved_before_growth_and_restored_before_token_reuse',v,v.read('x28')!=v.payload)
 v=key_inputs(e)
 prove('all_source_marker32_key_basis',v,z3.Or(v.read('x27')!=z3.ZeroExt(32,v.u)-SUCCESS,v.read('x25')!=z3.ZeroExt(32,v.u)-SUCCESS+0x68aa65787ec20240))
 v=lookup_request(e);record=v.record;caller_pre=v.values[(0xfffffe000a65c108,'x10')];caller_k=v.values[(0xfffffe000a65c114,'x10')]
 d=Model(e);d.seed('x0',record);d.run('lookup_decoder_key')
 prove('lookup_caller_and_helper_pre_multiply_codec_equality',d,caller_pre!=d.values[(0xfffffe000a5ae408,'x9')])
 encoded=cell(v,record,8)+caller_k;shape=resize(0x652019cc00000000,64)|z3.ZeroExt(32,v.u^0x6a48ac59)
 prove('lookup_packet_decodes_marker_key_token_capacity_and_outputs',v,z3.Or(encoded!=shape,
  cell(v,record+8,8)!=0,cell(v,record+0x10,8)!=v.src+0xcb4,cell(v,record+0x20,8)!=v.buffer,
  cell(v,record+0x28,4)-resize(caller_k,32)!=0x541,(cell(v,record+0x2c,4)^resize(caller_k,32))-0x4f950919!=v.capacity,
  v.read('x0')!=record,v.read('x8')!=0xfffffe000a5ae354,v.read('x17')!=0x6a0f,cell(v,v.sp+0x9e0,4)!=0x5cc),
  rewrites=[{'lemma':'all_source_marker32_key_basis'},{'lemma':'lookup_caller_and_helper_pre_multiply_codec_equality','rewrite':'Congruence through the common u64 multiplier.'}])
 q=Model(e);cells(q);q.seed('x23',q.record);q.seed('w20',0x91e);mem(q,q.record+0x18,4,q.status)
 q.run('lookup_return')
 prove('status_only_gate_to_occupied_writer_block',q,q.read('x8')!=z3.If(q.status==SUCCESS,resize(0xfffffe000a65c1fc,64),resize(0xfffffe000a65e4bc,64)))
 v=Model(e);cells(v);v.seed('x4',v.src);v.seed('x24',v.header);mem(v,v.sp+0x9e0,4,0x5cc);v.run('insert_address')
 entry=v.buffer+24*z3.ZeroExt(32,v.index)
 prove('insertion_index_stride_and_top_tag_guard',v,z3.Or(v.read('x10')!=entry,v.equal!=(((v.buffer^entry)&TAG)==0),v.read('w20')!=0xc0a))
 v.run('insert_retag');prove('alternate_top16_retag_transform',v,v.read('x10')!=((entry&((1<<48)-1))|(0xc8a2<<48)))
 v=insertion_request(e);caller_pre=v.values[(0xfffffe000a65c27c,'x9')];caller_k=v.values[(0xfffffe000a65c288,'x9')]
 d=Model(e);d.seed('x0',v.record);d.run('writer_decoder_key')
 prove('writer_caller_and_helper_pre_multiply_codec_equality',d,caller_pre!=d.values[(0xfffffe000a5aec88,'x8')])
 prove('occupied_writer_packet_key_payload_header_and_token',v,z3.Or(cell(v,v.record,8)!=entry,
  cell(v,v.record+8,4)-resize(caller_k,32)!=0xc28,cell(v,v.record+0x10,8)!=v.payload,
  cell(v,v.record+0x18,8)!=v.header,cell(v,v.record+0x20,4)-resize(caller_k,32)!=OCCUPIED,
  cell(v,v.record+0x28,8)+caller_k!=KEY0+z3.ZeroExt(32,v.u),v.read('x0')!=v.record,
  v.read('x8')!=0xfffffe000a5aec24,v.read('x17')!=0x3936),premises=[((v.buffer^entry)&TAG)==0],
  rewrites=[{'lemma':'writer_caller_and_helper_pre_multiply_codec_equality','rewrite':'Congruence through the common u64 multiplier.'}])
 v=Model(e);cells(v);v.seed('w22',v.raw_marker);v.run('post_writer')
 prove('post_writer_raw_marker_into_source_and_tunnel',v,z3.Or(cell(v,v.src+0xd0,4)!=v.raw_marker,cell(v,v.payload+0x6c,4)!=v.raw_marker))
 v=Model(e)
 extent=24*z3.ZeroExt(32,v.capacity);entry=v.buffer+24*z3.ZeroExt(32,v.index)
 bounds=[z3.ULE(v.buffer,entry),z3.ULE(entry+24,v.buffer+extent)]
 # Unsigned interpretation: all source products/additions are nonwrapping
 # under these integer bounds, so this lemma transports to the BV addresses.
 b,n,i=z3.Ints('TI_extent_base_u64 TI_extent_capacity_u32 TI_extent_index_u32')
 s=z3.SolverFor('QF_LIA');s.set(timeout=30000)
 s.add(b>0,b<2**64,n>0,n<2**32,i>=0,i<n,b+24*n<=2**64-1);assert s.check()==z3.sat
 s.add(z3.Or(b>b+24*i,b+24*i+24>b+24*n,b+24*i>2**64-1));assert s.check()==z3.unsat
 qs.append({'label':'all_valid_index32_entry_extent_within_full_array','result':'unsat','premises_nonvacuous':True,
  'query':s.to_smt2(),'certified_rewrites':[{'unsigned_interpretation':'u64 base, positive u32 capacity, bounded u32 index; 24*N and every selected address are proved nonwrapping.'}]})
 coverage.append({'label':'all_valid_index32_entry_extent_within_full_array','source_instruction_instances':0,'store_instances':0})
 owner=SimpleNamespace(sp=v.sp,record=v.record,header=v.header,buffer=v.buffer,payload=v.payload,
  capacity=v.capacity,index=v.index,entry=entry,frame_extent=(v.sp-16,16))
 prove('caller_storage_implies_original_writer_storage_premises',v,z3.Or(*[z3.Not(x) for x in WriterModel.owned(owner)]),
  premises=bounds,rewrites=[{'lemma':'all_valid_index32_entry_extent_within_full_array'}])
 # The prior null-flag branch has a dummy flag storage symbol; it is not read.
 owner.flag=v.payload+119;owner.index=v.src+0xcb4
 prove('caller_storage_implies_original_null_flag_lookup_storage_premises',v,z3.Or(*[z3.Not(x) for x in LookupModel.owned(owner)]))
 return qs,coverage,visited

def root_def_use(e):
 row=e['record_root_def_use_gap'];raw=bytes.fromhex(row['bytes_hex']);ii=list(DEC.disasm(raw,int(row['start'],16)))
 assert len(ii)==354 and len(ii)*4==len(raw)
 for i in ii:
  _,writes=i.regs_access();assert all(i.reg_name(r) not in ['x16','w16'] for r in writes)
  assert i.mnemonic not in ['b','bl','br','blr','braa','brab','blraa','blrab','ret','retab'] and not i.mnemonic.startswith(('b.','cb','tb'))
 return {'source_instructions_checked':len(ii),'X16_written':False,'control_transfer_present':False,'window_sha256':row['sha256']}

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();root=root_def_use(e)
 for r in e['bank_rules']:
  l,rbytes=bytes.fromhex(e['banks']['TL']['bytes_hex']),bytes.fromhex(e['banks']['TR']['bytes_hex'])
  assert all(x^rbytes[l[x]^int(r['key'],16)]==int(r['constant'],16) for x in range(256))
 qs,coverage,visited=proofs(e)
 prior=json.loads(read(ROOT/'userclient_hash_table_reclamation_audit.json'));labels=[
  'all_state32_empty_to_occupied_increment_gate','all_state32_increment_counter_and_exact_entry_stores',
  'all_state32_unchanged_counter_and_exact_entry_stores','token_c28_nonnull_entry_gate_and_decoded_token']
 pp=[]
 for label in labels:
  q=next(x for x in prior['source_proofs'] if x['label']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
  pp.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_hash_table_reclamation_audit.json')})
 prior=json.loads(read(ROOT/'userclient_hash_table_lookup_audit.json'))
 for label in ['empty_selected_index_and_success_status_stores','null_matched_optional_flag_gate',
  'null_matched_index_and_success_status_stores','null_optional_flag_skips_clear_and_enters_probe_setup']:
  q=next(x for x in prior['source_proofs'] if x['label']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
  pp.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_hash_table_lookup_audit.json')})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'scope':e['scope'],'source_proofs':qs,'coverage':coverage,'proved_source_PCs':sorted(map(hex,visited)),
  'record_root_def_use':root,'rechecked_prior_source_proofs':pp,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(pp),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(x['source_instruction_instances'] for x in coverage),
   'bank_input_cases_checked':512,'def_use_instructions_checked':354},
  'conditional_tunnel_to_table_insertion_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
