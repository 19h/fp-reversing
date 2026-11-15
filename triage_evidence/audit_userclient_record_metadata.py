#!/usr/bin/env python3
"""Source-pinned staged header, bounds, metadata and cursor obligations.
O(I+query DAG) construction/space; separate SMT cost, 30 s/query.
"""
import copy
import json
import z3
from capstone.arm64 import ARM64_OP_REG
from kext_port_tools import ROOT,TABLE,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from audit_userclient_input_reader import Model as ReaderModel,DEC,WORD_BYTES,TYPE_BYTES,TOKEN,PHASE,SUCCESS,mask
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_record_metadata as R

KEY0=0x02e859d27e491464
KEY1=0x4dae26df20976138

class Model(ReaderModel):
 def __init__(self,e):
  super().__init__(e)
  self.cursor=z3.BitVec('RM_cursor64',64);self.outer=z3.BitVec('RM_outer_length32',32)
  self.byte_offsets=[];self.byte_pos=0
 def owned(self):
  spans=[(self.sp,0x1120),(self.ctx,0x800),(self.src,0x1000),(self.buffer,z3.ZeroExt(32,self.outer))]
  out=[(self.sp&15)==0]
  for j,(a,n) in enumerate(spans):
   out.extend([a!=0,z3.ULE(a,resize(2**64-1,64)-n)])
   for b,m in spans[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,m in IMAGE_REGIONS:out.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  return out
 def load(self,a,n):
  if self.pc in WORD_BYTES|TYPE_BYTES:
   assert n==1 and self.byte_pos<len(self.byte_offsets);j=self.byte_offsets[self.byte_pos];self.byte_pos+=1
   self.address_checks.append(a==self.buffer+self.cursor+j)
   return self.plain[j]^mask(a,resize(KEY0,64))
  if self.pc in R.BRANCHES:
   assert n==8
   js=R.BRANCHES[self.pc]
   self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  return Base.load(self,a,n)
 def run(self,label,end=None):
  row=next(s for s in self.e['spans'] if s['label']==label);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if end is not None and i.address>=end:break
   if i.address==skip:continue
   self.pc=i.address;m=i.mnemonic;o=i.operands
   custom=m in ['ror','cmn','cmp','csel'] or m.startswith('b.') or m=='cset' and i.op_str.endswith((', hi',', lo')) or m in ['lsr','lsl'] and o[2].type==ARM64_OP_REG
   if custom:
    self.visited.add(i.address);self.count+=1
    if m.startswith('b.'):
     assert m in ['b.eq','b.ne'];condition=self.equal if m=='b.eq' else z3.Not(self.equal)
     if i.address in R.RETAGS:
      assert m=='b.eq' and o[0].imm&(2**64-1)==i.address+8;self.branch_guards.append(condition);skip=R.RETAGS[i.address]
     else:
      take=self.branch_choices.get(i.address,False);self.branch_guards.append(condition if take else z3.Not(condition))
      if take:self.direct_target=o[0].imm&(2**64-1);break
    elif m=='cmp':
     n=self.width(i.reg_name(o[0].reg));self.cmp_left=self.operand(i,o[0],n);self.cmp_right=self.operand(i,o[1],n);self.equal=self.cmp_left==self.cmp_right;self.carry=None
    elif m=='cmn':
     n=self.width(i.reg_name(o[0].reg));a,b=self.operand(i,o[0],n),self.operand(i,o[1],n);self.equal=a+b==0;self.carry=z3.ULT(a+b,a)
    elif m=='cset':
     cond=i.op_str.rsplit(',',1)[1].strip();v=z3.Not(self.carry) if cond=='lo' and self.carry is not None else z3.ULT(self.cmp_left,self.cmp_right) if cond=='lo' else z3.UGT(self.cmp_left,self.cmp_right)
     self.write(i.reg_name(o[0].reg),z3.If(v,resize(1,32),resize(0,32)))
    elif m=='csel':
     assert i.op_str.endswith(', ne');self.write(i.reg_name(o[0].reg),z3.If(z3.Not(self.equal),self.read(i.reg_name(o[1].reg)),self.read(i.reg_name(o[2].reg))))
    elif m=='ror':self.write(i.reg_name(o[0].reg),z3.RotateRight(self.read(i.reg_name(o[1].reg)),o[2].imm))
    else:
     n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);s=self.operand(i,o[2],n)&(n-1)
     self.write(i.reg_name(o[0].reg),z3.LShR(a,s) if m=='lsr' else a<<s)
   else:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    Base.run(self,'one');self.e,self.c=old_e,old_c
  return self

def setup(e):
 v=Model(e)
 for r,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('w3',TOKEN),('w1',PHASE),('w30',SUCCESS),
  ('w20',0x87f),('w15',0x09f7be0b),('w14',0xec),('x26',KEY0)]:v.seed(r,x)
 mem(v,v.sp+0xa80,8,v.cursor);mem(v,v.sp+0x890,8,v.ctx+0x3d8)
 mem(v,v.src+0xc8c,4,v.outer^SUCCESS);mem(v,v.ctx+0x618,8,v.buffer)
 mem(v,v.ctx+0x228,8,v.object)
 return v

def entered(e):return setup(e).run('parser_cursor_gate').run('parser_input_gate')
def prepared(e):return entered(e).run('header_extent').run('header_prepare').run('word_bridge')
def decoded(e):
 v=prepared(e);v.decode(range(4));v.run('tag_return');v.decode(range(4,6));v.run('type_return').run('length_bridge')
 v.decode(range(6,10));return v
def plain_tag(v):return z3.Concat(*v.plain[:4])
def tag(v):return plain_tag(v)^SUCCESS
def kind(v):return z3.Concat(*v.plain[4:6])^0x365e
def length(v):return z3.Concat(*v.plain[6:10])
def extent_ok(v):return z3.ULE(v.cursor+10+z3.ZeroExt(32,length(v)),z3.ZeroExt(32,v.outer))
def header_ok(v):return z3.ULE(v.cursor+10,z3.ZeroExt(32,v.outer))

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),'pointer_branch_guards':len(v.branch_guards)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)});visited.update(v.visited);print(label,flush=True)
 v=setup(e).run('input_alias_root');prove('original_staged_pointer_cell_alias',v,cell(v,v.sp+0x890,8)!=v.ctx+0x3d8)
 v=entered(e)
 prove('nonempty_input_phase_retains_staged_pointer_and_decoder_keys',v,z3.Or(cell(v,v.ctx+0x3d8,8)!=v.buffer,
  v.read('x14')!=0xfffffe000a642248,v.read('x9')!=v.cursor,v.read('x11')!=z3.ZeroExt(32,v.outer^SUCCESS),
  v.read('x20')!=KEY1,v.read('x26')!=KEY0),[z3.ULT(v.cursor,z3.ZeroExt(32,v.outer))])
 v.run('header_extent')
 prove('header_gate_exact_cursor_plus_ten_with_nonempty_cursor_invariant',v,z3.Or(
  cell(v,v.sp+0xbd8,8)!=v.cursor,v.read('x11')!=z3.If(header_ok(v),resize(0xfffffe000a642330,64),resize(0xfffffe000a6423c0,64))),
  [z3.ULT(v.cursor,z3.ZeroExt(32,v.outer))])
 rejected=copy.deepcopy(v);rejected.run('metadata_outcome_gate')
 prove('short_header_reaches_failure_frontier_without_cursor_advance',rejected,z3.Or(
  cell(rejected,rejected.sp+0xa80,8)!=rejected.cursor,rejected.read('w10')!=0,
  rejected.read('w23')!=0xce515bb8,rejected.read('x8')!=0xfffffe000a662440),
  [z3.ULT(rejected.cursor,z3.ZeroExt(32,rejected.outer)),z3.Not(header_ok(rejected))])
 v.run('header_prepare').run('word_bridge')
 prove('header_decoder_requests_original_staged_pointer_and_cursor',v,z3.Or(v.read('x11')!=0xfffffe000a637138,
  v.read('x8')!=v.buffer,v.read('x10')+v.read('x1')!=v.cursor,v.read('w9')!=0x17a),[header_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer))])
 v.decode(range(4));prove('four_staged_header_bytes_produce_encoded_tag',v,v.read('w22')!=tag(v),[header_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer))])
 header_offset=z3.BitVec('RM_header_offset64',64)
 prove('accepted_header_ten_read_offsets_fit_inside_staged_extent',v,z3.Or(
  z3.ULT(v.buffer+v.cursor+header_offset,v.buffer),
  z3.UGE(v.buffer+v.cursor+header_offset,v.buffer+z3.ZeroExt(32,v.outer))),
  [header_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer)),z3.ULT(header_offset,10)])
 v.run('tag_return');v.decode(range(4,6))
 prove('six_staged_header_bytes_produce_transformed_type_and_retain_tag',v,z3.Or(z3.Extract(15,0,v.read('w8'))!=kind(v),
  cell(v,v.src+0xa18,4)!=tag(v)),[header_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer))])
 v.run('type_return').run('length_bridge');v.decode(range(6,10))
 prove('ten_staged_header_bytes_produce_encoded_length_and_retain_type',v,z3.Or(v.read('w22')!=(length(v)^SUCCESS),
  cell(v,v.src+0x2a0,2)!=kind(v)),[header_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer))])
 v.run('length_extent')
 prove('record_extent_gate_candidate_cursor_and_exact_bounds_under_header_invariant',v,z3.Or(
  cell(v,v.src+0xcf8,8)!=v.cursor+10+z3.ZeroExt(32,length(v)),cell(v,v.src+0xa64,4)!=(length(v)^SUCCESS),
  v.read('x11')!=v.cursor+10,v.read('x8')!=z3.If(extent_ok(v),resize(0xfffffe000a639164,64),resize(0xfffffe000a6423c0,64))),
  [header_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer))])
 rejected=copy.deepcopy(v);rejected.run('metadata_outcome_gate')
 prove('oversized_body_retains_candidate_but_rejects_without_committing_cursor',rejected,z3.Or(
  cell(rejected,rejected.src+0xcf8,8)!=rejected.cursor+10+z3.ZeroExt(32,length(rejected)),
  cell(rejected,rejected.sp+0xa80,8)!=rejected.cursor,rejected.read('w10')!=0,
  rejected.read('w23')!=0xce515bb8,rejected.read('x8')!=0xfffffe000a662440),
  [header_ok(rejected),z3.ULT(rejected.cursor,z3.ZeroExt(32,rejected.outer)),z3.Not(extent_ok(rejected))])
 v.branch_choices[0xfffffe000a639174]=True;v.run('type_first_gate')
 v.branch_choices[0xfffffe000a63a78c]=True;v.run('type_selected_gate')
 prove('selected_type6685_dispatches_to_staged_body_publication',v,z3.BoolVal(v.direct_target!=0xfffffe000a63dc9c),
  [header_ok(v),extent_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer)),kind(v)==0x6685])
 v.run('body_publish').run('metadata_return').run('metadata_outcome_gate')
 prove('selected_type6685_bounded_payload_next_cursor_and_node_metadata_return',v,z3.Or(
  cell(v,v.ctx+0x280,8)!=v.buffer+v.cursor+10,cell(v,v.sp+0xa80,8)!=v.cursor+10+z3.ZeroExt(32,length(v)),
  cell(v,v.src+0xaec,4)!=tag(v),cell(v,v.src+0xa08,2)!=0x6685,
  cell(v,v.src+0x9e8,4)!=(length(v)^SUCCESS),v.read('w10')!=1,v.read('w23')!=SUCCESS,
  v.read('x8')!=qword(TABLE+8*0x88c)),
  [header_ok(v),extent_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer)),kind(v)==0x6685])
 next_cursor=cell(v,v.sp+0xa80,8)
 prove('accepted_selected_payload_half_open_extent_fits_staged_buffer',v,z3.Or(
  z3.ULT(cell(v,v.ctx+0x280,8),v.buffer),
  cell(v,v.ctx+0x280,8)+z3.ZeroExt(32,length(v))!=v.buffer+next_cursor,
  z3.UGT(v.buffer+next_cursor,v.buffer+z3.ZeroExt(32,v.outer))),
  [header_ok(v),extent_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer)),kind(v)==0x6685])
 prove('accepted_selected_record_strictly_advances_at_least_ten_and_stays_bounded',v,z3.Or(
  z3.ULT(next_cursor,v.cursor+10),z3.UGT(next_cursor,z3.ZeroExt(32,v.outer)),
  z3.ULE(next_cursor,v.cursor),z3.UGT(next_cursor,0xffffffff)),
  [header_ok(v),extent_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer)),kind(v)==0x6685])
 prove('zero_payload_selected_record_consumes_exactly_ten_header_bytes',v,z3.Or(
  next_cursor!=v.cursor+10,cell(v,v.ctx+0x280,8)!=v.buffer+next_cursor),
  [header_ok(v),extent_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer)),kind(v)==0x6685,length(v)==0])
 v.run('record_kind_gate')
 prove('decoded_zero_tag_type6685_selects_parser_success_before_node_construction',v,
  v.read('x11')!=0xfffffe000a6421b0,
  [header_ok(v),extent_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer)),kind(v)==0x6685,plain_tag(v)==0])
 prove('decoded_nonzero_tag_type6685_selects_ordinary_record_construction',v,
  v.read('x11')!=0xfffffe000a642454,
  [header_ok(v),extent_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer)),kind(v)==0x6685,plain_tag(v)!=0])
 prove('decoded_zero_tag_selected_success_allows_unconsumed_outer_suffix',v,
  v.read('x11')!=0xfffffe000a6421b0,
  [header_ok(v),extent_ok(v),z3.ULT(v.cursor,z3.ZeroExt(32,v.outer)),kind(v)==0x6685,plain_tag(v)==0,
   z3.ULT(next_cursor,z3.ZeroExt(32,v.outer))])
 for pc in R.RETAGS.values():
  row=next(s for s in e['spans'] if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16)
  raw=bytes.fromhex(row['bytes_hex'])[off:off+4];i=next(DEC.disasm(raw,pc));reg=i.reg_name(i.operands[0].reg)
  d=setup(e);old=z3.BitVec('RM_retag_input_'+format(pc,'x'),64);d.seed(reg,old)
  d.e=d.c={'spans':[{'label':'alternate','start':hex(pc),'bytes_hex':raw.hex()}]};d.run('alternate')
  prove('alternate_retag_'+format(pc,'x')+'_bit_transform_only',d,d.read(reg)!=((old&0xffffffffffff)|(0xc8a2<<48)))
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']}
 assert visited==selected,{'missing':sorted(map(hex,selected-visited)),'extra':sorted(map(hex,visited-selected))}
 rechecked=[]
 for f,label in [
  ('userclient_container_staging_audit.json','nonnull_site_FPTTLV_clears_two_pointer_fields_and_sets_reader_key'),
  ('userclient_container_staging_audit.json','all_cursor64_parser_gate_compares_widened_decoded_extent'),
  ('userclient_record_nodes_audit.json','post_header_cursor_tag_type_length_channels_and_separate_success_outcome'),
  ('userclient_record_nodes_audit.json','valid_header_outcome_enters_metadata_kind_gate'),
  ('userclient_record_publication_audit.json','append_tail_returns_unchanged_cursor_to_exact_parser_gate')]:
  p=next(p for p in json.loads(read(ROOT/f))['source_proofs'] if p['label']==label)
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert p['premises_nonvacuous'] and s.check()==z3.unsat
  rechecked.append({'artifact':f,'artifact_sha256':sha(ROOT/f),'label':label,'result':'unsat'})
 controls=[]
 for name,mutate in [
  ('instruction_byte',lambda x:x['spans'][0].update(bytes_hex='00'+x['spans'][0]['bytes_hex'][2:])),
  ('branch_pointer',lambda x:x['branch_pointers'][0].update(target='0x0')),
  ('header_width',lambda x:x['verified_counts'].update(header_bytes=9)),
  ('native_identity_claim',lambda x:x.update(native_input_identity_established=True))]:
  altered=copy.deepcopy(e);mutate(altered);assert altered!=e;controls.append({'alteration':name,'equality_check_rejects':True})
 return {'generator_sha256':sha(__file__),'source_sha256':e['source_sha256'],'scope':R.SCOPE,
  'source_proofs':qs,'proof_coverage':coverage,'proved_pcs':sorted(map(hex,visited)),
  'rechecked_prior_source_proofs':rechecked,'altered_evidence_controls':controls,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(rechecked),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'altered_evidence_rejections':len(controls),'selected_type_values':1,'alternate_retag_sites':len(R.RETAGS)},
  'conditional_record_metadata_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
