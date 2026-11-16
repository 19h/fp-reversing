#!/usr/bin/env python3
"""Instruction-derived alternate query header/scalar writer obligations.
O(instruction instances+query DAG) construction/space; SMT cost separate.
"""
import copy
import json
import z3
from kext_port_tools import ROOT,TABLE,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize
from audit_userclient_record_metadata import Model as MetadataModel
from audit_userclient_input_reader import DEC,TOKEN,PHASE,SUCCESS
from audit_userclient_record_writer import mask,KEY0,KEY1
import audit_userclient_query_records as QR
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_query_writer as R

WORD_PCS=[0xfffffe000a654ccc,0xfffffe000a654d18,0xfffffe000a654d74,0xfffffe000a654db0]
TYPE_PCS=[0xfffffe000a655014,0xfffffe000a655038]

class Model(QR.Model):
 def load(self,a,n):
  if self.pc in R.BRANCHES:
   js=R.BRANCHES[self.pc];assert n==8;self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  return super().load(a,n)
 def run(self,label,end=None):
  row=next(s for s in self.e['spans'] if s['label']==label);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if end is not None and i.address>=end:break
   if i.address==skip:continue
   self.pc=i.address
   if i.address in R.RETAGS:
    assert i.mnemonic=='b.eq' and i.operands[0].imm&(2**64-1)==i.address+8
    self.visited.add(i.address);self.count+=1;self.branch_guards.append(self.equal);skip=R.RETAGS[i.address]
   else:
    oe,oc=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    if i.mnemonic=='tst':Base.run(self,'one')
    else:MetadataModel.run(self,'one')
    self.e,self.c=oe,oc
  return self

def setup(e):
 prior=json.loads(read(ROOT/'userclient_query_records_checks.json'));combined=copy.deepcopy(prior);combined['spans']+=e['spans']
 v=QR.setup(combined);v.__class__=Model
 # Other shared-writer channels are independent private words. Their node
 # pointer values are formed but never dereferenced on this selected route.
 for off in [0x768,0x458,0x140,0x6b8]:mem(v,v.ctx+off,8,z3.BitVec('QW_other_node_'+format(off,'x'),64))
 for off in [0xd30,0xe28,0xdf8]:mem(v,v.src+off,4,z3.BitVec('QW_other_control_'+format(off,'x'),32))
 mem(v,v.src+0xb90,2,z3.BitVec('QW_other_type16',16))
 mem(v,v.sp+0x348,8,z3.BitVec('QW_saved_lookup_return64',64))
 return v

def ready(e,case):
 v=setup(e)
 if case=='first':
  v.run('query_version').returned();mem(v,v.src+0x96c,4,0x4c0b0000)
  v.run('query_capabilities').returned();mem(v,v.src+0x96c,4,0x1f8)
 else:v.seed('w22',0x42 if case=='second' else 0x68)
 v.run('request_'+case).run('shared_entry').run('shared_prepare').run('node_request_record').run('extent_gate').run('node_allocate')
 v.returned(v.new_node).run('node_result');v.with_node=True;v.run('node_initialize')
 v.returned(v.new_buffer).run('data_result');v.with_buffer=True
 return v.run('writer_entry')

def header(e,case):
 return ready(e,case).run('query_writer_setup').run('query_word_writer').run('query_type_writer').run('query_length_bridge').run('query_word_writer')

def complete(e,case):
 return header(e,case).run('query_scalar_gate').run('query_scalar_bridge').run('query_length_bridge').run('query_word_writer')

def byte_stores(v):return [s for s in v.stores if s['pc'] in WORD_PCS+TYPE_PCS]
def expected(tag,scalar):return (tag^SUCCESS).to_bytes(4,'big')+bytes.fromhex('9777')+(4).to_bytes(4,'big')+(scalar^SUCCESS).to_bytes(4,'big')

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set();records=[]
 prior_checks=json.loads(read(ROOT/'userclient_query_records_checks.json'));assert prior_checks==QR.R.build()
 for r in prior_checks['bank_rules']:
  left,right=(bytes.fromhex(prior_checks['banks'][r[n+'_name']]['bytes_hex']) for n in ['left','right'])
  assert all(j^right[left[j]^int(r['key'],16)]==int(r['constant'],16) for j in range(256))
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'pointer_branch_guards':len(v.branch_guards),'certified_bank_rewrites':copy.deepcopy(v.bank_rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)})
  visited.update(v.visited);print(label,flush=True)
 for case,idx,tag,scalar,callback in QR.REQUESTS:
  v=ready(e,case)
  prove(case+'_original_request_to_query_writer_entry_registers',v,z3.Or(v.read('w23')!=(tag^0x14ac30f9),v.read('w24')!=0x13c,
   v.read('w25')!=TOKEN,v.read('x16')!=v.new_node+0x18,v.read('x8')!=0xfffffe000a654ad4))
  v.run('query_writer_setup')
  prove(case+'_alternate_node_type_scalar_controls_and_first_word_dispatch',v,z3.Or(
   v.read('x8')!=v.new_node+0x18,v.read('x22')!=v.new_node,v.read('w4')!=0x3594,v.read('w2')!=SUCCESS-4,
   v.read('w1')!=SUCCESS-4,v.read('w6')!=((SUCCESS-4)^0x14ac30f9),
   cell(v,v.sp+0x480,4)!=(scalar^0x14ac30f9),z3.Extract(7,0,v.read('w11'))!=0x97,
   z3.Extract(7,0,v.read('w3'))!=0x77,v.read('x25')!=0xfffffe000a654c64))
  v.run('query_word_writer');ss=byte_stores(v);assert len(ss)==4
  plain=expected(tag,scalar)
  prove(case+'_protected_big_endian_tag_and_alternate_type_continuation',v,z3.Or(
   *[z3.Or(s['address']!=v.new_buffer+j,s['value']!=(plain[j]^mask(v.new_buffer+j))) for j,s in enumerate(ss)],
   v.read('x24')!=0xfffffe000a654fc8,v.read('x0')!=KEY1,v.read('x26')!=KEY0))
  v.run('query_type_writer');ss=byte_stores(v)[4:];assert len(ss)==2
  prove(case+'_protected_type9777_and_four_byte_length_channel',v,z3.Or(
   *[z3.Or(s['address']!=v.new_buffer+j+4,s['value']!=(plain[j+4]^mask(v.new_buffer+j+4))) for j,s in enumerate(ss)],
   v.read('w24')!=0x165,v.read('w25')!=0x439,v.read('x16')!=v.new_node+0x18,
   v.read('w23')!=((SUCCESS-4)^0x14ac30f9),v.read('x26')!=0xfffffe000a654c44))
  v.run('query_length_bridge').run('query_word_writer');ss=byte_stores(v)[6:];assert len(ss)==4
  prove(case+'_protected_big_endian_length4_and_query_scalar_gate',v,z3.Or(
   *[z3.Or(s['address']!=v.new_buffer+j+6,s['value']!=(plain[j+6]^mask(v.new_buffer+j+6))) for j,s in enumerate(ss)],
   v.read('x24')!=0xfffffe000a654dcc))
  v.run('query_scalar_gate')
  prove(case+'_type3594_extentcontrol_success_minus_four_admits_scalar',v,z3.Or(
   v.read('x20')!=0xfffffe000a654e34,v.read('w24')!=0x129,v.read('w23')!=0xce515bb8))
  v.run('query_scalar_bridge').run('query_length_bridge').run('query_word_writer');ss=byte_stores(v);assert len(ss)==14
  prove(case+'_complete_fourteen_protected_record_bytes_and_publication_continuation',v,z3.Or(
   *[z3.Or(s['size_bytes']!=1,s['address']!=v.new_buffer+j,s['value']!=(plain[j]^mask(v.new_buffer+j))) for j,s in enumerate(ss)],
   v.read('x24')!=0xfffffe000a655cb4,cell(v,v.new_node,8)!=0,cell(v,v.new_node+8,8)!=0,
   cell(v,v.new_node+0x10,4)!=14,cell(v,v.new_node+0x18,8)!=v.new_buffer,
   cell(v,v.ctx+0x58,8)!=v.new_node,cell(v,v.ctx+0x260,8)!=0xfffffe000a664230,
   cell(v,v.ctx+0x5a8,8)!=callback))
  v.run('query_publication_request')
  prove(case+'_exact_list_lookup_request_frontier_and_saved_callback',v,z3.Or(
   cell(v,v.ctx+0x50,8)!=0,v.read('x22')!=v.object,v.read('w9')!=tag,v.read('w0')!=0x19,v.read('w8')!=0x6c,
   v.read('x11')!=0xfffffe000a662ab4,v.read('x2')!=v.ctx,v.read('x4')!=v.src,
   v.read('w1')!=PHASE,v.read('w3')!=TOKEN,v.read('w30')!=SUCCESS,
   cell(v,v.ctx+0x58,8)!=v.new_node,cell(v,v.ctx+0x260,8)!=0xfffffe000a664230,
   cell(v,v.ctx+0x5a8,8)!=callback))
  v.run('query_lookup_entry')
  prove(case+'_lookup_entry_uses_w8_callback6c_and_retains_output_tag_pending_node',v,z3.Or(
   cell(v,v.ctx+0xc8,8)!=0xfffffe000a662b64,cell(v,v.ctx+0x758,8)!=cell(v,v.sp+0x348,8),
   cell(v,v.src,4)!=tag,v.read('x8')!=0xfffffe000a662be0,cell(v,v.ctx+0x50,8)!=0,
   cell(v,v.ctx+0x58,8)!=v.new_node,cell(v,v.ctx+0x260,8)!=0xfffffe000a664230,
   cell(v,v.ctx+0x5a8,8)!=callback))
  records.append({'case':case,'tag_control_u32':hex(tag),'plain_tag_u32':hex(tag^SUCCESS),
   'raw_type_u16':'0x9777','parser_normalized_type_u16':hex(0x9777^0x365e),'payload_extent_bytes':4,
   'scalar_control_u32':hex(scalar),'plain_scalar_u32':hex(scalar^SUCCESS),
   'plain_record_hex':plain.hex(),'saved_callback':hex(callback)})
 # Isolate the generic extent gate with arbitrary u32 controls, retaining its exact type branch.
 v=setup(e);length=z3.BitVec('QW_gate_extent_control32',32);v.seed('w4',0x3594);v.seed('w2',length);v.seed('w1',SUCCESS-4)
 v.run('query_scalar_gate')
 prove('all_extent_controls_query_scalar_gate_exact_success_or_retirement_frontier',v,
  v.read('x20')!=z3.If(length==SUCCESS-4,resize(0xfffffe000a654e34,64),resize(0xfffffe000a664074,64)))
 # The fixed raw type is an independent format congruence, not a claim of complete parser acceptance.
 v=setup(e)
 prove('raw_type9777_normalizes_to_parser_scalara129',v,resize(0x9777^0x365e,16)!=0xa129)
 profiles=[]
 for case,idx,tag,scalar,callback in QR.REQUESTS:
  v=complete(e,case);ss=byte_stores(v);plain=expected(tag,scalar)
  for residue in range(8):
   base=0x51000000+residue;sub=[(v.new_buffer,resize(base,64))]
   decoded=bytes(z3.simplify(z3.substitute(s['value']^mask(v.new_buffer+j),*sub)).as_long() for j,s in enumerate(ss))
   assert decoded==plain and len(ss)==14
   profiles.append({'case':case,'buffer_mod8':residue,'plain_record_hex':decoded.hex(),'byte_stores':14})
 # Flip one source MOV literal used only for the high type byte; retain the same packet/control flow.
 changed=copy.deepcopy(e);row=next(s for s in changed['spans'] if s['label']=='query_writer_setup');b=bytearray.fromhex(row['bytes_hex'])
 off=0xfffffe000a654b6c-int(row['start'],16);word=int.from_bytes(b[off:off+4],'little');b[off:off+4]=(word^(1<<5)).to_bytes(4,'little');row['bytes_hex']=b.hex()
 v=complete(changed,'first');s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,
  byte_stores(v)[4]['value']!=(0x97^mask(v.new_buffer+4)));assert s.check()==z3.sat
 prior=[]
 for name,labels in [('userclient_query_records_audit.json',[
  'first_constructor_packet_preserves_exact_metadata_control_words','second_constructor_packet_preserves_exact_metadata_control_words',
  'third_constructor_packet_preserves_exact_metadata_control_words','nonnull_data_result_selects_original_protected_writer_input_contract']),
  ('userclient_record_writer_audit.json',['all_tag32_first_four_protected_bytes_and_type_writer_continuation']),
  ('userclient_record_metadata_audit.json',['six_staged_header_bytes_produce_transformed_type_and_retain_tag'])]:
  old=json.loads(read(ROOT/name))
  for label in labels:
   q=next(q for q in old['source_proofs'] if q['label']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
   prior.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/name)})
 selected={int(i['ea'],16) for row in e['spans'] for i in row['instructions']};excluded=set(R.RETAGS.values())
 assert selected-excluded<=visited and not excluded&visited
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,'proved_source_PCs':sorted(map(hex,visited)),
  'rechecked_prior_source_proofs':prior,'record_profiles':profiles,'request_records':records,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(prior),
   'distinct_new_proved_instructions':len(selected-excluded),'distinct_predecessor_proved_instructions':len(visited-selected),
   'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),'excluded_retag_instructions':len(excluded),
   'record_profiles':len(profiles),'profile_byte_stores':14*len(profiles),'profile_base_mod8_cases':8,
   'bank_composition_input_cases':1280,'altered_type_literal_counterexample':True},
  'conditional_query_writer_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
