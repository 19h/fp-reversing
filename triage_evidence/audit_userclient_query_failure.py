#!/usr/bin/env python3
"""Prove selected constructor failure and allocator forwarding obligations.
O(I+256R+query DAG) construction/space; SMT search separate, 30 s/query.
"""
import copy
import json
import z3
from kext_port_tools import ROOT,TABLE,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize
from audit_userclient_record_metadata import Model as MetadataModel
from audit_userclient_input_reader import DEC,TOKEN,PHASE,SUCCESS
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_query_records as QR
import recover_userclient_query_failure as R

ERROR=0xce515bb2

class Model(QR.Model):
 def load(self,a,n):
  for name,(lp,rp,pp) in R.BANK_PCS.items():
   r=next(r for r in self.failure_receipt['bank_rules'] if r['name']==name);l,rr=int(r['left'],16),int(r['right'],16)
   if self.pc==lp:
    assert n==1;self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('QF_bank_'+name,8)
    self.address_checks.append(a==l+z3.ZeroExt(56,self.bank_input));return self.bank_byte
   if self.pc==rp:
    assert n==1;self.address_checks.append(a==rr+z3.ZeroExt(56,self.bank_byte^int(r['key'],16)))
    self.bank_rewrites.append({'pc':hex(self.pc),'rule':name,'inputs':256});return self.bank_input^int(r['constant'],16)
   if self.pc==pp:
    assert n==8;self.address_checks.append(a==int(r['slot'],16));return resize(int(r['original_pointer']['target'],16),64)
  if self.pc in R.BRANCHES:
   assert n==8;js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  return super().load(a,n)
 def run(self,label,end=None):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if end is not None and i.address>=end:break
   if i.mnemonic=='csel' and i.op_str.endswith(', eq'):
    self.pc=i.address;self.visited.add(i.address);self.count+=1;o=i.operands
    self.write(i.reg_name(o[0].reg),z3.If(self.equal,self.read(i.reg_name(o[1].reg)),self.read(i.reg_name(o[2].reg))))
   else:
    oe,oc=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    MetadataModel.run(self,'one');self.e,self.c=oe,oc
  return self

def setup(e):
 prior=json.loads(read(ROOT/'userclient_query_records_checks.json'));combined=copy.deepcopy(prior);combined['spans']+=e['spans']
 v=QR.setup(combined);v.__class__=Model;v.failure_receipt=e
 return v

def allocation(e,case='first'):
 v=setup(e).run('failure_status_producer')
 if case=='first':
  v.run('query_version').returned();mem(v,v.src+0x96c,4,0x4c0b0000)
  v.run('query_capabilities').returned();mem(v,v.src+0x96c,4,0x1f8)
 else:v.seed('w22',0x42 if case=='second' else 0x68)
 return v.run('request_'+case).run('shared_entry').run('shared_prepare').run('node_request_record').run('extent_gate').run('node_allocate')

def data_result(e,case='first',value=0):
 v=allocation(e,case).returned();v.seed('x0',v.new_node);v.run('node_result');v.with_node=True
 return v.run('node_initialize').returned(value).run('data_result')

def cleanup(e,buffer_present=False):
 v=data_result(e,value=0)
 if buffer_present:
  v.with_buffer=True;mem(v,v.new_node+0x18,8,v.new_buffer)
 v.seed('w23',v.status)
 return v.run('cleanup_gate')

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 for r in e['bank_rules']:
  l,rr=(bytes.fromhex(e['banks'][r[n+'_name']]['bytes_hex']) for n in ['left','right'])
  assert all(j^rr[l[j]^int(r['key'],16)]==int(r['constant'],16) for j in range(256))
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'certified_bank_rewrites':copy.deepcopy(v.bank_rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)})
  visited.update(v.visited);print(label,flush=True)
 v=setup(e).run('failure_status_producer')
 prove('original_saved_allocation_error_is_ce515bb2',v,z3.Or(cell(v,v.sp+0x9ec,4)!=ERROR,v.read('w23')!=ERROR))
 for case,idx,tag,scalar,callback in QR.REQUESTS:
  v=data_result(e,case)
  prove(case+'_conditional_null_data_selects_cleanup_with_saved_error_and_valid_node',v,z3.Or(
   v.read('w23')!=ERROR,v.read('x22')!=v.new_node,v.read('x8')!=0xfffffe000a664074,
   cell(v,v.new_node+0x18,8)!=0,cell(v,v.new_node+0x10,4)!=14,cell(v,v.ctx+0x58,8)!=v.new_node,
   cell(v,v.ctx+0x5a8,8)!=callback,v.read('w27')!=0x37))
  v.run('cleanup_gate')
  prove(case+'_null_data_skips_data_free_and_selects_typed_cleanup',v,z3.Or(v.read('x0')!=0,
   v.read('w19')!=0x63d,v.read('x8')!=0xfffffe000a66414c))
  v.run('cleanup_node_request')
  prove(case+'_requests_original_typed_cleanup_descriptor_and_pending_node',v,z3.Or(
   v.read('x0')!=0xfffffe000847bfa0,v.read('x1')!=v.new_node,v.read('x10')!=0xfffffe000c4ba368,v.read('x17')!=0x4d6a))
  v.returned().run('cleanup_node_return').run('constructor_return').run('request_return')
  prove(case+'_cleanup_return_preserves_error_pending_cell_and_saved_callback',v,z3.Or(
   v.read('w23')!=ERROR,v.read('x8')!=callback,cell(v,v.ctx+0x58,8)!=v.new_node,v.read('w3')!=TOKEN,v.read('w10')!=TOKEN))
  v.run('callback_'+case)
  target=0xfffffe000a65f358 if case!='third' else 0xfffffe000a656f00
  prove(case+'_saved_error_fails_internal_success_comparison',v,z3.Or(v.cmp_right!=SUCCESS,v.read('x8')!=target))
 # Generic cleanup request cut: a valid initialized pending node and optional data.
 # This does not establish which additional whole-command outcomes take this edge.
 for has_buffer in [False,True]:
  v=cleanup(e,has_buffer);suffix='nonnull_data' if has_buffer else 'null_data'
  prove(suffix+'_cleanup_preserves_arbitrary_status_and_exact_branch',v,z3.Or(v.read('w23')!=v.status,
   v.read('x8')!=(0xfffffe000a6640c4 if has_buffer else 0xfffffe000a66414c)))
  if has_buffer:
   v.run('cleanup_data_request')
   prove('nonnull_data_cleanup_requests_original_IOFreeData_extent14',v,z3.Or(v.read('x0')!=v.new_buffer,
    v.read('x1')!=14,v.read('x8')!=0xfffffe000c4ba84c,v.read('x17')!=0x85d))
   v.returned().run('cleanup_data_return')
   prove('data_cleanup_return_clears_buffer_and_selects_typed_cleanup',v,z3.Or(cell(v,v.new_node+0x18,8)!=0,
    v.read('x8')!=0xfffffe000a66414c,v.read('w19')!=0x63d))
  v.run('cleanup_node_request').returned().run('cleanup_node_return').run('constructor_return').run('request_return')
  prove(suffix+'_cleanup_custody_retains_raw_status_and_pending_cell',v,z3.Or(v.read('w23')!=v.status,
   cell(v,v.ctx+0x58,8)!=v.new_node,v.read('x8')!=QR.FIRST))
 # The node-null edge is only a precondition boundary. Do not perform its first
 # node load, emulate a fault, or assert any native allocation failure exists.
 v=allocation(e).returned(0).run('node_result').run('node_failure').run('cleanup_gate',end=0xfffffe000a664098)
 ins=next(DEC.disasm(bytes.fromhex(next(s for s in e['spans'] if s['label']=='cleanup_gate')['bytes_hex'])[32:36],0xfffffe000a664098))
 assert ins.mnemonic=='ldr' and ins.op_str=='x0, [x22, #0x18]'
 prove('null_node_cut_does_not_establish_valid_pending_node_storage',v,z3.Or(v.read('x22')!=0,
  v.address(ins,ins.operands[1])!=0x18,v.read('w23')!=ERROR,cell(v,v.ctx+0x58,8)!=0))
 # Lower allocation ABI: source blocks, with runtime zone/statistics selection
 # explicitly cut at the omitted native per-thread state and branch instructions.
 v=setup(e);v.seed('x0',v.ctx);mem(v,v.ctx+0x28,4,0x64);v.run('typed_adapter_flags')
 prove('descriptor64_adapter_selects_raw_flags8004',v,v.read('w1')!=0x8004)
 zone=z3.BitVec('QF_runtime_zone64',64);mem(v,v.ctx,8,zone);v.run('typed_lower_prefix')
 prove('lower_typed_allocator_strips_adapter_high_flags',v,z3.Or(v.read('w10')!=4,v.read('w9')!=0xd1000,v.read('x8')!=zone))
 stats=z3.BitVec('QF_runtime_statistics64',64);mem(v,v.ctx+8,8,stats);v.run('typed_statistics_load')
 d=copy.deepcopy(v);d.run('typed_zone_active')
 prove('runtime_active_zone_request_forwards_d1004',d,z3.Or(d.read('x0')!=zone,d.read('x1')!=stats,d.read('w2')!=0xd1004),[zone!=0])
 d=copy.deepcopy(v);alternate=z3.BitVec('QF_alternate_zone64',64);mem(d,d.ctx+0x30,8,alternate);d.run('typed_zone_empty')
 prove('runtime_empty_statistics_request_forwards_d1044',d,z3.Or(d.read('x0')!=alternate,d.read('x1')!=stats,d.read('w2')!=0xd1044),[zone!=0])
 mem(v,v.ctx+0x2c,4,32);v.run('typed_heap_request')
 prove('typed_null_zone_heap_request_uses_descriptor_size_and_raw_flags',v,z3.Or(v.read('x0')!=0xfffffe0007f36938,
  v.read('x1')!=32,v.read('w2')!=0xd1004,v.read('x3')!=0),[zone==0])
 # Verify the mask over every incoming u32, independently of the adapter literal.
 v=setup(e);v.seed('x0',v.ctx);flags=z3.BitVec('QF_arbitrary_input_flags32',32);v.seed('w1',flags);mem(v,v.ctx,8,zone);v.run('typed_lower_prefix')
 prove('all_incoming_flags32_lower_prefix_retains_only_three_bits',v,v.read('w10')!=(flags&7))
 v=setup(e);size=z3.BitVec('QF_data_requested_size64',64);v.seed('x19',size);v.run('data_heap_request')
 prove('data_allocator_forwards_full_size64_heap_and_raw_flags31000',v,z3.Or(v.read('x0')!=0xfffffe0007f8bfb0,
  v.read('x1')!=size,v.read('w2')!=0x31000,v.read('x3')!=0))
 selected={int(i['ea'],16) for row in e['spans'] for i in row['instructions']};assert selected<=visited,sorted(map(hex,selected-visited))
 # Independent negative control: altering the status literal must change the
 # recovered saved status, with all model and storage assumptions unchanged.
 changed=copy.deepcopy(e);row=next(s for s in changed['spans'] if s['label']=='failure_status_producer');b=bytearray.fromhex(row['bytes_hex'])
 b[:4]=(int.from_bytes(b[:4],'little')^(1<<5)).to_bytes(4,'little');row['bytes_hex']=b.hex();v=setup(changed).run('failure_status_producer')
 s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),cell(v,v.sp+0x9ec,4)!=ERROR);assert s.check()==z3.sat
 prior=[]
 old=json.loads(read(ROOT/'userclient_query_records_audit.json'))
 for label in ['shared_node_requests_original_typed_thirty_two_byte_descriptor',
  'nonnull_node_initializes_links_extent_and_requests_fourteen_data_bytes',
  'first_callback_uses_same_success_constant_and_exact_status_split',
  'second_callback_uses_same_success_constant_and_exact_status_split','third_callback_uses_same_success_constant_and_exact_status_split']:
  q=next(q for q in old['source_proofs'] if q['label']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
  prior.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_query_records_audit.json')})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,'proved_source_PCs':sorted(map(hex,visited)),
  'rechecked_prior_source_proofs':prior,'independent_totals':{'new_source_queries_unsat':len(qs),
   'prior_source_queries_unsat':len(prior),'distinct_new_proved_instructions':len(selected),
   'distinct_predecessor_proved_instructions':len(visited-selected),'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'bank_composition_input_cases':768,'saved_request_callback_cases':3,'altered_status_literal_counterexample':True},
  'conditional_query_failure_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
