#!/usr/bin/env python3
"""Instruction-derived kernel allocator boundary obligations.
O(I+query DAG) construction/space; separate SMT search, 30 s/query.
Authenticated returns and native callee effects remain explicit premises.
"""
import copy
import json
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG
from kext_port_tools import ROOT
from lskd_values_symbolic import Lift,resize,mem,cell
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_allocator_boundary as R

DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True

class Model(Lift):
 def __init__(self,e):
  super().__init__(e);self.e=e;self.visited=set();self.edge_checks=[];self.next=None;self.call_return=None;self.calls=[]
  self.sp0,self.desc,self.pointer,self.extent=z3.BitVecs('KA_entry_SP64 KA_descriptor64 KA_pointer64 KA_extent64',64)
  self.flags,self.size=z3.BitVecs('KA_descriptor_flags32 KA_descriptor_size32',32)
  self.initial={j:z3.BitVec('KA_initial_X'+str(j),64) for j in range(31)}
  for j,x in self.initial.items():self.seed('x'+str(j),x)
  self.seed('sp',self.sp0)
 def owned(self):
  return [(self.sp0&15)==0,z3.UGE(self.sp0,0x100),z3.ULE(self.sp0,resize(2**64-1-0x100,64)),
   self.desc!=0,(self.desc&7)==0,z3.ULE(self.desc,resize(2**64-1-64,64)),
   z3.Or(z3.ULE(self.desc+64,self.sp0-0x80),z3.ULE(self.sp0+0x80,self.desc))]
 def enter(self,label):
  # Explicit block-entry cut. Normal linked edges use run(), never enter().
  self.next=None;return self.run(label)
 def condition(self,name):
  return self.equal if name=='eq' else z3.Not(self.equal) if name=='ne' else z3.UGT(self.cmp_left,self.cmp_right) if name=='hi' else z3.UGE(self.cmp_left,self.cmp_right) if name=='hs' else None
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address)
   o=i.operands;m=i.mnemonic
   custom=m in ['adrp','b','bl','cbz','cbnz','b.hi','b.hs','tst','csel','cinc','clz','umaddl','nop','bti','ldp','stp'] or m in ['lsr','lsl'] and o[2].type==ARM64_OP_REG
   if not custom:
    old=self.c;self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};Lift.run(self,'one');self.c=old;continue
   self.count+=1
   if m in ['nop','bti']:continue
   if m=='adrp':self.write(i.reg_name(o[0].reg),resize(o[1].imm,64))
   elif m in ['b','bl']:
    self.next=resize(o[0].imm,64)
    if m=='bl':self.call_return=i.address+4;self.calls.append({'pc':hex(i.address),'target':hex(o[0].imm&(2**64-1))})
   elif m in ['cbz','cbnz']:
    pred=self.read(i.reg_name(o[0].reg))==0
    if m=='cbnz':pred=z3.Not(pred)
    self.next=z3.If(pred,resize(o[1].imm,64),resize(i.address+4,64))
   elif m.startswith('b.'):
    pred=self.condition(m[2:]);assert pred is not None;self.next=z3.If(pred,resize(o[0].imm,64),resize(i.address+4,64))
   elif m=='tst':
    n=self.width(i.reg_name(o[0].reg));self.equal=(self.operand(i,o[0],n)&self.operand(i,o[1],n))==0
   elif m in ['csel','cinc']:
    pred=self.condition(i.op_str.rsplit(',',1)[1].strip());assert pred is not None
    a=self.read(i.reg_name(o[1].reg));b=self.read(i.reg_name(o[2].reg)) if m=='csel' else a
    self.write(i.reg_name(o[0].reg),z3.If(pred,a if m=='csel' else a+1,b))
   elif m=='clz':
    a=self.read(i.reg_name(o[1].reg));n=a.size();v=resize(n,n)
    for j in range(n):v=z3.If(z3.Extract(j,j,a)==1,resize(n-1-j,n),v)
    self.write(i.reg_name(o[0].reg),v)
   elif m=='umaddl':
    self.write(i.reg_name(o[0].reg),z3.ZeroExt(32,self.read(i.reg_name(o[1].reg)))*z3.ZeroExt(32,self.read(i.reg_name(o[2].reg)))+self.read(i.reg_name(o[3].reg)))
   elif m in ['lsl','lsr']:
    n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);s=self.operand(i,o[2],n)&(n-1)
    self.write(i.reg_name(o[0].reg),z3.LShR(a,s) if m=='lsr' else a<<s)
   else:
    a=self.address(i,o[2]);n=self.width(i.reg_name(o[0].reg))//8
    for j in range(2):
     reg=i.reg_name(o[j].reg);at=z3.simplify(a+j*n)
     if m=='ldp':self.write(reg,self.load(at,n))
     else:self.store(at,n,self.read(reg),i.address)
    if i.writeback:
     base=i.reg_name(o[2].mem.base);self.write(base,self.read(base)+(o[3].imm if len(o)==4 else o[2].mem.disp))
  return self
 def returned(self,value):
  assert self.call_return is not None
  self.next=resize(self.call_return,64)
  for j in [*range(19),30]:self.seed('x'+str(j),z3.BitVec('KA_call_'+str(self.count)+'_X'+str(j),64))
  self.seed('x0',value);return self
 def finished(self,name):
  self.edge_checks.append(self.next==R.RETURNS[name]);return self

def descriptor(v,flags=None,size=None):
 mem(v,v.desc,8,0);mem(v,v.desc+0x28,4,v.flags if flags is None else flags)
 mem(v,v.desc+0x2c,4,v.size if size is None else size);v.seed('x0',v.desc);return v

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.edge_checks],bad)));r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2()})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores),'linked_edge_obligations':len(v.edge_checks)})
  visited.update(v.visited);print(label,flush=True)
 def restored(v,regs):return z3.Or(v.read('sp')!=v.sp0,*[v.read('x'+str(j))!=v.initial[j] for j in regs])
 # For the typed adapter, either ordinary lower result is preserved verbatim
 # through the saved-frame loads, not only the zero result.
 for name in ['typed_zone_return','typed_heap_return']:
  v=Model(e).run('typed_prologue');r=z3.BitVec('KA_typed_result64',64);v.seed('x0',r)
  v.enter(name).finished(name)
  prove(name+'_preserves_all_result64_and_restores_frame',v,z3.Or(v.read('x0')!=r,restored(v,[29,30])))
 # Complete selected data request to null-result epilogue, with ordinary call
 # return and PAC-valid envelope assumptions. No post-null accounting executes.
 v=Model(e);v.seed('x0',v.extent);v.run('data_allocate_enter')
 prove('data_request_full_extent64_heap_flags_and_saved_frame',v,z3.Or(v.read('x0')!=0xfffffe0007f8bfb0,
  v.read('x1')!=v.extent,v.read('w2')!=0x31000,v.read('x3')!=0,v.next!=0xfffffe000bcfe5b8,v.read('sp')!=v.sp0-32))
 v.returned(0).run('data_allocate_gate').run('data_allocate_null_return').finished('data_allocate_null_return')
 prove('conditional_null_size_allocator_result_returns_null_data_without_accounting',v,z3.Or(v.read('x0')!=0,restored(v,[19,20,29,30])))
 # Selected generic allocation result cut includes its actual saved frame.
 v=Model(e).run('size_allocate_prologue');zone_pointer,statistics=z3.BitVecs('KA_zone64 KA_stats64',64)
 v.seed('x19',zone_pointer);v.seed('x8',statistics);v.seed('x2',resize(0x31000,64));v.enter('size_zone_request')
 prove('selected_size_allocator_requests_zone_backend_with_statistics_and_flags',v,z3.Or(v.read('x0')!=zone_pointer,
  v.read('x1')!=statistics,v.read('w2')!=0x31000,v.read('x21')!=0x31000,v.next!=0xfffffe000bd75c64))
 v.returned(0).run('size_zone_result_gate').run('size_null_bridge').run('size_return_value').run('size_return_frame').finished('size_return_frame')
 prove('conditional_null_zone_result_survives_size_allocator_bridge_and_epilogue',v,z3.Or(v.read('x0')!=0,restored(v,[19,20,21,22,29,30])))
 # Zone choice is address formation under the selected <=32 B, bit0x100-clear
 # entry cut. Runtime heap/per-thread statistics preparation is not executed.
 v=Model(e);n=z3.BitVec('KA_small_extent64',64);base=z3.BitVec('KA_heap_zone_base16',16);small_flags=z3.BitVec('KA_small_flags32',32)
 v.seed('x1',n);v.seed('w2',small_flags);v.seed('w9',z3.ZeroExt(16,base));v.run('size_select')
 small=[z3.ULE(n,32),(small_flags&0x100)==0]
 prove('small_size14_or32_selects_zone_path_without_rounding',v,z3.Or(v.read('x10')!=n,v.next!=0xfffffe000bcfe678),small)
 v.run('size_zone_class');idx=z3.Extract(15,0,z3.ZeroExt(16,base)+z3.If(z3.UGT(n,16),resize(1,32),resize(0,32)))
 zone=resize(0xfffffe000caeb480,64)+192*z3.ZeroExt(48,idx)
 prove('all_small_size0_to32_zone_address_has_exact_mod16_index',v,z3.Or(v.read('x19')!=zone,v.next!=0xfffffe000bcfe6c0),small)
 for size in [14,32]:
  prove('query_size'+str(size)+'_has_exact_selected_zone_index',v,v.read('x19')!=(resize(0xfffffe000caeb480,64)+192*z3.ZeroExt(48,base if size==14 else base+1)),[n==size,(small_flags&0x100)==0])
 # Arbitrary descriptor bits are processed by both allocation and retirement.
 v=descriptor(Model(e));v.seed('w9',0xd1000);v.seed('w10',4);v.run('typed_heap_request')
 alloc_heap,alloc_size=v.read('x0'),v.read('x1')
 expected=z3.If((v.flags&8)!=0,resize(0xfffffe0007f8bfb0,64),z3.If((v.flags&0x8000)==0,resize(0xfffffe0007f36938,64),resize(0xfffffe0007e6a780,64)))
 prove('all_descriptor_flags_and_size32_typed_heap_allocation_arguments',v,z3.Or(alloc_heap!=expected,alloc_size!=z3.ZeroExt(32,v.size&0xffffff),v.next!=0xfffffe000bcfe5b8))
 v=descriptor(v);v.seed('x1',v.pointer);v.enter('typed_free_adapter').run('typed_free_gate').run('typed_free_heap_tail')
 prove('all_descriptor_flags_and_size32_typed_free_heap_congruence',v,z3.Or(v.read('x0')!=alloc_heap,v.read('x1')!=v.pointer,
  v.read('x2')!=alloc_size,v.next!=0xfffffe000bcfec48))
 prove('query_flags64_size32_typed_free_matches_fallback_allocation',v,z3.Or(v.read('x0')!=0xfffffe0007f36938,v.read('x2')!=32),[v.flags==0x64,v.size==32])
 # The descriptor must be valid even when the value is null: it is read first.
 v=descriptor(Model(e));z=z3.BitVec('KA_nonzero_runtime_zone64',64);mem(v,v.desc,8,z);v.seed('x1',v.pointer)
 v.run('typed_free_adapter').run('typed_free_gate').run('typed_free_zone_tail')
 prove('nonnull_runtime_zone_typed_free_tail_retains_descriptor_and_value',v,z3.Or(v.read('x0')!=v.desc,
  v.read('x1')!=v.pointer,v.next!=0xfffffe000bd7a4b8),[z!=0])
 # Data retirement has a native pointer-null guard before size/accounting work.
 v=Model(e);v.seed('x0',0);v.seed('x1',v.extent);v.run('data_free_enter').run('data_free_null_return').finished('data_free_null_return')
 prove('null_IOFreeData_returns_with_frame_restored_without_lower_call',v,z3.Or(restored(v,[19,20,29,30]),z3.BoolVal(bool(v.calls))))
 v=Model(e);v.seed('x0',v.pointer);v.seed('x1',v.extent);v.run('data_free_enter').run('data_free_request')
 prove('nonnull_IOFreeData_forwards_original_extent64_same_data_heap',v,z3.Or(v.read('x0')!=0xfffffe0007f8bfb0,
  v.read('x1')!=v.pointer,v.read('x2')!=v.extent,v.next!=0xfffffe000bcfec48),[v.pointer!=0])
 # Independently check the lower pointer-null guard and its complete epilogue.
 v=Model(e);v.seed('x1',0);v.run('size_free_enter').run('size_free_null_return').finished('size_free_null_return')
 prove('null_lower_size_free_returns_with_frame_restored_without_backend',v,z3.Or(restored(v,[19,20,21,22,29,30]),z3.BoolVal(bool(v.calls))))
 for size in [14,32]:
  v=Model(e);heap=z3.BitVec('KA_small_free_heap64',64);v.seed('x0',heap);v.seed('x1',v.pointer);v.seed('x2',size)
  v.run('size_free_enter').run('size_free_limit').run('size_free_small_gate').run('size_free_query')
  prove('nonnull_size'+str(size)+'_free_requests_zone_query_with_two_frame_outputs',v,z3.Or(
   v.read('x0')!=v.pointer,v.read('x1')!=v.sp0-64+8,v.read('w2')!=1,v.read('x3')!=v.sp0-64,
   v.read('x20')!=heap,v.read('x21')!=size,cell(v,v.sp0-64,8)!=0,cell(v,v.sp0-64+8,8)!=0,v.next!=0xfffffe000bd792dc),[v.pointer!=0])
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};assert selected==visited,sorted(map(hex,selected-visited))
 # Alter the final MOV X0,X2 to MOV X0,X1; the ordinary null-result theorem
 # must fail for a nonzero original size carried in X1 at this source cut.
 changed=copy.deepcopy(e);row=next(s for s in changed['spans'] if s['label']=='size_return_value');b=bytearray.fromhex(row['bytes_hex'])
 off=4;w=int.from_bytes(b[off:off+4],'little');b[off:off+4]=((w&~(31<<16))|(1<<16)).to_bytes(4,'little');row['bytes_hex']=b.hex()
 v=Model(changed).run('size_allocate_prologue');v.seed('x0',0);v.seed('x1',14);v.seed('x20',14)
 v.enter('size_zone_result_gate').run('size_null_bridge').run('size_return_value')
 s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.edge_checks,v.read('x0')!=0);assert s.check()==z3.sat
 prior=[]
 for name,labels in [('userclient_query_failure_audit.json',[
  'first_conditional_null_data_selects_cleanup_with_saved_error_and_valid_node',
  'first_cleanup_return_preserves_error_pending_cell_and_saved_callback',
  'first_saved_error_fails_internal_success_comparison',
  'typed_null_zone_heap_request_uses_descriptor_size_and_raw_flags',
  'data_allocator_forwards_full_size64_heap_and_raw_flags31000']),
  ('userclient_query_records_audit.json',['shared_node_requests_original_typed_thirty_two_byte_descriptor',
   'nonnull_node_initializes_links_extent_and_requests_fourteen_data_bytes'])]:
  old=json.loads(read(ROOT/name))
  for label in labels:
   q=next(q for q in old['source_proofs'] if q['label']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
   prior.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/name)})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,
  'proved_source_PCs':sorted(map(hex,visited)),'rechecked_prior_source_proofs':prior,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(prior),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'small_query_extents':2,
   'altered_return_register_counterexample':True},
  'conditional_kernel_allocator_boundary_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
