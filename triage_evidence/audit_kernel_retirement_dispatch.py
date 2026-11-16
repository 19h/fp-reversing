#!/usr/bin/env python3
"""Byte-array instruction proofs for small-retirement dispatch.
O(I+query DAG) construction/space; separate SMT search, 30 s/query.
PAC/AUT are conditional identity envelopes, not native authentication proofs.
"""
import copy
import json
import z3
from kext_port_tools import ROOT
from lskd_values_symbolic import resize
from audit_kernel_retirement_query import Model as QueryModel,DEC
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_retirement_dispatch as R

class Model(QueryModel):
 def __init__(self,e):
  e=copy.deepcopy(e);e['reused_caller_spans']=[];super().__init__(e)
  self.bytes=z3.Array('KD_initial_memory',z3.BitVecSort(64),z3.BitVecSort(8));self.initial_bytes=self.bytes
  self.load_cache={};self.load_bindings=[];self.regions=[];self.authentication_envelopes=[]
  self.heap,self.zone,self.element,self.request=z3.BitVecs('KD_heap64 KD_zone64 KD_element64 KD_request64',64)
  for reg,value in [('x0',self.heap),('x1',self.pointer),('x2',self.request),('x3',self.zone),('x4',self.element)]:self.seed(reg,value)
 def owned(self):
  spans=[(self.sp0-0x80,0x100),*self.regions]
  out=[(self.sp0&15)==0,z3.UGE(self.sp0,0x100),z3.ULE(self.sp0,resize(2**64-1-0x100,64))]
  for j,(a,n) in enumerate(spans):
   a=resize(a,64);out.extend([a!=0,z3.ULE(a,resize(2**64-1-n,64))])
   for b,m in spans[j+1:]:
    b=resize(b,64);out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
  return out
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic in ['ubfx','pacibsp','autibsp']:
    if self.next is not None:self.edge_checks.append(self.next==i.address)
    self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
    if i.mnemonic=='ubfx':
     o=i.operands;v=z3.LShR(self.read(i.reg_name(o[1].reg)),o[2].imm)&((1<<o[3].imm)-1);self.write(i.reg_name(o[0].reg),v)
    else:self.authentication_envelopes.append({'pc':hex(i.address),'instruction':i.mnemonic,'assumed_identity_envelope':True})
   else:
    old_e,old_c=self.e,self.c
    self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.e,self.c=old_e,old_c
  return self

def setup(e,heap=None,zone=None):
 v=Model(e)
 if heap is not None:v.heap=resize(heap,64);v.seed('x0',v.heap)
 if zone is not None:v.zone=resize(zone,64);v.seed('x3',v.zone)
 return v

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(c) for c in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));r=s.check();assert r==z3.sat,('vacuous',label,str(r),s.reason_unknown())
  s.add(*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV','query':s.to_smt2()})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores),'linked_edge_obligations':len(v.edge_checks),
   'authentication_envelopes':v.authentication_envelopes});visited.update(v.visited);print(label,flush=True)
 v=setup(e).run('geometry');delta=v.zone-R.BASE;admit=z3.ULT(delta,132480)
 prove('all_zone64_geometry_guard_exact_raw_132480_byte_interval',v,z3.Or(v.read('x19')!=v.zone,v.read('x8')!=delta,
  admit!=z3.And(z3.UGE(v.zone,R.BASE),z3.ULT(v.zone,R.BASE+132480)),
  v.read('sp')!=v.sp0-48,v.next!=z3.If(admit,resize(0xfffffe000bcfedbc,64),resize(0xfffffe000bcfeea8,64))))
 v.run('geometry_error')
 prove('rejected_zone64_calls_geometry_error_with_original_zone',v,z3.Or(v.read('x0')!=v.zone,v.next!=0xfffffe000c6336f8),[z3.Not(admit)])
 idx=z3.BitVec('KD_query_zone_id10',10);zone=resize(R.BASE,64)+192*z3.ZeroExt(54,idx)
 v=setup(e,zone=zone).run('geometry')
 prove('all_query_zone_id10_guard_admits_exact_ids_below_690',v,
  v.next!=z3.If(z3.ULT(idx,690),resize(0xfffffe000bcfedbc,64),resize(0xfffffe000bcfeea8,64)))
 v.regions.append((R.FLAGS,690*4));flag=v.load(resize(R.FLAGS,64)+4*z3.ZeroExt(54,idx),4);before=v.bytes
 v.run('index')
 prove('admitted_query_id10_reciprocal_indexes_exact_u32_flag_and_preserves_inputs',v,z3.Or(v.read('w8')!=flag,
  v.values[(0xfffffe000bcfedd4,'x8')]!=4*z3.ZeroExt(54,idx),
  v.read('x19')!=zone,v.read('x20')!=v.pointer,v.read('x21')!=v.element,v.read('x2')!=v.request,
  v.read('x0')!=v.heap,v.next!=z3.If((v.heap&1)==0,resize(0xfffffe000bcfee20,64),resize(0xfffffe000bcfedf0,64)),v.bytes!=before),[z3.ULT(idx,690)])
 # Heap selection starts at a verified index-block output cut. W8 is the
 # original flag word; X9 is the data heap; X19/20/21 carry zone/base/extent.
 def heap_cut(heap=None):
  v=setup(e,heap=heap);v.flag=z3.BitVec('KD_zone_flag32',32)
  for reg,value in [('w8',v.flag),('x9',R.DATA),('x19',v.zone),('x20',v.pointer),('x21',v.element)]:v.seed(reg,value)
  return v
 v=heap_cut();v.regions=[(v.heap,32)];stats=v.load(v.heap,8);before=v.bytes;v.enter('heap_stats')
 prove('normal_untagged_heap_loads_accounting_without_changing_heap_flags_or_element',v,z3.Or(v.read('x22')!=stats,
  v.read('x0')!=v.heap,v.read('w8')!=v.flag,v.read('x9')!=R.DATA,v.read('x19')!=v.zone,v.read('x20')!=v.pointer,v.read('x21')!=v.element,
  v.next!=0xfffffe000bcfee24,v.bytes!=before),[(v.heap&1)==0])
 for has_stats in [False,True]:
  v=heap_cut();view=v.heap&resize(2**64-2,64);v.regions=[(view,80),(R.DATA,32),(R.TYPED,32),(R.VARIABLE,32)]
  flags=v.load(view+0x48,4);own=v.load(view+8,8)
  selected=z3.If((flags&8)!=0,resize(R.DATA,64),z3.If((flags&0x8000)!=0,resize(R.VARIABLE,64),resize(R.TYPED,64)))
  fallback=v.load(selected,8);before=v.bytes;v.enter('tagged')
  pred=[(v.heap&1)!=0,own!=0 if has_stats else own==0]
  prove('tagged_all_flags_'+('view_accounting' if has_stats else 'heap_fallback')+'_selects_exact_heap_and_accounting',v,z3.Or(
   v.read('x0')!=selected,v.read('x22')!=own,v.read('w8')!=v.flag,v.read('x9')!=R.DATA,v.read('x2')!=v.request,
   v.read('x19')!=v.zone,v.read('x20')!=v.pointer,v.read('x21')!=v.element,v.bytes!=before,
   v.next!=(0xfffffe000bcfee24 if has_stats else 0xfffffe000bcfee20)),pred)
  if not has_stats:
   v.run('heap_stats');prove('tagged_zero_view_accounting_loads_selected_heap_accounting',v,
    z3.Or(v.read('x22')!=fallback,v.read('x0')!=selected,v.bytes!=before,v.next!=0xfffffe000bcfee24),pred)
 # This local classification certificate permits every u32 flag word and
 # u8 heap class. It does not assign native initialized values to either.
 def class_cut(heap=None):
  v=heap_cut(heap);v.regions=[(v.heap,32)];v.heap_class=v.load(v.heap+16,1);v.zone_class=z3.Extract(10,8,v.flag)
  v.enter('class_data');return v
 for name,heap in [('data',R.DATA),('second_special',R.SPECIAL),('ordinary',None)]:
  v=class_cut(heap);prem=[]
  if name!='data':
   if heap is None:prem=[(v.heap&1)==0,v.heap!=R.DATA,v.heap!=R.SPECIAL]
   v.run('class_second')
  v.run('class_ordinary' if name=='ordinary' else 'class_strict')
  allowed=z3.Or(v.zone_class==1,z3.ZeroExt(5,v.zone_class)==v.heap_class) if name=='ordinary' else z3.ZeroExt(5,v.zone_class)==v.heap_class
  prove(name+'_all_flag32_heapclass8_has_exact_admission_predicate',v,z3.Or(
   v.next!=z3.If(allowed,resize(0xfffffe000bcfee64,64),resize(0xfffffe000bcfee50,64)),
   v.read('x0')!=v.heap,v.read('x19')!=v.zone,v.read('x20')!=v.pointer,v.read('x21')!=v.element,
   v.read('x22')!=v.initial[22],v.read('x2')!=v.request),prem)
  # The rejection is a call boundary. No return or fatality is assumed.
  v.run('mismatch');prove(name+'_class_rejection_calls_error_with_heap_base_request_zone',v,z3.Or(
   v.next!=0xfffffe000c62d430,v.read('x0')!=v.heap,v.read('x1')!=v.pointer,
   v.read('x2')!=v.request,v.read('x3')!=v.zone),[*prem,z3.Not(allowed)])
 # Full linked normal paths include the real saved frame and source class
 # guards. The bzero call is an external boundary, never executed here.
 for name,heap,n in [('data14',R.DATA,14),('typed32',R.TYPED,32)]:
  v=setup(e,heap,zone);v.regions=[(R.FLAGS,690*4),(heap,32),(zone,64)]
  flag=v.load(resize(R.FLAGS,64)+4*z3.ZeroExt(54,idx),4);hc=v.load(resize(heap,64)+16,1);zc=z3.Extract(10,8,flag)
  stats=v.load(resize(heap,64),8);zone_stats=v.load(zone+8,8)
  v.seed('x2',n);v.request=resize(n,64)
  v.run('geometry').run('index').run('heap_stats').run('class_data')
  if name=='typed32':v.run('class_second').run('class_ordinary');allowed=z3.Or(zc==1,z3.ZeroExt(5,zc)==hc)
  else:v.run('class_strict');allowed=z3.ZeroExt(5,zc)==hc
  prem=[z3.ULT(idx,690),allowed];v.run('clear')
  prove(name+'_linked_guards_call_bzero_with_base_and_element_extent',v,z3.Or(v.next!=0xfffffe000c6480c0,
   v.read('x0')!=v.pointer,v.read('x1')!=v.element,v.read('x19')!=zone,v.read('x20')!=v.pointer,
   v.read('x21')!=v.element,v.read('x22')!=stats,v.read('sp')!=v.sp0-48),prem)
  # Ordinary ABI return may clobber every volatile GPR. Memory is a fresh
  # post-call array constrained only at the saved frame and optional zone
  # accounting field, so no no-op bzero memory model is silently assumed.
  frozen=copy.deepcopy(v)
  for have_stats in [False,True]:
   v=copy.deepcopy(frozen);saved=[(v.sp0-48+j,1,v.load(v.sp0-48+j,1)) for j in range(48)]
   v.bytes=z3.Array('KD_post_clear_memory_'+name+'_'+str(int(have_stats)),z3.BitVecSort(64),z3.BitVecSort(8))
   for address,width,value in saved:v.setmem(address,width,value)
   v.setmem(zone+8,8,zone_stats)
   v.returned(z3.BitVec('KD_arbitrary_clear_return64',64)).run('postclear')
   if not have_stats:v.run('zone_stats')
   v.run('handoff')
   prove(name+'_postclear_'+('heap_accounting' if have_stats else 'zone_fallback')+'_tail_args_frame_and_nonvolatile_restore',v,z3.Or(
    v.next!=0xfffffe000bd74fcc,v.read('x0')!=zone,v.read('x1')!=(stats if have_stats else zone_stats),
    v.read('x2')!=v.pointer,v.read('x3')!=v.element,v.read('sp')!=v.sp0,
    *[v.read('x'+str(j))!=v.initial[j] for j in [19,20,21,22,29,30]]),[*prem,stats!=0 if have_stats else stats==0])
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};assert visited==selected,sorted(map(hex,selected-visited))
 # A source mutation changing the ordinary fallback class from 1 to 2
 # must falsify the actual classification result for a concrete mismatch.
 changed=copy.deepcopy(e);row=next(s for s in changed['spans'] if s['label']=='class_ordinary')
 raw=bytearray.fromhex(row['bytes_hex']);word=int.from_bytes(raw[:4],'little');assert (word>>10)&0xfff==1
 raw[:4]=((word&~(0xfff<<10))|(2<<10)).to_bytes(4,'little');row['bytes_hex']=raw.hex()
 v=setup(changed,R.TYPED);v.seed('w8',1);v.seed('w10',0);v.enter('class_ordinary')
 s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.edge_checks,v.next!=0xfffffe000bcfee64);assert s.check()==z3.sat
 negative={'altered_ordinary_fallback_class_counterexample':True,'original_class':1,'altered_class':2,
  'zone_class':1,'heap_class':0,'result':'sat','query':s.to_smt2()}
 prior=[]
 old=json.loads(read(ROOT/'kernel_retirement_query_audit.json'))
 for label in ['caller14_admitted_u16_offset_uses_regular_base_and_original_extent','caller32_admitted_u16_offset_uses_regular_base_and_original_extent']:
  q=next(q for q in old['source_proofs'] if q['label']==label);s=z3.SolverFor(q['logic']);s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
  prior.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/'kernel_retirement_query_audit.json')})
 old=json.loads(read(ROOT/'mixed_data_retirement_checks.json'))
 for label in ['scalar_clear_partitions_extent_into_words_and_tail','large_clear_initial_and_tail_are_contained_and_join_aligned_region','large_clear_middle_iteration_stays_inside_extent']:
  q=next(q for q in old['proofs'] if q['name']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
  prior.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/'mixed_data_retirement_checks.json')})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,
  'proved_source_PCs':sorted(map(hex,visited)),'rechecked_prior_source_proofs':prior,'negative_control':negative,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(prior),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'normal_request_contexts':2,
   'altered_ordinary_fallback_class_counterexample':True},
  'conditional_kernel_retirement_dispatch_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
