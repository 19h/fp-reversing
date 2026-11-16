#!/usr/bin/env python3
"""Whole-helper finite abstract CFG certificate, local SMT and CPU components.
CFG O(V+E) times 18 abstract states; O(V) witness storage. Local formula DAG
and source/RAM replay costs are separate; source SMT is bounded by 60 s/query,
with 30 s/query for separation, composition and predecessor checks.
"""
import copy,json
from collections import deque
import z3
from capstone.arm64 import ARM64_EXT_UXTB
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import resize
from audit_kernel_zone_retirement import Model as Parent,DEC
import recover_kernel_retirement_magazines as R
import probe_kernel_retirement_magazines as CPU

def cfg(e,removed=None):
 raw=bytearray.fromhex(e['function']['bytes'])
 if removed is not None:raw[removed-R.HELPER:removed-R.HELPER+4]=bytes.fromhex('1f2003d5')
 instructions=list(DEC.disasm(raw,R.HELPER));by={i.address:i for i in instructions}
 graph={};calls=[];x19_writes=[]
 for i in instructions:
  m=i.mnemonic;o=i.operands
  if m=='retab':edges=[]
  elif m=='b':edges=[o[0].imm&(2**64-1)]
  elif m.startswith('b.'):edges=[o[0].imm&(2**64-1),i.address+4]
  elif m in ['cbz','cbnz','tbz','tbnz']:edges=[o[-1].imm&(2**64-1),i.address+4]
  else:edges=[i.address+4]
  graph[i.address]=edges
  if m=='bl':calls.append(i.address)
  if any(i.reg_name(j) in ['x19','w19'] for j in i.regs_access()[1]):x19_writes.append(i.address)
 assert x19_writes==[0xfffffe000bd7519c,0xfffffe000bd75588,0xfffffe000bd7559c,0xfffffe000bd756a4]
 # C denotes the incoming cache, U an unknown value and Z exact zero.
 # reset records an explicit source store, not external RAM noninterference.
 start=(R.HELPER,'U','U',False);queue=deque([start]);pred={start:None};returns=[];outside=[];bad=[]
 while queue:
  state=queue.popleft();pc,r19,r0,reset=state;i=by[pc];m=i.mnemonic;o=i.operands
  if pc==0xfffffe000bd7519c:r19='C'
  elif pc in [0xfffffe000bd7559c,0xfffffe000bd756a4]:r19='Z'
  elif pc==0xfffffe000bd75588:r19='U'
  if pc in [0xfffffe000bd753d8,0xfffffe000bd754c0] and m=='strh':
   assert i.op_str=='wzr, [x19, #6]';reset=True
  if m=='bl':r0='U'
  elif pc==0xfffffe000bd75580:r0=r19
  elif any(i.reg_name(j) in ['x0','w0'] for j in i.regs_access()[1]):r0='U'
  if m=='retab':
   returns.append({'pc':hex(pc),'X0_class':r0,'source_reset_seen':reset})
   if r0 not in ['C','Z'] or r0=='C' and not reset:
    path=[];p=state
    while p is not None:path.append(hex(p[0]));p=pred[p]
    bad.append(list(reversed(path)))
  for nxt in graph[pc]:
   if nxt not in by:
    outside.append({'from':hex(pc),'to':hex(nxt),'kind':'compiler_interval_fallthrough_after_error_call'});continue
   child=(nxt,r19,r0,reset)
   if child not in pred:pred[child]=state;queue.append(child)
 reachable={s[0] for s in pred}
 return {'source_nodes':len(by),'source_edges':sum(len(x) for x in graph.values()),'reachable_source_nodes':len(reachable),
  'abstract_states':len(pred),'ordinary_ABI_call_sites':len(calls),'x19_write_sites':list(map(hex,x19_writes)),
  'return_states':returns,'external_interval_edges':outside,'violating_paths':bad,
  'all_normal_returns_C_or_zero_with_source_reset_for_C':not bad,
  'all_source_nodes_reachable_in_branch_overapproximation':reachable==by.keys(),
  'meaning':'May-branch CFG overapproximation, ordinary nonvolatile-call ABI; reset means a source zero store was visited. Callee RAM effects, path feasibility and termination are not inferred.'}

class Model(Parent):
 def __init__(self,e):
  super().__init__(e);self.bytes=z3.Array('RM_local_memory',z3.BitVecSort(64),z3.BitVecSort(8))
  self.load_cache={};self.load_bindings=[];self.separation_rewrites={}
 def byte_owner(self,address):
  for index,(base,length) in enumerate([(self.sp0-0x80,0x100),*self.regions]):
   offset=z3.simplify(address-resize(base,64))
   if z3.is_bv_value(offset) and offset.as_long()<length:
    return {'owner_index':index,'base':resize(base,64).sexpr(),'extent_bytes':length,'byte_offset':offset.as_long()}
  return None
 def load(self,address,n):
  address=z3.simplify(resize(address,64))
  def select(array,at):
   if not z3.is_store(array):return z3.Select(array,at)
   stored=z3.simplify(array.arg(1));equal=z3.simplify(at==stored)
   if z3.is_true(equal):return array.arg(2)
   if z3.is_false(equal):return select(array.arg(0),at)
   left,right=self.byte_owner(at),self.byte_owner(stored)
   if left and right and left['owner_index']!=right['owner_index']:
    key=(at.sexpr(),stored.sexpr())
    self.separation_rewrites[key]={'load_byte_address':key[0],'store_byte_address':key[1],
     'read_region':left,'write_region':right,'rule':'disjoint_nonwrapping_regions_then_read_over_distinct_store'}
    return select(array.arg(0),at)
   return z3.If(equal,array.arg(2),select(array.arg(0),at))
  cells=[select(self.bytes,z3.simplify(address+j)) for j in reversed(range(n))]
  value=z3.simplify(z3.Concat(*cells) if n>1 else cells[0],blast_select_store=True)
  if '(select ' not in value.sexpr():return value
  key=value.sexpr()
  if key not in self.load_cache:
   fresh=z3.BitVec('RM_read_'+str(len(self.load_cache))+'_'+str(n*8),n*8)
   self.load_cache[key]=fresh;self.load_bindings.append(fresh==value)
  return self.load_cache[key]
 def operand(self,i,o,n):
  if o.ext==ARM64_EXT_UXTB:
   assert not o.shift.type;return resize(self.read(i.reg_name(o.reg))&0xff,n)
  return super().operand(i,o,n)
 def condition(self,n):
  if n=='ge':return self.cmp_left>=self.cmp_right
  return super().condition(n)
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   m=i.mnemonic;o=i.operands
   if m not in ['ldadda','ldapr','stlurb','cas'] and not (m=='str' and i.writeback):
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
   if m=='ldadda':
    at=self.address(i,o[2]);n=self.width(i.reg_name(o[0].reg))//8;old=self.load(at,n);add=self.read(i.reg_name(o[0].reg))
    self.store(at,n,old+add,i.address);self.write(i.reg_name(o[1].reg),old)
   elif m=='ldapr':self.write(i.reg_name(o[0].reg),self.load(self.address(i,o[1]),8))
   elif m=='stlurb':self.store(self.address(i,o[1]),1,self.read(i.reg_name(o[0].reg)),i.address)
   elif m=='cas':
    at=self.address(i,o[2]);old=self.load(at,8);expected=self.read(i.reg_name(o[0].reg));new=self.read(i.reg_name(o[1].reg))
    self.store(at,8,z3.If(old==expected,new,old),i.address);self.write(i.reg_name(o[0].reg),old)
   else:
    at=self.address(i,o[1]);self.store(at,8,self.read(i.reg_name(o[0].reg)),i.address);self.write(i.reg_name(o[1].mem.base),at)
  return self

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();graph=cfg(e)
 assert graph['all_normal_returns_C_or_zero_with_source_reset_for_C'] and graph['all_source_nodes_reachable_in_branch_overapproximation']
 negative=[]
 for pc in [0xfffffe000bd753d8,0xfffffe000bd754c0]:
  changed=cfg(e,pc);assert not changed['all_normal_returns_C_or_zero_with_source_reset_for_C'] and changed['violating_paths']
  negative.append({'source_store_replaced_with_NOP':hex(pc),'graph_invariant_rejected':True,'abstract_counterpath':changed['violating_paths'][0],'native_feasibility_claimed':False})
 proofs=[];coverage=[];separation=[];instantiations=[]
 a,b,n,m,i,j=z3.Ints('RM_region_a RM_region_b RM_extent_n RM_extent_m RM_byte_i RM_byte_j')
 s=z3.Solver();s.set(timeout=30000)
 s.add(a>=0,b>=0,n>0,m>0,a+n<2**64,b+m<2**64,i>=0,i<n,j>=0,j<m,
  z3.Or(a+n<=b,b+m<=a),(a+i)%(2**64)==(b+j)%(2**64));assert s.check()==z3.unsat
 separation.append({'label':'any_disjoint_nonwrapping_u64_regions_have_distinct_byte_addresses',
  'result':'unsat','logic':'QF_LIA','query':s.to_smt2()})
 x,y=z3.BitVecs('RM_array_byte_write64 RM_array_byte_read64',64);byte=z3.BitVec('RM_array_value8',8)
 memory=z3.Array('RM_array_before',z3.BitVecSort(64),z3.BitVecSort(8));s=z3.SolverFor('QF_AUFBV')
 s.add(x!=y,z3.Select(z3.Store(memory,x,byte),y)!=z3.Select(memory,y));assert s.check()==z3.unsat
 separation.append({'label':'read_over_distinct_byte_store_preserves_previous_read','result':'unsat','logic':'QF_AUFBV','query':s.to_smt2()})
 def prove(label,v,bad,premises=()):
  facts=getattr(v,'separation_facts',[])
  if facts:
   # Instantiate the generic integer/modulo-address lemma in the exact
   # u64 regions already required by owned(). Each offset/extent and
   # distinct owner pair was mechanically checked by disjoint(). This
   # avoids solving the same interval theorem again for byte aliases.
   instantiations.append({'label':label,'checked_region_windows':v.separation_windows,
    'byte_disequalities':len(facts),'generic_lemma':separation[0]['label'],
    'nonwrapping_u64_to_integer_modulo_interpretation':True})
  domain=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=60000);s.add(*domain,*v.bindings_for(domain));assert s.check()==z3.sat,('vacuous',label)
  # Loads retain one byte-array state and use checked region instances
  # of the two generic lemmas above. Keep the full storage domain that
  # justifies every such read-over-store rewrite.
  common=[*domain,*facts]
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=60000);s.add(*common,*v.bindings_for([*common,counter]),counter)
  r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  proofs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV',
   'source_domain':'owned storage and checked byte-array separation rewrites','query':s.to_smt2()})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks),
   'checked_read_store_rewrites':list(v.separation_rewrites.values())})
  print(label,flush=True)
 def disjoint(v,a,n,others):
  def region(address,extent):
   for index,(base,length) in enumerate(v.regions):
    offset=z3.simplify(resize(address,64)-resize(base,64))
    if z3.is_bv_value(offset) and offset.as_long()+extent<=length:
     return {'owner_region_index':index,'owner_base':resize(base,64).sexpr(),'owner_extent_bytes':length,
      'byte_offset':offset.as_long(),'window_extent_bytes':extent}
   raise AssertionError(('unowned separation window',address,extent))
  left=region(a,n);pairs=[]
  for b,m in others:
   right=region(b,m);assert left['owner_region_index']!=right['owner_region_index'];pairs.append({'left':left,'right':right})
  v.separation_windows=getattr(v,'separation_windows',[])+pairs
  v.separation_facts=getattr(v,'separation_facts',[])+[a+i!=b+j for i in range(n) for b,m in others for j in range(m)]
 def local():
  v=Model(e);v.cache=z3.BitVec('RM_cache64',64);v.regions.extend([(v.cache,64),(v.zone,192)])
  v.seed('x19',v.cache);v.seed('x20',v.zone);return v
 v=local();v.seed('x0',v.zone);quota=v.load(v.zone+0x7c,2);v.enter('quota')
 prove('entry_quota_exact_u16_zero_gate',v,z3.Or(v.read('w23')!=z3.ZeroExt(16,quota),v.next!=z3.If(quota==0,resize(0xfffffe000bd75434,64),resize(0xfffffe000bd751ac,64))))
 v=local();v.seed('x21',v.zone+0x60);word=v.load(v.zone+0x60,4);v.enter('ticket')
 owner_equal=z3.Extract(23,16,word)==z3.Extract(31,24,word)
 prove('ticket_atomic_add_uses_old_owner_bytes_and_modular_new_word',v,z3.Or(v.load(v.zone+0x60,4)!=word+0x1000000,
  v.next!=z3.If(owner_equal,resize(0xfffffe000bd751dc,64),resize(0xfffffe000bd7563c,64))))
 v=local();q=z3.BitVec('RM_quota16',16);full=z3.BitVec('RM_full32',32);clock=z3.BitVec('RM_clock64',64)
 v.seed('w23',q);v.seed('w9',full);v.seed('x22',clock);v.enter('retain');keep=z3.If(clock==0,z3.LShR(z3.ZeroExt(16,q),1),resize(0,32))
 prove('spill_retains_half_quota_only_without_marker_object',v,z3.Or(v.read('w12')!=keep,v.read('w9')!=full-keep))
 v=local();first,clock=z3.BitVecs('RM_first_full64 RM_marker_object64',64);v.regions.extend([(first,16),(clock,16)])
 stamp=v.load(first+8,8);epoch=v.load(clock,8);v.seed('x10',first);v.seed('x22',clock);v.enter('marker')
 prove('marker_predicate_is_signed_modular_difference_not_unsigned_order',v,v.next!=z3.If(stamp-epoch>=resize(1,64),resize(0xfffffe000bd756c8,64),resize(0xfffffe000bd752a8,64)))
 v=local();q=z3.BitVec('RM_transfer_quota16',16);full=v.load(v.cache+0x18,4);empty=v.load(v.zone+0x4c,4)
 v.seed('w23',q);v.enter('empty_bound');room=z3.ZeroExt(16,q)-full;take=z3.If(z3.ULT(room,empty),room,empty)
 prove('shared_empty_transfer_exact_raw_u32_minimum_and_zero_gate',v,z3.Or(v.read('w8')!=take,v.next!=z3.If(take==0,resize(0xfffffe000bd75398,64),resize(0xfffffe000bd7532c,64))))
 for name,owner in [('shared_unlock','zone'),('cache_unlock','cache')]:
  v=local();at=v.zone+0x60 if owner=='zone' else v.cache;v.seed('x20' if owner=='zone' else 'x21',v.zone if owner=='zone' else v.cache)
  old=v.load(at,4);v.enter(name);expected=z3.Concat(z3.Extract(31,24,old),z3.Extract(23,16,old)+resize(1,8),z3.Extract(15,0,old))
  prove(name+'_changes_only_owner_byte_mod256',v,v.load(at,4)!=expected)
 for no_full in [True,False]:
  v=local();pred=z3.BitVec('RM_pop_boundary64',64) if not no_full else v.cache+0x20
  if not no_full:v.regions.append((pred,16))
  # Snapshot genuine pointer fields from the same incoming byte array.
  # This avoids manufacturing stores merely to name the input values.
  v.setmem(v.cache+0x28,8,pred)
  empty=v.load(pred,8);v.regions.append((empty,144));nxt=v.load(empty,8)
  oldempty=v.load(v.cache+0x1c,4);v.seed('w8',oldempty);v.enter('local_pop')
  disjoint(v,empty,8,[(v.cache+0x28,8),(v.cache+0x1c,4),(pred,8)])
  if not no_full:disjoint(v,pred,8,[(v.cache+0x28,8),(v.cache+0x1c,4)])
  prove(('head_boundary' if no_full else 'node_boundary')+'_local_pop_removes_one_empty_and_clears_its_next',v,z3.Or(
   v.read('x0')!=empty,v.load(v.cache+0x1c,4)!=oldempty-1,v.load(pred,8)!=nxt,v.load(empty,8)!=0),[oldempty!=0])
  v=local();pred=z3.BitVec('RM_queue_prefix_boundary64',64) if not no_full else v.cache+0x20
  if not no_full:v.regions.append((pred,16))
  v.setmem(v.cache+0x28,8,pred);suffix=v.load(pred,8);oldfull=v.load(v.cache+0x18,4)
  v.enter('local_queue_prefix')
  if not no_full:disjoint(v,pred,8,[(v.cache+0x18,4),(v.cache+0x28,8)])
  prove(('head_boundary' if no_full else 'node_boundary')+'_queue_prefix_increments_full_count_and_reads_empty_suffix',v,z3.Or(
   v.load(v.cache+0x18,4)!=oldfull+1,v.read('x9')!=suffix,v.load(v.cache+0x28,8)!=pred),[oldfull==0 if no_full else oldfull!=0])
  v=local();pred=z3.BitVec('RM_queue_link_boundary64',64) if not no_full else v.cache+0x20
  oldmag,suffix=z3.BitVecs('RM_link_old_producer64 RM_link_suffix64',64)
  v.regions.append((oldmag,144))
  if not no_full:v.regions.append((pred,16))
  v.setmem(v.cache+0x28,8,pred);count=v.load(v.cache+0x18,4)
  v.seed('x8',oldmag+16);v.seed('x9',suffix);v.enter('local_queue_links')
  disjoint(v,oldmag,8,[(v.cache+0x18,4),(v.cache+0x28,8),(pred,8)])
  if not no_full:disjoint(v,pred,8,[(v.cache+0x18,4),(v.cache+0x28,8)])
  prove(('head_boundary' if no_full else 'node_boundary')+'_queue_links_append_old_producer_and_preserve_incremented_count',v,z3.Or(
   v.load(v.cache+0x18,4)!=count,v.load(pred,8)!=oldmag,v.load(oldmag,8)!=suffix,
   v.load(v.cache+0x28,8)!=oldmag,v.read('x21')!=v.cache))
 v=local();new,old=z3.BitVecs('RM_local_new_header64 RM_local_old_header64',64);v.regions.extend([(new,144),(old,144)])
 v.setmem(v.cache+16,8,old+16);v.seed('x0',new);v.enter('local_install')
 prove('local_install_clears_count_and_second_header_word_and_preserves_old_slots_register',v,z3.Or(
  v.load(v.cache+6,2)!=0,v.load(v.cache+16,8)!=new+16,v.load(new+8,8)!=0,v.read('x8')!=old+16))
 v=local();new,old=z3.BitVecs('RM_new_header64 RM_old_header64',64);v.regions.extend([(new,144),(old,144)])
 v.setmem(v.cache+16,8,old+16);first=v.load(new,8);v.seed('x0',new);v.enter('shared_install')
 prove('shared_install_clears_count_and_second_header_word_without_clearing_first',v,z3.Or(v.load(v.cache+6,2)!=0,
  v.load(v.cache+16,8)!=new+16,v.read('x8')!=old,v.load(new+8,8)!=0,v.load(new,8)!=first))
 v=local();clock,old=z3.BitVecs('RM_CAS_object64 RM_CAS_old_header64',64);v.regions.extend([(clock,16),(old,16)])
 stamp=v.load(old+8,8);before=v.load(clock+8,8);v.seed('x8',old);v.seed('x22',clock);v.enter('marker_cas')
 prove('marker_CAS_exact_expected_minus_four_new_marker_and_returned_old',v,z3.Or(v.load(clock+8,8)!=z3.If(before==stamp-4,stamp,before),v.read('x11')!=before))
 v=local();mag=z3.BitVec('RM_publish_slots64',64);v.regions.append((mag,0x80000));v.setmem(v.cache+16,8,mag)
 count=v.load(v.cache+6,2);v.seed('x1',v.cache);v.seed('w9',count);v.seed('x2',v.pointer);v.enter('caller_push')
 prove('caller_push_uses_raw_producer_count_and_publishes_pointer',v,z3.Or(v.load(v.cache+6,2)!=count+1,v.load(mag+8*z3.ZeroExt(48,count),8)!=v.pointer))
 v=local();mag=z3.BitVec('RM_consumer_slots64',64);v.regions.append((mag,0x80000));v.setmem(v.cache+8,8,mag)
 count=v.load(v.cache+4,2);producer=v.load(v.cache+6,2);index=z3.ZeroExt(48,count-1);element=v.load(mag+8*index,8)
 v.seed('x3',v.cache);v.enter('allocation_pop')
 prove('allocation_pop_consumes_opposite_count_and_slot_array_and_clears_selected_slot',v,z3.Or(v.load(v.cache+4,2)!=count-1,
  v.load(v.cache+6,2)!=producer,v.read('x20')!=element,v.load(mag+8*index,8)!=0),[count!=0])
 v=local();v.seed('sp',v.sp0-80)
 for j,off in [(24,-64),(23,-56),(22,-48),(21,-40),(20,-32),(19,-24),(29,-16),(30,-8)]:v.setmem(v.sp0+off,8,v.initial[j])
 v.enter('return');prove('common_helper_return_selects_original_cache_and_restores_80_byte_frame',v,z3.Or(
  v.read('x0')!=v.cache,v.read('sp')!=v.sp0,v.next!=v.initial[30],*[v.read('x'+str(j))!=v.initial[j] for j in [19,20,21,22,23,24,29,30]]))
 composition=[]
 k=z3.BitVec('RM_capacity16',16);s=z3.Solver();s.add(k!=0,z3.Not(z3.ULE(resize(1,16),k)));assert s.check()==z3.unsat
 composition.append({'label':'zero_producer_count_then_single_publication_fits_every_positive_u16_capacity','result':'unsat','query':s.to_smt2()})
 q=z3.BitVec('RM_repair_quota16',16);f,n=z3.BitVecs('RM_repair_local_full32 RM_repair_shared_full32',32)
 wide=z3.ZeroExt(1,f)+z3.ZeroExt(1,n);half=z3.LShR(z3.ZeroExt(16,q),1)
 s=z3.Solver();s.set(timeout=30000);s.add(z3.UGT(q,1),z3.UGE(f,z3.ZeroExt(16,q)),z3.ULE(wide,resize(0xffffffff,33)),f+n==half);assert s.check()==z3.unsat
 composition.append({'label':'coherent_nonoverflow_spill_counts_preclude_removing_entire_shared_full_prefix_by_half_quota','result':'unsat','query':s.to_smt2()})
 prior=[];old=json.loads(read(ROOT/'kernel_zone_retirement_audit.json'))
 for label in ['both_magazines_full_requests_helper_with_zone_cache_base_extent_and_three_spills',
  'ordinary_helper_return_restores_zone_thread_base_and_tests_full_result64',
  'zero_helper_result_restores_original_frame_and_tails_zone_base',
  'nonnull_helper_cache_publishes_base_with_raw_u16_count_wrap_without_new_capacity_gate']:
  q=next(x for x in old['source_proofs'] if x['label']==label);s=z3.SolverFor(q['logic']);s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
  prior.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/'kernel_zone_retirement_audit.json')})
 from kernel_vm_mig_tools import Image
 im=Image();parent=json.loads(read(ROOT/'kernel_zone_startup_profiles.json'))['cases'][7];profiles=[]
 assert parent['boundary']['kind']=='before_original_cache_refill'
 for j,c in enumerate(CPU.configurations()):
  row=CPU.Probe(im,e,parent,c).run();row['independent_oracle']=CPU.oracle(row);profiles.append(row)
  print('component',j,row['boundary']['kind'],len(row['source_visits']),flush=True)
 pcs={int(x['pc'],16) for row in profiles for x in row['source_visits']};helper_pcs={p for p in pcs if R.HELPER<=p<R.END}
 totals={'source_queries_unsat':len(proofs),'composition_queries_unsat':len(composition),'separation_lemmas_unsat':len(separation),'checked_separation_instantiations':len(instantiations),'prior_queries_unsat':len(prior),
  'source_block_PCs':len({p for c in coverage for p in c['PCs']}),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),
  'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),
  'checked_read_store_rewrites':sum(len(c['checked_read_store_rewrites']) for c in coverage),'CFG_source_nodes':graph['source_nodes'],
  'CFG_edges':graph['source_edges'],'CFG_abstract_states':graph['abstract_states'],'components':len(profiles),
  'returning_components':sum(r['boundary']['kind']=='original_retirement_returned' for r in profiles),
  'deeper_release_requests':sum(r['boundary']['kind']=='before_original_deeper_release' for r in profiles),
  'component_source_visits':sum(len(r['source_visits']) for r in profiles),'component_distinct_helper_PCs':len(helper_pcs),
  'independent_oracle_checks':sum(len(r['independent_oracle']['passed']) for r in profiles),'changed_source_CFG_controls':len(negative)}
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'probe_sha256':sha(CPU.__file__),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],
  'scope':R.SCOPE,'CFG_certificate':graph,'negative_controls':negative,'source_proofs':proofs,'coverage':coverage,
  'composition_proofs':composition,'separation_lemmas':separation,'separation_instantiations':instantiations,'rechecked_prior_source_proofs':prior,'components':profiles,'independent_totals':totals,
  'conditional_kernel_retirement_magazines_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
