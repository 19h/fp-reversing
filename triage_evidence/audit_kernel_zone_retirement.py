#!/usr/bin/env python3
"""Byte-array proofs for zone retirement, cache publication and thread custody.
O(I+query DAG) construction/space; separate SMT search, 30 s/query.
PAC/AUT return envelopes are conditional; AUTDA is uninterpreted, not native PAC.
"""
import copy
import json
import z3
from kext_port_tools import ROOT
from lskd_values_symbolic import resize
from audit_kernel_retirement_dispatch import Model as DispatchModel,DEC
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_zone_retirement as R

class Model(DispatchModel):
 def __init__(self,e):
  e=copy.deepcopy(e);e['spans']+=e['reused_caller_spans'];super().__init__(e)
  self.stats,self.thread=z3.BitVecs('ZT_statistics_base64 ZT_TPIDR_EL1_64',64)
  self.auth=z3.Function('ZT_uninterpreted_AUTDA',z3.BitVecSort(64),z3.BitVecSort(64),z3.BitVecSort(64))
  self.q0=z3.BitVec('ZT_initial_Q0',128)
  for reg,value in [('x0',self.zone),('x1',self.stats),('x2',self.pointer),('x3',self.element)]:self.seed(reg,value)
  self.setmem(0xfffffe0007e66e50,8,self.lo);self.setmem(0xfffffe0007e66e58,8,self.hi);self.setmem(0xfffffe0007e66f00,8,self.root)
  self.regions=[(0xfffffe0007e66e50,16),(0xfffffe0007e66f00,8)]
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   m=i.mnemonic;o=i.operands
   special=m in ['mrs','autda','subs','retab','udiv','ext'] or m in ['ldur','stur'] and i.reg_name(o[0].reg)=='q0' or m=='ldr' and i.writeback
   if not special:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
   if m=='mrs':
    assert i.op_str=='x10, tpidr_el1';self.seed('x10',self.thread)
   elif m=='autda':
    raw=self.read(i.reg_name(o[0].reg));modifier=self.read(i.reg_name(o[1].reg))
    self.write(i.reg_name(o[0].reg),self.auth(raw,modifier))
    self.authentication_envelopes.append({'pc':hex(i.address),'instruction':m,'uninterpreted_boundary':True})
   elif m=='subs':
    n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);b=self.operand(i,o[2],n);value=a-b
    self.write(i.reg_name(o[0].reg),value);self.equal=value==0;self.carry=z3.UGE(a,b)
   elif m=='retab':
    self.next=self.read('x30');self.authentication_envelopes.append({'pc':hex(i.address),'instruction':m,'assumed_identity_envelope':True})
   elif m=='udiv':
    n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);b=self.operand(i,o[2],n)
    self.write(i.reg_name(o[0].reg),z3.If(b==0,resize(0,n),z3.UDiv(a,b)))
   elif m=='ext':
    assert i.op_str=='v0.16b, v0.16b, v0.16b, #8';self.q0=z3.Concat(z3.Extract(63,0,self.q0),z3.Extract(127,64,self.q0))
   elif m in ['ldur','stur']:
    address=self.address(i,o[1])
    if m=='ldur':self.q0=self.load(address,16)
    else:self.store(address,16,self.q0,i.address)
   else:
    assert i.op_str=='x16, [x17, #0x40]!';address=self.address(i,o[1]);self.write('x16',self.load(address,8));self.write('x17',address)
  return self

def frame(v):
 v.seed('sp',v.sp0-48);v.seed('x29',v.sp0-16)
 v.setmem(v.sp0-16,8,v.initial[29]);v.setmem(v.sp0-8,8,v.initial[30]);return v

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(c) for c in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));r=s.check();assert r==z3.sat,('vacuous',label,str(r),s.reason_unknown())
  s.add(*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV','query':s.to_smt2()})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores),
   'linked_edge_obligations':len(v.edge_checks),'authentication_envelopes':v.authentication_envelopes})
  visited.update(v.visited);print(label,flush=True)
 def restored(v):return z3.Or(v.read('sp')!=v.sp0,v.read('x29')!=v.initial[29],v.read('x30')!=v.initial[30])
 def error(v):return z3.Or(v.next!=0xfffffe000c633aa0,v.read('x0')!=v.zone,v.read('x1')!=v.pointer)
 v=Model(e).run('entry');inside=z3.And(z3.ULE(v.lo,v.pointer),z3.ULT(v.pointer,v.hi))
 prove('entry_all_pointer64_exact_half_open_point_range_and_frame',v,z3.Or(v.read('x8')!=v.zone,
  v.read('x9')!=v.stats,v.read('x1')!=v.pointer,v.read('sp')!=v.sp0-48,
  v.next!=z3.If(inside,resize(0xfffffe000bd75004,64),resize(0xfffffe000bd75134,64))))
 v.run('validation_error');prove('range_rejection_calls_original_zone_pointer_error',v,error(v),[z3.Not(inside)])
 def metadata():
  v=Model(e).run('entry')
  # Read expected metadata from the post-prologue byte array, exactly the
  # state consumed next by the source. The separate entry certificate
  # establishes the range/frame contract without an epoch substitution.
  v.lo=v.load(resize(0xfffffe0007e66e50,64),8);v.hi=v.load(resize(0xfffffe0007e66e58,64),8)
  v.root=v.load(resize(0xfffffe0007e66f00,64),8)
  v.page_index=z3.LShR(v.pointer,10)&0xffffffff0;v.page=v.root+v.page_index
  v.regions.extend([(v.page,16),(v.zone,192)])
  v.header=v.load(v.page,2);v.derived=resize(R.BASE,64)+192*z3.ZeroExt(48,v.header&0x3ff)
  v.tail=v.load(v.zone+0x36,2);v.extra=v.load(v.page+2,1);v.multiplier=v.load(v.zone+0x30,4)
  v.inside=z3.And(z3.ULE(v.lo,v.pointer),z3.ULT(v.pointer,v.hi))
  v.delta=(v.pointer&0x3fff)-z3.ZeroExt(48,v.tail)
  v.displacement=v.delta+z3.If((v.header&0xf000)==0xe000,z3.ZeroExt(56,v.extra)<<14,resize(0,64))
  v.fits=z3.ULE(v.root,resize(2**64-17,64)-v.page_index)
  return v
 v=metadata().run('classify')
 prove('metadata_reclassification_uses_same_low10_zone_stride_and_exact_zone_comparison',v,z3.Or(
  v.read('x11')!=v.derived,v.next!=z3.If(v.derived==v.zone,resize(0xfffffe000bd75034,64),resize(0xfffffe000bd75134,64))),[v.inside,v.fits])
 v.run('validation_error');prove('zone_mismatch_calls_original_error_with_input_zone_and_base',v,error(v),[v.inside,v.fits,v.derived!=v.zone])
 for extended in [False,True]:
  v=metadata().run('classify').run('displacement');prem=[v.inside,v.fits,v.derived==v.zone,
   (v.header&0xf000)==0xe000 if extended else (v.header&0xf000)!=0xe000]
  if extended:v.run('extended_displacement')
  prove(('extended' if extended else 'ordinary')+'_metadata_exact_mod64_displacement',v,z3.Or(v.read('x11')!=v.displacement,
   v.read('x8')!=v.zone,v.read('x9')!=v.stats,v.read('x2')!=v.pointer,v.read('x3')!=v.element,
   v.load(v.zone+0x30,4)!=v.multiplier,v.read('sp')!=v.sp0-48,
   v.load(v.sp0-16,8)!=v.initial[29],v.load(v.sp0-8,8)!=v.initial[30],v.next!=0xfffffe000bd75054),prem)
 # Generic block certificate avoids combining unrelated byte-array alias
 # obligations with nonlinear multiplication in one solver search. Both
 # prefixes above establish its displacement/zone/frame/multiplier state.
 v=frame(Model(e));v.regions.append((v.zone,192));d=z3.BitVec('ZT_alignment_displacement64',64)
 v.seed('x11',d);v.seed('x8',v.zone);v.seed('x9',v.stats);v.seed('x2',v.pointer);v.seed('x3',v.element)
 m=v.load(v.zone+0x30,4);accept=z3.ULT(z3.Extract(31,0,d)*m,m);v.enter('alignment')
 prove('all_displacement64_and_multiplier32_exact_low32_modular_product_gate',v,
  v.next!=z3.If(accept,resize(0xfffffe000bd75064,64),resize(0xfffffe000bd75134,64)))
 v.run('validation_error');prove('all_displacement_rejection_error_operands',v,error(v),[z3.Not(accept)])
 # Seven original creator words publish separate u64/u32 quotient fields.
 v=Model(e);v.regions.append((v.zone,64));v.seed('x22',v.zone);v.seed('x25',v.element);v.enter('multiplier_producer')
 d32=z3.Extract(31,0,v.element);q64=z3.If(v.element==0,resize(0,64),z3.UDiv(resize(0xffffffff,64),v.element))+1
 q32=z3.If(d32==0,resize(0,32),z3.UDiv(resize(0xffffffff,32),d32))+1
 prove('creator_all_extent64_exact_u64_and_u32_quotient_fields_including_zero_divisors',v,z3.Or(
  v.load(v.zone+0x28,8)!=q64,v.load(v.zone+0x30,4)!=q32,v.read('x25')!=v.element))
 # Selected cache paths start at the validated accounting entry with the
 # real return frame. They do not inject an allocation or authentication result.
 def cache(capture=e):
  v=frame(Model(capture));v.seed('x8',v.zone);v.seed('x9',v.stats)
  v.regions.extend([(v.zone,192),(v.thread,512),(0xfffffe0007e6a248,2)])
  v.cpu=v.load(v.thread+0x1b8,2);v.nest=v.load(v.thread+0x1c8,4)
  v.cpu_offset=z3.ZeroExt(48,v.cpu)<<14;v.account=v.stats+v.cpu_offset
  v.regions.append((v.account,16));v.old_stat=v.load(v.account+8,8)
  v.account_fits=z3.ULE(v.stats,resize(2**64-17,64)-v.cpu_offset)
  v.enter('accounting')
  # The cache slot is read after accounting in the source. Define its
  # expected value in that same byte-array epoch, without an extra reload
  # equality across the earlier thread/statistics stores.
  v.raw=v.load(v.zone+0x40,8);v.modifier=((v.zone+0x40)&0xffffffffffff)|0x8b6b000000000000
  v.authenticated=v.auth(v.raw,resize(v.modifier,64));v.cache=v.authenticated+v.cpu_offset
  return v
 v=cache()
 prove('thread_cpu_accounting_exact_u32_increment_16KiB_stride_and_u64_extent_add',v,z3.Or(
  v.read('x10')!=v.thread,v.read('x9')!=v.account,v.read('x11')!=v.cpu_offset,
  v.load(v.thread+0x1c8,4)!=v.nest+1,v.load(v.account+8,8)!=v.old_stat+v.element,
  v.read('x8')!=v.zone,v.read('x2')!=v.pointer,v.read('x3')!=v.element),[v.account_fits])
 v.run('cache_raw');prove('cache_raw_pointer_load_updates_slot_register_and_has_exact_null_branch',v,z3.Or(
  v.read('x17')!=v.zone+0x40,v.read('x16')!=v.raw,
  v.next!=z3.If(v.raw==0,resize(0xfffffe000bd7515c,64),resize(0xfffffe000bd75098,64))),[v.account_fits])
 v.run('cache_auth');prove('cache_auth_boundary_uses_full_slot_modifier_and_tests_its_result',v,z3.Or(
  v.read('x17')!=resize(v.modifier,64),v.read('x16')!=v.authenticated,
  v.next!=z3.If(v.authenticated==0,resize(0xfffffe000bd7515c,64),resize(0xfffffe000bd750a4,64))),[v.account_fits,v.raw!=0])
 for reason in ['raw_null','auth_null']:
  v=cache().run('cache_raw');prem=[v.account_fits]
  if reason=='raw_null':prem.append(v.raw==0)
  else:v.run('cache_auth');prem.extend([v.raw!=0,v.authenticated==0])
  v.run('release_tail');prove(reason+'_deeper_release_restores_frame_for_zone_base_and_retains_nesting',v,z3.Or(
   v.next!=0xfffffe000bd756f8,v.read('x0')!=v.zone,v.read('x1')!=v.pointer,restored(v),
   v.load(v.thread+0x1c8,4)!=v.nest+1,v.load(v.account+8,8)!=v.old_stat+v.element),prem)
 def populated(capture=e):
  v=cache(capture);v.regions.append((v.cache,24));v.cur=v.load(v.cache+6,2);v.spare=v.load(v.cache+4,2)
  v.cur_mag=v.load(v.cache+16,8);v.spare_mag=v.load(v.cache+8,8);v.cap=v.load(resize(0xfffffe0007e6a248,64),2)
  v.regions.extend([(v.cur_mag,0x80000),(v.spare_mag,0x80000)])
  v.cache_fits=z3.ULE(v.authenticated,resize(2**64-25,64)-v.cpu_offset)
  v.run('cache_raw').run('cache_auth').run('cache_gate')
  v.prem=[v.account_fits,v.cache_fits,v.raw!=0,v.authenticated!=0];return v
 v=populated();prove('current_magazine_count_capacity_gate_exact_u16_comparison',v,z3.Or(
  v.read('x1')!=v.cache,v.read('w9')!=z3.ZeroExt(16,v.cur),v.read('w12')!=z3.ZeroExt(16,v.cap),
  v.next!=z3.If(z3.ULT(v.cur,v.cap),resize(0xfffffe000bd750bc,64),resize(0xfffffe000bd750f8,64))),v.prem)
 v.run('spare_gate');prove('full_current_magazine_checks_spare_count_before_helper',v,
  v.next!=z3.If(z3.ULT(v.spare,v.cap),resize(0xfffffe000bd75104,64),resize(0xfffffe000bd75140,64)),[*v.prem,z3.UGE(v.cur,v.cap)])
 for swapped in [False,True]:
  # Local publication certificates start at the established cache gate
  # cut. Accounting was independently proved before this boundary.
  v=Model(e);v.cache=z3.BitVec('ZT_publication_cache64',64)
  # This local cut reads no prologue/global cells. Quantify arbitrary
  # post-gate memory directly, avoiding irrelevant prior-store aliases.
  v.bytes=z3.Array('ZT_publication_memory',z3.BitVecSort(64),z3.BitVecSort(8))
  v.load_cache={};v.load_bindings=[]
  v.regions.extend([(v.cache,24),(v.thread,512)])
  v.cur=v.load(v.cache+6,2);v.spare=v.load(v.cache+4,2)
  v.cur_mag=v.load(v.cache+16,8);v.spare_mag=v.load(v.cache+8,8)
  v.cap=z3.BitVec('ZT_publication_capacity16',16);v.postnest=v.load(v.thread+0x1c8,4)
  v.regions.extend([(v.cur_mag,0x80000),(v.spare_mag,0x80000)])
  for reg,value in [('x1',v.cache),('w9',v.cur),('w12',v.cap),('x2',v.pointer),('x10',v.thread)]:v.seed(reg,value)
  prem=[z3.UGE(v.cur,v.cap),z3.ULT(v.spare,v.cap)] if swapped else [z3.ULT(v.cur,v.cap)]
  if swapped:v.enter('spare_gate').run('swap')
  chosen=v.spare if swapped else v.cur;mag=v.spare_mag if swapped else v.cur_mag
  if swapped:v.run('push')
  else:v.enter('push')
  bad=[v.load(v.cache+6,2)!=chosen+1,v.load(mag+8*z3.ZeroExt(48,chosen),8)!=v.pointer,
   v.load(v.thread+0x1c8,4)!=v.postnest]
  if swapped:bad.extend([v.load(v.cache+4,2)!=v.cur,v.load(v.cache+16,8)!=v.spare_mag,v.load(v.cache+8,8)!=v.cur_mag])
  prove(('spare_swap' if swapped else 'current_fast')+'_publication_exact_counts_pointer_slot_and_thread_state',v,z3.Or(*bad),prem)
  v.run('nest_gate');prove(('spare_swap' if swapped else 'current_fast')+'_postpublication_zero_routes_to_nesting_error',v,
   v.next!=z3.If(v.postnest==0,resize(0xfffffe000bd75120,64),resize(0xfffffe000bd750d4,64)),prem)
 v=populated().run('spare_gate').run('helper_request')
 prove('both_magazines_full_requests_helper_with_zone_cache_base_extent_and_three_spills',v,z3.Or(
  v.next!=0xfffffe000bd75180,v.read('x0')!=v.zone,v.read('x1')!=v.cache,v.read('x2')!=v.pointer,v.read('x3')!=v.element,
  v.load(v.sp0-40,8)!=v.zone,v.load(v.sp0-32,8)!=v.thread,v.load(v.sp0-24,8)!=v.pointer),
  [*v.prem,z3.UGE(v.cur,v.cap),z3.UGE(v.spare,v.cap)])
 # A fresh post-helper state preserves exactly the supplied caller frame
 # and ordinary nonvolatile/SP ABI. No pre-call RAM contents are retained.
 result=z3.BitVec('ZT_helper_result64',64)
 def helper_cut():
  v=frame(Model(e));v.regions.extend([(v.zone,192),(v.thread,512)])
  v.setmem(v.sp0-40,8,v.zone);v.setmem(v.sp0-32,8,v.thread);v.setmem(v.sp0-24,8,v.pointer)
  v.call_return=0xfffffe000bd75150;v.returned(result).run('helper_return');return v
 v=helper_cut();prove('ordinary_helper_return_restores_zone_thread_base_and_tests_full_result64',v,z3.Or(
  v.read('x8')!=v.zone,v.read('x10')!=v.thread,v.read('x2')!=v.pointer,
  v.next!=z3.If(result==0,resize(0xfffffe000bd7515c,64),resize(0xfffffe000bd75174,64))))
 v.run('release_tail');prove('zero_helper_result_restores_original_frame_and_tails_zone_base',v,z3.Or(
  v.next!=0xfffffe000bd756f8,v.read('x0')!=v.zone,v.read('x1')!=v.pointer,restored(v)),[result==0])
 v=helper_cut();v.regions.append((result,24));count=v.load(result+6,2);mag=v.load(result+16,8);v.regions.append((mag,0x80000))
 v.run('helper_cache').run('push');prove('nonnull_helper_cache_publishes_base_with_raw_u16_count_wrap_without_new_capacity_gate',v,z3.Or(
  v.read('x1')!=result,v.load(result+6,2)!=count+1,v.load(mag+8*z3.ZeroExt(48,count),8)!=v.pointer,
  v.read('x8')!=mag,v.read('x10')!=v.thread,v.next!=0xfffffe000bd750cc),[result!=0])
 def nesting(pending=False):
  v=frame(Model(e));v.regions.append((v.thread,512));v.seed('x10',v.thread)
  v.n=v.load(v.thread+0x1c8,4)
  if pending:
   v.pending=v.load(v.thread+0x1c0,8);v.regions.append((v.pending,96));v.pending_flag=v.load(v.pending+0x4c,1)
  return v.enter('nest_gate')
 v=nesting();prove('post_push_nesting_zero_has_exact_error_call_gate',v,
  v.next!=z3.If(v.n==0,resize(0xfffffe000bd75120,64),resize(0xfffffe000bd750d4,64)))
 v.run('nest_error');prove('zero_nesting_stops_at_original_error_call_boundary',v,v.next!=0xfffffe000c63aec8,[v.n==0])
 v=nesting().run('nest_drop');prove('nonzero_nesting_decrements_u32_and_only_one_checks_pending_state',v,z3.Or(
  v.load(v.thread+0x1c8,4)!=v.n-1,
  v.next!=z3.If(v.n==1,resize(0xfffffe000bd750e0,64),resize(0xfffffe000bd750ec,64))),[v.n!=0])
 v.run('return');prove('nesting_above_one_returns_with_original_frame_link_and_counter',v,z3.Or(
  v.next!=v.initial[30],restored(v),v.load(v.thread+0x1c8,4)!=v.n-1,
  *[v.read('x'+str(j))!=v.initial[j] for j in range(19,29)]),[z3.UGT(v.n,1)])
 for pending in [False,True]:
  v=nesting(True).run('nest_drop').run('pending');prem=[v.n==1,(v.pending_flag&4)!=0 if pending else (v.pending_flag&4)==0]
  v.run('pending_tail' if pending else 'return')
  prove(('pending_bit2' if pending else 'no_pending_bit2')+'_nesting_one_restores_frame_and_selects_tail_or_return',v,z3.Or(
   v.next!=(resize(0xfffffe000be8663c,64) if pending else v.initial[30]),restored(v),v.load(v.thread+0x1c8,4)!=0),prem)
 # Reuse the actual nine-word small-dispatch tail under its already-proved
 # saved-frame cut, then execute the zone-retirement entry without a reset.
 v=frame(Model(e))
 for j,off in [(22,-48),(21,-40),(20,-32),(19,-24)]:v.setmem(v.sp0+off,8,v.initial[j])
 for reg,value in [('x19',v.zone),('x20',v.pointer),('x21',v.element),('x22',v.stats)]:v.seed(reg,value)
 v.enter('handoff');prove('small_dispatch_tail_exact_zone_statistics_base_extent_and_frame_join',v,z3.Or(
  v.next!=0xfffffe000bd74fcc,v.read('x0')!=v.zone,v.read('x1')!=v.stats,v.read('x2')!=v.pointer,
  v.read('x3')!=v.element,restored(v),*[v.read('x'+str(j))!=v.initial[j] for j in [19,20,21,22]]))
 v.run('entry');prove('linked_small_dispatch_tail_enters_zone_range_gate_with_same_base_and_extent',v,z3.Or(
  v.read('x8')!=v.zone,v.read('x9')!=v.stats,v.read('x1')!=v.pointer,v.read('x2')!=v.pointer,
  v.read('x3')!=v.element,v.next!=0xfffffe000bd75004),[z3.ULE(v.lo,v.pointer),z3.ULT(v.pointer,v.hi)])
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};reused={int(i['ea'],16) for s in e['reused_caller_spans'] for i in s['instructions']}
 assert visited==selected|reused,sorted(map(hex,(selected|reused)-visited))
 changed=copy.deepcopy(e);row=next(s for s in changed['spans'] if s['label']=='push');raw=bytearray.fromhex(row['bytes_hex'])
 assert row['instructions'][3]['ea']=='0xfffffe000bd750c8';raw[12:16]=bytes.fromhex('1f2003d5');row['bytes_hex']=raw.hex()
 v=populated(changed).run('push');bad=v.load(v.cur_mag+8*z3.ZeroExt(48,v.cur),8)!=v.pointer
 common=[*v.owned(),*v.edge_checks,*v.prem,z3.ULT(v.cur,v.cap)]
 s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for([*common,bad]),bad);assert s.check()==z3.sat
 negative={'altered_cache_publication_store_counterexample':True,'result':'sat','query':s.to_smt2()}
 composition=[]
 for extent in [16,32,48]:
  d=z3.BitVec('ZT_nonnegative_displacement14',14);wide=z3.ZeroExt(18,d);m=((2**32-1)//extent+1)&0xffffffff
  s=z3.Solver();s.set(timeout=30000);s.add(z3.ULT(wide*m,resize(m,32))!=(z3.URem(wide,resize(extent,32))==0));assert s.check()==z3.unsat
  composition.append({'label':'producer_extent'+str(extent)+'_nonnegative_14bit_displacement_gate_equals_divisibility',
   'extent_bytes':extent,'multiplier_u32':m,'result':'unsat','query':s.to_smt2()})
 prior=[];old=json.loads(read(ROOT/'kernel_retirement_dispatch_audit.json'))
 for label in ['data14_postclear_zone_fallback_tail_args_frame_and_nonvolatile_restore',
  'data14_postclear_heap_accounting_tail_args_frame_and_nonvolatile_restore',
  'typed32_postclear_zone_fallback_tail_args_frame_and_nonvolatile_restore',
  'typed32_postclear_heap_accounting_tail_args_frame_and_nonvolatile_restore']:
  q=next(q for q in old['source_proofs'] if q['label']==label);s=z3.SolverFor(q['logic']);s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
  prior.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/'kernel_retirement_dispatch_audit.json')})
 old=json.loads(read(ROOT/'mixed_data_retirement_checks.json'));q=next(q for q in old['proofs'] if q['name']=='metadata_zone_index_uses_same_192_byte_stride')
 s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
 prior.append({'label':q['name'],'result':'unsat','source_audit_sha256':sha(ROOT/'mixed_data_retirement_checks.json')})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,
  'composition_proofs':composition,'proved_source_PCs':sorted(map(hex,visited)),
  'rechecked_prior_source_proofs':prior,'negative_control':negative,
  'independent_totals':{'new_source_queries_unsat':len(qs),'new_composition_queries_unsat':len(composition),'prior_source_queries_unsat':len(prior),
   'distinct_new_proved_instructions':len(selected),'distinct_reused_proved_instructions':len(reused),
   'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'complete_tail_instructions':109,
   'altered_cache_publication_store_counterexample':True},
  'conditional_kernel_zone_retirement_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
