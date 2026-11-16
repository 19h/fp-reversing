#!/usr/bin/env python3
"""Original main/timebase/trace/full-registry sort and first tunable callback.
O(visits+journals+mapped bytes) time/space. No native target or callback model.
"""
import json
import struct
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_rpc502_vm_handoff import compressed
from probe_kernel_vm_mig import Probe as Core,P,SIZE,SP
from probe_kernel_secure_dt_execution import tree_node,serialize,scalar
import probe_kernel_bootstrap_state_composition as B
import recover_kernel_startup_registry_abi as R
NEW_REGIONS=[(R.BASE,R.END-R.BASE),(R.CURSOR,8),(R.RATIO,16),(R.EVENT_STATE,12),(R.EVENTS,16384),(R.LAST_PHASE,4)]
REGIONS=B.REGIONS+NEW_REGIONS
NEW_APIS=[*R.ADDITIONS,R.TUNABLE]
INITIAL_SYSTEM={**B.INITIAL_SYSTEM,'s3_4_c15_c10_6':0x123456789}

class Probe(B.Probe):
 def __init__(self,image,c,mutate=None):
  super().__init__(image,c);self.mutate=mutate;self.system=dict(INITIAL_SYSTEM);self.bootstrap=None;self.sort_entry=None;self.dispatch_entry=None;self.callback_dispatch=None;self.callback_return=None
  if c.get('defaults_properties'):
   root=B.B.fixture(c);root['children'].append(tree_node('defaults',[(key,scalar(value,4)) for key,value in c['defaults_properties'].items()]));blob,nodes=serialize(root)
   self.fixture(B.B.TREE,bytes(max(len(self.blob),len(blob))));self.fixture(B.B.TREE,blob);self.blob,self.nodes=blob,nodes;self.c['extent']=len(blob)
   args=bytearray(self.u.mem_read(B.B.INPUT,1152));struct.pack_into('<I',args,0x68,len(blob));self.fixture(B.B.INPUT,bytes(args))
  e=json.loads(read(ROOT/(R.P+'_checks.json')));destinations=[(int(t['destination'],16),t['size_bytes']) for t in e['tunable_descriptors']]
  self.extra_regions=[*NEW_REGIONS,*dict.fromkeys((a,n) for a,n in destinations if not any(lo<=a<a+n<=lo+m for lo,m in B.REGIONS))];self.regions=[*B.REGIONS,*self.extra_regions]
  for a,n in self.extra_regions:
   raw=b''.join(image.logical_page(pg) for pg in range(a&~4095,(a+n+4095)&~4095,4096));off=a&4095
   self.image_fixture(a,raw[off:off+n],'Original logical registry/timebase/trace/phase storage before main entry; native lifetime unknown')
  self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in e['functions']]
  self.before=bytes(self.u.mem_read(P,SIZE));self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or any(lo<=a<a+n<=lo+length for lo,length in self.regions),(hex(a),n)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def full_snapshot(self,a):
  row=super().full_snapshot(a);row['registry_image_globals']=[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in self.extra_regions];return row
 def code(self,u,a,n,d):
  self.flush()
  while self.active and self.entries[self.active[-1]]['return_PC']==hex(a) and self.entries[self.active[-1]]['entry_SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   self.returns.append({'entry_index':self.active.pop(),'before_visit':len(self.visits),'return_value':hex(self.reg(0))})
  if a==0xfffffe000c639dd8:
   self.bootstrap=self.full_snapshot(a);return Core.code(self,u,a,n,d)
  if a==R.SORT:self.sort_entry=self.full_snapshot(a)
  if a==R.DISPATCH:self.dispatch_entry=self.full_snapshot(a)
  if a==0xfffffe000c630374:self.callback_return=self.full_snapshot(a)
  if a==0xfffffe000c63037c:return self.stop('original_first_registry_callback_return_and_cursor_publication')
  if a in NEW_APIS:
   self.active.append(len(self.entries));self.entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':[hex(self.reg(j)) for j in range(6)],'return_PC':hex(self.reg(30)),'before_visit':len(self.visits)})
  raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
  if a==0xfffffe000c630370:
   assert i.mnemonic=='blraa' and i.op_str=='x8, x17' and self.reg(8)==R.TUNABLE and self.reg(17)==0x2abe and raw==self.image.k.read(a,4);self.callback_dispatch=self.full_snapshot(a)
   event={'PC':hex(a),'kind':'blraa','scope':'original_registry_callback','operands':i.op_str,'before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(self.reg(8)),'modifier_X17':hex(self.reg(17)),'argument_X0':hex(self.reg(0))};self.logical.append(event);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,R.TUNABLE);return
  if R.QUICKSORT<=a<0xfffffe000c61c630 and i.mnemonic=='blraa':
   assert i.op_str=='x19, x17' and self.reg(19)==R.COMPARE and self.reg(17)==0xe4fe and raw==self.image.k.read(a,4)
   event={'PC':hex(a),'kind':'blraa','scope':'registry_comparator','operands':i.op_str,'before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(self.reg(19)),'modifier_X17':hex(self.reg(17))};self.logical.append(event);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,R.COMPARE);return
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=3000000);self.flush();assert self.reason=='original_first_registry_callback_return_and_cursor_publication',self.boundary
  assert self.bootstrap and self.sort_entry and self.dispatch_entry and self.callback_dispatch and self.callback_return
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_NZCV':self.entry_NZCV,'entry_registers31':self.entry_regs,'initial_vectors':['0x0']*32,'initial_system':INITIAL_SYSTEM,'final_system':self.system,'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'initial_image_pages':[{'address':hex(pg),'bytes_hex':raw.hex()} for pg,raw in sorted(self.initial_pages.items())],'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in self.regions],'final_page_sha256':{hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)},'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_effects':self.logical,'original_call_entries':self.events,'original_API_entries':self.entries,'original_API_returns':self.returns,'unfinished_API_entry_indices':self.active,'prefix_checkpoint':self.prefix,'original_platform_return':self.platform_return,'pre_enumeration_checkpoint':self.join,'original_enumeration_return':self.enumerated,'original_post_helper_return':self.post,'declared_selector0e_calls':self.wrapper,'bootstrap_state_checkpoint':self.bootstrap,'sort_entry_checkpoint':self.sort_entry,'dispatch_entry_checkpoint':self.dispatch_entry,'first_callback_dispatch_checkpoint':self.callback_dispatch,'first_callback_return_checkpoint':self.callback_return,'fixture_extent_bytes':len(self.blob),'fixture_node_addresses':{k:hex(v) for k,v in self.nodes.items()},'final_vectors':[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)],'boundary':self.boundary,'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,**{n:False for n in R.FALSE}}

def cases():
 return [{'label':'continuous_default_timebase_and_first_tunable','CPUs':[{}],'boot_text':''},
 {'label':'tree_property_controls_first_tunable','CPUs':[{}],'boot_text':'','defaults_properties':{'kern.memstat_pressure_mb':7}},
 {'label':'option_overrides_tree_and_48M_timebase','CPUs':[{'timebase-frequency':48000000}],'boot_text':'memorystatus_pressure_threshold_mb=13','defaults_properties':{'kern.memstat_pressure_mb':7}}]
