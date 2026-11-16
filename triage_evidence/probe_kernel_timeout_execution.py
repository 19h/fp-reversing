#!/usr/bin/env python3
"""Continuous original main through all phase-two callbacks.
Linear visits/journals/RAM; no new callback-result model or frame epoch.
"""
import json,struct
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_kernel_vm_mig import Probe as Core,P,SIZE
from probe_kernel_secure_dt_execution import tree_node,serialize,scalar
import probe_kernel_platform_environment_execution as ENV
import probe_kernel_uuid_formatter_execution as B
import recover_kernel_timeout_execution as R

class Probe(B.Probe):
 def __init__(self,image,c,mutate=None):
  super().__init__(image,c,None);self.mutate=mutate;self.phase_two_checkpoint=None;self.phase_three_boundary=None
  if c.get('machine_timeouts') or c.get('chosen_timeouts'):
   root=ENV.fixture(c)
   if c.get('machine_timeouts'):root['children'].append(tree_node('machine-timeouts',[(k,scalar(v,n)) for k,(v,n) in c['machine_timeouts'].items()]))
   if c.get('chosen_timeouts'):
    chosen=next((x for x in root['children'] if bytes.fromhex(x['properties'][0][1]['bytes_hex'])==b'chosen\0'),None)
    if chosen is None:chosen=tree_node('chosen');root['children'].append(chosen)
    chosen['children'].append(tree_node('machine-timeouts',[(k,scalar(v,n)) for k,(v,n) in c['chosen_timeouts'].items()]))
   blob,nodes=serialize(root);self.fixture(ENV.TREE,bytes(max(len(self.blob),len(blob))));self.fixture(ENV.TREE,blob);self.blob,self.nodes=blob,nodes;self.c['extent']=len(blob);args=bytearray(self.u.mem_read(ENV.INPUT,1152));struct.pack_into('<I',args,0x68,len(blob));self.fixture(ENV.INPUT,bytes(args))
  self.e=json.loads(read(ROOT/(R.P+'_checks.json')));self.descriptors={int(d['address'],16):d for d in self.e['timeout_descriptors']};desired=[*R.GLOBAL_REGIONS,*[(int(d['destination_pointer']['target'],16),8) for d in self.descriptors.values()]];self.timeout_regions=B.B.complement(desired,self.regions);self.regions+=self.timeout_regions
  for a,n in self.timeout_regions:
   raw=b''.join(image.logical_page(pg) for pg in range(a&~4095,(a+n+4095)&~4095,4096));off=a&4095;self.image_fixture(a,raw[off:off+n],'Original logical timeout destinations/cache before main entry; native lifetime unknown')
  self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in self.e['functions']];self.before=bytes(self.u.mem_read(P,SIZE));self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def full_snapshot(self,a):
  row=super().full_snapshot(a);row['timeout_image_globals']=[{'address':hex(p),'bytes_hex':bytes(self.u.mem_read(p,n)).hex()} for p,n in self.timeout_regions];return row
 def outputs(self,target,arg):
  if target in [R.ORDINARY,R.SPECIAL]:return [(int(self.descriptors[arg]['destination_pointer']['target'],16),8),(0xfffffe000cb62710,1),(0xfffffe000cb62718,8)]
  if target==R.LOCK:return [(a,n) for a,n in R.GLOBAL_REGIONS if a not in [0xfffffe000cb62710,0xfffffe000cb62718]]
  return super().outputs(target,arg)
 def code(self,u,a,n,d):
  self.flush()
  while self.active and self.entries[self.active[-1]]['return_PC']==hex(a) and self.entries[self.active[-1]]['entry_SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   self.returns.append({'entry_index':self.active.pop(),'before_visit':len(self.visits),'return_value':hex(self.reg(0))})
  if a==R.DISPATCH:
   cursor=int.from_bytes(u.mem_read(R.B.B.B.CURSOR,8),'little');phase,rank,target,arg=struct.unpack('<IIQQ',u.mem_read(cursor,24));index=(cursor-R.B.B.B.BASE)//24
   if phase==3:self.phase_three_boundary={'cursor':hex(cursor),'phase_u32':phase,'rank_u32':rank,'target':hex(target),'argument':hex(arg)};return self.stop('before_first_phase_three_callback_BLRAA')
   if phase==2:
    if self.phase_two_checkpoint is None:
     self.phase_two_checkpoint=self.full_snapshot(a);self.phase_two_checkpoint['mapped_page_sha256']={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)};self.phase_two_boundary={'cursor':hex(cursor),'phase_u32':phase,'rank_u32':rank,'target':hex(target),'argument':hex(arg)}
    assert self.reg(8)==target and self.reg(0)==arg and self.reg(17)==0x2abe and target in [R.ORDINARY,R.SPECIAL,R.LOCK]
    c={'before_visit':len(self.visits),'sorted_index':index,'cursor':hex(cursor),'phase_u32':phase,'rank_u32':rank,'target':hex(target),'argument':hex(arg),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'thread':hex(self.system['tpidr_el1'])};self.callback_entries.append(c);self.current_callback=c
    raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);self.logical.append({'PC':hex(a),'kind':'blraa','scope':'original_registry_callback','operands':'x8, x17','before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(target),'modifier_X17':hex(self.reg(17)),'argument_X0':hex(arg)});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,target);return
  if R.COMMON<=a<0xfffffe000bd11150:
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic=='blraa' and i.op_str=='x16, x17':
    assert raw==self.image.k.read(a,4) and self.reg(16)==R.STACK_STUB and self.reg(17)==0xfffffe0007f95e28
    self.logical.append({'PC':hex(a),'kind':'blraa','scope':'original_timeout_stack_probe','operands':i.op_str,'before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(self.reg(16)),'modifier_X17':hex(self.reg(17)),'probe_size_X9':hex(self.reg(9))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,R.STACK_STUB);return
  if a in R.APIS:
   self.active.append(len(self.entries));self.entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':[hex(self.reg(j)) for j in range(6)],'return_PC':hex(self.reg(30)),'before_visit':len(self.visits)})
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row.update(phase_two_entry_checkpoint=self.phase_two_checkpoint,phase_three_dispatch_boundary=self.phase_three_boundary,**{n:True for n in R.TRUE},**{n:False for n in R.FALSE});return row

def cases():
 return [B.cases()[0],
 {'label':'timeout_boot_options_and_lock_preparation','CPUs':[{}],'boot_text':'ml-timeout-debug-ack=1000000 ml-timeout-debug-ack-scale=3 ml-timeout-global-scale=2 slto_us=10 tlto_us=8 mtxspin=999999 max_wfe_us=7'},
 {'label':'timeout_tree_chosen_then_boot_precedence','CPUs':[{}],'boot_text':'ml-timeout-debug-ack=1000000000 ml-timeout-debug-ack-scale=7 ml-timeout-global-scale=11','machine_timeouts':{'debug-ack':[900000000,8],'debug-ack-scale':[2,4],'global-scale':[3,4]},'chosen_timeouts':{'debug-ack':[700000000,8],'debug-ack-scale':[4,4],'global-scale':[5,4]}},
 {'label':'timeout_tree_then_chosen_without_boot_override','CPUs':[{}],'boot_text':'','machine_timeouts':{'debug-ack':[900000000,8],'debug-ack-scale':[2,4],'global-scale':[3,4]},'chosen_timeouts':{'debug-ack':[700000000,8],'debug-ack-scale':[4,4],'global-scale':[5,4]}},
 {'label':'timeout_watchdog_minus1_gate','CPUs':[{}],'boot_text':'wdt=-1'},
 {'label':'timeout_global_scale_saturates_nonzero_defaults','CPUs':[{}],'boot_text':'ml-timeout-global-scale=0xffffffffffffffff'}]
