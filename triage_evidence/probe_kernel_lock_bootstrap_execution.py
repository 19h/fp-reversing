#!/usr/bin/env python3
"""Continuous original startup through phase-three callbacks.
Linear source visits, journal bytes and mapped storage. No new return model.
"""
import json,struct
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
import probe_kernel_timeout_execution as B
import recover_kernel_lock_bootstrap_execution as R

class Probe(B.Probe):
 def __init__(self,image,c,mutate=None):
  super().__init__(image,c,None);self.mutate=mutate;self.phase_three_checkpoint=None;self.next_phase=None
  self.lock_e=json.loads(read(ROOT/(R.P+'_checks.json')));self.lock_descriptors={int(d['argument'],16):d for d in self.lock_e['descriptors'] if int(d['argument'],16)}
  self.lock_regions=B.B.B.complement(R.regions(self.lock_e),self.regions);self.regions+=self.lock_regions
  for a,n in self.lock_regions:
   raw=b''.join(image.logical_page(pg) for pg in range(a&~4095,(a+n+4095)&~4095,4096));self.image_fixture(a,raw[a&4095:(a&4095)+n],'Original logical lock destinations and static group-ID storage before main entry; native lifetime unknown')
  self.regions=B.B.B.merge(self.regions)
  self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in self.lock_e['functions']];self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def full_snapshot(self,a):
  row=super().full_snapshot(a)
  if hasattr(self,'lock_regions'):row['lock_image_globals']=[{'address':hex(p),'bytes_hex':bytes(self.u.mem_read(p,n)).hex()} for p,n in self.lock_regions]
  return row
 def outputs(self,target,arg):
  if target==R.FIRST:return [(0xfffffe000cb60590,0x148),(R.REGISTRY,0xe8),(R.BANK,8),(R.BITMAP,128),(0xfffffe0007e635c8,4),(0xfffffe0007e63610,4)]
  if target==R.FIXED:return [(0xfffffe000cb2a5e0,16),(0xfffffe000caaf868,0x18)]
  if target==R.LATE:return [(0xfffffe000cac4200,0x80)]
  if target==R.REGLOCK:return [(arg+0xc0,16),(0xfffffe000caad718,0x18)]
  if target in [R.GROUP,R.ATTR,R.MUTEX,R.RW,R.SPIN,R.TICKET,R.PLAIN]:
   d=self.lock_descriptors[arg];out=[(int(d['destination'],16),0x148 if target==R.GROUP else 4 if target==R.ATTR else 16)]
   if target==R.GROUP:out += [(R.REGISTRY+0xdc,8),(R.BANK,8192),(R.BITMAP,128)]
   if target in [R.MUTEX,R.RW,R.SPIN] and d['pointers'][1]:out.append((int(d['pointers'][1]['target'],16),0x18))
   return out
  return super().outputs(target,arg)
 def code(self,u,a,n,d):
  if a==R.STOP:
   self.flush();self.next_phase={'call_PC':hex(a),'target':hex(R.FRONTIER),'kind':'original_main_direct_BL_after_phase_three_return'};return self.stop('before_original_post_lock_timeout_wait_queue_initializer_BL')
  if a==R.DISPATCH:
   self.flush();cursor=int.from_bytes(u.mem_read(R.B.B.B.B.CURSOR,8),'little');phase,rank,target,arg=struct.unpack('<IIQQ',u.mem_read(cursor,24));index=(cursor-R.B.B.B.B.BASE)//24
   if phase>3:
    self.next_phase={'cursor':hex(cursor),'phase_u32':phase,'rank_u32':rank,'target':hex(target),'argument':hex(arg)};return self.stop('before_first_post_phase_three_callback_BLRAA')
   if phase==3:
    if self.phase_three_checkpoint is None:
     self.phase_three_checkpoint=self.full_snapshot(a);self.phase_three_checkpoint['mapped_page_sha256']={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}
    assert self.reg(8)==target and self.reg(0)==arg and self.reg(17)==0x2abe
    c={'before_visit':len(self.visits),'sorted_index':index,'cursor':hex(cursor),'phase_u32':phase,'rank_u32':rank,'target':hex(target),'argument':hex(arg),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'thread':hex(self.system['tpidr_el1'])};self.callback_entries.append(c);self.current_callback=c
    raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);self.logical.append({'PC':hex(a),'kind':'blraa','scope':'original_registry_callback','operands':'x8, x17','before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(target),'modifier_X17':hex(self.reg(17)),'argument_X0':hex(arg)});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,target);return
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row.update(phase_three_entry_checkpoint=self.phase_three_checkpoint,post_phase_three_dispatch_boundary=self.next_phase,phase_three_callbacks_executed=len(self.callback_returns)==1029,native_phase_three_completed=False);return row

def cases():return [B.cases()[0],{'label':'continuous_lock_statistics_flags','CPUs':[{}],'boot_text':'lcks=0xb'}]
