#!/usr/bin/env python3
"""Original kmsg construction from raw populated-cache objects and notification.
O(visits+RAM+effects), O(image+RAM+journals). Zone/cache/heap/thread epochs and
remaining transport/hash/lock/destructor effects remain models, not native IPC.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_kernel_notification_send import Probe as NotificationParent
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_kmsg_allocation';ALLOC=0xfffffe000bcc24a4;ZONEALLOC=0xfffffe000bd75c64;ZERO=0xfffffe000bc9d9c0
KMSG=P+0xd0000;HEAPH=P+0xd4000;HEAPB=P+0xd8000;ZONE=P+0xb0000;STATS=P+0xb1000;CACHE=P+0xb2000;SLOTS=P+0xb3000;SPARE=P+0xb3100;PENDING=P+0xb4000;THREAD=P+0x2c000
def simd(u):return[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
class AllocationMixin:
 def allocation_setup(self,c,src):
  self.allocation_frames=[];self.sign=[];self.alloc_overlays=[];self.allowed=[(int(f['start'],16),int(f['end'],16))for f in src['functions']];self.cpu_index=c.get('cpu_index',0);self.cache_at=CACHE+(self.cpu_index<<14);self.stats_at=STATS+(self.cpu_index<<14);mode=c.get('cache_mode','primary')
  self.alloc_overlay(KMSG,bytes(256),'Declared zeroed raw cache element; initialization fields are written by original constructor');self.alloc_overlay(KMSG+256,b'\xa5','Guard outside declared256-byte element')
  if 'dirty_offset'in c:self.alloc_overlay(KMSG+c['dirty_offset'],b'\xaa','Controlled zero-check precondition violation')
  z=bytearray(256);struct.pack_into('<H',z,0x34,256);struct.pack_into('<Q',z,0x40,0 if mode=='null_pointer'else CACHE);self.alloc_overlay(ZONE,bytes(z),'Declared zone metadata and per-CPU cache base');self.alloc_overlay(self.stats_at,bytes(16),'Declared selected-CPU allocation statistics')
  cache=bytearray(64);struct.pack_into('<HHQQ',cache,4,1 if mode=='primary'else 0,1 if mode=='swap'else 0,SLOTS,SPARE);self.alloc_overlay(self.cache_at,bytes(cache),'Declared current/spare selected-CPU cache state');self.alloc_overlay(SLOTS,struct.pack('<QQ',KMSG if mode=='primary'else 0,0),'Declared current slot list');self.alloc_overlay(SPARE,struct.pack('<QQ',KMSG if mode=='swap'else 0,0),'Declared spare slot list')
  pending=bytearray(0x50);pending[0x4c]=c.get('pending_flag',0);self.alloc_overlay(PENDING,bytes(pending),'Declared pending-preemption object');self.alloc_overlay(THREAD+0x1b8,struct.pack('<H',self.cpu_index),'Declared CPU index');self.alloc_overlay(THREAD+0x1c0,struct.pack('<Q',PENDING),'Declared pending object pointer');self.alloc_overlay(THREAD+0x1c8,struct.pack('<I',0),'Declared initial preemption nesting')
  if c['phase']=='allocator':
   self.alloc_overlay(HEAPH,b'\xa5'*4096,'Private external-header observation window');self.alloc_overlay(HEAPB,b'\xa5'*4096,'Private external-body observation window')
  self.image_fixture(0xfffffe000caec680,struct.pack('<QQ',ZONE,STATS),'Declared kmsg zone/statistics cells; original file cells are zero')
 def alloc_overlay(self,a,b,why):self.alloc_overlays.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why});self.fixture(a,b)
 def allocation_code(self,u,a,n,d):
  self.flush()
  if a in[ALLOC,ZONEALLOC,ZERO,0xfffffe000bd75d20,0xfffffe000bcc268c,0xfffffe000bcc6948]:
   self.allocation_frames.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'cache64_hex':bytes(u.mem_read(self.cache_at,64)).hex(),'stats16_hex':bytes(u.mem_read(self.stats_at,16)).hex(),'thread_nesting':int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little')})
  if a==0xfffffe000bcfe5b8:
   which='body'if self.reg(30)==0xfffffe000bcc25fc else'header';assert self.reg(30)in[0xfffffe000bcc25fc,0xfffffe000bcc266c];result=0 if self.c.get('heap_failure')==which else HEAPB if which=='body'else HEAPH;self.model(a,'declared_raw_'+which+'_heap_allocation',result);return True
  if a==0xfffffe000bcfec48:self.model(a,'declared_failed_header_body_release_request',0);return True
  if a==0xfffffe000be8663c:self.model(a,'declared_pending_preemption_helper',0);return True
  if a==0xfffffe000c633ccc:self.stop('before_original_zero_check_failure');return True
  if a==0xfffffe000bd75e20:self.stop('before_original_cache_refill');return True
  if a==0xfffffe000bd76394:self.stop('before_original_zone_fallback');return True
  if any(x<=a<z for x,z in self.allowed):
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic in['autda','pacda']:
    assert raw==self.image.k.read(a,4);target=self.auth if i.mnemonic=='autda'else self.sign;target.append({'pc':hex(a),'pointer':hex(self.reg(16 if i.mnemonic=='autda'else 17)),'modifier':hex(self.reg(17 if i.mnemonic=='autda'else 16))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return True
  return False
 def allocation_fields(self):
  return{'allocation_frames':self.allocation_frames,'allocation_environment_overlays':self.alloc_overlays,'logical_data_signing':self.sign,'selected_cpu_index':self.cpu_index,'selected_cache_address':hex(self.cache_at),'selected_statistics_address':hex(self.stats_at),'final_zone256_hex':bytes(self.u.mem_read(ZONE,256)).hex(),'final_cache64_hex':bytes(self.u.mem_read(self.cache_at,64)).hex(),'final_statistics16_hex':bytes(self.u.mem_read(self.stats_at,16)).hex(),'final_slots16_hex':bytes(self.u.mem_read(SLOTS,16)).hex(),'final_spare_slots16_hex':bytes(self.u.mem_read(SPARE,16)).hex(),'final_thread_nesting':int.from_bytes(bytes(self.u.mem_read(THREAD+0x1c8,4)),'little'),'final_raw_kmsg256_hex':bytes(self.u.mem_read(KMSG,256)).hex(),'raw_kmsg_guard_hex':bytes(self.u.mem_read(KMSG+256,1)).hex()}
class AllocatorProbe(AllocationMixin,CPU):
 def __init__(self,im,c,src):
  super().__init__(im,'selector',{'id':0});self.kind=PREFIX;self.c=c;self.initial=[];self.image_initial=[];self.auth=[];self.entry=ALLOC;self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD);self.allocation_setup(c,src)
  for j,x in enumerate([c['size'],c.get('aux',0),c.get('descriptors',0),c.get('flags',1)]):self.set(j,x)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.entryQ=simd(self.u)
 def image_fixture(self,a,b,why):self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':why})
 def code(self,u,a,n,d):
  if a==HALT:return self.stop('allocator_returned')
  if self.allocation_code(u,a,n,d):return
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason is not None
  row={'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'entry_Q_registers32':self.entryQ,'final_Q_registers32':simd(self.u),'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_state_transfer':{'path':'private_zero_RAM','case':None,**compressed(bytes(SIZE))},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'memory_overlays':[],'register_overlays':[],'private_system_register_fixtures':[{'register':'TPIDR_EL1','value':hex(THREAD)}],'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'declared_effects':[],'logical_data_authentication':self.auth,'opaque_hash_inputs':[],'entry_frames':[],'boundary':self.boundary,'header_address':hex(KMSG+0x40),'body_address':hex(KMSG+0x60),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_image_globals':[{'address':e['address'],'bytes_hex':bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()}for e in self.image_initial],**{k:False for k in FLAGS}};row.update(self.allocation_fields());return row
class NotificationProbe(AllocationMixin,NotificationParent):
 def __init__(self,im,c,src,producer):
  super().__init__(im,{**c,'storage_class':0},src,producer);assert self.initial[:2]==[{'address':hex(KMSG),'bytes_hex':bytes(1024).hex()},{'address':hex(KMSG+0x3f),'bytes_hex':'00'}];self.initial=self.initial[2:];self.overlays=self.overlays[2:];self.u.mem_write(KMSG,decode(producer['final_private_RAM'])[KMSG-P:KMSG-P+1024]);self.allocation_setup(self.c,src)
 def code(self,u,a,n,d):
  if self.allocation_code(u,a,n,d):return
  if a==ALLOC:return CPU.code(self,u,a,n,d)
  return super().code(u,a,n,d)
 def run(self):r=super().run();r.update(self.allocation_fields());return r
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());producer=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];configs=[]
 for args in[(44,0,0,1),(88,0,1,1),(392,0,2,1),(124,0,0,1),(125,0,0,1),(176,0,8,1),(180,0,9,1),(125,0,0,0x11),(180,0,9,0),(44,12,0,1),(125,0,0,3),(44,0,0,0x21),(0xffffffbc,0,0,1),(44,0xffffffff,0,1),(180,0,0x40000000,0),(180,0,0x10000000,1)]:configs.append({'phase':'allocator','size':args[0],'aux':args[1],'descriptors':args[2],'flags':args[3]})
 configs.extend([{'phase':'allocator','size':125,'heap_failure':'body'},{'phase':'allocator','size':180,'descriptors':9,'heap_failure':'header'},{'phase':'allocator','size':44,'cache_mode':'swap'},{'phase':'allocator','size':44,'cpu_index':1},{'phase':'allocator','size':44,'pending_flag':4},{'phase':'allocator','size':44,'cache_mode':'empty'},{'phase':'allocator','size':44,'cache_mode':'null_pointer'}])
 for offset in[0,63,64,127,128,255]:configs.append({'phase':'allocator','size':44,'dirty_offset':offset})
 for status in[0,5,0x10000003,0x10000004,0x10000007,0x1000000d]:configs.append({'phase':'notification','queue_status':status,'accepted_output':True})
 configs.append({'phase':'notification','queue_status':0,'cache_mode':'swap'});rows=[]
 for c in configs:
  r=(NotificationProbe(im,c,src,producer)if c['phase']=='notification'else AllocatorProbe(im,c,src)).run();rows.append(r);print(json.dumps({'case':len(rows)-1,'config':c,'visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'nesting':r['final_thread_nesting'],'class_bits':bytes.fromhex(r['final_raw_kmsg256_hex'])[0x3f]>>6}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_send_right_lifecycle_profiles.json','probe_kernel_notification_send.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py','recover_kernel_send_right_lifecycle.py']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
