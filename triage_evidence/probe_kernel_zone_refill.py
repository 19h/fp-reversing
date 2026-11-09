#!/usr/bin/env python3
"""Resume actual held refill CPU/RAM state through original refill/fill/bitmap code.
O(visits+RAM+effects), O(image+RAM+journals). Inventory/page/lock epochs are
premises; no whole refill, fill, selection, allocation or zero-check model.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_kernel_kmsg_allocation import AllocationMixin
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_zone_refill';REFILL=0xfffffe000bd75e20;FILL=0xfffffe000bd76db4;SELECT=0xfffffe000bd76ad0;ZONE=0xfffffe000caec680;CACHE=P+0xb2000;STATS=P+0xb1000;THREAD=P+0x2c000;PAGE=P+0xd0000;META=P+0xc0000;BITMAP=P+0xc1000;MAG=P+0xbc000;EMPTY=P+0xbd000;INDEX=PAGE>>14;HEADBASE=0xfffffe000ca8c000

def simd(u):return[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
class Probe(AllocationMixin,CPU):
 def __init__(self,im,c,src,parent):
  super().__init__(im,'selector',{'id':0});self.kind=PREFIX;self.c=c;self.initial=[];self.image_initial=[];self.auth=[];self.sign=[];self.allocation_frames=[];self.frames=[];self.overlays=[];self.alloc_overlays=[];self.allowed=[(int(f['start'],16),int(f['end'],16))for f in src['functions']];self.cache_at=CACHE;self.stats_at=STATS;self.parent=parent;self.entry=REFILL;self.transfer={'path':'kernel_zone_startup_profiles.json','case':7,**parent['final_private_RAM']};self.u.mem_write(P,decode(self.transfer))
  for e in parent['final_image_globals']:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact held-prefix image-global transfer')
  for j,x in enumerate(parent['boundary']['registers31']):self.set(j,int(x,16))
  self.u.reg_write(ar.UC_ARM64_REG_SP,int(parent['boundary']['SP'],16));self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(parent['boundary']['NZCV'],16));self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  for j,x in enumerate(parent['final_Q_registers32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_SP=hex(self.u.reg_read(ar.UC_ARM64_REG_SP));self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.entryQ=simd(self.u)
  self.patch(0xfffffe000cb0bc50,bytes(4),'Declared lock-wakeup epoch0');self.patch(0xfffffe000cb115b0,bytes(4),'Declared lock-instrumentation epoch0');self.patch(0xfffffe000ca92380,bytes([c.get('phase',0)]),'Declared zone phase byte');self.patch(PAGE,bytes(16384),'Declared zero raw element arena');self.patch(PAGE+16384,b'\xa5','Guard outside raw arena')
  mode=c['mode'];quota=c.get('quota',0)
  if quota:self.patch(ZONE+0x7c,struct.pack('<H',quota),'Declared local magazine quota')
  if mode in['shared','local']:
   n=c.get('magazines',1);empty=c.get('empty_magazines',0)
   for k in range(n):
    raw=bytearray(16+16*8);struct.pack_into('<Q',raw,0,MAG+(k+1)*0x100 if k+1<n else EMPTY if mode=='local'and empty else 0)
    for h in range(16):struct.pack_into('<Q',raw,16+h*8,PAGE+k*0x1000+h*256)
    self.patch(MAG+k*0x100,bytes(raw),'Declared full magazine with distinct raw element addresses')
   for k in range(empty):self.patch(EMPTY+k*0x100,struct.pack('<QQ',EMPTY+(k+1)*0x100 if k+1<empty else 0,0),'Declared empty magazine chain')
   if mode=='shared':
    self.patch(ZONE+0x48,struct.pack('<IIQQ',n,0,MAG,MAG+(n-1)*0x100),'Declared shared full/empty counts, head and full-prefix boundary')
    if empty:self.patch(CACHE+0x18,struct.pack('<IIQQ',0,empty,EMPTY,CACHE+0x20),'Declared local empty inventory before shared refill')
   else:
    self.patch(CACHE+0x18,struct.pack('<IIQQ',n,empty,MAG,MAG+(n-1)*0x100),'Declared local full/empty counts, head and full-prefix boundary');self.patch(ZONE+0x58,struct.pack('<Q',ZONE+0x50),'Declared empty shared prefix boundary')
   if c.get('security_bit12'):self.patch(0xfffffe0007e6a7a0+4*24,struct.pack('<I',1<<12),'Controlled selected zone-security bit12')
  if mode=='page':
   used=c.get('used',16);free=c.get('bitmap',((1<<64)-1)^((1<<used)-1));cursor=c.get('cursor',0)
   self.patch(ZONE+0x9c,struct.pack('<I',INDEX),'Declared partial-page list head');self.patch(ZONE+0xa8,struct.pack('<I',64-used),'Declared available raw elements');self.patch(ZONE+0xb0,bytes(4),'Declared no pending reserve');self.patch(0xfffffe0007e66f00,struct.pack('<Q',META-INDEX*16),'Declared biased page-metadata array base');self.patch(0xfffffe0007e66e70,struct.pack('<Q',BITMAP),'Declared external bitmap array base');self.patch(META,struct.pack('<HHIII',0x1018,used,0,0,(ZONE+0x9c-(HEADBASE-4))>>2),'Declared one-page ID24 partial metadata and head backlink');self.patch(BITMAP,struct.pack('<Q',free),'Declared free-bit bitmap with one bit per available element');self.patch(STATS+0x18,struct.pack('<I',cursor),'Declared allocation-selection cursor')
 def image_fixture(self,a,b,why):self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':why})
 def patch(self,a,b,why):
  self.ensure(a,len(b));self.overlays.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why})
  if P<=a<a+len(b)<=P+SIZE:self.fixture(a,b)
  else:self.image_fixture(a,b,why)
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or ZONE<=a<a+n<=ZONE+192,(hex(a),n);e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('original_constructor_returned_after_refill')
  if a in[REFILL,FILL,SELECT,0xfffffe000bd75de4,0xfffffe000bd76294,0xfffffe000bd76f70,0xfffffe000bd77210]:self.frames.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments5':[hex(self.reg(j))for j in range(5)],'zone192_hex':bytes(u.mem_read(ZONE,192)).hex(),'cache64_hex':bytes(u.mem_read(CACHE,64)).hex(),'stats32_hex':bytes(u.mem_read(STATS,32)).hex(),'metadata16_hex':bytes(u.mem_read(META,16)).hex(),'bitmap8_hex':bytes(u.mem_read(BITMAP,8)).hex(),'thread_nesting':int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little')})
  if a==0xfffffe000bd0ae78:
   assert self.reg(0)in[CACHE,ZONE+0x80];return self.model(a,'declared_lock_acquisition',0)
  if a in[0xfffffe000bd769d8,0xfffffe000bd71c10]:return self.stop('before_original_page_supply',{'requested_entry':hex(a)})
  if a>=0xfffffe000c633000 and a<0xfffffe000c634000:return self.stop('before_original_allocation_guard',{'requested_entry':hex(a)})
  if a==REFILL:return CPU.code(self,u,a,n,d)
  if self.allocation_code(u,a,n,d):return
  if not any(x<=a<z for x,z in self.allowed):return self.stop('before_uncaptured_refill_code',{'requested_entry':hex(a)})
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason is not None;g=[]
  for e in self.image_initial:
   a=int(e['address'],16);n=len(e['bytes_hex'])//2
   if not any(int(old['address'],16)<=a and a+n<=int(old['address'],16)+len(old['bytes_hex'])//2 for old in g):g.append({'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()})
  result=int(self.boundary['registers31'][0],16);returned=self.boundary['kind']=='original_constructor_returned_after_refill'
  return{'configuration':self.c,'zone_address':hex(ZONE),'selected_cache_address':hex(CACHE),'selected_statistics_address':hex(STATS),'entry_PC':hex(self.entry),'entry_SP':self.entry_SP,'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'entry_Q_registers32':self.entryQ,'final_Q_registers32':simd(self.u),'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_state_transfer':self.transfer,'private_system_register_fixtures':[{'register':'TPIDR_EL1','value':hex(THREAD)}],'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'memory_overlays':self.overlays,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_data_authentication':self.auth,'logical_data_signing':self.sign,'startup_frames':[],'allocation_frames':self.allocation_frames,'refill_frames':self.frames,'boundary':self.boundary,'final_zone192_hex':bytes(self.u.mem_read(ZONE,192)).hex(),'final_cache64_hex':bytes(self.u.mem_read(CACHE,64)).hex(),'final_statistics32_hex':bytes(self.u.mem_read(STATS,32)).hex(),'final_metadata16_hex':bytes(self.u.mem_read(META,16)).hex(),'final_bitmap8_hex':bytes(self.u.mem_read(BITMAP,8)).hex(),'final_returned_element256_hex':bytes(self.u.mem_read(result,256)).hex()if returned else None,'final_raw_arena16384_hex':bytes(self.u.mem_read(PAGE,16384)).hex(),'raw_arena_guard_hex':bytes(self.u.mem_read(PAGE+16384,1)).hex(),'final_thread_nesting':int.from_bytes(bytes(self.u.mem_read(THREAD+0x1c8,4)),'little'),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_image_globals':g,**{k:False for k in FLAGS}}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());parent=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'][7];assert parent['boundary']['kind']=='before_original_cache_refill';configs=[{'mode':'empty'},{'mode':'shared'},{'mode':'shared','magazines':2},{'mode':'local','quota':2},{'mode':'local','quota':2,'empty_magazines':4},{'mode':'shared','quota':2,'magazines':2},{'mode':'shared','quota':2,'magazines':2,'security_bit12':True},{'mode':'page'},{'mode':'page','used':63},{'mode':'page','cursor':63,'bitmap':((1<<64)-1)^(((1<<16)-1)<<16)},{'mode':'shared','quota':2,'magazines':2,'empty_magazines':4},{'mode':'page','phase':255}];rows=[]
 for c in configs:
  r=Probe(im,c,src,parent).run();rows.append(r);print(json.dumps({'case':len(rows)-1,'configuration':c,'visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'X0':r['boundary']['registers31'][0],'nesting':r['final_thread_nesting']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_zone_startup_profiles.json','probe_kernel_vm_mig.py','probe_kernel_kmsg_allocation.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py','recover_kernel_send_right_lifecycle.py']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
