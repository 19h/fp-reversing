#!/usr/bin/env python3
"""Original fixed-zone startup/creator/cache initialization in private shadow.
O(visits+RAM+effects), O(image+RAM+journals). Bootstrap count/flags, raw per-CPU
storage/magazines and locks are premises; no native boot, IPC or PAC executes.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from probe_kernel_kmsg_allocation import AllocationMixin
PREFIX='kernel_zone_startup';ARRAY=0xfffffe000caeb480;STARTUP=0xfffffe000c63222c;CREATE=0xfffffe000bd772b4;CACHEINIT=0xfffffe000bd77bb0;STATS=P+0xb1000;CACHE=P+0xb2000;MAGVIEW=P+0x88000;MAGZONE=P+0x8a000;MAGSTATS=P+0x8b000;PUB=P+0x8000
def simd(u):return[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
class Probe(CPU):
 def __init__(self,im,c,src,entry):
  super().__init__(im,'selector',{'id':0});self.kind=PREFIX;self.c=c;self.initial=[];self.image_initial=[];self.auth=[];self.sign=[];self.frames=[];self.magazines=[];self.entry=STARTUP;self.ident=entry['identifier_u16'];self.zone=ARRAY+192*self.ident;self.spec=int(entry['specification_address'],16);self.catalog_entry=entry;self.allowed=[(int(f['start'],16),int(f['end'],16))for f in src['functions']]
  self.image_fixture(self.zone,bytes(192),'Declared uncreated fixed-zone shadow');self.image_fixture(0xfffffe000caeb45a,struct.pack('<H',40),'Declared bootstrap epoch with fixed slots reserved');self.image_fixture(0xfffffe000cb7f2c8,bytes(2),'Declared created-zone count epoch0');self.image_fixture(0xfffffe0007f8b5f0,bytes(4),'Declared phase word0, preserve original zone name');self.image_fixture(0xfffffe000caeb600,struct.pack('<Q',0xfffffe000caeb600),'Declared ready allocation-context slot2 self pointer');self.image_fixture(0xfffffe0007e66f38,struct.pack('<I',c.get('instances',1)),'Declared per-CPU storage instance count');self.image_fixture(0xfffffe0007e6a248,struct.pack('<H',c.get('magazine_capacity',16)),'Declared magazine entry-capacity word');self.image_fixture(0xfffffe0007e66e38,struct.pack('<I',c.get('cache_budget',0x100000)),'Declared cache budget word');self.image_fixture(0xfffffe0007e66f58,struct.pack('<Q',MAGVIEW),'Declared magazine allocation view');self.image_fixture(0xfffffe0007e6a7a0+4*self.ident,bytes(4),'Declared selected zone-security entry epoch0');self.fixture(MAGVIEW,struct.pack('<QQ',MAGZONE,MAGSTATS));self.fixture(PUB,b'\xa5'*8)
  if c.get('publication_variant'):self.image_fixture(self.spec,struct.pack('<Q',PUB),'Controlled optional-publication slot variant')
  if 'size_variant'in c:self.image_fixture(self.spec+16,struct.pack('<Q',c['size_variant']),'Controlled size variant, not original startup specification')
  self.set(0,self.spec);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.entryQ=simd(self.u)
 def image_fixture(self,a,b,why):self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':why})
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or self.zone<=a<a+n<=self.zone+192 or 0xfffffe000cb7f2c8<=a<a+n<=0xfffffe000cb7f2ca or 0xfffffe000caeb45a<=a<a+n<=0xfffffe000caeb45c or 0xfffffe0007e6a7a0+4*self.ident<=a<a+n<=0xfffffe0007e6a7a4+4*self.ident,(hex(a),n)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('startup_callback_returned')
  if a==0xfffffe000c62a2b0:return self.stop('before_original_startup_failure')
  if a in[STARTUP,CREATE,CACHEINIT,0xfffffe000bd77480,0xfffffe000bd77714,0xfffffe000c632254]:self.frames.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments5':[hex(self.reg(j))for j in range(5)],'zone192_hex':bytes(u.mem_read(self.zone,192)).hex()})
  if a==0xfffffe000bd71a20:
   assert self.reg(0)==0xfffffe000caeb600 and(self.reg(1),self.reg(2))in[(32,7),(64,0x3f)];return self.model(a,'declared_raw_percpu_statistics_storage'if self.reg(1)==32 else'declared_raw_percpu_cache_storage',STATS if self.reg(1)==32 else CACHE)
  if a==0xfffffe000bd75c64:
   idx=len(self.magazines);ptr=P+0xb2ff0+idx*0x100;assert self.reg(0)==MAGZONE and self.reg(1)==MAGSTATS and self.reg(2)==0x8004;self.magazines.append({'index':idx,'pointer':hex(ptr)});return self.model(a,'declared_raw_magazine_storage',ptr)
  callbacks={0xfffffe000bd0bfa4:'declared_registry_lock',0xfffffe000bd0c2cc:'declared_registry_unlock',0xfffffe000bd0aab4:'declared_zone_lock',0xfffffe000bd0ab18:'declared_zone_unlock'}
  if a in callbacks:return self.model(a,callbacks[a],0)
  if not any(x<=a<z for x,z in self.allowed):return self.stop('before_unmodeled_startup_code')
  raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert raw==self.image.k.read(a,4)
  if i.mnemonic in['autda','pacda']:
   target=self.auth if i.mnemonic=='autda'else self.sign;target.append({'pc':hex(a),'pointer':hex(self.reg(16 if i.mnemonic=='autda'else 17)),'modifier':hex(self.reg(17 if i.mnemonic=='autda'else 16))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if i.mnemonic in['brk','blraa']:return self.stop('before_unmodeled_authenticated_setup',{'instruction':i.mnemonic+' '+i.op_str})
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason is not None;addrs=list(dict.fromkeys((int(e['address'],16),len(e['bytes_hex'])//2)for e in self.image_initial));return{'configuration':self.c,'catalog_entry_address':self.catalog_entry['entry_address'],'identifier':self.ident,'zone_address':hex(self.zone),'specification_address':hex(self.spec),'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'entry_Q_registers32':self.entryQ,'final_Q_registers32':simd(self.u),'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_data_authentication':self.auth,'logical_data_signing':self.sign,'startup_frames':self.frames,'raw_magazine_returns':self.magazines,'boundary':self.boundary,'final_zone192_hex':bytes(self.u.mem_read(self.zone,192)).hex(),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in addrs],'final_statistics32_hex':bytes(self.u.mem_read(STATS,32)).hex(),'final_cache_instances64_hex':[bytes(self.u.mem_read(CACHE+(j<<14),64)).hex()for j in range(self.c.get('instances',1))],'publication_u64':int.from_bytes(bytes(self.u.mem_read(PUB,8)),'little'),**{k:False for k in FLAGS}}
class Consumer(AllocationMixin,CPU):
 def __init__(self,im,c,src,parent,index):
  super().__init__(im,'selector',{'id':0});self.kind=PREFIX;self.c=c;self.initial=[];self.image_initial=[];self.auth=[];self.sign=[];self.allocation_frames=[];self.alloc_overlays=[];self.entry=0xfffffe000bcc24a4;self.allowed=[(int(f['start'],16),int(f['end'],16))for f in src['functions']];self.zone=int(parent['zone_address'],16);self.cpu_index=c.get('cpu_index',0);self.cache_at=CACHE+(self.cpu_index<<14);self.stats_at=STATS+(self.cpu_index<<14);self.transfer={'path':PREFIX+'_profiles.json','case':index,**parent['final_private_RAM']};self.u.mem_write(P,decode(self.transfer))
  for e in parent['final_image_globals']:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact original startup output transfer')
  self.fixture(P+0xd0000,bytes(256));self.fixture(P+0xd0100,b'\xa5');self.fixture(P+0x2c1b8,struct.pack('<H',self.cpu_index));self.fixture(P+0x2c1c0,struct.pack('<Q',P+0xb4000));self.fixture(P+0x2c1c8,bytes(4));self.fixture(P+0xb4000,bytes(80));self.slot=int.from_bytes(bytes(self.u.mem_read(self.cache_at+8,8)),'little')
  if c.get('fill_cache'):self.fixture(self.cache_at+4,struct.pack('<H',1));self.fixture(self.slot,struct.pack('<Q',P+0xd0000))
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,P+0x2c000)
  for j,x in enumerate([44,0,0,1]):self.set(j,x)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.entryQ=simd(self.u);self.parent=parent
 def image_fixture(self,a,b,why):self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':why})
 def code(self,u,a,n,d):
  if a==HALT:return self.stop('consumer_allocator_returned')
  if self.allocation_code(u,a,n,d):return
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason is not None
  return{'configuration':self.c,'identifier':24,'zone_address':hex(self.zone),'initial_state_transfer':self.transfer,'selected_cache_address':hex(self.cache_at),'selected_statistics_address':hex(self.stats_at),'current_slot_address':hex(self.slot),'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'entry_Q_registers32':self.entryQ,'final_Q_registers32':simd(self.u),'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'private_system_register_fixtures':[{'register':'TPIDR_EL1','value':hex(P+0x2c000)}],'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_data_authentication':self.auth,'logical_data_signing':self.sign,'startup_frames':[],'allocation_frames':self.allocation_frames,'boundary':self.boundary,'final_zone192_hex':bytes(self.u.mem_read(self.zone,192)).hex(),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_image_globals':[{'address':e['address'],'bytes_hex':bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()}for e in self.image_initial],'final_statistics32_hex':bytes(self.u.mem_read(self.stats_at,32)).hex(),'final_cache_instances64_hex':[bytes(self.u.mem_read(CACHE+(j<<14),64)).hex()for j in range(self.parent['configuration'].get('instances',1))],'final_kmsg256_hex':bytes(self.u.mem_read(P+0xd0000,256)).hex(),'final_slot16_hex':bytes(self.u.mem_read(self.slot,16)).hex(),'final_thread_nesting':int.from_bytes(bytes(self.u.mem_read(P+0x2c1c8,4)),'little'),'raw_kmsg_guard_hex':bytes(self.u.mem_read(P+0xd0100,1)).hex(),**{k:False for k in FLAGS}}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());rows=[]
 for ident,c in[(24,{}),(22,{}),(23,{}),(24,{'instances':2}),(24,{'cache_budget':0xffffffff,'magazine_capacity':1}),(24,{'publication_variant':True}),(24,{'size_variant':257})]:
  c={'identifier':ident,**c};entry=next(e for e in src['zone_startup_entries']if e['identifier_u16']==ident);r=Probe(im,c,src,entry).run();rows.append(r);print(json.dumps({'case':len(rows)-1,'config':c,'visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'zone':r['zone_address']}),flush=True)
 for index,c in[(0,{'phase':'consumer','fill_cache':False}),(0,{'phase':'consumer','fill_cache':True}),(3,{'phase':'consumer','fill_cache':True,'cpu_index':1})]:
  r=Consumer(im,c,src,rows[index],index).run();rows.append(r);print(json.dumps({'case':len(rows)-1,'config':c,'visits':len(r['source_visits']),'boundary':r['boundary']['kind']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','probe_kernel_vm_mig.py','probe_kernel_kmsg_allocation.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py','recover_kernel_send_right_lifecycle.py']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
