#!/usr/bin/env python3
"""Source environment, original kext constructor and kernel RPC request prefix.
O(image+source visits+RAM+effects), O(image+RAM+journals). Raw backing, initial
cache inventory, namespace/host/thread epochs, copy/hash/tag/preflight and PAC
remain declared. No native host IPC, VM, kernel scheduling or authentication.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,HALT
from probe_kernel_special_reply import Zone
from probe_rpc502_vm_handoff import compressed,decode
from probe_kext_constructor_request import Probe as ConstructorParent
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_rpc_request';THREAD=P+0x60000;OWNER=P+0x5c000;TASK=P+0x987c0;STATS=P+0x58000;CPU_DATA=P+0xb4000;D0=P+0xc0070;D1=P+0xc0100;REPLY=P+0x80070;TS=P+0xa8040;KMSG=P+0xd0000;KS=P+0x54000;RS=P+0x54100;SERVER=P+0xdd000;TABLE=0x400000100000;HOST=0xfffffe000cad0238;PSP=P+0xe8000;META=(P+0x9c000-((KMSG>>10)&0xffffffff0))&((1<<64)-1)
def qregs(u):return[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
class Aux:
 def ensure(self,a,n=1):
  if TABLE<=a<a+n<=TABLE+4096:
   if TABLE not in self.pages:self.u.mem_map(TABLE,4096);self.u.mem_write(TABLE,bytes(4096));self.pages.add(TABLE)
   return
  return super().ensure(a,n)
 def global_fixture(self,a,b,why):self.ensure(a,len(b));before=bytes(self.u.mem_read(a,len(b)));self.u.mem_write(a,b);self.overlays.append({'space':'global','address':hex(a),'before_hex':before.hex(),'after_hex':b.hex(),'reason':why});self._remember(a,b)
 def _remember(self,a,b):
  found=False
  for e in self.image_initial:
   at=int(e['address'],16);n=len(e['bytes_hex'])//2
   if max(at,a)<min(at+n,a+len(b)):e['bytes_hex']=bytes(self.u.mem_read(at,n)).hex()
   found|=at==a and n==len(b)
  if not found:self.image_initial.append({'address':hex(a),'bytes_hex':b.hex()})
 def overlay(self,a,b,why):self.overlays.append({'space':'private','address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why});self.fixture(a,b)
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or TABLE<=a<a+n<=TABLE+4096 or HOST+8<=a<a+n<=HOST+16 or a in[0xfffffe0007e62b68,0xfffffe0007e63348] or 0xfffffe000ccc0000<=a<a+n<=0xfffffe000ccd0000,(hex(a),n)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
class Environment(Aux,CPU):
 def __init__(self,im,src,c,kind,parent,origin,zones):
  super().__init__(im,'selector',{'id':0});self.kind=kind;self.c=c;self.initial=[];self.image_initial=[];self.overlays=[];self.auth=[];self.sign=[];self.frames=[];self.allocations=[];self.allowed=[(int(f['start'],16),int(f['end'],16))for f in src['functions']];self.transfer={**origin,**compressed(parent['ram'])};self.u.mem_write(P,parent['ram'])
  for e in parent['globals']:self.ensure(int(e['address'],16),len(e['bytes_hex'])//2);self.u.mem_write(int(e['address'],16),bytes.fromhex(e['bytes_hex']));self.image_initial.append(dict(e))
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD);self.u.reg_write(ar.UC_ARM64_REG_SP,PSP);self.u.reg_write(ar.UC_ARM64_REG_PSTATE,(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&~0x3c0)|0x3c0)
  for j in range(31):self.set(j,0)
  self.set(30,HALT)
  if kind=='bootstrap':
   th=bytearray(1536);struct.pack_into('<Q',th,0xb0,0x11);struct.pack_into('<Q',th,0x1c0,CPU_DATA);struct.pack_into('<I',th,0x1f8,4);struct.pack_into('<Q',th,0x420,OWNER);struct.pack_into('<I',th,0x518,0x1234);th[0x43b]=0x11;own=bytearray(56);struct.pack_into('<Q',own,0,THREAD);struct.pack_into('<Q',own,0x28,TASK);table=bytearray(4096);struct.pack_into('<QIIQ',table,72,D0,0x20001,0,0);struct.pack_into('<QIIQ',table,96,D1,0x20001,0,0)
   for a,b in[(THREAD,bytes(th)),(OWNER,bytes(own)),(TASK-0x7c0,bytes(0xe90)),(TASK+0x318,struct.pack('<Q',KS)),(TASK+0x3d0,struct.pack('<Q',STATS)),(STATS,bytes(32)),(CPU_DATA,bytes(0x300)),(D0,bytes(144)),(D1,bytes(144)),(REPLY,bytes(144)),(TS,bytes(96)),(KS,bytes(128)),(RS,bytes(128)),(SERVER,bytes(128)),(SERVER+0x48,struct.pack('<Q',TABLE|5)),(KMSG,bytes(256)),(KMSG+256,b'\xa5')]:self.overlay(a,b,'Declared kernel-thread/host/recipient and raw object epoch')
   for a,typ in[(D0,22),(D1,22),(REPLY,22),(TS,28),(KMSG,24),(OWNER,3),(TASK-0x7c0,26),(KS,40),(SERVER,40)]:self.overlay(META+((a>>10)&0xffffffff0),struct.pack('<H',typ),'Declared typed allocation metadata')
   for z in zones:
    for e in z['source_private_regions']:self.overlay(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact original zone producer private-record import')
    self.global_fixture(int(z['zone_address'],16),bytes.fromhex(z['final_zone192_hex']),'Exact original zone-record import')
   # Explicit populated-cache epoch; original allocator consumes the slot.
   self.overlay(P+0x4d004,struct.pack('<H',1),'Declared one-element current cache inventory after source startup');self.overlay(P+0x4e010,struct.pack('<Q',KMSG),'Declared raw zeroed kmsg cache element')
   for a,b in[(0xfffffe0007e66e50,struct.pack('<QQ',P,P+SIZE)),(0xfffffe0007e66f00,struct.pack('<Q',META)),(0xfffffe0007e66ea0,struct.pack('<QQ',P,P+SIZE)),(0xfffffe0007e6d038,struct.pack('<I',0x40000)),(0xfffffe0007e5c470,struct.pack('<Q',int(zones[2]['zone_address'],16))),(0xfffffe0007e62b68,bytes(8)),(0xfffffe0007e63348,bytes(8)),(0xfffffe0007e5c221,bytes(1)),(HOST+8,bytes(8)),(HOST+0x10+17*8,struct.pack('<Q',D0)),(HOST+0x10+34*8,struct.pack('<Q',D1)),(TABLE,bytes(table))]:self.global_fixture(a,b,'Declared pool/type/host/table/policy epoch or source ipc-space-zone publication')
  if kind=='bootstrap':self.entry=0xfffffe000c629780;args=[]
  elif kind.startswith('dest_init'):self.entry=0xfffffe000bccd170;args=[D0 if kind.endswith('0')else D1,SERVER,0x101,0,0,0x303 if kind.endswith('0')else 0x403]
  elif kind.startswith('dest_unlock'):self.entry=0xfffffe000bd0ab18;args=[(D0 if kind.endswith('0')else D1)+0x14]
  elif kind=='reply_create':self.entry=0xfffffe000bcf8e14;args=[]
  else:raise AssertionError(kind)
  for j,v in enumerate(args):self.set(j,v)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entryQ=qregs(self.u);self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('original_environment_component_returned')
  if a==0xfffffe000c62982c and self.kind=='bootstrap':return self.stop('before_unrelated_bootstrap_kernel_object')
  if a==0xfffffe000bd75c64:
   count=len(self.allocations);ret=[KS,RS][count]if self.kind=='bootstrap'else REPLY;self.allocations.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'returned_pointer':hex(ret)});return self.model(a,'declared_raw_special_space_storage'if self.kind=='bootstrap'else'declared_raw_reply_port_storage',ret)
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_unrecovered_environment_callee')
  raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
  if i.mnemonic in ['autda','pacda']:
   rr=[int(s.strip()[1:])for s in i.op_str.split(',')];e={'pc':hex(a),'registers':rr,'pointer':hex(self.reg(rr[0])),'modifier':hex(self.reg(rr[1]))};(self.auth if i.mnemonic=='autda'else self.sign).append(e);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason is not None
  return {'kind':self.kind,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(PSP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'entry_Q_registers32':self.entryQ,'entry_DAIF_mask':'0x3c0','current_thread':hex(THREAD),'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_state_transfer':self.transfer,'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'input_overlays':self.overlays,'logical_data_authentication':self.auth,'logical_data_signing':self.sign,'raw_allocations':self.allocations,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'boundary':self.boundary,'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_image_globals':[{'address':e['address'],'bytes_hex':bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()}for e in self.image_initial],'final_Q_registers32':qregs(self.u),'final_DAIF_mask':hex(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0),**{k:False for k in FLAGS}}
WATCH=[0xfffffe000bcf27ac,0xfffffe000bcf258c,0xfffffe000bcf5e28,0xfffffe000bcf59e0,0xfffffe000bcc68c4,0xfffffe000bcc24a4,0xfffffe000bd75c64,0xfffffe000bcc2390,0xfffffe000bcc6b10,0xfffffe000bcc9718,0xfffffe000bcd0628,0xfffffe000bcc7040,0xfffffe000bcc7c34,0xfffffe000bccef30,0xfffffe000bcf5c18,0xfffffe000bcc83b4]
class Request(Aux,ConstructorParent):
 def __init__(self,im,src,c,parent,origin):
  super().__init__(im,c);caller_private=self.initial;caller_global=self.image_initial;self.initial=[];self.image_initial=[];self.overlays=[];self.auth=[];self.sign=[];self.frames=[];self.hashes=[];self.raw=[];self.handoff=None;self.transfer={**origin,**compressed(parent['ram'])};self.u.mem_write(P,parent['ram'])
  # ConstructorParent installs globals eagerly; restore original bytes before
  # applying the independently source-produced environment and caller overlays.
  for e in caller_global:
   a=int(e['address'],16);n=len(e['bytes_hex'])//2;self.u.mem_write(a,im.logical_page(a&~4095)[a&4095:(a&4095)+n])
  for e in parent['globals']:
   a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append(dict(e))
  for e in caller_private:self.overlay(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Explicit constructor name/output/staging caller epoch')
  for e in caller_global:self.global_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Explicit constructor initialized/map/page-shift epoch')
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD);self.u.reg_write(ar.UC_ARM64_REG_PSTATE,(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&~0x3c0)|0x3c0);self.entryQ=qregs(self.u);self.entrySP=hex(self.u.reg_read(ar.UC_ARM64_REG_SP));self.allowed+= [(int(f['start'],16),int(f['end'],16))for f in src['functions']];self.kext_ranges=self.allowed[:1];self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def record_frame(self,a):
  e={'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP))}
  for at,n,key in[(THREAD,1536,'thread1536_hex'),(D0,144,'destination0_144_hex'),(D1,144,'destination1_144_hex'),(REPLY,144,'reply144_hex'),(TS,96,'turnstile96_hex'),(KMSG,256,'kmsg256_hex')]:e[key]=bytes(self.u.mem_read(at,n)).hex()
  self.frames.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a in WATCH:self.record_frame(a)
  if a==0xfffffe000bcf5e28:
   self.handoff={'pc':hex(a),'source_visit_index':len(self.visits),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'NZCV':hex(u.reg_read(ar.UC_ARM64_REG_NZCV)),'Q_registers32':qregs(u),'DAIF_mask':hex(u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0),'TPIDR_EL1':hex(u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)),'message_address':hex(self.reg(0)),'message88_hex':bytes(u.mem_read(self.reg(0),88)).hex(),'private_RAM':compressed(bytes(u.mem_read(P,SIZE))),'handoff_overlays':[]}
  if a==0xfffffe000bcc83b4:return self.stop('before_original_common_RPC_receive')
  if a==HALT:return self.stop('constructor_returned_before_receive')
  if a==0xfffffe000bd75c64 and self.reg(0)in[0xfffffe000caec500,0xfffffe000caec980]:
   ptr=REPLY if self.reg(0)==0xfffffe000caec500 else TS;nbytes=144 if ptr==REPLY else 96;self.raw.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'returned_pointer':hex(ptr),'object_before_hex':bytes(u.mem_read(ptr,nbytes)).hex()});return self.model(a,'declared_raw_reply_port_storage'if ptr==REPLY else'declared_raw_turnstile_storage',ptr)
  if a==0xfffffe000bc9d90c:
   self.hashes.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'bytes_hex':bytes(u.mem_read(self.reg(0),self.reg(1))).hex()});return self.model(a,'opaque_keyed_hash_result',0x123456789abcdef0)
  if a==0xfffffe000c647f10:
   dst,src,size=[self.reg(j)for j in range(3)];self.effect(dst,bytes(u.mem_read(src,size)),'Explicit disjoint byte-copy primitive');return self.modeled(a,'declared_byte_copy',dst)
  if a in[0xfffffe000bcc0f9c,0xfffffe000bcd9f3c]:return self.model(a,'declared_send_preflight'if a==0xfffffe000bcc0f9c else'declared_message_tag_helper',0)
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_unrecovered_request_callee')
  raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert raw==self.image.k.read(a,4)
  if i.mnemonic=='brk':return self.stop('before_original_request_trap',{'instruction':i.op_str})
  if i.mnemonic in['autda','pacda']:
   rr=[int(s.strip()[1:])for s in i.op_str.split(',')];(self.auth if i.mnemonic=='autda'else self.sign).append({'pc':hex(a),'visit':len(self.visits),'registers':rr,'pointer':hex(self.reg(rr[0])),'modifier':hex(self.reg(rr[1]))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if i.mnemonic in['blraa','braa'] and self.reg(int(i.op_str.split(',')[0][1:])) in[0xfffffe000bcf27ac,0xfffffe000bcf258c]:
   rr=[int(s.strip()[1:])for s in i.op_str.split(',')];target=self.reg(rr[0]);self.edges.append({'pc':hex(a),'visit':len(self.visits),'kind':i.mnemonic,'target':hex(target),'modifier':hex(self.reg(rr[1]))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.calls.append({'pc':hex(a),'target':hex(target),'args8':[hex(self.reg(j))for j in range(8)]});self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,target);return
  if any(lo<=a<hi for lo,hi in self.kext_ranges):return ConstructorParent.code(self,u,a,n,d)
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry)
  try:self.u.emu_start(self.entry,0,count=400000)
  except Exception:
   print({'failure_pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),'args8':[hex(self.reg(j))for j in range(8)],'last_visits':self.visits[-4:]},flush=True);raise
  self.flush();assert self.reason is not None
  return {'kind':'constructor_RPC_request','configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':self.entrySP,'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'entry_Q_registers32':self.entryQ,'entry_DAIF_mask':'0x3c0','current_thread':hex(THREAD),'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_state_transfer':self.transfer,'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'input_overlays':self.overlays,'logical_data_authentication':self.auth,'logical_data_signing':self.sign,'logical_edges':self.edges,'calls':self.calls,'snapshots':self.snapshots,'allocations':self.allocs,'raw_storage_contracts':self.raw,'opaque_hash_inputs':self.hashes,'request_frames':self.frames,'continuous_constructor_handoff':self.handoff,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'boundary':self.boundary,'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_image_globals':[{'address':e['address'],'bytes_hex':bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()}for e in self.image_initial],'final_Q_registers32':qregs(self.u),'final_DAIF_mask':hex(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0),**{k:False for k in FLAGS}}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());zs=json.loads((ROOT/'kernel_zone_startup_source.json').read_text());zones=[]
 for name,base in [('ipc ports',P+0x40000),('turnstiles',P+0x44000),('ipc spaces',P+0x48000),('ipc kmsgs',P+0x4c000)]:
  e=next(e for e in src['rpc_zone_entries']if e['name']==name);z=Zone(im,{'identifier':e['identifier_u16'],'storage_base':base},zs,e).run();assert z['boundary']['kind']=='startup_callback_returned';zones.append(z);print(json.dumps({'zone':name,'visits':len(z['source_visits'])}),flush=True)
 env=[];requests=[]
 for family,(mode,prebound)in enumerate([(1,False),(1,True),(0,False),(0,True)]):
  c={'page_shift':14,'length':28,'cpu_type':0x100000c,'cpu_subtype':0,'origin':1,'mode':mode,'prebound_reply':prebound};parent={'ram':bytes(SIZE),'globals':[]};origin={'path':'explicit_zero_RAM','case':None};kinds=['bootstrap','dest_init0','dest_unlock0','dest_init1','dest_unlock1']+(['reply_create']if prebound else[])
  for kind in kinds:
   r=Environment(im,src,c,kind,parent,origin,zones).run();r['family']=family;env.append(r);print(json.dumps({'family':family,'kind':kind,'pc':r['boundary']['pc'],'visits':len(r['source_visits'])}),flush=True);assert r['boundary']['kind']in['original_environment_component_returned','before_unrelated_bootstrap_kernel_object'],r['boundary'];parent={'ram':decode(r['final_private_RAM']),'globals':r['final_image_globals']};origin={'path':PREFIX+'_profiles.json','environment':len(env)-1}
  r=Request(im,src,c,parent,origin).run();r['family']=family;requests.append(r);print(json.dumps({'family':family,'request_boundary':r['boundary'],'visits':len(r['source_visits'])}),flush=True)
 deps=[PREFIX+'_source.json','probe_kernel_special_reply.py','probe_kernel_zone_startup.py','probe_kext_constructor_request.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'zone_producers':zones,'environment':env,'requests':requests,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
