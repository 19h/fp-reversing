#!/usr/bin/env python3
"""Original port init -> turnstile init -> receive pre-block -> original sender.
O(image+visits+RAM+effects), O(image+RAM+journals). Raw turnstile allocation and
CPU/call/loan contexts are declared; no native allocation, blocking or transport.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,HALT
from probe_kernel_waitq_receiver import Probe as Sender,PORT,INNER,RECV,THREAD,SCRATCH
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_waitq_enqueue';PSP=P+0xe8000;ZONE=P+0xa0000;STATS=P+0xa1000;ZCELL=0xfffffe000caec980
PORTINIT=0xfffffe000bccd170;TSALLOC=0xfffffe000bd682cc;UNLOCK=0xfffffe000bd0ab18;RECEIVE=0xfffffe000bcc83b4;BLOCK=0xfffffe000bd28f6c
CONFIGS=[{'interruptibility':0,'thread_limit':2,'priority':0},{'interruptibility':2,'thread_limit':2,'priority':31},{'interruptibility':1,'thread_limit':2,'priority':63,'DAIF_mask':0x200},{'interruptibility':2,'thread_limit':2,'priority':31,'abort_flags':0x10},{'interruptibility':2,'thread_limit':0,'priority':95,'abort_flags':0x10},{'interruptibility':1,'thread_limit':2,'priority':31,'abort_flags':0x30},{'interruptibility':2,'thread_limit':2,'priority':31,'abort_flags':0x30},{'interruptibility':1,'thread_limit':2,'priority':31,'abort_flags':0x10}]
def simd(u):return[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
class Phase(CPU):
 def __init__(self,im,src,c,kind,base,globals,origin):
  super().__init__(im,'selector',{'id':0});self.kind=kind;self.c=c;self.initial=[];self.image_initial=[];self.auth=[];self.sign=[];self.frames=[];self.patches=[];self.u.mem_write(P,base);self.transfer={**origin,**compressed(base)};self.allowed=[(int(f['start'],16),int(f['end'],16))for f in src['functions']]
  for e in globals:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,RECV);self.u.reg_write(ar.UC_ARM64_REG_SP,PSP);self.u.reg_write(ar.UC_ARM64_REG_PSTATE,(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&~0x3c0)|c.get('DAIF_mask',0x3c0))
  for j in range(31):self.set(j,0)
  self.set(30,HALT)
  if kind=='port_init':
   b=bytearray(0x600);struct.pack_into('<Q',b,0xb0,0x11);struct.pack_into('<H',b,0xc8,c['thread_limit']);struct.pack_into('<Q',b,0x1c0,P+0xb4000);struct.pack_into('<I',b,0x1f8,4);struct.pack_into('<I',b,0x210,c.get('abort_flags',0));struct.pack_into('<h',b,0x216,c['priority']);struct.pack_into('<I',b,0x388,44)
   for a,v in[(PORT,bytes(144)),(INNER,bytes(96)),(RECV,bytes(b))]:self.overlay(a,v,'Declared fresh port/turnstile storage and running receiver context')
   self.image_fixture(ZCELL,struct.pack('<QQ',ZONE,STATS));self.entry=PORTINIT;args=[PORT,P+0xdd000,0x101,0,0,0x303]
  elif kind=='port_unlock':self.entry=UNLOCK;args=[PORT+0x14]
  elif kind=='turnstile_allocate':self.entry=TSALLOC;args=[]
  else:
   assert kind=='receive_wait';self.overlay(RECV+0x30,struct.pack('<Q',INNER),'Explicit current-thread loan publication of preceding original allocation result');self.entry=RECEIVE;args=[PORT+0x10,0,c['interruptibility'],RECV,0]
  for j,x in enumerate(args):self.set(j,x)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.entryQ=simd(self.u)
 def image_fixture(self,a,b):self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex()})
 def overlay(self,a,b,why):self.patches.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why});self.fixture(a,b)
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE,(hex(a),n);e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('original_component_returned')
  if a==BLOCK:return self.stop('before_original_thread_block')
  if a==0xfffffe000c62a2b0:return self.stop('before_original_context_guard')
  if a==0xfffffe000bd75c64 and self.kind=='turnstile_allocate':assert self.reg(30)==0xfffffe000bd682f0;return self.model(a,'declared_zeroed_raw_turnstile_allocation',INNER)
  if not any(x<=a<z for x,z in self.allowed):return self.stop('before_unrecovered_original_callee')
  if a in[0xfffffe000bd68474,0xfffffe000bd28280,0xfffffe000bd6bc48,0xfffffe000bd69c78,0xfffffe000bd6be3c,0xfffffe000bcc8914,0xfffffe000bcc8408]:self.frames.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'port144_hex':bytes(u.mem_read(PORT,144)).hex(),'inner96_hex':bytes(u.mem_read(INNER,96)).hex(),'receiver1536_hex':bytes(u.mem_read(RECV,1536)).hex(),'DAIF_mask':hex(u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0)})
  raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
  if i.mnemonic=='pacda':assert raw==self.image.k.read(a,4);self.sign.append({'pc':hex(a),'pointer':hex(self.reg(17)),'modifier':hex(self.reg(16))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason is not None
  return{'kind':self.kind,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(PSP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'entry_Q_registers32':self.entryQ,'entry_DAIF_mask':hex(self.c.get('DAIF_mask',0x3c0)),'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_state_transfer':self.transfer,'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'input_overlays':self.patches,'logical_data_authentication':self.auth,'logical_data_signing':self.sign,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'producer_frames':self.frames,'boundary':self.boundary,'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_image_globals':[{'address':e['address'],'bytes_hex':bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()}for e in self.image_initial],'final_Q_registers32':simd(self.u),'final_DAIF_mask':hex(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0),'final_port144_hex':bytes(self.u.mem_read(PORT,144)).hex(),'final_inner96_hex':bytes(self.u.mem_read(INNER,96)).hex(),'final_receiver1536_hex':bytes(self.u.mem_read(RECV,1536)).hex(),**{k:False for k in FLAGS}}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());ns=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];rows=[];consumers=[];seed=json.loads((ROOT/'kernel_waitq_receiver_profiles.json').read_text())['cases'][1];base=bytearray(decode(seed['initial_state_transfer']))
 for e in seed['initial_private_fixtures']:a=int(e['address'],16)-P;b=bytes.fromhex(e['bytes_hex']);base[a:a+len(b)]=b
 for family,c in enumerate(CONFIGS):
  ram=bytes(base);globals=seed['initial_image_fixtures'];origin={'path':'kernel_waitq_receiver_profiles.json','case':1,'epoch':'Entry RAM after its declared fixtures'}
  for kind in['port_init','port_unlock','turnstile_allocate','receive_wait']:
   r=Phase(im,src,c,kind,ram,globals,origin).run();r['family']=family;rows.append(r);ram=decode(r['final_private_RAM']);globals=r['final_image_globals'];origin={'path':PREFIX+'_profiles.json','case':len(rows)-1,'epoch':'Exact preceding component final RAM'};print(json.dumps({'case':len(rows)-1,'family':family,'kind':kind,'visits':len(r['source_visits']),'boundary':r['boundary']['kind']}),flush=True)
  sender=Sender(im,{'receivers':[{'capacity':44}],'interrupt_mask':c.get('DAIF_mask',0x3c0)},src,ns);sender.u.mem_write(P,ram);sender.image_initial=[]
  for e in globals:sender.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact original enqueue producer global transfer')
  result=sender.run();metadata={k:result.pop(k)for k in['memory_overlays','allocation_environment_overlays','queue_environment_overlays','waitq_environment_overlays','initial_private_fixtures']};result.update(initial_state_transfer={**origin,**compressed(ram)},initial_private_fixtures=[],preparation_metadata_not_reapplied=metadata,family=family,enqueue_configuration=c);consumers.append(result);print(json.dumps({'consumer':family,'visits':len(result['source_visits']),'boundary':result['boundary']['kind']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_waitq_receiver_profiles.json','kernel_send_right_lifecycle_profiles.json','probe_kernel_waitq_receiver.py','probe_kernel_kmsg_queue.py','probe_kernel_kmsg_allocation.py','probe_kernel_notification_send.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py']},'cases':rows,'consumers':consumers,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
