#!/usr/bin/env python3
"""Original constructor prefixes with declared replies/VM/time and startup frontier.
O(image bytes+visits+fixture bytes), O(image bytes+private RAM+journals).
No native IPC, application, VM, clock, logger, hardware or PAC effects.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kext_constructor_request import Probe as Request,P,SP,HALT,STAGING,NAME,OUT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_constructor_request import sha
PREFIX='kext_constructor_reply_state';MAPPED=P+0x88000;REPCOPY=P+0x87000;MT=0xfffffe000cccb088
class Probe(Request):
 def __init__(self,im,c):
  super().__init__(im,c);self.extra_models=[];self.state_snapshots=[];self.transport_request=None;self.declared_reply=None
  if not c['warm']:
   self.u.mem_write(0xfffffe000ccca078,b'\0')
   for f in self.image_initial:
    if f['address']=='0xfffffe000ccca078':f['bytes_hex']='00'
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000a5b5180:
   assert self.reg(13)==0;return self.stop('before_unavailable_address_table_load',{'effective_address':'0x0','mask_cell':'0xfffffe000ccceaf8','table_base_cell':'0xfffffe000cccda68','native_validity':'unknown'})
  if a in [0xfffffe000a612530,0xfffffe000a611288,0xfffffe000a5b4eac,0xfffffe000a5b4f18]:
   if a!=0xfffffe000a5b4eac or not any(s['pc']==hex(a)for s in self.state_snapshots):self.state_snapshots.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
  if a==0xfffffe000bcf5e28:
   assert self.c['warm'];self.transport_request=bytes(u.mem_read(self.reg(0),88)).hex();msg=self.reg(0);mid=602 if self.c['mode']==1 else 800;b=bytearray(392);struct.pack_into('<IIQQII',b,0,0x80000000,392,0,0,0,mid);struct.pack_into('<I',b,32,2);struct.pack_into('<QII',b,36,REPCOPY,0x01000101,4096);struct.pack_into('<QII',b,52,0,0x01000101,0);b[68:76]=bytes.fromhex('0000000001000000');struct.pack_into('<I',b,76,0xbeefed02);struct.pack_into('<II',b,384,4096,0);self.declared_reply=bytes(b).hex();self.effect(msg,bytes(b),'Explicit successful internal reply model, no application execution or native conversion');return self.modeled(a,'transport_reply_model',0)
  if a==0xfffffe000a508e34:
   args=[self.reg(j)for j in range(3)];assert args[0]==P+0x84000 and args[2]==REPCOPY;self.effect(args[1],struct.pack('<Q',MAPPED),'Opaque mapped-address copyout result');return self.modeled(a,'copyout_model',0)
  if a==0xfffffe000a508e0c:
   assert[self.reg(j)for j in range(5)]==[P+0x84000,MAPPED,MAPPED+0x4000,3,0];return self.modeled(a,'wire_model',self.c['wire_return'])
  if a==0xfffffe000bce3a8c:
   self.effect(self.reg(0),struct.pack('<Q',1700000000),'Declared seconds64');self.effect(self.reg(1),struct.pack('<I',123456),'Declared microseconds32');return self.modeled(a,'calendar_time_model',0)
  if a==0xfffffe000c4babac:
   assert self.reg(0)==0xfffffe000790caf5;return self.modeled(a,'IOLog_no_effect_model',0)
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=900000);self.flush();assert self.reason==('before_unavailable_address_table_load'if self.c['warm']else'before_external_code'),self.boundary
  extent=getattr(self,'staging_extent',0);self.ensure(MT,2496)
  for address,size in [(0xfffffe000cccda68,8),(0xfffffe000ccceaf8,4)]:self.ensure(address,size)
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0,'native_owner_extents_established':False},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_edges':self.edges,'calls':self.calls,'snapshots':self.snapshots,'state_snapshots':self.state_snapshots,'allocations':self.allocs,'boundary':self.boundary,'transport_request88_hex':self.transport_request,'declared_reply392_hex':self.declared_reply,'staging_extent_bytes':extent,'staging_final_hex':bytes(self.u.mem_read(STAGING,extent+1)).hex(),'name_final_hex':bytes(self.u.mem_read(NAME,len(self.name))).hex(),'output_handle_final_hex':bytes(self.u.mem_read(OUT,8)).hex(),'message88_hex':None,'final_scratch160_hex':bytes(self.u.mem_read(P+0x20000,160)).hex(),'final_owner1088_hex':bytes(self.u.mem_read(P+0x24000,1088)).hex(),'final_child152_hex':bytes(self.u.mem_read(P+0x22000,152)).hex(),'final_shared704_hex':bytes(self.u.mem_read(P+0x23000,704)).hex(),'final_MT2496_hex':bytes(self.u.mem_read(MT,2496)).hex(),'final_head_hex':bytes(self.u.mem_read(0xfffffe000cccca58,8)).hex(),'final_missing_globals_hex':{hex(a):bytes(self.u.mem_read(a,n)).hex()for a,n in [(0xfffffe000cccda68,8),(0xfffffe000ccceaf8,4)]},'native_target_executed':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();rows=[]
 for warm,mode,status in [(1,1,0),(1,0,0),(1,1,4),(0,1,0)]:
  c=dict(warm=warm,mode=mode,wire_return=status,page_shift=14,length=28,cpu_type=0x100000c,cpu_subtype=0,origin=1);r=Probe(im,c).run();rows.append(r);print(json.dumps({'configuration':c,'visits':len(r['source_visits']),'boundary':r['boundary']['pc'],'allocations':len(r['allocations'])}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','probe_kext_constructor_request.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
