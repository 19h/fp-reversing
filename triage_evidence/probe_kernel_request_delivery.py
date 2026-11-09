#!/usr/bin/env python3
"""Exact source-produced copy request -> receiver OOL mapping and user message.
O(image+visits+RAM+effects), O(image+RAM+journals). Receiver context, class19
view size, VM allocation/user-byte-copy/raw retirement and logical PAC are
explicit; no native mapping, scheduling, IPC, user trap or daemon runs.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_request_receive import Probe as Parent,RECV,MAP,USER,SPACE,TABLE,KMSG,TS,LOAN,DESC,RESULTS,P,SIZE,qregs
from probe_kernel_vm_mig import Probe as CPU
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_request_delivery';HEADER=P+0x88010;BACK=P+0x8c000;OOL=P+0x4000
class Probe(Parent):
 def __init__(self,im,src,c,parent):
  super().__init__(im,src,c,parent);self.transfer['path']='kernel_request_copyin_profiles.json'if self.kind=='receiver_turnstile_allocate'else PREFIX+'_profiles.json';self.transfer.pop('request',None);self.transfer.pop('loan',None);self.transfer['case_origin']='request'if self.kind=='receiver_turnstile_allocate'else'loan';self.transfer['producer']=c['producer'];self.delivery_frames=[];self.delivery_handoffs=[];self.effects=[];self.copy_calls=[];self.alloc_calls=[];self.storage_returns=[];self.setup_offset=len(self.overlays)
  if self.kind=='receiver_turnstile_allocate':
   self.overlay(OOL,b'\xa5'*16385,'Declared disjoint page-aligned receiver mapping observation and guard')
  self.overlay(MAP,bytes(1024),'Declared receiver map observation extent; native allocation unknown')
  for a,b in[(MAP+0x10,struct.pack('<QQ',P,P+SIZE)),(MAP+0x2c,struct.pack('<I',14)),(MAP+0x88,struct.pack('<I',3))]:self.overlay(a,b,'Declared receiver map range/page shift/reference epoch')
  meta=int.from_bytes(bytes(self.u.mem_read(0xfffffe0007e66f00,8)),'little');self.overlay(meta+((MAP>>10)&0xffffffff0),struct.pack('<H',16),'Declared receiving map type-cell epoch');self.global_overlay(0xfffffe000caec2f4,struct.pack('<H',48),'Declared class19 element extent48 consistent with source constructor; creation remains unknown')
 def effect(self,a,symbol,result,patches=()):
  ev={'pc':hex(a),'before_source_visit_index':len(self.visits),'symbol':symbol,'arguments8':[hex(self.reg(j))for j in range(8)],'patches':[]}
  for at,b in patches:ev['patches'].append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
  self.effects.append(ev);return self.model(a,symbol,result)
 def delivery_frame(self,a):
  self.delivery_frames.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'copy48_hex':bytes(self.u.mem_read(HEADER,48)).hex(),'backing29_hex':bytes(self.u.mem_read(BACK,29)).hex(),'OOL29_hex':bytes(self.u.mem_read(OOL,29)).hex(),'user148_hex':bytes(self.u.mem_read(USER,148)).hex(),'kmsg256_hex':bytes(self.u.mem_read(KMSG,256)).hex()})
 def code(self,u,a,n,d):
  self.flush()
  if a in[DESC,0xfffffe000bdd148c,0xfffffe000bdcb374,0xfffffe000bdcbbb0,0xfffffe000bdc76b4,0xfffffe000be7798c,0xfffffe000bcfec48,0xfffffe000bd74fcc,0xfffffe000bcc62d0,0xfffffe000bcc67a4,0xfffffe000bcc6468]:self.delivery_frame(a)
  if a in[DESC,0xfffffe000bdd148c,0xfffffe000bdcb374,0xfffffe000bcc62d0]:self.delivery_handoffs.append({'pc':hex(a),'source_visit_index':len(self.visits),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'NZCV':hex(u.reg_read(ar.UC_ARM64_REG_NZCV)),'Q_registers32':qregs(u),'private_RAM':compressed(bytes(u.mem_read(P,SIZE)))})
  if a==DESC:return CPU.code(self,u,a,n,d)
  if a==0xfffffe000bdc76b4:
   self.alloc_calls.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'stack_prefix12_hex':bytes(u.mem_read(u.reg_read(ar.UC_ARM64_REG_SP),12)).hex()});return self.effect(a,'declared_receiver_VM_allocation',0,[(self.reg(1),struct.pack('<Q',OOL))])
  if a==0xfffffe000be7798c:
   src,dst,count=self.reg(0),self.reg(1),self.reg(2);assert P<=src<src+count<=P+SIZE and(P<=dst<dst+count<=P+SIZE);data=bytes(u.mem_read(src,count));self.copy_calls.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments3':[hex(self.reg(j))for j in range(3)],'source_hex':data.hex(),'destination_before_hex':bytes(u.mem_read(dst,count)).hex()});return self.effect(a,'declared_receiver_user_byte_copy',0,[(dst,data)])
  if a==0xfffffe000bcfec48:self.storage_returns.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'copy48_hex':bytes(u.mem_read(HEADER,48)).hex()});return self.model(a,'declared_raw_copy_backing_retirement',0)
  if a==0xfffffe000bd74fcc and self.reg(2)in[HEADER,KMSG]:
   ptr=self.reg(2);size=48 if ptr==HEADER else 256;self.storage_returns.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'object_hex':bytes(u.mem_read(ptr,size)).hex()});return self.model(a,'declared_raw_copy_header_retirement'if ptr==HEADER else'declared_raw_kmsg_retirement',0)
  if a==0xfffffe000be63ea0:return self.effect(a,'declared_current_map_leaf',0,[(self.reg(0)+0x428,struct.pack('<Q',self.reg(1)))])
  if a in[0xfffffe000bd098c8,0xfffffe000bd08ec0,0xfffffe000bd0a08c]:return self.model(a,'declared_VM_map_lock_primitive',0)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.update(delivery_environment_overlay_start=self.setup_offset,delivery_frames=self.delivery_frames,delivery_full_CPU_RAM_handoffs=self.delivery_handoffs,declared_delivery_effects=self.effects,VM_allocation_contracts=self.alloc_calls,user_byte_copy_contracts=self.copy_calls,raw_VM_kmsg_retirement_contracts=self.storage_returns,final_user8192_hex=bytes(self.u.mem_read(USER,8192)).hex(),final_OOL16384_hex=bytes(self.u.mem_read(OOL,16384)).hex(),final_OOL_guard_hex=bytes(self.u.mem_read(OOL+16384,1)).hex(),final_copy_header48_hex=bytes(self.u.mem_read(HEADER,48)).hex(),final_backing29_hex=bytes(self.u.mem_read(BACK,29)).hex());return r

def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());prior=json.loads((ROOT/'kernel_request_copyin_profiles.json').read_text());loans=[];rows=[]
 for j,q in enumerate(prior['cases']):
  c={'producer':j,'capacity':88,'options':2,'phase':'loan'};r=Probe(im,src,c,q).run();loans.append(r);assert r['boundary']['kind']=='original_receiver_turnstile_allocated',r['boundary'];print(json.dumps({'loan':j,'visits':len(r['source_visits'])}),flush=True)
 for j in range(4):
  for capacity,options in[(88,2),(148,0x7000002)]:
   c={'producer':j,'capacity':capacity,'options':options};r=Probe(im,src,c,loans[j]).run();rows.append(r);print(json.dumps({'case':len(rows)-1,'configuration':c,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_request_copyin_profiles.json','probe_kernel_request_receive.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py']},'loans':loans,'cases':rows,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
