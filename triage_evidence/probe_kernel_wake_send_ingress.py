#!/usr/bin/env python3
"""Original wake construct/member -> Mach -47 ingress/send -> two set receives.
Exact original CF user regions are transferred as a declared component epoch.
Raw backing/copy/hash/tag/PAC contracts remain explicit; no native Mach effects.
"""
import json,struct
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from probe_cf_runloop_wake_port import Probe as Parent,Startup,WPORT,WNODE
from probe_kernel_timer_port_create import KMSGZONE
from probe_kernel_portset_delivery import INSERT_ARGS,TASK_NAME
from probe_kernel_request_receive import RECV,TASK,SPACE,USER
from probe_kernel_vm_mig import P as B,SIZE,HALT
from probe_rpc502_vm_handoff import compressed
from recover_kernel_portset_delivery import INSERT
from recover_kernel_wake_send_ingress import P,FLAGS,sha,HANDLER,SEND,ROFLAGS
from replay_cf_runloop_handoff import unpack,LOW,LOW_SIZE
ARGS=B+0xbb100;RO=B+0xf0000;WKMSG=B+0xd4000;TOKEN=B+0xf4000
class Probe(Parent):
 def __init__(self,im,s,c,parent,zones,startup):
  super().__init__(im,s,c,parent,zones,startup);self.ingress_frames=[];self.ingress_returns=[];self.ingress_handoffs=[];self.ingress_models=[];self.raw_wake_count=0;self.packet=s['CF_original_trap_packets'][c['packet']];stack=unpack(self.packet['lower_stack'],LOW,LOW_SIZE);self.u.mem_map(LOW,LOW_SIZE);self.u.mem_write(LOW,stack)
  for e in self.packet['regions']:assert bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()==e['bytes_hex']
  ro=bytearray(128);struct.pack_into('<Q',ro,8,TASK);self.overlay(RO,bytes(ro),'Declared task-readonly record with owner and flags0');self.overlay(RO+128,b'\xa5','Declared RO guard');self.global_overlay(0xfffffe0007e6d048,struct.pack('<I',0x40000),'Declared readonly pool alignment multiplier for 16KiB-aligned record');self.overlay(TASK+0x3f8,struct.pack('<Q',RO),'Declared current task readonly pointer');self.overlay(ARGS,b''.join(int(v,16).to_bytes(8,'little')for v in self.packet['arguments8']),'Exact original libkernel eight-slot trap argument record');self.overlay(WKMSG,bytes(256),'Declared disjoint raw wake kmsg backing');self.overlay(WKMSG+256,b'\xa5','Declared raw wake kmsg guard')
  meta=int.from_bytes(bytes(self.u.mem_read(0xfffffe0007e66f00,8)),'little')
  for a,ident in((RO,5),(WKMSG,24)):self.overlay(meta+((a>>10)&0xffffffff0),struct.pack('<H',ident),'Declared RO/kmsg type metadata epoch')
  self.overlay(B+0x5b000,bytes(64),'Declared per-CPU send counter backing');self.overlay(TASK+0x3d0,struct.pack('<Q',B+0x5b000),'Declared per-CPU send-counter pointer');self.overlay(RECV+0x1b8,bytes(2),'Declared current CPU index0');self.overlay(TOKEN,struct.pack('<8I',0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88),'Declared task-associated sender identity record with distinct u32 markers');self.overlay(TOKEN+32,b'\xa5','Declared identity record guard');self.overlay(TASK+0x320,struct.pack('<Q',TOKEN),'Declared task sender-identity pointer; native owner/type semantics unknown')
 def ingress_frame(self,a):return{'pc':hex(a),**self.cpu(),'phase':self.phase,'wake_port144_hex':bytes(self.u.mem_read(WPORT,144)).hex(),'wake_kmsg256_hex':bytes(self.u.mem_read(WKMSG,256)).hex(),'user148_hex':bytes(self.u.mem_read(USER,148)).hex()}
 def ingress_transition(self,a,args,label,patches=()):self.transition(a,args,label,patches);self.ingress_handoffs.append(self.stage_handoffs.pop())
 def wake_transition(self,a,args,label,patches=()):
  if label=='wake_insert_to_service_insert':self.phase='wake_send';return self.ingress_transition(HANDLER,(ARGS,),'wake_insert_to_original_Mach47')
  return super().wake_transition(a,args,label,patches)
 def ingress_model(self,a,name,value,patches=()):
  e={'pc':hex(a),'before_source_visit_index':len(self.visits),'name':name,'before':self.ingress_frame(a),'patches':[]}
  for at,b in patches:e['patches'].append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
  self.model(a,name,value);e['result']=hex(value);e['after']=self.ingress_frame(self.u.reg_read(A.UC_ARM64_REG_PC));self.ingress_models.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a in(HANDLER,ROFLAGS,SEND,0xfffffe000bcdd8a4,0xfffffe000bcdd9e4,0xfffffe000bcc24a4,0xfffffe000bcc30b0,0xfffffe000bcdd4b4,0xfffffe000bcc7040,0xfffffe000bcc7c34,0xfffffe000bcddaf4):self.ingress_frames.append(self.ingress_frame(a))
  if a==HALT and self.phase=='wake_send':
   self.ingress_returns.append({**self.ingress_frame(a),'private_RAM':compressed(bytes(u.mem_read(B,SIZE)))})
   if self.c.get('vector_copyin_error'):assert self.reg(0)==0x10000002;return self.stop('original_Mach47_vector_copyin_error_returned')
   assert self.reg(0)==0;self.phase='insert';return self.ingress_transition(INSERT,(INSERT_ARGS,),'wake_send_to_service_insert',[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,self.receive_name,self.pset_name))])
  if self.phase=='wake_send'and a==0xfffffe000bd75c64:
   assert self.reg(0)==KMSGZONE and self.reg(1)==B+0xb1000 and self.reg(2)==0x8004 and self.raw_wake_count==0 and bytes(u.mem_read(WKMSG,256))==bytes(256);self.raw_wake_count+=1;return self.ingress_model(a,'declared_raw_wake_kmsg256',WKMSG)
  if self.phase=='wake_send'and a==0xfffffe000be76e18:
   src,dst,size=[self.reg(j)for j in range(3)];assert LOW<=src<=src+size<=LOW+LOW_SIZE and B<=dst<=dst+size<=B+SIZE and size<=256;err=int(bool(self.c.get('vector_copyin_error')and self.reg(30)==0xfffffe000bcdd8a8));return self.ingress_model(a,'declared_exact_original_CF_user_copyin',err,[]if err else[(dst,bytes(u.mem_read(src,size)))])
  if self.phase=='wake_send'and a==0xfffffe000c647f10:
   dst,src,size=[self.reg(j)for j in range(3)];assert B<=dst<=dst+size<=B+SIZE and size<=256 and(B<=src<=src+size<=B+SIZE or LOW<=src<=src+size<=LOW+LOW_SIZE);return self.ingress_model(a,'declared_disjoint_wake_byte_copy',dst,[(dst,bytes(u.mem_read(src,size)))])
  if self.phase=='wake_send'and a in(0xfffffe000bcc0f9c,0xfffffe000bcd9f3c):return self.ingress_model(a,'declared_wake_send_preflight'if a==0xfffffe000bcc0f9c else'declared_wake_message_tag_helper',0)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.update(ingress_frames=self.ingress_frames,ingress_returns=self.ingress_returns,ingress_handoffs=self.ingress_handoffs,ingress_models=self.ingress_models,original_CF_user_epoch=self.packet,final_CF_lower_stack={**compressed(bytes(self.u.mem_read(LOW,LOW_SIZE))),'address':hex(LOW)},final_wake_kmsg256_hex=bytes(self.u.mem_read(WKMSG,256)).hex(),wake_kmsg_guard_hex=bytes(self.u.mem_read(WKMSG+256,1)).hex(),readonly_guard_hex=bytes(self.u.mem_read(RO+128,1)).hex(),identity_guard_hex=bytes(self.u.mem_read(TOKEN+32,1)).hex());return r

from probe_cf_runloop_wake_port import CFProbe as CFParent
from recover_cf_wake_send_wrapper import MACH
from probe_cf_source_scheduling import OOL
class CFProbe(CFParent):
 def __init__(self,c,k,s):super().__init__(c,k,s);self.wake_receive_transfers=[];self.wake_received=False;self.pool_tokens=[];self.pool_count=0
 def hook(self,u,a,n,d):
  self.flush()
  pools=self.source['pool_runtime_boundaries']
  if a==int(pools['push']['target'],16):
   before=list(self.pool_tokens);self.pool_count+=1;token=0x123400000+self.pool_count;self.pool_tokens.append(token);return self.mode_model(a,'declared_objc_autorelease_pool_push',token,extra={'pool_tokens_before':[hex(v)for v in before],'pool_tokens_after':[hex(v)for v in self.pool_tokens]})
  if a==int(pools['pop']['target'],16):
   before=list(self.pool_tokens);assert self.pool_tokens and self.reg(0)==self.pool_tokens[-1];self.pool_tokens.pop();return self.mode_model(a,'declared_objc_autorelease_pool_pop',0,extra={'pool_tokens_before':[hex(v)for v in before],'pool_tokens_after':[hex(v)for v in self.pool_tokens]})
  if a==MACH and self.phase=='runloop':
   assert[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,self.facility,0xffffffff,0]
   if not self.wake_received:
    ret=next(e for e in self.input['pset_stage_returns']if e['phase']=='first_receive');raw=bytes.fromhex(ret['user148_hex']);assert int.from_bytes(raw[4:8],'little')==24 and int.from_bytes(raw[12:16],'little')==0x807;self.wake_receive_transfers.append(self.run_frame(a));self.wake_received=True;return self.mode_model(a,'original_kernel_wake_set_receive_return',0,[(USER,raw[:92])],{'wake_receive_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'wire_size_bytes':92}})
   return super(CFParent,self).hook(u,a,n,d)
  if a==0x18472907c:
   assert self.reg(0)in self.collections;return self.mode_model(a,'declared_source_cardinality_after_wake_receive',len(self.collections[self.reg(0)]))
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();assert self.wake_received;r['wake_receive_transfers']=self.wake_receive_transfers;r['final_pool_tokens']=[hex(v)for v in self.pool_tokens];return r

if __name__=='__main__':
 s=json.loads((ROOT/(P+'_source.json')).read_text());im=Image();loans=json.loads((ROOT/'kernel_request_delivery_profiles.json').read_text())['loans'];zones=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'];startup=Startup(im,s,40).run();rows=[]
 configs=[{'producer':j,'packet':k,'capacity':3072,'options':0x07000806,'receive_twice':True}for k in(0,1)for j in(0,2)]+[{'producer':2,'packet':1,'capacity':3072,'options':0x07000806,'vector_copyin_error':True}]
 for cfg in configs:
  r=Probe(im,s,cfg,loans[cfg['producer']],zones,startup).run();rows.append(r);print(cfg,r['boundary']['kind'],r['boundary']['pc'],r['boundary']['registers31'][0],len(r['source_visits']),flush=True)
 cf=[];cs={**s['CF_source'],'root_caller_options':s['root_caller_options']}
 for j in range(4):
  assert rows[j]['boundary']['kind']=='receive_frontend_returned',rows[j]['boundary']
  r=CFProbe({'kernel_case':j,'mode':'schedule_then_run','repeat':1,'wake_case':'waiting','send_status':0},rows[j],cs).run();cf.append(r);print('CF',j,r['boundary']['kind'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','kernel_request_delivery_profiles.json','kernel_zone_startup_profiles.json','probe_cf_runloop_wake_port.py','recover_'+P+'.py']},'startup_cases':[startup],'cases':rows,'CF_cases':cf,**{k:False for k in FLAGS}};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
