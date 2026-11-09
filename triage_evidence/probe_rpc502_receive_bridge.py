#!/usr/bin/env python3
"""Original complex receive/header/body/packing with declared namespace/VM effects.
Source schema supplies the 88-byte request; all object/namespace/VM initial
states and helper outputs are private premises. No native mapping or rights.
O(cases*visits+effects) time, O(one private map+journals) space.
"""
import json,struct
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
from probe_kernel_receive_delivery import Probe as Parent,P,RX,D,Q,TASK,SPACE,MAP,USER
COPY=P+0x68000;REPLY=P+0x64000;OOL=P+0x70000;ENTRY=P+0x74000;META=P+0x78000
class Probe(Parent):
 def __init__(self,image,cfg,prior):
  super().__init__(image,cfg,prior);self.bridge_effects=[];self.reply_state_calls=0;self.vm_calls=[];self.allowed_body=[(a,int(image.k.function(a)['end'],16))for a in [0xfffffe000bcc5564,0xfffffe000bdd148c]]
  n=cfg['length'];c=cfg['copy_extent'];self.payload=b'/tmp/fp'+b'A'*(n-8)+b'\0'+bytes(c-n);head=int(prior['reply_header'],16);header=struct.pack('<IIQQII',0x80001211,88,D,REPLY,0,502);descriptor=struct.pack('<IQII',1,COPY,0x01000100,n);tail=bytes.fromhex('0000000001000000')+struct.pack('<IQQQ',n,0x100000c,0,1);assert len(header+descriptor+tail)==88;self.fixture(head,header+descriptor)
  body=P+0x16000 if cfg['storage_class']&1 else head+52;self.fixture(body,tail+bytes.fromhex(prior['reply_trailer']['bytes_hex']));self.fixture(D+0x88,struct.pack('<I',1));self.fixture(D+0x8c,struct.pack('<I',0));self.fixture(REPLY+2,bytes([1]));self.fixture(REPLY+4,struct.pack('<I',2));self.fixture(COPY+0x10,struct.pack('<Q',0));self.fixture(COPY+0x20,struct.pack('<Q',c));self.fixture(COPY+0x2d,bytes([cfg['copy_type']]));self.fixture(MAP+0x2c,bytes([14]));self.fixture(META,struct.pack('<H',0x13));self.fixture(OOL,bytes([0xa5])*0x4000)
  for address,data in [(0xfffffe0007e66e50,struct.pack('<QQ',P,P+0x100000)),(0xfffffe0007e66f00,struct.pack('<Q',(META-((COPY>>10)&0xffffffff0))&((1<<64)-1)))]:self.ensure(address,len(data));self.u.mem_write(address,data);self.image_initial.append({'address':hex(address),'bytes_hex':data.hex(),'provenance':'declared private VM-copy bounds/zone metadata; native allocation validity unknown'})
 def effect_model(self,a,symbol,result,patches=(),x1=None):
  event={'pc':hex(a),'before_source_visit_index':len(self.visits),'symbol':symbol,'arguments6':[hex(self.reg(j))for j in range(6)],'patches':[],'return_value':result,'native_effects_executed':False}
  for address,data,role in patches:event['patches'].append({'address':hex(address),'before_hex':bytes(self.u.mem_read(address,len(data))).hex(),'after_hex':data.hex(),'role':role});self.u.mem_write(address,data)
  self.bridge_effects.append(event);self.model(a,symbol,result)
  if x1 is not None:self.set(1,x1);self.models[-1]['after_registers31'][1]=hex(x1);event['second_return_register']=hex(x1)
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000bccc258:return self.effect_model(a,'reply_object_state_model',0x100,x1=0)
  if a==0xfffffe000bcbc0f0:return self.effect_model(a,'reply_name_entry_model',0,[(self.reg(2),struct.pack('<I',0x203),'reply name'),(self.reg(3),struct.pack('<Q',ENTRY),'namespace entry')])
  callbacks={0xfffffe000bd0af50:'space_lock_model',0xfffffe000bd0b348:'space_unlock_model',0xfffffe000bcbbff4:'space_reserve_entries_model',0xfffffe000bcd5b90:'namespace_publish_model',0xfffffe000bcc8f4c:'no_senders_state_model',0xfffffe000bdc6308:'VM_copy_discard_model',0xfffffe000bdc1ec0:'VM_region_deallocate_model',0xfffffe000bcc1c44:'body_error_observer_model'}
  if a in callbacks:return self.model(a,callbacks[a],0)
  if a==0xfffffe000bdc1cd4:
   result=self.c['allocate_result'];patches=[]if result else[(self.reg(1),struct.pack('<Q',OOL),'allocated address')];return self.effect_model(a,'VM_receiver_allocate_model',result,patches)
  if a in [0xfffffe000bdcb374,0xfffffe000bdd048c]:
   result=self.c['map_result'];patches=[]
   if result==0:
    if a==0xfffffe000bdcb374:patches.append((self.reg(1),struct.pack('<Q',OOL),'mapped address'));target=OOL
    else:target=self.reg(1)
    assert self.reg(3)==len(self.payload);patches.append((target,self.payload,'declared mapped payload'))
   return self.effect_model(a,'VM_copyout_model'if a==0xfffffe000bdcb374 else'VM_overwrite_model',result,patches)
  if any(lo<=a<hi for lo,hi in self.allowed_body):
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
   if i.mnemonic in ['pacibsp','autibsp']:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
   elif i.mnemonic=='retab':u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
   elif i.mnemonic=='autda':self.auth.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'native_authentication_executed':False});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
   assert i.mnemonic not in ['svc','hvc','smc','brk','blraa','pacda'],(hex(a),i.mnemonic)
   return
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r['bridge_effects']=self.bridge_effects;r['mapped_payload_hex']=bytes(self.u.mem_read(OOL,self.c['copy_extent'])).hex();r['destination_send_refs']=int.from_bytes(bytes(self.u.mem_read(D+0x88,4)),'little');r['reply_object_refs']=int.from_bytes(bytes(self.u.mem_read(REPLY+4,4)),'little');return r
def configurations(rows):
 out=[]
 for index,prior in enumerate(rows):
  cfg=prior['configuration']
  if cfg['case']!='enqueue'or cfg['node_qos']:continue
  for length in [8,37]:
   for label,typ,extra,mr,ar_ in [('kernel_buffer',3,0,0,0),('kernel_resource_error',3,0,6,0),('kernel_memory_error',3,0,5,0),('entry_equal',2,0,0,0),('entry_expanded',2,1,0,0),('entry_overwrite_error',2,1,6,0),('entry_allocate_error',2,1,0,6)]:out.append(({'kind':'queued','case':label,'upstream_index':index,'portset':False,'prepost':False,'valid':1,'options':0x07000002,'limit':3072,'aux_limit':0,'timeout':0,'wait_result':1,'receive_name':0x107,'port_context':0x123456789abcdef0,'copy_failure_at':0,'trailer_extent':68,'storage_class':cfg['storage_class'],'result_record_requested':False,'length':length,'copy_extent':length+extra,'copy_type':typ,'map_result':mr,'allocate_result':ar_},prior))
 return out
if __name__=='__main__':
 image=Image();prior=json.loads((ROOT/'kernel_queue_send_profiles.json').read_text());rows=[]
 for j,(cfg,seed)in enumerate(configurations(prior['cases'])):r=Probe(image,cfg,seed).run();rows.append(r);print(j,cfg['storage_class'],cfg['case'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_receive_bridge_source.json','probe_kernel_receive_delivery.py','kernel_queue_send_profiles.json','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'native_VM_or_namespace_effects_executed':False,'full_goal_complete':False};(ROOT/'rpc502_receive_bridge_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
