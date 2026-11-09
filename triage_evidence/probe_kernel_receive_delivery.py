#!/usr/bin/env python3
"""Original receive->results->name/header conversion->packing with copyout model.
Upstream queue state, receiver/space/map/port frames and an explicit caller
handover are private premises. Copyout effects are declared and bounded to a
private user buffer. Native rights, user copyout, free and PAC never execute.
O(cases*visits+effects) time, O(one private map+journals) space.
"""
import json,struct
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
from probe_kernel_queue_receive import Probe as Parent,P,RX,D,Q,TASK,HALT
from recover_kernel_receive_delivery import RESULTS,HEADER,DESTINATION,PACK,PORT_CHECK,PORT_UNLOCK
SPACE=P+0x48000;MAP=P+0x4a000;ALIVE=P+0x4c000;USER=P+0x50000;OUT=P+0x58000;ZONE=P+0x60000;ZONE_AUX=P+0x62000
class Probe(Parent):
 def __init__(self,image,cfg,prior):
  super().__init__(image,cfg,prior);self.kind='delivery';self.stage=0;self.handovers=[];self.copyouts=[];self.delivery_cuts=[];self.completion_snapshots=[];self.allowed.extend((a,int(image.k.function(a)['end'],16))for a in [RESULTS,HEADER,DESTINATION,PACK,PORT_CHECK,PORT_UNLOCK]);self.fixture(TASK+0x318,struct.pack('<Q',SPACE));self.fixture(SPACE+0x48,struct.pack('<Q',ALIVE));self.fixture(RX+0x428,struct.pack('<Q',MAP));self.fixture(MAP+0x18,struct.pack('<Q',0xffffffffffffffff));self.fixture(RX+0x378,struct.pack('<QQ',USER,0));self.fixture(RX+0x398,struct.pack('<Q',D));self.fixture(D+1,bytes([1]));self.fixture(D+4,struct.pack('<I',3));self.fixture(D+0x48,struct.pack('<Q',SPACE));self.fixture(D+0x34,struct.pack('<I',cfg['receive_name']));self.fixture(D+0x78,struct.pack('<Q',cfg['port_context']));self.fixture(D+0x8c,struct.pack('<I',1));self.fixture(USER,bytes([0xa5])*4096);self.fixture(OUT,bytes([0xa5])*40);self.fixture(ZONE+0x34,struct.pack('<H',0x100));self.ensure(0xfffffe000caec680,16);self.u.mem_write(0xfffffe000caec680,struct.pack('<QQ',ZONE,ZONE_AUX));self.image_initial.append({'address':'0xfffffe000caec680','bytes_hex':struct.pack('<QQ',ZONE,ZONE_AUX).hex(),'provenance':'declared private allocator-view fixture; native view unknown'})
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT and self.stage==0:
   out_pointer=OUT if self.c['result_record_requested']else 0;e={'before_source_visit_index':len(self.visits),'from_PC':hex(HALT),'to_PC':hex(RESULTS),'before_X0':hex(self.reg(0)),'after_X0':hex(out_pointer),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'other_registers_preserved':True,'native_caller_continuity_established':False};self.handovers.append(e);self.stage=1;self.set(0,out_pointer);u.reg_write(ar.UC_ARM64_REG_PC,RESULTS);return
  if a==0xfffffe000bcdd008:
   address=u.reg_read(ar.UC_ARM64_REG_SP)+0x10;self.completion_snapshots.append({'pc':hex(a),'source_visit_index':len(self.visits),'address':hex(address),'bytes_hex':bytes(u.mem_read(address,40)).hex(),'published_pointer':hex(self.reg(19))})
  if a in [HEADER,DESTINATION,PACK]:self.delivery_cuts.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments6':[hex(self.reg(j))for j in range(6)]})
  if a==0xfffffe000be7798c:
   src,dst,count=[self.reg(j)for j in range(3)];payload=bytes(u.mem_read(src,count));assert USER<=dst<=dst+count<=USER+4096;index=len(self.copyouts)+1;status=1 if self.c['copy_failure_at']==index else 0;before=bytes(u.mem_read(dst,count));effect={'pc':hex(a),'before_source_visit_index':len(self.visits),'source':hex(src),'destination':hex(dst),'size_bytes':count,'source_hex':payload.hex(),'before_hex':before.hex(),'return_value':status,'writes_on_failure_modeled':False,'native_effects_executed':False};self.copyouts.append(effect)
   if status==0:u.mem_write(dst,payload)
   return self.model(a,'private_copyout_model',status)
  callbacks={0xfffffe000bccc128:('port_lock_model',0),0xfffffe000bcc1344:('receive_observer_model',0),0xfffffe000bcda458:('receive_auxiliary_model',0),0xfffffe000bcc2868:('message_buffer_cleanup_model',0),0xfffffe000c6480c0:('message_zone_check_model',0),0xfffffe000bd74fcc:('message_zone_free_model',0)}
  if a in callbacks:return self.model(a,*callbacks[a])
  if any(lo<=a<hi for lo,hi in self.allowed[-6:]):
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
   if i.mnemonic in ['pacibsp','autibsp']:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
   elif i.mnemonic=='retab':u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
   elif i.mnemonic=='autda':self.auth.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'native_authentication_executed':False});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
   assert i.mnemonic not in ['svc','hvc','smc','brk','blraa','pacda'],(hex(a),i.mnemonic)
   return
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.update({'kind':'delivery','caller_handovers':self.handovers,'declared_copyouts':self.copyouts,'delivery_entry_cuts':self.delivery_cuts,'completion_snapshots':self.completion_snapshots,'private_user_buffer_hex':bytes(self.u.mem_read(USER,4096)).hex(),'receive_result_record_hex':bytes(self.u.mem_read(OUT,40)).hex(),'destination_object_refs':int.from_bytes(bytes(self.u.mem_read(D+4,4)),'little'),'destination_send_once_refs':int.from_bytes(bytes(self.u.mem_read(D+0x8c,4)),'little')});return r
def configurations(prior):
 out=[]
 for j,r in enumerate(prior):
  c=r['configuration']
  if c['case']!='enqueue'or c['node_qos']:continue
  for selector,extent in [(0,8),(3,52),(7,68)]:
   for cap in [36+extent,3072]:
    for name in [0x123,0x87654321]:
     for fail in ([0,1,2]if c['storage_class']&1 else[0,1]):out.append(({'kind':'queued','case':'receive_delivery','upstream_index':j,'portset':False,'prepost':False,'valid':1,'options':2|(selector<<24),'limit':cap,'aux_limit':0,'timeout':0,'wait_result':1,'receive_name':name,'port_context':0x123456789abcdef0,'copy_failure_at':fail,'trailer_extent':extent,'storage_class':c['storage_class'],'result_record_requested':cap!=3072},r))
 return out
if __name__=='__main__':
 image=Image();prior=json.loads((ROOT/'kernel_queue_send_profiles.json').read_text());rows=[]
 for j,(cfg,r)in enumerate(configurations(prior['cases'])):p=Probe(image,cfg,r).run();rows.append(p);print(j,cfg['storage_class'],cfg['trailer_extent'],cfg['copy_failure_at'],len(p['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_receive_delivery_source.json','probe_kernel_queue_receive.py','kernel_queue_send_profiles.json','kernel_queue_receive_source.json','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'private_copyout_effects_are_models':True,'native_user_delivery_established':False,'full_goal_complete':False};(ROOT/'kernel_receive_delivery_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
