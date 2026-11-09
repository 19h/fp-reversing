#!/usr/bin/env python3
"""Source-produced queue/receiver state transfer into original receive code.
Upstream private state is reconstructed from its verified fixtures/write log;
new receiver frames, old-node payloads, locks/scheduler/hash/PAC are models.
O(cases*visits + journals) time, O(one private map+journals) space.
No native receive, user copyout, queue, scheduler or authentication executes.
"""
import json,struct
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
from probe_kernel_vm_mig import Probe as Base,P,SIZE,HALT,SP
from recover_kernel_queue_receive import RECEIVE,ON_THREAD,CONTINUE,COPY_SIZE,TRAILER_SIZE,VERIFY,TRAILER_PTR
M=P+0x12000;D=P+0x18000;Q=D+0x28;WAITER=P+0x28000;TASK=P+0x2a000;TURN=P+0x34000;RX=P+0x38000;SET=P+0x3c000;STATS=P+0x40000
class Probe(Base):
 def __init__(self,image,cfg,upstream):
  super().__init__(image,'stub',{'port_class':'null','bits':0,'request_size':56,'address':0,'size':0,'body_placement':'joined'});self.kind=cfg['kind'];self.c=cfg;self.u.mem_write(P,bytes(SIZE));self.initial=[];self.image_initial=[];self.auth=[];self.sign=[];self.cuts=[];self.hashes=[]
  for e in upstream['initial_private_fixtures']:self.fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
  for e in upstream['source_writes']:self.fixture(int(e['address'],16),bytes.fromhex(e['after_hex']))
  for e in upstream['initial_image_fixtures']:a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append(e)
  for j in range(31):self.set(j,0)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.receiver=WAITER if self.kind in ['user_fields','rpc_fields']else RX;self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,self.receiver);self.sysregs=[{'register':'TPIDR_EL1','value':hex(self.receiver)}];self.allowed=[(a,int(image.k.function(a)['end'],16))for a in [RECEIVE,ON_THREAD,COPY_SIZE,TRAILER_SIZE,VERIFY,TRAILER_PTR]]
  if self.kind in ['user_fields','rpc_fields']:
   self.entry=0xfffffe000bcdccf8 if self.kind=='user_fields'else 0xfffffe000bcf5c48;self.cut=0xfffffe000bcdcd1c if self.kind=='user_fields'else 0xfffffe000bcf5c64;self.allowed.append((self.entry,self.cut));self.set(24 if self.kind=='user_fields'else 19,self.receiver)
  else:
   self.entry=RECEIVE;self.cut=None;self.fixture(D+0x10,struct.pack('<I',3));self.fixture(D+0x15,bytes([cfg['valid']]));self.fixture(SET,struct.pack('<I',5));self.fixture(SET+5,bytes([cfg['valid']]));self.fixture(RX+0x390,struct.pack('<Q',cfg['options']));self.fixture(RX+0x388,struct.pack('<II',cfg['limit'],cfg['aux_limit']));self.fixture(RX+0x3a0,struct.pack('<II',0xa5a5a5a5,0x5a5a5a5a));self.fixture(RX+0x3b8,struct.pack('<Q',0));self.fixture(TASK+0x3d8,struct.pack('<Q',STATS));self.fixture(STATS,struct.pack('<Q',0xffffffffffffffff));self.fixture(RX+0x1b8,struct.pack('<H',0));self.fixture(RX+0x428,struct.pack('<Q',0))
   if self.kind=='empty':self.fixture(Q,struct.pack('<Q',0));self.fixture(Q+0x10,struct.pack('<H',0))
   # Existing ring-node payloads were outside the upstream insertion contract.
   # Supply explicit simple-message payloads without changing source-produced links/QoS.
   header=bytes(self.u.mem_read(int(upstream['reply_header'],16),32));body=bytes.fromhex('000000000100000000000000');trailer=bytes.fromhex(upstream['reply_trailer']['bytes_hex'])
   for e in upstream['node_storage']:
    n=int(e['address'],16);self.fixture(n+0x40,header+body+trailer);self.fixture(n+0x38,bytes.fromhex(upstream['reply_signature_word']));self.fixture(n+0x30,struct.pack('<H',0))
   for j,v in enumerate([SET if cfg['portset']else D+0x10,cfg['timeout'],1,RX,0]):self.set(j,v)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.upstream=upstream
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('returned')
  if a==self.cut:return self.stop('consumer_cut')
  if a in [0xfffffe000bcc8408,0xfffffe000bcc85e4]:self.cuts.append({'pc':hex(a),'source_visit_index':len(self.visits),'X0':hex(self.reg(0))})
  callbacks={0xfffffe000bd0aecc:('waitq_lock_model',0),0xfffffe000bd0ab18:('waitq_unlock_model',0),0xfffffe000bd7e9c4:('current_task_model',TASK),0xfffffe000bd68474:('turnstile_prepare_model',TURN),0xfffffe000bccece8:('receive_inheritor_update_model',0),0xfffffe000bd6bc48:('assert_receive_wait_model',self.c.get('wait_result',1)),0xfffffe000bd69f7c:('turnstile_cleanup_model',0),0xfffffe000bd6bfb0:('portset_prepost_model',D+0x10 if self.c.get('prepost',False)else 0),0xfffffe000bd28f6c:('thread_block_model',self.c.get('block_result',1))}
  if a==0xfffffe000bd794c4:return self.model(a,'message_object_validation_model',0)
  if a in callbacks:return self.model(a,*callbacks[a])
  if a==0xfffffe000bc9d90c:
   self.hashes.append({'address':hex(self.reg(0)),'size_bytes':self.reg(1),'bytes_hex':bytes(u.mem_read(self.reg(0),self.reg(1))).hex(),'seed':hex(self.reg(2)),'mode':self.reg(3)});return self.model(a,'opaque_hash_return_model',[0x123456789abcdef0,0xfedcba9876543210][len(self.hashes)-1])
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_unmodeled_code')
  raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);ins=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if ins.mnemonic in ['pacibsp','autibsp']:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif ins.mnemonic=='retab':u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  elif ins.mnemonic=='autda':self.auth.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'native_authentication_executed':False});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif ins.mnemonic=='pacda':self.sign.append({'pc':hex(a),'pointer':hex(self.reg(17)),'modifier':hex(self.reg(16)),'native_authentication_executed':False});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  assert ins.mnemonic not in ['svc','hvc','smc','blraa','brk','pacia'],(hex(a),ins.mnemonic)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=200000);self.flush();assert self.reason in ['returned','consumer_cut'],self.boundary
  return {'kind':self.kind,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0,'native_owner_extents_established':False},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'private_system_register_fixtures':self.sysregs,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_data_authentication':self.auth,'logical_data_signing':self.sign,'source_return_cuts':self.cuts,'opaque_hash_inputs':self.hashes,'boundary':self.boundary,'queue_storage_hex':bytes(self.u.mem_read(Q,0x20)).hex(),'receiver':hex(self.receiver),'receiver_storage_hex':bytes(self.u.mem_read(self.receiver+0x380,0xb0)).hex(),'received_counter':int.from_bytes(bytes(self.u.mem_read(STATS,8)),'little'),'native_target_executed':False,'hardware_PAC_executed':False,'full_goal_complete':False}
def cases(upstream):
 rows=[];base={'kind':'queued','portset':False,'prepost':False,'valid':1,'options':0,'limit':44,'aux_limit':0xffffffff,'timeout':0,'wait_result':1}
 for i,r in enumerate(upstream):
  if any(e['pc']=='0xfffffe000bcc2bc4'for e in r['source_visits']):
   for label,opts,lim in [('fit',0,44),('small_take',0,43),('small_peek',4,43)]:rows.append(({**base,'case':label,'upstream_index':i,'options':opts,'limit':lim},r))
   if r['configuration']['case']=='enqueue'and not r['configuration']['node_qos']:
    for label,opts,lim in [('set_fit',0,44),('set_peek',4,43)]:rows.append(({**base,'case':label,'upstream_index':i,'portset':True,'prepost':True,'options':opts,'limit':lim},r))
  if r['logical_data_signing']:
   for kind in ['user_fields','rpc_fields']:rows.append(({**base,'kind':kind,'case':'direct_consumer','upstream_index':i},r))
 seed=upstream[0]
 for name,changes in [('poll',{'options':0x100}),('invalid',{'valid':0}),('wait_timeout',{}),('wait_interrupted',{'wait_result':2}),('wait_restart',{'wait_result':3}),('set_poll',{'portset':True,'options':0x100}),('set_timeout',{'portset':True}),('set_interrupted',{'portset':True,'wait_result':2}),('block_timeout',{'wait_result':0xffffffff,'block_result':1}),('block_interrupted',{'wait_result':0xffffffff,'block_result':2}),('block_restart',{'wait_result':0xffffffff,'block_result':3})]:rows.append(({**base,'kind':'empty','case':name,'upstream_index':0,**changes},seed))
 return rows
if __name__=='__main__':
 image=Image();prior=json.loads((ROOT/'kernel_queue_send_profiles.json').read_text());rows=[]
 for j,(cfg,r)in enumerate(cases(prior['cases'])):
  out=Probe(image,cfg,r).run();rows.append(out);print(j,cfg['kind'],cfg['case'],len(out['source_visits']),flush=True)
 obj={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_queue_receive_source.json','kernel_queue_send_profiles.json','kernel_queue_send_checks.json','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'source_state_transfer_is_private_model':True,'native_delivery_established':False,'full_goal_complete':False};(ROOT/'kernel_queue_receive_profiles.json').write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
