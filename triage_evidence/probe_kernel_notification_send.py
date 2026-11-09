#!/usr/bin/env python3
"""Source-produced no-senders packet through original send-only and outer return.
O(visits+RAM+effects), O(image+RAM+journals). Allocator layout, byte copy, locks,
preflight/queue/tag/free effects and PAC are declared; no native IPC or retirement.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_notification_send';KMSG=P+0xd0000;HEADER=P+0xd4000;DATA=P+0xd8000;ACCEPT=P+0xdc000;KSPACE=P+0xdc800;USPACE=P+0xdd000;THREAD=P+0x2c000;NOTIFY=P+0xc0000
class Probe(CPU):
 def __init__(self,im,c,src,producer):
  super().__init__(im,'selector',{'id':0});self.kind=PREFIX;self.c=c;self.initial=[];self.image_initial=[];self.effects=[];self.auth=[];self.frames=[];self.hashes=[];self.entry=0xfffffe000bcf55dc;self.allowed=[(int(f['start'],16),int(f['end'],16))for f in src['functions']];self.transfer={'path':'kernel_send_right_lifecycle_profiles.json','case':11,**producer['final_private_RAM']};self.u.mem_write(P,decode(self.transfer));self.overlays=[];self.reg_overlays=[]
  for e in producer['final_image_globals']:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact no-senders producer final-global transfer')
  b=producer['boundary']
  for j,x in enumerate(b['registers31']):self.set(j,int(x,16))
  self.u.reg_write(ar.UC_ARM64_REG_SP,int(b['SP'],16));self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(b['NZCV'],16));self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  for j,x in enumerate(producer['final_Q_registers32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))
  self.entryQ=producer['final_Q_registers32'];self.packet=int(producer['notification_packet']['address'],16);self.header=KMSG+0x40 if c['storage_class']<2 else HEADER;self.body=DATA if c['storage_class']&1 else self.header+32
  self.overlay(KMSG,bytes(0x400),'Declared initialized kmsg allocation object, private observation extent1024');self.overlay(KMSG+0x3f,bytes([c['storage_class']<<6]),'Declared storage-class field')
  if c['storage_class']>=2:self.overlay(KMSG+0xe8,struct.pack('<Q',HEADER),'Declared external header pointer')
  if c['storage_class']&1:self.overlay(KMSG+0xf0,struct.pack('<Q',DATA),'Declared split body pointer')
  if c['storage_class']>=2:self.overlay(HEADER,b'\xa5'*256,'Private external-header observation window')
  if c['storage_class']&1:self.overlay(DATA,b'\xa5'*256,'Private external-body observation window')
  self.overlay(ACCEPT,b'\xa5'*4,'Optional accepted-state output canary');self.overlay(THREAD+0xc8,struct.pack('<H',c.get('thread_flags',0)),'Declared send thread-flag epoch');self.overlay(NOTIFY+0x48,struct.pack('<Q',USPACE),'Declared non-kernel receiver identity')
  if c.get('destination_null'):self.overlay(self.packet+8,bytes(8),'Controlled NULL destination substitution after source emission')
  if c.get('destination_inactive'):self.overlay(NOTIFY+1,b'\x00','Controlled target-state substitution after source emission')
  self.image_fixture(0xfffffe0007e62b68,struct.pack('<Q',KSPACE),'Declared kernel-space identity distinct from target receiver');self.image_fixture(0xfffffe0007e5c221,b'\x00','Declared zero send guard-policy byte')
  for j,x in[(1,c.get('send_bytes',44)),(2,c.get('options',0x50001)),(4,ACCEPT if c.get('accepted_output')else 0)]:
   if self.reg(j)!=x:self.reg_overlays.append({'register':'X'+str(j),'before':hex(self.reg(j)),'after':hex(x),'reason':'Explicit wrapper-ABI variant, not an original notification call argument'});self.set(j,x)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entrySP=hex(self.u.reg_read(ar.UC_ARM64_REG_SP));self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def overlay(self,a,b,why):self.overlays.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why});self.fixture(a,b)
 def image_fixture(self,a,b,why):self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':why})
 def effect(self,a,symbol,result,patches=()):
  e={'pc':hex(a),'before_source_visit_index':len(self.visits),'symbol':symbol,'patches':[],'native_effects_executed':False}
  for ptr,b in patches:e['patches'].append({'address':hex(ptr),'before_hex':bytes(self.u.mem_read(ptr,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(ptr,b)
  self.effects.append(e);return self.model(a,symbol,result)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('outer_notification_caller_returned')
  if a in[0xfffffe000c629938,0xfffffe000c641fa8,0xfffffe000bcc922c]:return self.stop('before_validation_or_final_reference')
  framepcs=[0xfffffe000bcf55dc,0xfffffe000bcc68c4,0xfffffe000bcc6b10,0xfffffe000bcc9718,0xfffffe000bcc7040,0xfffffe000bcf5688,0xfffffe000bcd059c]
  if a in framepcs:self.frames.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments5':[hex(self.reg(j))for j in range(5)],'header32_hex':bytes(u.mem_read(self.header,32)).hex(),'body12_hex':bytes(u.mem_read(self.body,12)).hex(),'accepted_u32':int.from_bytes(bytes(u.mem_read(ACCEPT,4)),'little')})
  if a==0xfffffe000bcc24a4:return self.model(a,'declared_kmsg_allocate',0 if self.c.get('allocation_null')else KMSG)
  if a==0xfffffe000bc9d90c:
   self.hashes.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'bytes_hex':bytes(u.mem_read(self.reg(0),self.reg(1))).hex()});return self.model(a,'opaque_keyed_hash_result',0x123456789abcdef0)
  if a==0xfffffe000c647f10:return self.effect(a,'declared_byte_copy',self.reg(0),[(self.reg(0),bytes(u.mem_read(self.reg(1),self.reg(2))))])
  models={0xfffffe000bcd9f3c:('declared_message_tag_helper',0),0xfffffe000bccc128:('declared_destination_lock',0),0xfffffe000bd0ab18:('declared_destination_unlock',0),0xfffffe000bcc0f9c:('declared_send_preflight',self.c.get('preflight_status',0)),0xfffffe000bcc7c34:('declared_queue_send',self.c.get('queue_status',0)),0xfffffe000bcc1cec:('declared_send_failure_helper',0),0xfffffe000bcc2c40:('declared_message_destroy',0),0xfffffe000bcc2974:('declared_kmsg_buffer_free',0)}
  if a in models:return self.model(a,*models[a])
  if not any(x<=a<z for x,z in self.allowed):return self.stop('before_unmodeled_code')
  raw=bytes(u.mem_read(a,4));ins=next(self.image.k.cs.disasm(raw,a));assert raw==self.image.k.read(a,4)
  if ins.mnemonic=='autda':self.auth.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if ins.mnemonic=='brk':return self.stop('before_original_trap',{'immediate':ins.op_str})
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason is not None
  addrs=list(dict.fromkeys((int(e['address'],16),len(e['bytes_hex'])//2)for e in self.image_initial));return{'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':self.entrySP,'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'entry_Q_registers32':self.entryQ,'final_Q_registers32':[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)],'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_state_transfer':self.transfer,'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'memory_overlays':self.overlays,'register_overlays':self.reg_overlays,'private_system_register_fixtures':[{'register':'TPIDR_EL1','value':hex(THREAD)}],'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'declared_effects':self.effects,'logical_data_authentication':self.auth,'opaque_hash_inputs':self.hashes,'entry_frames':self.frames,'boundary':self.boundary,'header_address':hex(self.header),'body_address':hex(self.body),'final_header32_hex':bytes(self.u.mem_read(self.header,32)).hex(),'final_body12_hex':bytes(self.u.mem_read(self.body,12)).hex(),'final_trailer68_hex':bytes(self.u.mem_read(self.body+12,68)).hex(),'final_kmsg1024_hex':bytes(self.u.mem_read(KMSG,0x400)).hex(),'final_accepted_u32':int.from_bytes(bytes(self.u.mem_read(ACCEPT,4)),'little'),'final_thread_flags_u16':int.from_bytes(bytes(self.u.mem_read(THREAD+0xc8,2)),'little'),'final_destination144_hex':bytes(self.u.mem_read(NOTIFY,144)).hex(),'final_source_port144_hex':bytes(self.u.mem_read(P+0x83000,144)).hex(),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in addrs],**{k:False for k in FLAGS}}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());producer=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];configs=[]
 for cls in range(4):
  for status in[0,5,0x10000003,0x10000004,0x10000007,0x1000000d]:configs.append({'storage_class':cls,'queue_status':status})
  configs.extend([{'storage_class':cls,'allocation_null':True,'accepted_output':True},{'storage_class':cls,'destination_null':True,'accepted_output':True},{'storage_class':cls,'accepted_output':True},{'storage_class':cls,'destination_inactive':True}])
 for flags in[0,0x400,0x800,0xc00]:
  for options in[0x50001,0x2000050001]:configs.append({'storage_class':0,'thread_flags':flags,'options':options,'accepted_output':True})
 configs.extend([{'storage_class':0,'preflight_status':1,'accepted_output':True},{'storage_class':0,'send_bytes':31,'accepted_output':True},{'storage_class':0,'queue_status':5,'accepted_output':True},{'storage_class':0,'queue_status':0x10000003,'accepted_output':True}]);rows=[]
 for c in configs:
  r=Probe(im,c,src,producer).run();rows.append(r);print(json.dumps({'case':len(rows)-1,'config':c,'visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'accepted':r['final_accepted_u32']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_send_right_lifecycle_profiles.json','recover_kernel_send_right_lifecycle.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
