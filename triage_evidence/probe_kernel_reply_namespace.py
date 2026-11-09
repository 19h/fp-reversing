#!/usr/bin/env python3
"""Original reply namespace allocation/publication and produced-name lookup.
O(image+visits+RAM+effects), O(image+RAM+journals). Private namespace/port/type,
source packet imports and logical PAC are declared; keyed hash is modeled.
No native namespace, IPC, user copy, VM, scheduling or retirement executes.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,HALT
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_reply_namespace';RECV=P+0x60000;PORT=P+0xc0000;SPACE=P+0xdd000;TABLE=0x400000100000;REPLY=P+0x80070;TASK=P+0x74000;FOREIGN=P+0x88000;OWNER=P+0x8c000;KMSG=P+0xd0000;MAP=P+0x78000;OUT=P+0x94000;PSP=P+0xe8000
CONFIGS=[{'index':2,'old_bits':0,'constructor_case':1},{'index':5,'old_bits':0x02000000,'constructor_case':17},{'index':2,'old_bits':0xfc000000,'constructor_case':1},{'index':41,'old_bits':0xf8000000,'constructor_case':1},{'index':2,'old_bits':0,'constructor_case':1,'free_head_zero':True},{'index':2,'old_bits':0,'constructor_case':1,'threshold_counter':36},{'index':42,'old_bits':0,'constructor_case':1},{'index':2,'old_bits':0,'constructor_case':1,'threshold_counter':35}]
WATCH=[0xfffffe000bcc4e98,0xfffffe000bcbbff4,0xfffffe000bccc258,0xfffffe000bcbc0f0,0xfffffe000bcbc228,0xfffffe000bcd5b90,0xfffffe000bcd5d50,0xfffffe000bcc5294,0xfffffe000bcc53dc,0xfffffe000bcc5564,0xfffffe000be57f8c,0xfffffe000bcc92e4,0xfffffe000bcc931c]
class Aux:
 def ensure(self,a,n=1):
  if TABLE<=a<a+n<=TABLE+4096:
   if TABLE not in self.pages:self.u.mem_map(TABLE,4096);self.u.mem_write(TABLE,bytes(4096));self.pages.add(TABLE)
   return
  return super().ensure(a,n)
class Probe(Aux,CPU):
 def __init__(self,im,src,c,kind,parent,origin,sourcepacket,rawkmsg):
  super().__init__(im,'selector',{'id':0});self.kind=kind;self.c=c;self.initial=[];self.image_initial=[];self.auth=[];self.sign=[];self.frames=[];self.hashes=[];self.overlays=[];self.transfer={**origin,**compressed(parent['ram'])};self.u.mem_write(P,parent['ram']);self.allowed=[(int(f['start'],16),int(f['end'],16))for f in src['functions']]
  for e in parent['globals']:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
  self.u.reg_write(ar.UC_ARM64_REG_SP,PSP);self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,RECV);self.u.reg_write(ar.UC_ARM64_REG_PSTATE,(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&~0x3c0)|0x200)
  for j in range(31):self.set(j,0)
  self.set(30,HALT);self.packet_import=None
  if kind=='destination_make_send_1':
   meta=int.from_bytes(bytes(self.u.mem_read(0xfffffe0007e66f00,8)),'little')
   for a,b in[(REPLY,bytes(144)),(SPACE+0x14,struct.pack('<II',c.get('threshold_counter',0),1)),(SPACE+0x1c,struct.pack('<I',0x35)),(SPACE+0x50,struct.pack('<Q',TASK)),(SPACE+0x70,struct.pack('<II',0xffffffff,0)),(OWNER,bytes(0x340)),(OWNER+0x318,struct.pack('<Q',FOREIGN)),(OUT,b'\xa5'*16),(meta+((REPLY>>10)&0xffffffff0),struct.pack('<H',22))]:self.overlay(a,b,'Declared namespace free-list/seed/task/type and fresh reply storage')
   table=bytearray(bytes(self.u.mem_read(TABLE,4096)));struct.pack_into('<I',table,12,0 if c.get('free_head_zero')else c['index']);struct.pack_into('<QIIII',table,c['index']*24,0,c['old_bits'],0,0x11223344,0x55667788);self.global_overlay(TABLE,bytes(table),'Declared free entry and next link; preserve other entries')
   self.global_overlay(0xfffffe000caec530,bytes.fromhex(src['port_zone_validation_source']['bytes8_hex']),'Exactly eight original startup class22 validation bytes')
  if kind.startswith('destination_make_send'):self.entry=0xfffffe000bccffa4;args=[PORT]
  elif kind=='reply_init':self.entry=0xfffffe000bccd170;args=[REPLY,FOREIGN,0x101,OWNER,0,0x707]
  elif kind=='reply_unlock':self.entry=0xfffffe000bd0ab18;args=[REPLY+0x14]
  elif kind=='reply_make_send_once':self.entry=0xfffffe000bcd0694;args=[REPLY]
  elif kind=='header':
   b=bytearray(rawkmsg);packet=bytearray(sourcepacket);struct.pack_into('<IIQQ',packet,0,0x80001211,88,PORT,REPLY);b[0x40:0x40+88]=packet;self.overlay(KMSG,bytes(b),'Source-produced inline kmsg container plus explicit RPC internal-header representation; no transport join');self.packet_import={'constructor_case':c['constructor_case'],'constructor_message88_hex':sourcepacket.hex(),'internal_message88_hex':packet.hex(),'source_kmsg_container256_hex':rawkmsg.hex(),'native_transport_continuity_established':False};self.entry=0xfffffe000bcc4e98;args=[KMSG,SPACE,MAP,0x07000002]
  elif kind.startswith('translate'):
   bits=struct.unpack('<I',bytes(self.u.mem_read(TABLE+c['index']*24+8,4)))[0];name=(c['index']<<8)|((bits>>24)&0xfc)|3
   if kind=='translate_stale':name^=4
   self.overlay(OUT,b'\xa5'*16,'Declared independent lookup output canary');self.entry=0xfffffe000bcc92e4;args=[SPACE,name,0 if kind=='translate_wrong_right'else 2,OUT]
  elif kind=='lookup_unlock':self.entry=0xfffffe000bd0ab18;args=[REPLY+0x14]
  else:raise AssertionError(kind)
  for j,x in enumerate(args):self.set(j,x)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.entryQ=[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
 def image_fixture(self,a,b):self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex()})
 def overlay(self,a,b,why):self.overlays.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why,'space':'private'});self.fixture(a,b)
 def global_overlay(self,a,b,why):
  self.ensure(a,len(b));self.overlays.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why,'space':'image_global'});self.u.mem_write(a,b)
  for e in self.image_initial:
   if e['address']==hex(a)and len(e['bytes_hex'])==len(b)*2:e['bytes_hex']=b.hex();break
  else:self.image_initial.append({'address':hex(a),'bytes_hex':b.hex()})
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or TABLE<=a<a+n<=TABLE+4096,(hex(a),n);e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a in WATCH:self.frames.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'port144_hex':bytes(u.mem_read(PORT,144)).hex(),'reply144_hex':bytes(u.mem_read(REPLY,144)).hex(),'space128_hex':bytes(u.mem_read(SPACE,128)).hex(),'entry24_hex':bytes(u.mem_read(TABLE+self.c['index']*24,24)).hex(),'header88_hex':bytes(u.mem_read(KMSG+0x40,88)).hex(),'nesting':int.from_bytes(bytes(u.mem_read(RECV+0x1c8,4)),'little')})
  if a==HALT:return self.stop('original_component_returned')
  if a==0xfffffe000bcc5564:return self.stop('before_original_descriptor_copyout')
  if a==0xfffffe000bcbc3a8:return self.stop('before_original_namespace_growth')
  if a==0xfffffe000bc9d90c:self.hashes.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'bytes_hex':bytes(u.mem_read(self.reg(0),self.reg(1))).hex()});return self.model(a,'opaque_keyed_hash_result',0x123456789abcdef0)
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_unrecovered_original_callee')
  raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
  if i.mnemonic=='brk':return self.stop('before_original_namespace_trap',{'immediate':i.op_str})
  if i.mnemonic in ['autda','pacda']:
   assert raw==self.image.k.read(a,4);ptr,mod=(16,17)if i.mnemonic=='autda'else(17,16);e={'pc':hex(a),'pointer':hex(self.reg(ptr)),'modifier':hex(self.reg(mod))};(self.auth if i.mnemonic=='autda'else self.sign).append(e);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason is not None
  return {'kind':self.kind,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(PSP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'entry_Q_registers32':self.entryQ,'entry_DAIF_mask':'0x200','private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_state_transfer':self.transfer,'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'input_overlays':self.overlays,'packet_import':self.packet_import,'logical_data_authentication':self.auth,'logical_data_signing':self.sign,'namespace_frames':self.frames,'opaque_hash_inputs':self.hashes,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'boundary':self.boundary,'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_image_globals':[{'address':e['address'],'bytes_hex':bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()}for e in self.image_initial],'final_Q_registers32':[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)],'final_DAIF_mask':hex(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0),'final_port144_hex':bytes(self.u.mem_read(PORT,144)).hex(),'final_reply144_hex':bytes(self.u.mem_read(REPLY,144)).hex(),'final_space128_hex':bytes(self.u.mem_read(SPACE,128)).hex(),'final_entry24_hex':bytes(self.u.mem_read(TABLE+self.c['index']*24,24)).hex(),'final_header88_hex':bytes(self.u.mem_read(KMSG+0x40,88)).hex(),'final_output16_hex':bytes(self.u.mem_read(OUT,16)).hex(),'final_nesting':int.from_bytes(bytes(self.u.mem_read(RECV+0x1c8,4)),'little'),**{k:False for k in FLAGS}}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());prior=json.loads((ROOT/'kernel_receive_copyout_profiles.json').read_text());ctors=json.loads((ROOT/'kext_constructor_request_profiles.json').read_text());raw=decode(prior['consumers'][0]['final_private_RAM'])[0xd0000:0xd0100];rows=[];lookups=[]
 for family,c in enumerate(CONFIGS):
  parent={'ram':decode(prior['finishes'][0]['final_private_RAM']),'globals':prior['finishes'][0]['final_image_globals']};origin={'path':'kernel_receive_copyout_profiles.json','finish':0}
  packet=bytes.fromhex(ctors['cases'][c['constructor_case']]['message88_hex'])
  for kind in ['destination_make_send_1','destination_make_send_2','reply_init','reply_unlock','reply_make_send_once','header']:
   r=Probe(im,src,c,kind,parent,origin,packet,raw).run();r['family']=family;rows.append(r);parent={'ram':decode(r['final_private_RAM']),'globals':r['final_image_globals']};origin={'path':PREFIX+'_profiles.json','case':len(rows)-1};print(json.dumps({'case':len(rows)-1,'family':family,'kind':kind,'visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'pc':r['boundary']['pc']}),flush=True)
  if r['boundary']['kind']=='before_original_descriptor_copyout':
   base=parent;baseorigin=origin
   for kind in ['translate_valid','lookup_unlock','translate_wrong_right','translate_stale']:
    if kind in ['translate_wrong_right','translate_stale']:parent=base;origin=baseorigin
    q=Probe(im,src,c,kind,parent,origin,packet,raw).run();q['family']=family;lookups.append(q);parent={'ram':decode(q['final_private_RAM']),'globals':q['final_image_globals']};origin={'path':PREFIX+'_profiles.json','lookup':len(lookups)-1};print(json.dumps({'lookup':len(lookups)-1,'family':family,'kind':kind,'visits':len(q['source_visits']),'boundary':q['boundary']['kind'],'return':q['boundary']['registers31'][0]}),flush=True)
 deps=[PREFIX+'_source.json','kernel_receive_copyout_profiles.json','kext_constructor_request_profiles.json','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cases':rows,'lookups':lookups,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
