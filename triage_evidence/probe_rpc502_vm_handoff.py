#!/usr/bin/env python3
"""Original type3 factories feed exact whole-RAM copyout/discard components.
VM/copy/lock/allocator models, explicit entry changes and logical PAC; no native
transport, VM or retirement. O(visits+RAM+effects), O(RAM+journals).
"""
import base64,hashlib,json,struct,zlib
from unicorn import arm64_const as ar
from probe_rpc502_reply_copyin import Probe as Parent,P,SIZE,SP,HALT,MAP,THREAD,KMAP,MSG,EXT,COPIES,BACKS,SOURCES,ZONE,AUX
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='rpc502_vm_handoff';OUT=P+0x16000;DEST=P+0x30000;PENDING=P+0x2f000;COUNTER=0xfffffe000cb810f0;G=0xfffffe0007e6a01c;V=0xfffffe0007f8b5f0

def compressed(b):return {'address':hex(P),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'zlib_base64':base64.b64encode(zlib.compress(b,9)).decode('ascii')}
def decode(e):
 b=zlib.decompress(base64.b64decode(e['zlib_base64']));assert len(b)==e['size_bytes']==SIZE and hashlib.sha256(b).hexdigest()==e['sha256'];return b
class Probe(Parent):
 def __init__(self,im,c,source,seed,producer=None,producer_index=None):
  cfg={**seed['configuration'],**c};cfg['legacy_fixture_label']=cfg.pop('case');header=int(seed['message_header_address'],16);fixture=next(bytes.fromhex(e['bytes_hex'])for e in seed['initial_private_fixtures']if int(e['address'],16)==header);super().__init__(im,cfg,fixture);self.c=cfg;self.stage=c['stage'];self.parent_case=producer_index;self.frames=[];self.contexts=[];self.transfer=None
  if producer is None:
   for a,b in[(KMAP+0x10,struct.pack('<QQ',P,P+SIZE)),(KMAP+0x2c,b'\x0e'),(KMAP+0x88,struct.pack('<I',3)),(THREAD+0x428,struct.pack('<Q',MAP)),(THREAD+0x1c0,struct.pack('<Q',PENDING)),(OUT,b'\xa5'*16),(DEST,b'\xa5'*32768)]:self.fixture(a,b)
   metabase=next(int.from_bytes(bytes.fromhex(e['bytes_hex']),'little')for e in self.image_initial if e['address']=='0xfffffe0007e66f00');self.fixture(metabase+((KMAP>>10)&0xffffffff0),struct.pack('<H',0x10))
   for a,b in[(G,im.k.read(G,4)),(V,im.k.read(V,4)),(COUNTER,struct.pack('<I',7))]:self.image_fixture(a,b,'Original-file policy values; private copyout error-counter epoch7')
  else:
   ram=decode(producer['final_private_RAM']);self.u.mem_write(P,ram);self.initial=[];self.transfer={'producer_case':producer_index,**producer['final_private_RAM']};self.image_initial=[]
   for e in producer['final_image_globals']:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact producer final image-global transfer')
  if self.stage!='copyin':
   self.active=c['descriptor_index'];ptr=int.from_bytes(bytes(self.u.mem_read(header+36+16*self.active,8)),'little');self.input_copy=ptr
   for j in range(31):self.set(j,0)
   if self.stage=='copyout':self.entry=0xfffffe000bdd1574;args=[KMAP,OUT,ptr]
   else:assert self.stage=='discard';self.entry=0xfffffe000bdc6308;args=[ptr]
   for j,x in enumerate(args):self.set(j,x)
   self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP)
  self.allowed=[(int(f['start'],16),int(f['end'],16))for f in source['functions']];self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def model(self,a,symbol,result):
  super().model(a,symbol,result);self.models[-1]['descriptor_index']=self.active
 def image_fixture(self,a,b,why):self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':why})
 def write(self,u,t,a,n,v,d):
  if a==COUNTER:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  frame_arity={0xfffffe000bdd15a4:5,0xfffffe000bdd1574:3,0xfffffe000bdcb374:5,0xfffffe000bdc6308:1,0xfffffe000bcfec48:3,0xfffffe000bd74fcc:4}
  if a in frame_arity:self.frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(frame_arity[a])]})
  if a==0xfffffe000bdcc234:self.contexts.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(2)],'result_X8':hex(self.reg(8))})
  if a==0xfffffe000bdcc374:self.contexts.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(0))],'record24_hex':bytes(u.mem_read(self.reg(0),24)).hex()})
  if a==0xfffffe000bdc76b4:
   self.effect(a,'VM_allocate_model',self.c.get('allocation_result',0),[]if self.c.get('allocation_result',0)else[(self.reg(1),struct.pack('<Q',DEST),'declared mapped address')]);self.effects[-1]['stack_prefix12_hex']=bytes(u.mem_read(u.reg_read(ar.UC_ARM64_REG_SP),12)).hex();return
  if a==0xfffffe000be7798c:return self.effect(a,'copyout_model',self.c.get('copy_result',0),[]if self.c.get('copy_result',0)else[(self.reg(1),bytes(u.mem_read(self.reg(0),self.reg(2))),'exact producer backing bytes copied')])
  if a==0xfffffe000be63ea0:return self.effect(a,'map_switch_leaf_model',0,[(self.reg(0)+0x428,struct.pack('<Q',self.reg(1)),'declared private current-map switch/restore')])
  calls={0xfffffe000bd0a08c:'map_unlock_model',0xfffffe000c266d34:'VM_error_observer_model'}
  if a in calls:return self.model(a,calls[a],0)
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();addresses=list(dict.fromkeys((int(e['address'],16),len(e['bytes_hex'])//2)for e in self.image_initial));row.update(source_producer_case=self.parent_case,initial_private_RAM_transfer=self.transfer,final_private_RAM=compressed(bytes(self.u.mem_read(P,SIZE))),final_image_globals=[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in addresses],VM_handoff_frames=self.frames,map_context_frames=self.contexts,source_policy=int.from_bytes(bytes(self.u.mem_read(G,4)),'little'),source_policy_V=int.from_bytes(bytes(self.u.mem_read(V,4)),'little'),current_map=hex(int.from_bytes(bytes(self.u.mem_read(THREAD+0x428,8)),'little')),destination_map_refs=int.from_bytes(bytes(self.u.mem_read(KMAP+0x88,4)),'little'),copy_error_counter=int.from_bytes(bytes(self.u.mem_read(COUNTER,4)),'little'),mapped_address=int.from_bytes(bytes(self.u.mem_read(OUT,8)),'little'),mapped_region32768_hex=bytes(self.u.mem_read(DEST,32768)).hex(),native_IPC_executed=False,native_retirement_executed=False,native_namespace_conversion_executed=False,complete_FairPlay_round_trip_established=False,idb_mutated=False,full_goal_complete=False);return row

def main():
 im=Image();source=json.loads((ROOT/(PREFIX+'_source.json')).read_text());old=json.loads((ROOT/'rpc502_reply_copyin_profiles.json').read_text())['cases'];seeds=[old[j]for j in[10,14,18,22]];rows=[]
 def add(c,seed,producer=None):
  r=Probe(im,c,source,seed,None if producer is None else rows[producer],producer).run();rows.append(r);print(json.dumps({'case':len(rows)-1,'stage':c['stage'],'producer':producer,'lengths':r['configuration']['lengths'],'raw_u32':r['return_u32'],'visits':len(r['source_visits'])}),flush=True);return len(rows)-1
 for j,seed in enumerate(seeds):add({'stage':'copyin','legacy_fixture_case':[10,14,18,22][j]},seed)
 for j,seed in enumerate(seeds):
  out=add({'stage':'copyout','descriptor_index':0},seed,j);add({'stage':'discard','descriptor_index':1},seed,out)
 for label,changes in [('allocation_error',{'allocation_result':6}),('copy_error',{'copy_result':5})]:
  out=add({'stage':'copyout','descriptor_index':0,'outcome':label,**changes},seeds[1],1);first=add({'stage':'discard','descriptor_index':0},seeds[1],out);add({'stage':'discard','descriptor_index':1},seeds[1],first)
 deps=[PREFIX+'_source.json','rpc502_reply_copyin_profiles.json','probe_rpc502_reply_copyin.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cases':rows,'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'native_retirement_executed':False,'native_namespace_conversion_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
