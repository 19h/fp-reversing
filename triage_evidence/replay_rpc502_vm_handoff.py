#!/usr/bin/env python3
"""Independent original CPU/effect replay with whole-RAM transfer verification.
O(visits+RAM+effects), O(RAM+journals). No probe import or native VM operation.
"""
import base64,hashlib,struct,zlib
from unicorn import arm64_const as ar
from replay_kernel_reply_send import Replay as Parent
P=0x6500000000;SIZE=0x100000;MAP=P+0x2a000;KMAP=P+0x2e000;THREAD=P+0x2c000;SOURCES=[P+0x50000,P+0x60000];BACKS=[P+0x70000,P+0x78000];COPIES=[P+0x68000,P+0x69000];ZONE=P+0x86000;AUX=P+0x88000;OUT=P+0x16000;DEST=P+0x30000

def decode(e):
 b=zlib.decompress(base64.b64decode(e['zlib_base64']));assert e['address']==hex(P)and len(b)==e['size_bytes']==SIZE and hashlib.sha256(b).hexdigest()==e['sha256'];return b
class Replay(Parent):
 def __init__(self,image,p):
  q=dict(p)
  if p['initial_private_RAM_transfer']is not None:q['initial_private_fixtures']=[{'address':hex(P),'bytes_hex':decode(p['initial_private_RAM_transfer']).hex()}]
  super().__init__(image,q);self.effects=p['declared_effects'];self.ei=self.si=self.ci=self.switches=0;self.sign=p['logical_data_signing'];self.active=None;self.fi={k:0 for k in ['VM_handoff_frames','map_context_frames']}
  for e in p['private_system_register_fixtures']:assert e['register']=='TPIDR_EL1';self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,int(e['value'],16))
 def code(self,u,a,n,d):
  self.finish();c=self.p['configuration'];stage=c['stage'];lens=c['lengths']
  for key,j in list(self.fi.items()):
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   self.fi[key]+=1;assert e['arguments']==[hex(self.reg(k))for k in range(len(e['arguments']))]
   if 'result_X8'in e:assert e['result_X8']==hex(self.reg(8))
   if 'record24_hex'in e:assert e['record24_hex']==bytes(u.mem_read(self.reg(0),24)).hex()
   self.counts[key+'_checked']+=1
  if a==0xfffffe000bdd15a4:
   e=self.p['VM_copyin_entries'][self.ci];self.ci+=1;self.active=SOURCES.index(self.reg(1));assert e['source_visit_index']==self.seq and e['descriptor_index']==self.active and e['arguments5']==[hex(self.reg(j))for j in range(5)]and[self.reg(j)for j in range(4)]==[MAP,SOURCES[self.active],lens[self.active],1];self.counts['original_copyin_argument_frames_checked']+=1
  if self.ei<len(self.effects)and self.effects[self.ei]['pc']==hex(a)and self.effects[self.ei]['before_source_visit_index']==self.seq:
   e=self.effects[self.ei];self.ei+=1;want=[];result=0;idx=self.active
   if a==0xfffffe000bcfe5b8:assert stage=='copyin'and[self.reg(j)for j in range(4)]==[0xfffffe0007f8bfb0,lens[idx],0,0];result=BACKS[idx]
   elif a==0xfffffe000bd75c64:assert stage=='copyin'and[self.reg(j)for j in range(3)]==[ZONE,AUX,4];result=COPIES[idx]
   elif a==0xfffffe000bdc2fc0:assert stage=='copyin'and[self.reg(j)for j in range(5)]==[MAP,SOURCES[idx],BACKS[idx],lens[idx],1];want=[(BACKS[idx],bytes(u.mem_read(SOURCES[idx],lens[idx])))]
   elif a==0xfffffe000bdc76b4:
    assert stage=='copyout'and[self.reg(j)for j in range(8)]==[KMAP,OUT,((lens[0]+16383)//16384)*16384,0,0x6000000000000000,0,0,0]and e['stack_prefix12_hex']==bytes(u.mem_read(u.reg_read(ar.UC_ARM64_REG_SP),12)).hex()==struct.pack('<III',3,7,1).hex();result=c.get('allocation_result',0)
    if not result:want=[(OUT,struct.pack('<Q',DEST))]
   elif a==0xfffffe000be7798c:
    assert stage=='copyout'and[self.reg(j)for j in range(3)]==[BACKS[0],DEST,lens[0]];result=c.get('copy_result',0)
    if not result:want=[(DEST,bytes(u.mem_read(BACKS[0],lens[0])))]
   elif a==0xfffffe000be63ea0:
    assert stage=='copyout'and[self.reg(j)for j in range(2)]==[THREAD,KMAP if self.switches==0 else MAP];self.switches+=1;want=[(THREAD+0x428,struct.pack('<Q',self.reg(1)))]
   elif a==0xfffffe000c6480c0:assert self.reg(0)in COPIES and self.reg(1)==48;want=[(self.reg(0),bytes(48))]
   else:raise AssertionError(hex(a))
   assert int(self.models[self.mi]['return_value'],16)==result and len(e['patches'])==len(want)
   for (ptr,b),saved in zip(want,e['patches'],strict=True):assert saved['address']==hex(ptr)and saved['before_hex']==bytes(u.mem_read(ptr,len(b))).hex()and saved['after_hex']==b.hex();u.mem_write(ptr,b);self.counts['declared_effect_patches_checked']+=1;self.counts['declared_effect_bytes_checked']+=len(b)
   self.counts['declared_effect_calls_checked']+=1
  if self.si<len(self.sign)and self.sign[self.si]['pc']==hex(a)and self.seq<len(self.p['source_visits'])and self.p['source_visits'][self.seq]['pc']==hex(a):
   e=self.sign[self.si];self.si+=1;raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic=='pacda'and raw==self.image.k.read(a,4)and raw.hex()==self.p['source_visits'][self.seq]['bytes_hex']and self.reg(17)==int(e['pointer'],16)and self.reg(16)==int(e['modifier'],16);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_data_sign_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.ei==len(self.effects)and self.si==len(self.sign)and self.ci==len(self.p['VM_copyin_entries'])and all(j==len(self.p[k])for k,j in self.fi.items())
  assert bytes(self.u.mem_read(P,SIZE))==decode(self.p['final_private_RAM']);self.counts['whole_final_RAM_images_checked']+=1;self.counts['whole_final_RAM_bytes_checked']+=SIZE
  for e in self.p['final_image_globals']:assert bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()==e['bytes_hex'];self.counts['final_image_globals_checked']+=1
  assert self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)==THREAD;return dict(self.counts)
