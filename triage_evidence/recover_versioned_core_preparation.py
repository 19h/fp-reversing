#!/usr/bin/env python3
"""Original selector21 admitted preparation in a private A64 guest.

Fresh core-entry prefixes, source table loop and conditional helper. Successful
heap returns remain register-only models. Stop before unexamined calls; strict
initialization forbids consuming private fill. No native API/IPC/IDB executes.
O(C*(B+V+E)+256R) time/space; at most 20000 visits per continuation.
"""
import json,struct
from collections import Counter
from copy import deepcopy
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,IMAGE,CS,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import probe_versioned_core_entry as Parent
import recover_versioned_core_entry as Entry

P='versioned_core_preparation';HELPER=0xfffffe000a5b4314
PINS={'versioned_core_entry_checks.json':'3843173c58a27020559624f24f9c71d4c9c44d355f3c073d705daacd94db62b5','versioned_core_entry_replays.json':'0f55e7933e0430ffed4e38c8b6e4e3fee0635ba8777de7c008f52b91335c5761','daemon_postblock_dispatch_checks.json':'3cd216630458c65aa34c0f2b1f6155c35a7cfc8206eb97b0fdcc6788e0b401b0'}
DEPS=['recover_versioned_core_entry.py','probe_versioned_core_entry.py','kernel_native_reader.py','kext_port_tools.py','recover_carrier_control.py','recover_kext_cold_init.py',*PINS]

def regions(k):
 return [dict(span(k,0xfffffe000a5a5bf4,0xfffffe000a5a72bc),label='admitted_preparation'),dict(span(k,HELPER,0xfffffe000a5b62e0),label='conditional_helper'),dict(span(k,0xfffffe000a628060,0xfffffe000a628104),label='unsigned_compare_leaf'),dict(span(k,0xfffffe000a6172b8,0xfffffe000a61c404),label='block_helper')]

class Run(Parent.Run):
 def __init__(self,k,ss,c,payload):
  self.continuing=False;super().__init__(k,ss,c);self.transfers=[];self.payload=payload;self.prefix_boundary=None;self.checkpoints=[]
  self.args[3]=payload['generated_word32'];self.setreg(3,self.args[3])
  if payload['optional16_hex']is not None:self.seed(Parent.P+0x1000,bytes.fromhex(payload['optional16_hex']))
  self.seed(Parent.P+0x1200,bytes.fromhex(payload['processed16_hex']))
  self.extra_globals=[0xfffffe000ccc3318,0xfffffe000ccc3140]
  for a in self.extra_globals:self.seed(a,k.read(a,8))
  a=0xfffffe000ccceaf4;self.u.mem_map(a&~4095,4096);self.seed(a,k.read(a,8));self.external_known=set(range(a,a+8))
 def read(self,u,access,a,n,value,data):
  if not Parent.P<=a<a+n<=Parent.P+0x20000 and not any(v<=a<a+n<=v+sz for v,off,sz in IMAGE.segments):assert all(j in self.external_known for j in range(a,a+n)),('undefined external read',hex(u.reg_read(ar.UC_ARM64_REG_PC)),hex(a),n)
  return super().read(u,access,a,n,value,data)
 def write(self,u,access,a,n,value,data):
  if any(g<=a<a+n<=g+8 for g in self.extra_globals):
   e={'visit':len(self.visits)-1,'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,access,a,n,value,data)
 def code(self,u,a,n,data):
  if not self.continuing:return super().code(u,a,n,data)
  self.flush();raw=self.k.read(a,4);assert raw==IMAGE.read(a,4)==bytes(u.mem_read(a,4));ins=next(CS.disasm(raw,a));m=ins.mnemonic
  assert any(x<=a<a+4<=z for x,z in self.ranges),('source escape',hex(a))
  if a in [0xfffffe000a5a5d18,0xfffffe000a5a6294,0xfffffe000a5a6298,0xfffffe000a61765c,0xfffffe000a617c28,0xfffffe000a617d00]:
   self.checkpoints.append({'pc':hex(a),'before_visit':len(self.visits),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]})
  if a==0xfffffe000a5a6e5c:
   addr=u.reg_read(ar.UC_ARM64_REG_SP)+0x130
   assert ins.op_str=='w24, [sp, #0x130]'and not all(j in self.known for j in range(addr,addr+4))
   self.boundary={'kind':'before_undefined_frame_word_read','pc':hex(a),'address':hex(addr),'size_bytes':4,'known_bytes':sum(j in self.known for j in range(addr,addr+4)),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)],'instruction_executed':False};return u.emu_stop()
  if m=='blraa':
   target=self.reg(int(ins.op_str.split(',')[0][1:]));mod=self.reg(17)
   if a not in [0xfffffe000a5a5e18,0xfffffe000a5b4530,0xfffffe000a5b4d20,0xfffffe000a5a6294,0xfffffe000a617490]:
    self.boundary={'kind':'before_unexamined_source_call','pc':hex(a),'target':hex(target),'modifier':hex(mod),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)],'target_executed':False};return u.emu_stop()
   assert(target,mod)=={0xfffffe000a5a5e18:(HELPER,0x85d),0xfffffe000a5b4530:(0xfffffe000a687ecc,0x4d6a),0xfffffe000a5b4d20:(0xfffffe000a628060,0xfae5),0xfffffe000a5a6294:(0xfffffe000a6172b8,0x6a0f),0xfffffe000a617490:(0xfffffe000a687ecc,0x4d6a)}[a]
  self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if m in ['braa','blraa']:
   target=self.reg(int(ins.op_str.split(',')[0][1:]));mod=self.reg(17);assert any(x<=target<z for x,z in self.ranges),('transfer escape',hex(a),hex(target))
   reads=[e for e in self.reads if e['size_bytes']==8 and POOL<=int(e['address'],16)<POOL+0xc000 and int.from_bytes(bytes.fromhex(e['bytes_hex']),'little')==target];assert reads,('missing pointer read',hex(a),hex(target));slot=int(reads[-1]['address'],16)
   self.transfers.append({'pc':hex(a),'target':hex(target),'modifier':hex(mod),'matched_source_pointer_read':hex(slot),'pointer_read_visit':reads[-1]['visit'],'visit':len(self.visits)-1,'call':m=='blraa'})
   if m=='blraa':self.setreg(30,a+4)
   return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if m in ['pacibsp','bti']:return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m=='retab':return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  assert m not in ['br','blr','bl','svc','hvc','smc','brk']and not m.startswith(('pac','aut','xpac')),(hex(a),m)
 def run(self):
  row=super().run();self.prefix_boundary=deepcopy(self.boundary);cut=len(self.visits);self.prefix_boundary['source_visits']=cut;self.boundary=None;self.continuing=True
  self.u.emu_start(Entry.ACCEPT,0,count=20000);self.flush();assert self.boundary is not None
  row.update(configuration=self.case,source_prefix_boundary=self.prefix_boundary,boundary=self.boundary,source_transfers=self.transfers,source_checkpoints=self.checkpoints,source_payload=self.payload,continuation_visits=len(self.visits)-cut,count_cell_at_boundary=self.snapshot(Parent.Q,4),final_workspace=self.snapshot(Parent.W,0x180),final_auxiliary=self.snapshot(Parent.A,0x100),final_processed_input=self.snapshot(Parent.P+0x1200,16),prefixes_reexecuted=True)
  return row

def payloads():
 daemon=json.loads(read(ROOT/'daemon_postblock_dispatch_checks.json'));out=[]
 for j,case in enumerate(daemon['cases']):
  t=case['api_view']['source_shape']['terms'];word=lambda a:int.from_bytes(bytes(t[a:a+4]),'little');mode=word(0)
  assert mode in [2,5]and word(4)==0xb4d3a486 and word(0x220)==16
  out.append({'daemon_case_index':j,'daemon_configuration':case['configuration'],'mode32':mode,'marker32':word(4),'generated_word32':word(8),'optional16_hex':bytes(t[12:28]).hex()if mode==5 else None,'processed16_hex':bytes(t[32:48]).hex(),'optional_mode2_origins_retained':[v['origin']for v in t[12:28]]if mode==2 else None})
 return out

def configurations():
 for original in payloads():
  for profile in ['baseline','block_bit0','generated_bit0']+(['optional_bit0']if original['mode32']==5 else[]):
   payload=deepcopy(original);payload['operand_profile']=profile
   if profile=='generated_bit0':payload['generated_word32']^=1
   if profile in ['block_bit0','optional_bit0']:
    key='processed16_hex'if profile=='block_bit0'else'optional16_hex';raw=bytearray.fromhex(payload[key]);raw[0]^=1;payload[key]=raw.hex()
   for epoch in [0,1]:
    c={'mode32':payload['mode32'],'marker32':payload['marker32'],'epoch':epoch,'pattern':0xa5 if epoch==0 else 0x3c,'placement':epoch*0x100,'global_fixture':'original'if epoch==0 else'declared_noise','count32':512}
    yield c,payload

def build():
 for name,digest in PINS.items():assert sha(ROOT/name)==digest,name
 k,old=Entry.source();ss=regions(k);allregions=old+ss;rows=[];totals=Counter()
 for c,payload in configurations():
  v=Run(k,allregions,c,payload);r=v.run();rows.append(r);totals.update(Parent.audit_bytes(r,k));totals['continuation_visits']+=r['continuation_visits']
 out={'scope':__doc__,'generator_sha256':sha(__file__),'parent_pins':PINS,'dependencies':{n:sha(ROOT/n)for n in DEPS},'kernel_collection_sha256':k.sha256,'source_regions':ss,'cases':rows,'verified_counts':{'cases':len(rows),**totals},'native_target_executed':False,'model_memory_writes':0,'full_goal_complete':False}
 return out

if __name__=='__main__':
 obj=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(obj['verified_counts']),flush=True)
