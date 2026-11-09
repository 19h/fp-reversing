#!/usr/bin/env python3
"""Original PID1-associated gate publication, zone policy, locks and refill joins.
O(visits+RAM+effects), O(image+RAM+journals). Process/setup/followup/random results
and counter/page epochs are declared; no native process, locks, entropy or IPC.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_kernel_kmsg_allocation import AllocationMixin
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_cache_gate';GATE=0xfffffe000ca92380;POLICY=0xfffffe000bd7b938;PUBLISH=0xfffffe000c266258;CURSOR=0xfffffe000bd76a6c;ZONE=0xfffffe000caec680;ARRAY=0xfffffe000caeb480;FREE=0xfffffe000cb510e0;RESERVED=0xfffffe000cb2a2b8;THREAD=P+0x2c000;PENDING=P+0xb4000;STATS=P+0xb1000;CACHE=P+0xb2000;PROC=P+0x86000;KERNPROC=P+0x82000;PAGE=P+0xd0000;META=P+0xc0000;BITMAP=P+0xc1000;INDEX=PAGE>>14;HEADBASE=0xfffffe000ca8c000

def simd(u):return[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
class Probe(AllocationMixin,CPU):
 def __init__(self,im,c,src,parent,path,index):
  super().__init__(im,'selector',{'id':0});self.kind=PREFIX;self.c=c;self.mode=c['mode'];self.initial=[];self.image_initial=[];self.auth=[];self.sign=[];self.frames=[];self.allocation_frames=[];self.alloc_overlays=[];self.overlays=[];self.cache_at=CACHE;self.stats_at=STATS;self.allowed=[(int(f['start'],16),int(f['end'],16))for f in src['functions']];self.transfer={'path':path,'case':index,**parent['final_private_RAM']};self.u.mem_write(P,decode(self.transfer));self.parent=parent;self.ensure(GATE)
  for e in parent['final_image_globals']:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact prior component image-global output')
  self.patch(THREAD+0x1b8,bytes(2),'Declared current CPU0');self.patch(THREAD+0x1c0,struct.pack('<Q',PENDING),'Declared pending-state pointer');self.patch(THREAD+0x1c8,bytes(4),'Declared new call epoch nesting0');self.patch(PENDING,bytes(80),'Declared no pending-preemption work');self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  if self.mode=='publication':self.entry=PUBLISH;self.patch(0xfffffe0007f8c250,struct.pack('<Q',KERNPROC),'Declared kernproc pointer for initial setup call')
  elif self.mode=='policy':
   self.entry=POLICY;self.patch(0xfffffe000caeb600,bytes(8),'Selective policy registry epoch: allocation-context slot2 is not a created record');self.patch(FREE,struct.pack('<I',c.get('free',100)),'Declared free-page counter');self.patch(RESERVED,struct.pack('<I',c.get('reserved',50)),'Declared reserved-page counter')
   if 'gate'in c:self.patch(GATE,bytes([c['gate']]),'Controlled initial cache-gate byte')
   self.patch(ZONE+0x74,struct.pack('<I',c.get('events',0)),'Declared current interval event counter')
   if 'quota'in c:self.patch(ZONE+0x7c,struct.pack('<H',c['quota']),'Controlled initial active local quota')
   if 'prior_score'in c:self.patch(ZONE+0x78,struct.pack('<I',c['prior_score']),'Controlled prior filtered event score')
   self.patch(ZONE+0x84,struct.pack('<I',10),'Declared zone capacity-comparison bound');self.patch(ZONE+0x8c,struct.pack('<I',c.get('capacity',1)),'Declared zone capacity-comparison current value')
   for ident in range(1,40):
    a=ARRAY+192*ident;self.ensure(a,8)
    if ident!=24:assert int.from_bytes(bytes(self.u.mem_read(a,8)),'little')!=a
  elif self.mode=='cursor':self.entry=CURSOR;self.patch(STATS+0x18,struct.pack('<I',c['cursor']),'Declared prior allocation-selection cursor')
  else:
   assert self.mode=='allocator';self.entry=0xfffffe000bcc24a4;self.patch(PAGE,bytes(16384),'Declared raw zero arena');self.patch(PAGE+16384,b'\xa5','Guard outside raw arena');self.patch(ZONE+0x9c,struct.pack('<I',INDEX),'Declared partial-page metadata index');self.patch(ZONE+0xa8,struct.pack('<I',48),'Declared48 available raw elements');self.patch(ZONE+0xb0,bytes(4),'Declared no pending reserve');self.patch(0xfffffe0007e66f00,struct.pack('<Q',META-INDEX*16),'Declared biased page-metadata array base');self.patch(0xfffffe0007e66e70,struct.pack('<Q',BITMAP),'Declared external bitmap base');self.patch(META,struct.pack('<HHIII',0x1018,16,0,0,(ZONE+0x9c-(HEADBASE-4))>>2),'Declared selected partial page with16 used elements');self.patch(BITMAP,struct.pack('<Q',((1<<64)-1)^((1<<16)-1)),'Declared48 free element bits')
  for j in range(31):self.set(j,HALT if j==30 else 0)
  if self.mode=='cursor':self.set(0,ZONE);self.set(1,0);self.set(2,STATS)
  if self.mode=='allocator':
   for j,x in enumerate([44,0,0,1]):self.set(j,x)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.entryQ=simd(self.u)
 def image_fixture(self,a,b,why):self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':why})
 def patch(self,a,b,why):
  self.ensure(a,len(b));self.overlays.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why})
  if P<=a<a+len(b)<=P+SIZE:self.fixture(a,b)
  else:self.image_fixture(a,b,why)
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or ZONE<=a<a+n<=ZONE+192 or GATE<=a<a+n<=GATE+1 or 0xfffffe000cb51668<=a<a+n<=0xfffffe000cb51670 or 0xfffffe000ca92370<=a<a+n<=0xfffffe000ca92374 or a==0xfffffe000cb81100 and n==1,(hex(a),n);e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('original_'+self.mode+'_call_returned')
  if a==0xfffffe000c2cf4a0:return self.stop('before_original_PID1_followup')
  if a in[PUBLISH,POLICY,CURSOR,0xfffffe000bd7b984,0xfffffe000bd7b9fc,0xfffffe000bd7bb18,0xfffffe000bd7bc6c,0xfffffe000bd7bc88,0xfffffe000c2662bc,0xfffffe000c2662f0,0xfffffe000bd75e20,0xfffffe000bd76db4,0xfffffe000bd76ad0]:self.frames.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'zone192_hex':bytes(u.mem_read(ZONE,192)).hex(),'statistics32_hex':bytes(u.mem_read(STATS,32)).hex(),'gate_u8':int.from_bytes(bytes(u.mem_read(GATE,1)),'little'),'thread_nesting':int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little')})
  if a==0xfffffe000c2b2928:assert self.mode=='publication'and[self.reg(j)for j in range(4)]==[0,0,KERNPROC,2];return self.model(a,'declared_initial_setup_object',THREAD)
  if a==0xfffffe000c2b9748:assert self.mode=='publication'and self.reg(0)==1;return self.model(a,'declared_proc_find_PID1',PROC if self.c.get('process_present',True)else 0)
  if a==0xfffffe000bd5d120:assert self.mode=='policy'and self.reg(0)==0xfffffe000cb7f1f0 and self.reg(1)==0;return self.model(a,'declared_thread_call_enter1',0)
  if a==0xfffffe000be57f8c:assert self.mode=='cursor';return self.model(a,'declared_cursor_step_result',self.c['step'])
  if a in[0xfffffe000bd0abac,0xfffffe000bd0ab80,0xfffffe000beda010,0xfffffe000be8663c]:return self.stop('before_unmodeled_lock_or_preemption_helper',{'entry':hex(a)})
  if a==0xfffffe000bd75e20:return CPU.code(self,u,a,n,d)
  if self.allocation_code(u,a,n,d):return
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=30000);self.flush();assert self.reason is not None;g=[]
  for e in self.image_initial+[{'address':hex(a),'bytes_hex':bytes(n).hex()}for a,n in[(GATE,1),(0xfffffe000cb51668,8),(0xfffffe000ca92370,4),(0xfffffe000cb81100,1)]]:
   a=int(e['address'],16);n=len(e['bytes_hex'])//2;self.ensure(a,n)
   if not any(int(old['address'],16)<=a and a+n<=int(old['address'],16)+len(old['bytes_hex'])//2 for old in g):g.append({'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()})
  z=bytes(self.u.mem_read(ZONE,192));ret=int(self.boundary['registers31'][0],16)
  return{'configuration':self.c,'zone_address':hex(ZONE),'selected_cache_address':hex(CACHE),'selected_statistics_address':hex(STATS),'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'entry_Q_registers32':self.entryQ,'final_Q_registers32':simd(self.u),'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_state_transfer':self.transfer,'private_system_register_fixtures':[{'register':'TPIDR_EL1','value':hex(THREAD)}],'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'memory_overlays':self.overlays,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_data_authentication':self.auth,'logical_data_signing':self.sign,'startup_frames':[],'allocation_frames':self.allocation_frames,'gate_policy_frames':self.frames,'boundary':self.boundary,'final_zone192_hex':z.hex(),'final_gate_u8':int.from_bytes(bytes(self.u.mem_read(GATE,1)),'little'),'final_statistics32_hex':bytes(self.u.mem_read(STATS,32)).hex(),'final_cache64_hex':bytes(self.u.mem_read(CACHE,64)).hex(),'final_thread_nesting':int.from_bytes(bytes(self.u.mem_read(THREAD+0x1c8,4)),'little'),'final_metadata16_hex':bytes(self.u.mem_read(META,16)).hex(),'final_bitmap8_hex':bytes(self.u.mem_read(BITMAP,8)).hex(),'final_element256_hex':bytes(self.u.mem_read(ret,256)).hex()if self.boundary['kind']=='original_allocator_call_returned'else None,'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_image_globals':g,**{k:False for k in FLAGS}}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());boot=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'][0];configs=[{'mode':'publication'},{'mode':'publication','process_present':False},{'mode':'policy','from_boot':True},{'mode':'policy'},{'mode':'policy','free':50},{'mode':'policy','parent':4,'free':49},{'mode':'policy','parent':4,'free':51},{'mode':'policy','free':0x80000000,'reserved':0x7fffffff},{'mode':'policy','events':400},{'mode':'policy','events':400,'quota':2},{'mode':'policy','events':400,'quota':200},{'mode':'policy','quota':2},{'mode':'policy','quota':1},{'mode':'policy','events':400,'quota':5,'capacity':10},{'mode':'policy','parent':8},{'mode':'cursor','cursor':0,'step':2},{'mode':'cursor','cursor':63,'step':8},{'mode':'allocator','parent':0},{'mode':'allocator','parent':8},{'mode':'allocator','parent':4}];rows=[]
 for c in configs:
  idx=c.get('parent',0);selfparent=c['mode']in['policy','allocator']and not c.get('from_boot');parent=rows[idx]if selfparent else boot;path=PREFIX+'_profiles.json'if selfparent else'kernel_zone_startup_profiles.json';r=Probe(im,c,src,parent,path,idx if selfparent else 0).run();rows.append(r);print(json.dumps({'case':len(rows)-1,'configuration':c,'visits':len(r['source_visits']),'gate':r['final_gate_u8'],'quota':int.from_bytes(bytes.fromhex(r['final_zone192_hex'])[0x7c:0x7e],'little'),'boundary':r['boundary']['kind']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_zone_startup_profiles.json','probe_kernel_vm_mig.py','probe_kernel_kmsg_allocation.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py','recover_kernel_send_right_lifecycle.py']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
