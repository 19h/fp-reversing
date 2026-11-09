#!/usr/bin/env python3
"""Exact queued constructor state -> original receive frontend/dequeue/header.
O(image+visits+RAM+effects), O(image+RAM+journals). Receiver call/task/map/SMR/
namespace epochs and raw retirement/hash/PAC are declared; no packet replacement,
native IPC, scheduler, descriptor VM copyout or daemon execution occurs.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,HALT
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_request_receive';SENDER=P+0x60000;RECV=P+0x64000;OWNER=P+0x68000;TASK=P+0x947c0;MAP=P+0x78000;STATS=P+0x5a000;SMR=P+0x9d000;USER=P+0x1000;PSP=P+0xe6000;SPACE=P+0xdd000;TABLE=0x400000100000;D0=P+0xc0070;D1=P+0xc0100;REPLY=P+0x80070;TS=P+0xa8040;KMSG=P+0xd0000;LOAN=P+0xac040;FRONT=0xfffffe000bcdd4e4;RESULTS=0xfffffe000bcdcc7c;DESC=0xfffffe000bcc5564
WATCH=[FRONT,0xfffffe000bcc8cf4,0xfffffe000bcdd568,0xfffffe000bcc83b4,0xfffffe000bcc8514,0xfffffe000bcc86e4,0xfffffe000bcc87d8,RESULTS,0xfffffe000bcdce14,0xfffffe000bcc4e98,0xfffffe000bcbbff4,0xfffffe000bcbc0f0,0xfffffe000bcd5b90,0xfffffe000bcceb64,0xfffffe000bd74fcc,DESC]
def qregs(u):return[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
class Probe(CPU):
 def ensure(self,a,n=1):
  if TABLE<=a<a+n<=TABLE+4096:
   if TABLE not in self.pages:self.u.mem_map(TABLE,4096);self.u.mem_write(TABLE,bytes(4096));self.pages.add(TABLE)
   return
  return super().ensure(a,n)
 def __init__(self,im,src,c,parent):
  super().__init__(im,'selector',{'id':0});self.kind='receiver_turnstile_allocate'if c.get('phase')=='loan'else'queued_request_receive';self.c=c;self.initial=[];self.image_initial=[];self.overlays=[];self.auth=[];self.sign=[];self.frames=[];self.hashes=[];self.retire=[];self.raw=[];self.handoffs=[];self.allowed=[(int(f['start'],16),int(f['end'],16))for f in src['functions']];self.transfer={**({'path':'kernel_rpc_request_profiles.json','request':c['producer']}if self.kind=='receiver_turnstile_allocate'else{'path':PREFIX+'_profiles.json','loan':c['producer']}),**parent['final_private_RAM']};self.u.mem_write(P,decode(self.transfer))
  for e in parent['final_image_globals']:self.ensure(int(e['address'],16),len(e['bytes_hex'])//2);self.u.mem_write(int(e['address'],16),bytes.fromhex(e['bytes_hex']));self.image_initial.append(dict(e))
  self.destination=D0 if c['producer']<2 else D1;self.receive_name=0x303 if self.destination==D0 else 0x403;meta=int.from_bytes(bytes(self.u.mem_read(0xfffffe0007e66f00,8)),'little');th=bytearray(1536);struct.pack_into('<Q',th,0xb0,17);struct.pack_into('<Q',th,0x1c0,P+0xb4000);struct.pack_into('<I',th,0x1f8,4);struct.pack_into('<Q',th,0x420,OWNER);struct.pack_into('<Q',th,0x428,MAP);struct.pack_into('<I',th,0x518,0x4321);own=bytearray(56);struct.pack_into('<Q',own,0,RECV);struct.pack_into('<Q',own,0x28,TASK)
  for a,b in[(RECV,bytes(th)),(OWNER,bytes(own)),(TASK-0x7c0,bytes(0xe90)),(TASK-0x7c0+0x60,struct.pack('<I',4242)),(TASK+0x318,struct.pack('<Q',SPACE)),(TASK+0x3d8,struct.pack('<Q',STATS)),(TASK+0x6c8,struct.pack('<I',1)),(STATS,bytes(32)),(MAP,bytes(128)),(MAP+0x18,struct.pack('<Q',0xffffffffffffffff)),(MAP+0x2c,struct.pack('<I',14)),(USER,b'\xa5'*8192),(SMR,bytes(64)),(SPACE+0x14,struct.pack('<II',0,1)),(SPACE+0x1c,struct.pack('<I',0x35)),(SPACE+0x50,struct.pack('<Q',TASK)),(SPACE+0x70,struct.pack('<II',0xffffffff,0)),(meta+((OWNER>>10)&0xffffffff0),struct.pack('<H',3)),(meta+(((TASK-0x7c0)>>10)&0xffffffff0),struct.pack('<H',26))]:self.overlay(a,b,'Declared disjoint receiver thread/owner/task/map/SMR/user-buffer and namespace allocation epoch')
  if self.kind=='receiver_turnstile_allocate':
   for a,b in[(LOAN,bytes(96)),(LOAN+96,b'\xa5'),(meta+((LOAN>>10)&0xffffffff0),struct.pack('<H',28))]:self.overlay(a,b,'Declared raw receiver turnstile allocation storage and type metadata')
  else:self.overlay(RECV+0x30,struct.pack('<Q',LOAN),'Declared current-thread loan publication of preceding original allocator result')
  table=bytearray(bytes(self.u.mem_read(TABLE,4096)));struct.pack_into('<I',table,12,2);struct.pack_into('<QIIII',table,48,0,0,0,0x11223344,0x55667788)
  for a,b in[(TABLE,bytes(table)),(0xfffffe000caac348,struct.pack('<Q',0x100)),(0xfffffe000caac350,struct.pack('<Q',SMR))]:self.global_overlay(a,b,'Declared receiver free-entry/SMR epoch; preserve original service entries')
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,RECV);self.u.reg_write(ar.UC_ARM64_REG_SP,PSP);self.u.reg_write(ar.UC_ARM64_REG_PSTATE,(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&~0x3c0)|0x200)
  for j in range(31):self.set(j,0)
  for j,v in enumerate([USER,0,c['options'],0,0,c['capacity'],0,self.receive_name]):self.set(j,v)
  if self.kind=='receiver_turnstile_allocate':
   for j in range(31):self.set(j,0)
  self.set(30,HALT);self.entry=0xfffffe000bd682cc if self.kind=='receiver_turnstile_allocate'else FRONT;self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.entryQ=qregs(self.u);self.post_setup_packet=bytes(self.u.mem_read(KMSG,256)).hex()
 def overlay(self,a,b,why):self.overlays.append({'space':'private','address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why});self.fixture(a,b)
 def global_overlay(self,a,b,why):
  self.ensure(a,len(b));self.overlays.append({'space':'global','address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why});self.u.mem_write(a,b);found=False
  for e in self.image_initial:
   at=int(e['address'],16);n=len(e['bytes_hex'])//2
   if max(a,at)<min(a+len(b),at+n):e['bytes_hex']=bytes(self.u.mem_read(at,n)).hex()
   found|=at==a and n==len(b)
  if not found:self.image_initial.append({'address':hex(a),'bytes_hex':b.hex()})
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or TABLE<=a<a+n<=TABLE+4096,(hex(a),n);e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def frame(self,a):
  e={'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP))}
  for at,n,key in[(SENDER,1536,'sender1536_hex'),(RECV,1536,'receiver1536_hex'),(self.destination,144,'destination144_hex'),(REPLY,144,'reply144_hex'),(TS,96,'turnstile96_hex'),(KMSG,256,'kmsg256_hex'),(SPACE,128,'space128_hex'),(TABLE+48,24,'entry24_hex')]:e[key]=bytes(self.u.mem_read(at,n)).hex()
  self.frames.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a in WATCH:self.frame(a)
  if a==DESC:return self.stop('before_original_request_descriptor_copyout')
  if a==RESULTS and self.c.get('stop_at_results'):return self.stop('before_original_receive_results_with_queue_preserved')
  if a in[0xfffffe000bcdd708,RESULTS,0xfffffe000bcc4e98]:self.handoffs.append({'pc':hex(a),'source_visit_index':len(self.visits),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'NZCV':hex(u.reg_read(ar.UC_ARM64_REG_NZCV)),'Q_registers32':qregs(u),'private_RAM':compressed(bytes(u.mem_read(P,SIZE)))})
  if a==HALT:return self.stop('original_receiver_turnstile_allocated'if self.kind=='receiver_turnstile_allocate'else'receive_frontend_returned')
  if a==0xfffffe000bd75c64 and self.kind=='receiver_turnstile_allocate':self.raw.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'returned_pointer':hex(LOAN),'object_before_hex':bytes(u.mem_read(LOAN,96)).hex()});return self.model(a,'declared_zeroed_raw_receiver_turnstile_storage',LOAN)
  if a==0xfffffe000bd28f6c:return self.stop('before_original_scheduler_block')
  if a==0xfffffe000bc9d90c:self.hashes.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'bytes_hex':bytes(u.mem_read(self.reg(0),self.reg(1))).hex()});return self.model(a,'opaque_keyed_hash_result',0x123456789abcdef0)
  if a==0xfffffe000bd74fcc:self.retire.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'turnstile96_hex':bytes(u.mem_read(TS,96)).hex()});return self.model(a,'declared_raw_turnstile_retirement',0)
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_unrecovered_request_receive_callee')
  raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert raw==self.image.k.read(a,4)
  if i.mnemonic=='brk':return self.stop('before_original_receive_trap',{'instruction':i.op_str})
  if i.mnemonic in['autda','pacda']:
   rr=[int(v.strip()[1:])for v in i.op_str.split(',')];(self.auth if i.mnemonic=='autda'else self.sign).append({'pc':hex(a),'visit':len(self.visits),'registers':rr,'pointer':hex(self.reg(rr[0])),'modifier':hex(self.reg(rr[1]))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry)
  try:self.u.emu_start(self.entry,0,count=50000)
  except Exception:print({'PC':hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),'arguments8':[hex(self.reg(j))for j in range(8)],'last_visits':self.visits[-3:]},flush=True);raise
  self.flush();assert self.reason is not None
  return {'kind':self.kind,'configuration':self.c,'destination':hex(self.destination),'receive_name':hex(self.receive_name),'entry_PC':hex(self.entry),'entry_SP':hex(PSP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'entry_Q_registers32':self.entryQ,'entry_DAIF_mask':'0x200','current_thread':hex(RECV),'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_state_transfer':self.transfer,'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'input_overlays':self.overlays,'post_setup_original_kmsg256_hex':self.post_setup_packet,'logical_data_authentication':self.auth,'logical_data_signing':self.sign,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'opaque_hash_inputs':self.hashes,'raw_retirement_contracts':self.retire,'raw_storage_contracts':self.raw,'receive_frames':self.frames,'continuous_receive_handoffs':self.handoffs,'boundary':self.boundary,'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_image_globals':[{'address':e['address'],'bytes_hex':bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()}for e in self.image_initial],'final_Q_registers32':qregs(self.u),'final_DAIF_mask':hex(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0),**{k:False for k in FLAGS}}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());prior=json.loads((ROOT/'kernel_rpc_request_profiles.json').read_text());rows=[];loans=[]
 for j in range(4):
  r=Probe(im,src,{'producer':j,'capacity':88,'options':2,'phase':'loan'},prior['requests'][j]).run();loans.append(r);assert r['boundary']['kind']=='original_receiver_turnstile_allocated',r['boundary'];print(json.dumps({'loan':j,'visits':len(r['source_visits'])}),flush=True)
 configs=[{'producer':j,'capacity':cap,'options':opt}for j in range(4)for cap,opt in[(88,2),(148,0x7000002)]]+[{'producer':j,'capacity':87,'options':6,'stop_at_results':True}for j in[0,2]]
 for c in configs:
  r=Probe(im,src,c,loans[c['producer']]).run();rows.append(r);print(json.dumps({'case':len(rows)-1,'configuration':c,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_rpc_request_profiles.json','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py']},'loans':loans,'cases':rows,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
