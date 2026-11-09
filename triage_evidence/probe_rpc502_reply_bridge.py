#!/usr/bin/env python3
"""Private original-code RPC502 reply construction and post-transport parsing.
Application outputs, NDR binding and user/kernel transfer are declared fixtures.
O(cases*source visits) time; O(private map+journals) space. No native IPC/PAC.
"""
import json,struct
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,CS
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha
from probe_kernel_vm_mig import Probe as Base,P,SIZE,SP,HALT
REQ=P+0x10000;REP=P+0x20000;NDR=P+0x30000;R0=P+0x40000;R1=P+0x41000;OUT=P+0x42000
NDR8=bytes.fromhex('0000000001000000');OOL0=P+0x50000;OOL1=P+0x60000
class View:
 def __init__(self):self.k=self;self.cs=CS
 def read(self,a,n):return IMAGE.read(a,n)
 def logical_page(self,a):return IMAGE.read(a,4096)

class Probe(Base):
 def __init__(self,image,kind,fixture,config):
  fixture=bytes(fixture)
  super().__init__(image,'stub',{'port_class':'null','bits':0,'request_size':56,'address':0,'size':0,'body_placement':'joined'});self.kind=kind;self.c=config;self.u.mem_write(P,bytes(SIZE));self.initial=[];self.image_initial=[]
  for j in range(31):self.set(j,0)
  self.set(30,HALT)
  if kind=='demux_prefix':
   self.entry=0x100005274;self.allowed=[(self.entry,0x100005298)];self.fixture(REQ,fixture);self.fixture(REP,bytes(400));self.set(0,REQ);self.set(1,REP);self.end=0x100005298
  elif kind=='daemon_completion':
   self.entry=0x1000051fc;self.allowed=[(self.entry,0x100005260)];self.fixture(REP,fixture);self.fixture(NDR,NDR8);self.ensure(0x1010b1e10,8);word=struct.pack('<Q',NDR);self.u.mem_write(0x1010b1e10,word);self.image_initial=[{'address':'0x1010b1e10','bytes_hex':word.hex(),'provenance':'declared private binding for imported NDR_record'}];self.set(0,config['application_status']);self.set(19,REP);self.end=None
  else:
   assert kind=='kext_reply';self.entry=0xfffffe000a5a20fc;self.allowed=[(self.entry,0xfffffe000a5a229c)];self.fixture(SP+8,fixture);self.fixture(R0,bytes([0xa5])*136);self.fixture(R1,bytes([0xa5])*172);self.fixture(OUT,bytes([0xa5])*24)
   self.set(0,config['transport_status']);self.set(20,R1);self.set(21,R0);self.set(22,1);self.set(29,SP+0x1d0);self.fixture(SP+0x1e0,struct.pack('<4Q',OUT,OUT+8,OUT+12,OUT+20));self.end=0xfffffe000a5a229c
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def code(self,u,a,n,d):
  self.flush()
  if a==self.end or(self.kind=='daemon_completion'and a in [0x100005214,0x100005260]):return self.stop('component_complete')
  if self.kind=='kext_reply'and a in [0xfffffe000a69f314,0xfffffe000a69f364,0xfffffe000a69f384]:return self.model(a,{0xfffffe000a69f314:'message_destroy_request_only',0xfffffe000a69f364:'MIG_dealloc_noop_model',0xfffffe000a69f384:'MIG_put_noop_model'}[a],0)
  assert any(lo<=a<hi for lo,hi in self.allowed),hex(a);raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});assert i.mnemonic not in ['svc','hvc','smc','brk','blraa','autda','pacda']
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason=='component_complete',self.boundary
  row={'kind':self.kind,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'boundary':self.boundary,'native_target_executed':False}
  if self.kind=='kext_reply':row.update({'status_u32':self.reg(19)&0xffffffff,'record0_hex':bytes(self.u.mem_read(R0,136)).hex(),'record1_hex':bytes(self.u.mem_read(R1,172)).hex(),'OOL_outputs_hex':bytes(self.u.mem_read(OUT,24)).hex()})
  else:row['reply_storage_hex']=bytes(self.u.mem_read(REP,400)).hex()
  return row

def pattern(n,seed):return bytes((seed+37*j)&255 for j in range(n))
def transfer(user):
 """Declared 64-bit internal representation, not native IPC conversion."""
 bits,size,remote,local,voucher,mid=struct.unpack_from('<6I',user);assert local==voucher==0
 return struct.pack('<IIQQII',bits,size+8,0,P+0x70000,0,mid)+user[24:size]+bytes(400-size-8)
def put(buf,offset,value,width=4):buf[offset:offset+width]=value.to_bytes(width,'little')

def main():
 view=View();ki=Image();rows=[];joins=[]
 request=struct.pack('<6I',0x80001112,80,203,107,0,502)+bytes(124)
 prefix=Probe(view,'demux_prefix',request,{}).run();rows.append(prefix);head=bytes.fromhex(prefix['reply_storage_hex']);assert head[:24]==struct.pack('<6I',18,36,203,0,0,602)
 emitted=[]
 for status,n0,n1 in [(0,0,0),(0,1,37),(0,4096,8192),(0,0xffffffff,0xffffffff),(-300,0,0),(-309,0,0),(5,0,0)]:
  initial=bytearray(head);put(initial,0x24,0x01000101);put(initial,0x34,0x01000101);put(initial,0x1c,OOL0,8);put(initial,0x2c,OOL1,8);initial[0x44:0xcc]=pattern(136,17);initial[0xcc:0x178]=pattern(172,113);put(initial,0x178,n0);put(initial,0x17c,n1)
  cfg={'application_status':status,'count0':n0,'count1':n1,'application_executed':False};em=Probe(view,'daemon_completion',initial,cfg).run();rows.append(em);emitted.append(em)
  wire=bytes.fromhex(em['reply_storage_hex']);kernel=transfer(wire);kr=Probe(ki,'kext_reply',kernel,{'transport_status':0,'emitter_index':len(rows)-1,'variant':'unaltered_declared_transfer'}).run();rows.append(kr);joins.append({'emitter_case':len(rows)-2,'consumer_case':len(rows)-1,'user_inline_bytes':int.from_bytes(wire[4:8],'little'),'kernel_inline_bytes':int.from_bytes(kernel[4:8],'little'),'native_transfer_established':False})
 # Deliberate single-field ABI substitutions; no native parser or malformed IPC.
 canonical=transfer(bytes.fromhex(emitted[2]['reply_storage_hex']))
 variants=[('unexpected_id',28,603,4),('death_pill_id',28,71,4),('descriptor_count',32,1,4),('inline_size',4,384,4),('remote_nonnull',8,1,8),('descriptor0_type',47,0,1),('descriptor1_type',63,0,1),('descriptor0_repeat',384,4097,4),('descriptor1_repeat',388,8193,4),('NDR_opaque',68,0xffffffffffffffff,8),('descriptor_flags_opaque0',44,0x7f887766,4),('descriptor_flags_opaque1',60,0x7f887766,4)]
 # Keep type byte1 in the flags-only variants.
 variants[-2]=('descriptor_copy_flags_opaque0',44,0x01887766,4);variants[-1]=('descriptor_copy_flags_opaque1',60,0x01887766,4)
 for name,off,value,width in variants:
  b=bytearray(canonical);put(b,off,value,width);rows.append(Probe(ki,'kext_reply',b,{'transport_status':0,'variant':name}).run())
 simple=transfer(bytes.fromhex(emitted[4]['reply_storage_hex']))
 for name,off,value,width in [('simple_zero_status',40,0,4),('simple_size',4,36,4),('simple_remote',8,1,8)]:
  b=bytearray(simple);put(b,off,value,width);rows.append(Probe(ki,'kext_reply',b,{'transport_status':0,'variant':name}).run())
 for status in [0x10000002,0x10000003,0x10000010,0x10000004,0x10004003,0xffffffff]:rows.append(Probe(ki,'kext_reply',canonical,{'transport_status':status,'variant':'transport_status'}).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_reply_bridge_source.json','probe_kernel_vm_mig.py','daemon_receive_tools.py','kernel_vm_mig_tools.py']},'cases':rows,'declared_transfers':joins,'native_application_execution_established':False,'native_IPC_executed':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False};(ROOT/'rpc502_reply_bridge_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'transfers':len(joins)}),flush=True)
if __name__=='__main__':main()
