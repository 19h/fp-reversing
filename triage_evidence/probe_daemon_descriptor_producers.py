#!/usr/bin/env python3
"""Continuous original caller->adapter->entry source with an original cache helper.
Private entry context,initial writable image,TLS and allocation tokens are fixtures.
No target import,host IPC or native PAC executes. O(F+C*(J+V+E)) time and
O(F+largest trace+private RAM) space using a per-page fixup index.
"""
import json,hashlib,struct,itertools
from pathlib import Path
from collections import defaultdict
import unicorn as uc
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_MEM,ARM64_EXT_SXTW,ARM64_EXT_SXTX
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from recover_daemon_iokit_census import text_section
from daemon_import_bindings import binding
P=0x6800000000;SIZE=0x100000;CALLER=0x10039c894;ADAPTER=0x100abca64;CALLEE=0x100a59bb4;HELPER=0x180587cd4;END=0x10039c940;GUARD=P+0xe0000;TLS=P+0xf0000
SOURCE_CAPTURE=None
FIXPAGES=defaultdict(list)
for at,row in FIXUPS.items():FIXPAGES[at&~4095].append((at,row))
IMPORTS={name:0x7c000000+256*j for j,name in enumerate(sorted({r['target']for r in FIXUPS.values()if isinstance(r['target'],str)}),1)}
ADDENDS={at:binding(at)['total_addend']for at,r in FIXUPS.items()if r['kind'].endswith('bind')}
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
class Run:
 def __init__(self,c):
  global SOURCE_CAPTURE
  if SOURCE_CAPTURE is None:SOURCE_CAPTURE=json.loads((ROOT/'daemon_descriptor_producers_source.json').read_text())
  self.c=c;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);self.cs.detail=True;self.pages=set();self.known=bytearray(SIZE);self.initial=[];self.image_fixtures=[];self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.edges=[];self.calls=[];self.checkpoints=[];self.reason=None;self.boundary=None;self.seq=0;self.C=P+0x60000+c['placement'];self.FP=self.C+0x4000;self.R=self.FP-256;self.TOKEN=P+0x1000 if c['nonnull']else 0;self.countercell=P+0x2000;self.reserve=16*((((c['counter64']*0x2ebd+1)&((1<<64)-1))>>60)+1);self.helper_SP=self.C-64-self.reserve-96
  self.u.mem_map(P,SIZE);self.u.mem_write(P,bytes([c['pattern']&255])*SIZE)
  for j in range(31):self.set(j,((0x123456789abcdef*j)^c['pattern'])&((1<<64)-1))
  for j in range(32):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),(c['pattern']<<64)|c['pattern'])
  self.fixture(self.C+0x2328,struct.pack('<Q',self.TOKEN));self.fixture(self.C+0x2480,b'\x00'*8);self.fixture(self.C+0xb30,struct.pack('<Q',0x100e99a00));self.fixture(self.countercell,struct.pack('<Q',c['counter64']));self.fixture(GUARD,struct.pack('<Q',0xf1e2d3c4b5a69788));self.fixture(TLS-48,struct.pack('<Q',self.helper_SP+1 if c['probe']=='fast'else 0));self.fixture(TLS-40,struct.pack('<Q',self.helper_SP-0x40000));self.u.reg_write(ar.UC_ARM64_REG_TPIDRRO_EL0,TLS)
  for a,b in [(0x1010b1e18,struct.pack('<Q',GUARD)),(0x1010b66a8,struct.pack('<Q',c['controllers'][0])),(0x1010c4670,struct.pack('<Q',c['controllers'][1])),(0x1010b9098,struct.pack('<Q',c['controllers'][0]^0x2468ace)),(0x1010c4e18,struct.pack('<Q',c['controllers'][0]))]:
   self.ensure(a,len(b));self.u.mem_write(a,b);self.image_fixtures.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'declared_image_fixture'})
  self.set(8,self.countercell);self.set(1,0x100f4e390);self.set(26,0x1010b66a8);self.set(27,0x1010c4670);self.set(28,TABLE);self.set(25,0xa6);self.set(30,0xa5cd4cf);self.set(29,self.FP);self.u.reg_write(ar.UC_ARM64_REG_SP,self.C);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_Q=[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.unmapped);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(uc.UC_HOOK_CODE,self.code)
 def reg(self,j):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
 def set(self,j,v):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),v&((1<<64)-1))
 def fixture(self,a,b):
  self.u.mem_write(a,b);self.known[a-P:a-P+len(b)]=bytes([1])*len(b);self.initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'declared_private_fixture'})
 def ensure(self,a,n=1):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if P<=pg<P+SIZE or pg in self.pages:continue
   if pg==HELPER&~4095:
    raw=bytearray(4096);b=bytes.fromhex(SOURCE_CAPTURE['stack_probe_original_function']['bytes']);raw[HELPER-pg:HELPER-pg+len(b)]=b
   elif 0x100000000<=pg<0x102000000:
    try:raw=bytearray(IMAGE.read(pg,4096))
    except ValueError:raw=bytearray(4096)
    for at,r in FIXPAGES[pg]:
     t=r['target'];v=HELPER if t=='libSystem/___chkstk_darwin'else GUARD if t=='libSystem/___stack_chk_guard'else IMPORTS[t]if isinstance(t,str)else t;v=(v+ADDENDS.get(at,0))&((1<<64)-1);raw[at-pg:at-pg+8]=struct.pack('<Q',v)
   else:return self.stop('before_unmapped_owner_access',{'address':hex(a),'size_bytes':n})
   self.u.mem_map(pg,4096);self.pages.add(pg);self.u.mem_write(pg,bytes(raw))
 def unmapped(self,u,t,a,n,v,d):self.ensure(a,n);return self.reason is None
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def snapshot(self,a,n):return {'address':hex(a),'size_bytes':n,'bytes_hex':bytes(self.u.mem_read(a,n)).hex(),'known_mask_hex':self.known[a-P:a-P+n].hex()}
 def stop(self,reason,detail=None):
  self.reason=reason;self.boundary={'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),'kind':reason,'source_visits':self.seq,'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'detail':detail};self.u.emu_stop()
 def read(self,u,t,a,n,v,d):
  row={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()}
  if P<=a<a+n<=P+SIZE:row['known_mask_hex']=self.known[a-P:a-P+n].hex();assert all(self.known[a-P:a-P+n])or int(row['pc'],16)in[0x180587d24,0x180587d38],row
  self.reads.append(row)
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or 0x101000000<=a<a+n<0x102000000,(hex(a),n)
  if P<=a<a+n<=P+SIZE:self.known[a-P:a-P+n]=bytes([1])*n
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def register(self,name):
  if name in ['xzr','wzr']:return 0
  return self.u.reg_read(getattr(ar,'UC_ARM64_REG_'+name.upper()))
 def preflight(self,ins):
  if not ins.mnemonic.startswith(('ldr','ldur','ldp','ldnp','ldar','ldax')):return True
  op=next((o for o in ins.operands if o.type==ARM64_OP_MEM),None)
  if op is None:return True
  a=self.register(ins.reg_name(op.mem.base))+op.mem.disp
  if op.mem.index:
   name=ins.reg_name(op.mem.index);idx=self.register(name)
   if op.ext in[ARM64_EXT_SXTW,ARM64_EXT_SXTX]:bits=32 if op.ext==ARM64_EXT_SXTW else 64;idx=(idx&((1<<bits)-1));idx-=1<<bits if idx>>(bits-1)else 0
   a+=idx<<op.shift.value
  a&=(1<<64)-1;name=ins.reg_name(ins.operands[0].reg);n=1 if ins.mnemonic.endswith('b')else 2 if ins.mnemonic.endswith('h')else 4 if ins.mnemonic.endswith('sw')or name.startswith('w')else 16 if name.startswith('q')else 8;n*=2 if ins.mnemonic.startswith(('ldp','ldnp'))else 1
  if P<=a<a+n<=P+SIZE and not all(self.known[a-P:a-P+n])and ins.address not in[0x180587d24,0x180587d38]:self.stop('before_unknown_private_read',{'address':hex(a),'size_bytes':n,'instruction':ins.mnemonic+' '+ins.op_str,'snapshot':self.snapshot(a,n)});return False
  return True
 def code(self,u,a,n,d):
  self.flush()
  if a==END:return self.stop('after_original_outer_stack_adjustment')
  if not(0x100000000<=a<0x100e2c000 or HELPER<=a<HELPER+108):return self.stop('before_unmodeled_code_target')
  raw=bytes(u.mem_read(a,4));original=bytes.fromhex(SOURCE_CAPTURE['stack_probe_original_function']['bytes'])[a-HELPER:a-HELPER+4]if HELPER<=a<HELPER+108 else IMAGE.read(a,4);assert raw==original;ins=next(self.cs.disasm(raw,a));m=ins.mnemonic
  if not self.preflight(ins):return
  if a in [ADAPTER,CALLEE,HELPER,0x100a636ec,0x10095f074,0x1006583b0,0x10039c930]:self.checkpoints.append({'pc':hex(a),'source_visit_index':self.seq,'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]})
  if m in['blraa','blraaz','blr']:
   names=[x.strip()for x in ins.op_str.split(',')];target=self.register(names[0]);modifier=self.register(names[1])if len(names)>1 else None
   if target in IMPORTS.values():return self.stop('before_unmodeled_import_call',{'target':hex(target),'symbol':next(k for k,v in IMPORTS.items()if v==target),'modifier':hex(modifier)if modifier is not None else None})
   assert 0x100000000<=target<0x100e2c000 or target==HELPER,(hex(a),hex(target));self.calls.append({'pc':hex(a),'source_visit_index':self.seq,'target':hex(target),'modifier':hex(modifier)if modifier is not None else None,'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments8':[hex(self.reg(j))for j in range(8)],'record':self.snapshot(self.R,24)})
  self.visits.append({'pc':hex(a),'source_visit_index':self.seq,'bytes_hex':raw.hex(),'image':'installed_cache_stack_probe'if HELPER<=a<HELPER+108 else'daemon'});self.seq+=1
  if m in['pacibsp','paciasp','autibsp','autiasp','paciza']:return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m in['braa','br','blraa','blr','blraaz']:
   names=[x.strip()for x in ins.op_str.split(',')];target=self.register(names[0]);modifier=self.register(names[1])if len(names)>1 else None;self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(target),'modifier':hex(modifier)if modifier is not None else None,'kind':m})
   if m.startswith('bl'):self.set(30,a+4)
   self.ensure(target);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if m in['ret','retab','retaa']:
   target=self.reg(30);self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(target),'modifier':None,'kind':m});self.ensure(target);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  assert m not in['svc','hvc','smc','bl'],(hex(a),m)
 def run(self,limit=20000):
  self.ensure(CALLER);self.u.emu_start(CALLER,0,count=limit);self.flush()
  if self.reason is None:self.stop('source_visit_limit')
  return {'configuration':self.c,'entry_PC':hex(CALLER),'entry_SP':hex(self.C),'entry_FP':hex(self.FP),'record_address':hex(self.R),'entry_registers31':self.entry_regs,'entry_Q_registers32':self.entry_Q,'entry_NZCV':self.entry_NZCV,'entry_TPIDRRO_EL0':hex(TLS),'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_fixtures,'image_backing_premise':'original file bytes with logical fixups; file-unbacked image pages initialized to zero as explicit private image fixtures, not observed native state','initial_private_undefined_bytes':'physical backing is declared pattern; only listed fixtures and source writes are defined','source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'logical_edges':self.edges,'source_calls':self.calls,'checkpoints':self.checkpoints,'boundary':self.boundary,'final_record':self.snapshot(self.R,24),'final_counter':self.snapshot(self.C+0x2480,8),'payload_owner':{'address':hex(self.TOKEN),'size_bytes':8 if self.TOKEN else 0,'initially_opaque':True},'final_payload':self.snapshot(self.TOKEN,8)if self.TOKEN else None,'fixture_PC_transitions':0,'native_target_executed':False,'full_goal_complete':False}
def cases():
 for nonnull,probe,counter,placement,controllers in itertools.product([False,True],['fast','walk'],[0,0x123456789abcdef0,0xffffffffffffffff],[0,0x100],[(0,0),(0xffffffff,0x87654321)]):yield {'nonnull':nonnull,'probe':probe,'counter64':counter,'placement':placement,'controllers':controllers,'pattern':0xa5a5a5a5a5a5a5a5 if placement else 0x5a5a5a5a5a5a5a5a}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  r=Run(c).run();rows.append(r);print(json.dumps({'case':j,'nonnull':c['nonnull'],'probe':c['probe'],'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 deps=['daemon_descriptor_producers_source.json','daemon_receive_tools.py','daemon_receive_fixups.txt'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_producers_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
