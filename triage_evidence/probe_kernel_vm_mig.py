#!/usr/bin/env python3
"""Private original-source kernel MIG initialization, selector and stub cases.
Original image bytes/logical fixups and zero-filled private RAM are explicit
fixtures. Conversion/VM/release callbacks and PAC are models, not native effects.
O(source visits + image/fixup bytes) time; O(private RAM + journals) space.
"""
import json,struct
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image,INIT,SELECTOR,STUB,HASH,MAXPROBE,COUNT,CONVERT,RELEASE,LEAF,SLOTS
P=0x6500000000;SIZE=0x100000;HALT=P+0xe0000;SP=P+0xf0000;REQ=P+0x1000;PORT=P+0x2000;MAP=P+0x3000;REP=P+0x4000;BODY=P+0x5000;TRAILER=P+0x6000
class Probe:
 def __init__(self,image,kind,config,hash_seed=None):
  self.image=image;self.kind=kind;self.c=config;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.models=[];self.initial=[];self.image_initial=[];self.reason=None;self.boundary=None;self.u.mem_map(P,SIZE);self.u.mem_write(P,bytes(SIZE));self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.set(30,HALT)
  if kind=='init':self.entry=INIT;self.allowed=[(INIT,0xfffffe000c62a6d8)]
  elif kind=='selector':self.entry=SELECTOR;self.allowed=[(SELECTOR,0xfffffe000bd8b38c)];self.fixture(REQ+0x1c,struct.pack('<I',config['id']));self.set(0,REQ)
  elif kind=='lookup':
   self.entry=0xfffffe000bcf4338;self.allowed=[(self.entry,0xfffffe000bcf43b8)];self.fixture(REQ+0x1c,struct.pack('<I',config['id']));self.set(22,REQ);self.ensure(HASH,SLOTS*24);self.u.mem_write(HASH,bytes.fromhex(hash_seed['bytes_hex']));self.ensure(MAXPROBE,4);self.u.mem_write(MAXPROBE,struct.pack('<I',hash_seed['maximum_probe']));self.image_initial=[{'address':hex(HASH),'bytes_hex':hash_seed['bytes_hex'],'provenance':'source-produced initializer output; component fixture'},{'address':hex(MAXPROBE),'bytes_hex':struct.pack('<I',hash_seed['maximum_probe']).hex(),'provenance':'source-produced initializer output; component fixture'}]
  else:
   assert kind=='stub';self.entry=STUB;self.allowed=[(STUB,0xfffffe000bd8b244)];port={'null':0,'sentinel':(1<<64)-1,'type24':PORT,'normal':PORT}[config['port_class']];header=struct.pack('<IIQQII',config['bits'],config['request_size'],port,0x12345678,0,4801);self.fixture(REQ,header+bytes.fromhex('0000000001000000')+struct.pack('<QQ',config['address'],config['size']));self.fixture(PORT,bytes([0x24 if config['port_class']=='type24'else 1]));self.fixture(REP,bytes([0xa5])*64);self.fixture(BODY,bytes([0x5a])*16)
   for j,value in enumerate([REQ,REQ+32,TRAILER,REP,REP+32 if config['body_placement']=='joined'else BODY]):self.set(j,value)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.missing);self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
 def reg(self,j):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
 def set(self,j,v):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),v&((1<<64)-1))
 def fixture(self,a,b):self.u.mem_write(a,b);self.initial.append({'address':hex(a),'bytes_hex':b.hex()})
 def ensure(self,a,n=1):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if P<=pg<P+SIZE or pg in self.pages:continue
   raw=self.image.logical_page(pg);self.u.mem_map(pg,4096);self.u.mem_write(pg,raw);self.pages.add(pg)
 def missing(self,u,t,a,n,v,d):
  try:self.ensure(a,n);return True
  except StopIteration:self.stop('before_unavailable_owner',{'address':hex(a),'size_bytes':n});return False
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def read(self,u,t,a,n,v,d):self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or HASH<=a<a+n<=HASH+SLOTS*24 or a in [MAXPROBE,COUNT],(hex(a),n);e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def stop(self,kind,detail=None):self.reason=kind;self.boundary={'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),'kind':kind,'detail':detail,'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))};self.u.emu_stop()
 def model(self,a,symbol,result):
  ret=self.reg(30);event={'pc':hex(a),'before_source_visit_index':len(self.visits),'symbol':symbol,'arguments8':[hex(self.reg(j))for j in range(8)],'return_pc':hex(ret),'return_value':hex(result),'native_effects_executed':False};self.models.append(event)
  for j in range(18):self.set(j,((j+1)*0x123456789abcdef)^len(self.models)*0x8b3dc651)
  self.set(0,result);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000 if len(self.models)&1 else 0);event['after_registers31']=[hex(self.reg(j))for j in range(31)];event['after_NZCV']=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.u.reg_write(ar.UC_ARM64_REG_PC,ret)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('returned')
  if self.kind=='init'and a==0xfffffe000c62a604:return self.stop('before_initializer_print')
  if self.kind=='lookup'and a==0xfffffe000bcf43b4:return self.stop('lookup_decision')
  if self.kind=='stub'and a in [CONVERT,LEAF,RELEASE]:
   result=self.c['converted_map']if a==CONVERT else self.c['VM_result']if a==LEAF else 0;return self.model(a,{CONVERT:'port_to_map_model',LEAF:'VM_deallocate_model',RELEASE:'map_release_model'}[a],result)
  if not any(x<=a<z for x,z in self.allowed):return self.stop('before_unmodeled_code')
  raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);ins=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if ins.mnemonic in ['pacibsp','autibsp']:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif ins.mnemonic=='retab':u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  assert ins.mnemonic not in ['svc','hvc','smc','autda','blraa','brk'],(hex(a),ins.mnemonic)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=200000);self.flush();assert self.reason in ['returned','before_initializer_print','lookup_decision'],self.boundary
  out={'kind':self.kind,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0,'native_owner_extents_established':False},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'image_backing':'original KC file bytes with logical format-8 pointers as explicit private initial state','source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'boundary':self.boundary,'native_target_executed':False,'hardware_PAC_executed':False,'full_goal_complete':False}
  if self.kind=='init':out['hash_output']={'address':hex(HASH),'bytes_hex':bytes(self.u.mem_read(HASH,SLOTS*24)).hex(),'maximum_probe':int.from_bytes(bytes(self.u.mem_read(MAXPROBE,4)),'little'),'count_word':int.from_bytes(bytes(self.u.mem_read(COUNT,4)),'little')}
  if self.kind=='stub':out['reply_header_storage_hex']=bytes(self.u.mem_read(REP,64)).hex();out['separate_reply_body_hex']=bytes(self.u.mem_read(BODY,16)).hex()
  return out
def main():
 image=Image();source=json.loads((ROOT/'kernel_vm_mig_source.json').read_text());rows=[];init=Probe(image,'init',{}).run();rows.append(init);model=source['hash_model'];expected=bytearray(SLOTS*24)
 for e in model['insertions']:struct.pack_into('<IIQII',expected,e['index']*24,e['id'],0xffffffff,int(e['stub']['target'],16),e['reply_size'],e['reply_descriptors'])
 assert init['hash_output']['bytes_hex']==expected.hex()and init['hash_output']['maximum_probe']==model['maximum_probe']and init['hash_output']['count_word']==model['final_count_word'];print('initializer source/model match',len(init['source_visits']),flush=True)
 for mid in [0,4799,*range(4800,4831),0x80000000,0xffffffff]:rows.append(Probe(image,'selector',{'id':mid}).run())
 for mid in [0,4799,*range(4800,4831),0x80000000,0xffffffff]:rows.append(Probe(image,'lookup',{'id':mid},init['hash_output']).run())
 configs=[]
 for placement in ['joined','separate']:
  for bits,size in [(0,0),(0,48),(0,55),(0,57),(0,0xffffffff),(0x80000000,56)]:configs.append({'bits':bits,'request_size':size,'port_class':'null','converted_map':0,'VM_result':0,'address':0,'size':0,'body_placement':placement})
  for port,converted in [('null',0),('sentinel',0),('type24',0),('normal',0),('normal',MAP)]:
   for result in [0,4,0xffffffff]:
    for address,size in [(0,0),(0x123456789abcdef0,4096),((1<<64)-1,(1<<64)-1)]:configs.append({'bits':0,'request_size':56,'port_class':port,'converted_map':converted,'VM_result':result,'address':address,'size':size,'body_placement':placement})
 for cfg in configs:
  r=Probe(image,'stub',cfg).run();rows.append(r)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kernel_vm_mig_source.json']},'kernel_sha256':image.k.sha256,'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'full_goal_complete':False};(ROOT/'kernel_vm_mig_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'stub_cases':len(configs)}),flush=True)
if __name__=='__main__':main()
