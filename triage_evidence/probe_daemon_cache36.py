#!/usr/bin/env python3
"""Continue cache36 initialization from restored source/ABI byte provenance.
O(restored bytes+new source visits+effects) time/space per case. All original
__DATA reads require defined bytes; source stores may define writable owners.
No native allocator,IPC,library operation or hardware PAC executes.
"""
import json,hashlib,base64,zlib
from pathlib import Path
from capstone.arm64_const import ARM64_OP_MEM,ARM64_EXT_SXTW,ARM64_EXT_SXTX
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from daemon_import_bindings import binding
from recover_daemon_object_creation import sha
from recover_daemon_object_clock import sections
from probe_daemon_object_clock import Run as ClockRun
from probe_daemon_object_initialization import Run as InitialRun,P,SIZE,IMPORTS
from capture_daemon_object_clock import memory_width
MASK=(1<<64)-1
class Run(ClockRun):
 def __init__(self,context,cfg):
  parents=json.loads((ROOT/'daemon_object_clock_context.json').read_text());parent=parents['contexts'][context['parent_case_index']];super().__init__(parent,context['parent_outcome']);self.cache_context=context;self.cache_cfg=cfg;self.runtime_sections=[s for s in sections()if s['segment']=='__DATA'];self.global_pages.update(pg for s in self.runtime_sections for pg in range(s['start']&~4095,((s['start']+s['size_bytes']-1)&~4095)+4096,4096));known=set()
  for r in context['known_byte_groups']:
   a=int(r['address'],16);b=bytes.fromhex(r['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b);known.update(range(a,a+len(b)))
  self.defined={a for a in known if P<=a<P+SIZE};self.global_defined={a for a in known if 0x100000000<=a<0x102000000};self.mutable_globals.update(self.global_defined)
  for a,h in context['owner_snapshots'].items():assert bytes(self.u.mem_read(int(a,16),len(h)//2)).hex()==h
  for j,v in enumerate(context['boundary']['registers31']):self.set('x'+str(j),int(v,16))
  self.set('sp',int(context['boundary']['SP'],16));self.reg_sources={n:int(a,16)for n,a in context['register_pointer_origins'].items()};self.memory_sources={int(a,16):int(v,16)for a,v in context['memory_pointer_origins'].items()};self.allocated={int(a,16):n for a,n in context['allocated_owners'].items()};self.owners.update(self.allocated);self.cache_calls=0;self.steps=[];self.events=[];self.pending=[];self.edges=[];self.api=[];self.fix=set();self.source_pool={};self.reason=None;self.done=False;self.previous_i=None;self.previous_sources={};self.arbitrary_heap_reads=[];self.entry_cache_regs=[hex(self.reg('x'+str(j)))for j in range(31)]
 def address(self,i,o):
  a=self.regname(i.reg_name(o.mem.base))+o.mem.disp
  if o.mem.index:
   index=self.regname(i.reg_name(o.mem.index))
   if o.ext in [ARM64_EXT_SXTW,ARM64_EXT_SXTX]:bits=32 if o.ext==ARM64_EXT_SXTW else 64;index&=(1<<bits)-1;index-=1<<bits if index>>(bits-1)else 0
   a+=index<<o.shift.value
  return a&MASK
 def preflight(self,i):
  vectors=[i.reg_name(r)for r in i.regs_access()[0]if i.reg_name(r).startswith(('q','v','d','s'))and i.reg_name(r)[1:].isdigit()]
  if vectors:return self.stop('before_unmodeled_vector_read',{'registers':vectors})or False
  o=next((x for x in i.operands if x.type==ARM64_OP_MEM),None)
  if o is not None:
   a=self.address(i,o);n=memory_width(i);owner=next((s for s in self.runtime_sections if s['start']<=a<a+n<=s['start']+s['size_bytes']),None)
   if owner is not None and i.mnemonic.startswith(('str','stur','stp','stnp','stlr','stlx')):
    assert owner['initial_protection']&2;self.ensure(a,n);return True
   if owner is not None and not all(x in self.global_defined for x in range(a,a+n)):return self.stop('before_unmodeled_runtime_global',{'address':hex(a),'size_bytes':n,'instruction':i.mnemonic+' '+i.op_str,'section':owner['section']})or False
  return super().preflight(i)
 def write(self,u,t,a,n,v,d):
  super().write(u,t,a,n,v,d)
  if any(s['start']<=a<a+n<=s['start']+s['size_bytes']for s in getattr(self,'runtime_sections',[])):self.global_defined.update(range(a,a+n));self.mutable_globals.update(range(a,a+n))
 def code(self,u,a,n,d):
  self.flush();self.finish_pointer_sources()
  if not 0x100000000<=a<0x100e2c000:return self.stop('before_external_code',{'target':hex(a)})
  raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4);i=next(self.dec.disasm(raw,a));self.source_pool[hex(a)]={'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str};m=i.mnemonic
  if m in ['blraa','blr']:
   names=[x.strip()for x in i.op_str.split(',')];target=self.regname(names[0])
   if target in IMPORTS.values():
    slot=self.reg_sources.get(self.canonical(names[0]));assert slot in FIXUPS;record=FIXUPS[slot];b=binding(slot);word=int(b['word'],16);assert target==IMPORTS[record['target']]+b['total_addend']and b['authenticated']and(word>>48)&7==0 and self.regname(names[1])==((word>>32)&65535)
    if b['symbol']=='_CFRelease':
     assert slot==0x1010a02e0 and self.reg('x17')==0x1883;argument=self.reg('x0')
     if argument not in [0x1010b1a18,0x6d00001000,0x6d00002000,0x6d00003000,0x6d00004000,0x6d00005000]:return self.stop('before_unmodeled_release_argument',{'argument':hex(argument),'binding':b})
     before={n:self.reg(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]}
     for j in range(1,18):self.set('x'+str(j),(((j+37)*0x143256789abcdef)^self.cache_cfg['heap_pattern'])&MASK)
     for j in list(range(18))+[30]:self.reg_sources.pop('x'+str(j),None)
     returned=0xf0f0f0f012345678^self.cache_cfg['heap_pattern'];self.set('x0',returned);self.set('x30',a+4);self.set('nzcv',self.cache_cfg['NZCV_after']);assert all(self.reg(n)==v for n,v in before.items());self.api.append({'pc':hex(a),'binding':b,'arguments1':[hex(argument)],'returned_X0':hex(returned),'void_return':'arbitrary full64 value; no result semantics','lifetime_effect':'release request only; native reference counts unknown','preserved_GPR_SP':before,'native_call_executed':False});self.steps.append((a,raw.hex()));self.set('pc',a+4);return
    if a==0x1009ba810:
     assert b['symbol']=='_CFNumberGetValue'and slot==0x1010a0b28 and self.reg('x17')==0x8642 and self.reg('x0')==0x6d00004000 and self.reg('x1')==4 and self.reg('x2')==self.F+0x2b70
     before={n:self.reg(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]};address=self.reg('x2');written=self.cache_cfg['chip_value64'].to_bytes(8,'little');self.u.mem_write(address,written);self.defined.update(range(address,address+8))
     for j in range(1,18):self.set('x'+str(j),(((j+41)*0x143256789abcdef)^self.cache_cfg['heap_pattern'])&MASK)
     for j in list(range(18))+[30]:self.reg_sources.pop('x'+str(j),None)
     returned=(0xabcdef12<<32)|self.cache_cfg['number_return_W0'];self.set('x0',returned);self.set('x30',a+4);self.set('nzcv',self.cache_cfg['NZCV_after']);assert all(self.reg(n)==v for n,v in before.items());self.api.append({'pc':hex(a),'binding':b,'arguments3':['0x6d00004000','0x4',hex(address)],'requested_type':'kCFNumberSInt64Type; SDK enum 4','returned_X0':hex(returned),'writes':[{'address':hex(address),'bytes_hex':written.hex()}],'return_premise':'full W0 is declared, including upper24 Boolean-register sensitivity; output supplied independently even on failure','preserved_GPR_SP':before,'native_call_executed':False});self.steps.append((a,raw.hex()));self.set('pc',a+4);return
    if a==0x1009b42d4:
     assert b['symbol']=='_CFStringCreateWithFormat'and slot==0x1010a0008 and self.reg('x17')==0xfe9e and self.reg('x0')==self.reg('x1')==0 and self.reg('x2')==0x1010b1b18 and all(x in self.defined for x in range(self.F,self.F+8));arg=bytes(self.u.mem_read(self.F,8));assert int.from_bytes(arg,'little')==self.cache_cfg['chip_value64'];before={n:self.reg(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]}
     for j in range(1,18):self.set('x'+str(j),(((j+47)*0x143256789abcdef)^self.cache_cfg['heap_pattern'])&MASK)
     for j in list(range(18))+[30]:self.reg_sources.pop('x'+str(j),None)
     returned=0x6d00005000 if self.cache_cfg['format_present']else 0;self.set('x0',returned);self.set('x30',a+4);self.set('nzcv',self.cache_cfg['NZCV_after']);assert all(self.reg(n)==v for n,v in before.items());self.api.append({'pc':hex(a),'binding':b,'arguments3':['0x0','0x0','0x1010b1b18'],'variadic_stack':[{'address':hex(self.F),'bytes_hex':arg.hex(),'source':'CFNumberGetValue declared output; original STR X10,[SP]'}],'format_literal':'%qi','returned':hex(returned),'returned_object':'opaque token; native string bytes and formatting unknown','preserved_GPR_SP':before,'native_call_executed':False});self.steps.append((a,raw.hex()));self.set('pc',a+4);return
    if a in [0x100bab21c,0x100c9941c,0x100a42444,0x100b2c150]:
     query={0x100bab21c:(0x1010b1af8,'serial_present','SerialNumber',0x6d00001000),0x100c9941c:(0x1010b1ab8,'wifi_present','WifiAddress',0x6d00002000),0x100a42444:(0x1010b1a38,'bluetooth_present','BluetoothAddress',0x6d00003000),0x100b2c150:(0x1010b1b38,'chip_present','UniqueChipID',0x6d00004000)}[a];expected_key,option,property_name,token=query;assert b['symbol']=='_MGCopyAnswer'and slot==0x1010a0dc8 and self.reg('x0')==expected_key and self.reg('x1')==0;present=self.cache_cfg[option];returned=token if present else 0;before={n:self.reg(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]}
     for j in range(1,18):self.set('x'+str(j),(((j+31)*0x143256789abcdef)^self.cache_cfg['heap_pattern'])&MASK)
     for j in list(range(18))+[30]:self.reg_sources.pop('x'+str(j),None)
     self.set('x0',returned);self.set('x30',a+4);self.set('nzcv',self.cache_cfg['NZCV_after']);assert all(self.reg(n)==v for n,v in before.items());self.api.append({'pc':hex(a),'binding':b,'key_CFString':hex(expected_key),'observed_X1':'0x0','property_mapping':property_name,'returned':hex(returned),'returned_object':'opaque full64 token; native type/bytes unknown','preserved_GPR_SP':before,'native_call_executed':False});self.steps.append((a,raw.hex()));self.set('pc',a+4);return
    if a!=0x1009c0148 or self.cache_calls:return self.stop('before_unmodeled_import',{'symbol':record['target'],'binding':b,'arguments8':[hex(self.reg('x'+str(j)))for j in range(8)]})
    assert b['symbol']=='_malloc'and slot==0x10109ff58 and self.reg('x0')==36 and self.reg('x17')==0x6aa4;ptr=P+self.cache_cfg['heap_offset'];before={n:self.reg(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]};self.owners[ptr]=36;self.allocated[ptr]=36;self.u.mem_write(ptr,bytes([self.cache_cfg['heap_pattern']])*36);self.defined.difference_update(range(ptr,ptr+36))
    for j in range(1,18):self.set('x'+str(j),(((j+23)*0x143256789abcdef)^self.cache_cfg['heap_pattern'])&MASK)
    for j in list(range(18))+[30]:self.reg_sources.pop('x'+str(j),None)
    self.set('x0',ptr);self.set('x30',a+4);self.set('nzcv',self.cache_cfg['NZCV_after']);assert all(self.reg(n)==v for n,v in before.items());self.api.append({'pc':hex(a),'binding':b,'requested_bytes':36,'returned':hex(ptr),'preserved_GPR_SP':before,'uninitialized_owner':'36 private bytes; reads rejected until defined by source','native_call_executed':False});self.cache_calls+=1;self.steps.append((a,raw.hex()));self.set('pc',a+4);return
  if m=='bl':
   target=i.operands[0].imm;assert 0x100000000<=target<0x100e2c000;self.steps.append((a,raw.hex()));self.edges.append({'pc':hex(a),'target':hex(target),'kind':'bl','slot':None,'modifier':None});self.set('x30',a+4);self.ensure(target);self.set('pc',target);return
  return InitialRun.code(self,u,a,n,d)
 def run(self,limit=1000000):
  start=0x1009c0148;self.ensure(start);self.u.emu_start(start,0,count=limit);self.flush()
  if self.reason is None:self.stop('source_visit_limit')
  assert not self.arbitrary_heap_reads
  t={'clock_case_index':self.cache_context['clock_case_index'],'parent_payload_sha256':self.cache_context['parent_payload_sha256'],'configuration':self.cache_cfg,'entry_PC':hex(start),'entry_SP':hex(self.F),'entry_registers31':self.entry_cache_regs,'steps':self.steps,'events':self.events,'edges':self.edges,'source_pool':self.source_pool,'used_fixups':[hex(a)for a in sorted(self.fix)],'API_models':self.api,'allocated_owners':{hex(a):n for a,n in self.allocated.items()},'owner_snapshots':{hex(a):bytes(self.u.mem_read(a,n)).hex()for a,n in self.allocated.items()},'cache_pointer_cell_hex':bytes(self.u.mem_read(0x1010c6840,8)).hex(),'cache_owner_defined_bytes':sum(a in self.defined for a in range(P+self.cache_cfg['heap_offset'],P+self.cache_cfg['heap_offset']+36)),'boundary':self.boundary};raw=json.dumps(t,separators=(',',':')).encode();return {'clock_case_index':t['clock_case_index'],'configuration':self.cache_cfg,'source_visits':len(self.steps),'API_models_count':len(self.api),'cache_owner_defined_bytes':t['cache_owner_defined_bytes'],'boundary':self.boundary,'payload_zlib_base64':base64.b64encode(zlib.compress(raw)).decode(),'payload_sha256':hashlib.sha256(raw).hexdigest(),'native_target_executed':False,'full_goal_complete':False}
def configurations():
 for offset,pattern,nzcv in [(0x38000,0xa5,0x50000000),(0x38100,0x5a,0xa0000000)]:
  for serial,wifi,bluetooth,chip in [(False,False,False,False),(True,False,False,False),(True,True,False,False),(True,True,True,False),(True,True,True,True)]:
   for status in ([0,1,0x1000001]if chip else[0]):
    for formatted in ([False,True]if chip and status else[False]):yield {'heap_offset':offset,'heap_pattern':pattern,'NZCV_after':nzcv,'serial_present':serial,'wifi_present':wifi,'bluetooth_present':bluetooth,'chip_present':chip,'number_return_W0':status,'chip_value64':0xfedcba9876543210 if pattern==0x5a else 0x0123456789abcdef,'format_present':formatted}
def main():
 contexts=json.loads((ROOT/'daemon_cache36_context.json').read_text());rows=[]
 for context in contexts['contexts']:
  for cfg in configurations():
   r=Run(context,cfg).run();rows.append(r);print(json.dumps({'clock_case':r['clock_case_index'],'configuration':cfg,'source_visits':r['source_visits'],'cache_defined_bytes':r['cache_owner_defined_bytes'],'boundary':{k:v for k,v in r['boundary'].items()if k!='registers31'}}),flush=True)
 deps=['daemon_cache36_context.json','probe_daemon_object_clock.py','probe_daemon_object_initialization.py','capture_daemon_object_clock.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache36_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
