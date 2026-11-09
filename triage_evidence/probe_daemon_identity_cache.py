#!/usr/bin/env python3
"""Continue identity formatting toward actual cache consumers.
O(restored bytes+new visits+effects) time/space per case. Only explicit API
outcomes are supplied; unknown imports, runtime globals and private reads stop.
No native property, library, allocator, IPC or PAC operation executes.
"""
import json,hashlib,base64,zlib
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from daemon_import_bindings import binding
from recover_daemon_object_creation import sha
from probe_daemon_cache36 import Run as Parent,P,SIZE,IMPORTS,MASK
from probe_daemon_object_initialization import Run as InitialRun
class Run(Parent):
 def __init__(self,context,cfg):
  parents=json.loads((ROOT/'daemon_cache36_context.json').read_text());old=next(x for x in parents['contexts']if x['clock_case_index']==context['clock_case_index']);super().__init__(old,context['parent_configuration']);self.identity_context=context;self.identity_cfg=cfg
  for a,h in context['owner_snapshots'].items():self.u.mem_write(int(a,16),bytes.fromhex(h))
  known=set()
  for r in context['known_byte_groups']:
   a=int(r['address'],16);b=bytes.fromhex(r['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b);known.update(range(a,a+len(b)))
  self.defined={a for a in known if P<=a<P+SIZE};self.global_defined={a for a in known if 0x100000000<=a<0x102000000};self.mutable_globals.update(self.global_defined);self.allocated={int(a,16):n for a,n in context['allocated_owners'].items()};self.owners.update(self.allocated)
  for a,h in context['owner_snapshots'].items():assert bytes(self.u.mem_read(int(a,16),len(h)//2)).hex()==h
  for j,v in enumerate(context['boundary']['registers31']):self.set('x'+str(j),int(v,16))
  self.set('sp',int(context['boundary']['SP'],16));assert self.F==self.reg('sp');self.reg_sources={n:int(a,16)for n,a in context['register_pointer_origins'].items()};self.memory_sources={int(a,16):int(v,16)for a,v in context['memory_pointer_origins'].items()};self.steps=[];self.events=[];self.pending=[];self.edges=[];self.api=[];self.fix=set();self.source_pool={};self.reason=None;self.done=False;self.previous_i=None;self.previous_sources={};self.arbitrary_heap_reads=[];self.entry_identity_regs=[hex(self.reg('x'+str(j)))for j in range(31)];state=0xffffffffffffffff if context['parent_configuration']['heap_pattern']==0x5a else 0;self.ensure(0x1010b69d0,8);self.u.mem_write(0x1010b69d0,state.to_bytes(8,'little'));self.global_defined.update(range(0x1010b69d0,0x1010b69d8));self.mutable_globals.update(range(0x1010b69d0,0x1010b69d8));self.extension_fixtures=[{'address':'0x1010b69d0','bytes_hex':state.to_bytes(8,'little').hex(),'provenance':'declared initial u64 helper state; original read/write owner identified, native value unknown'}]
 def api_return(self,a,raw,b,returned,details):
  before={n:self.reg(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]}
  for j in range(1,18):self.set('x'+str(j),(((j+53)*0x143256789abcdef)^self.identity_cfg['clobber_pattern'])&MASK)
  for j in list(range(18))+[30]:self.reg_sources.pop('x'+str(j),None)
  self.set('x0',returned);self.set('x30',a+4);self.set('nzcv',self.identity_cfg['NZCV_after']);assert all(self.reg(n)==v for n,v in before.items());self.api.append({'pc':hex(a),'binding':b,**details,'returned_X0':hex(returned),'preserved_GPR_SP':before,'native_call_executed':False});self.steps.append((a,raw.hex()));self.fix.add(int(b['slot'],16));self.set('pc',a+4)
 def code(self,u,a,n,d):
  self.flush();self.finish_pointer_sources()
  if not 0x100000000<=a<0x100e2c000:return self.stop('before_external_code',{'target':hex(a)})
  raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4);i=next(self.dec.disasm(raw,a));self.source_pool[hex(a)]={'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
  if i.mnemonic in ['blraa','blr']:
   names=[x.strip()for x in i.op_str.split(',')];target=self.regname(names[0])
   if target in IMPORTS.values():
    slot=self.reg_sources.get(self.canonical(names[0]));assert slot in FIXUPS;b=binding(slot);word=int(b['word'],16);assert target==IMPORTS[FIXUPS[slot]['target']]+b['total_addend']and b['authenticated']and(word>>48)&7==0 and self.regname(names[1])==((word>>32)&65535)
    if a==0x100ad6fcc:
     assert b['symbol']=='_CFStringCreateWithFormat'and slot==0x1010a0008 and self.reg('x0')==self.reg('x1')==0 and self.reg('x2')==0x1010b1a98;assert all(x in self.defined for x in range(self.F,self.F+40));args=bytes(u.mem_read(self.F,40));expected=[0x6d00001000,0x1010b1a18,0x6d00005000,0x6d00002000,0x6d00003000];assert [int.from_bytes(args[j*8:j*8+8],'little')for j in range(5)]==expected;returned=0x6d00006000 if self.identity_cfg['identity_present']else 0;return self.api_return(a,raw,b,returned,{'arguments3':['0x0','0x0','0x1010b1a98'],'variadic_stack40_hex':args.hex(),'format_literal':'%@%@%@%@%@','object_contents':'opaque; exact native formatted bytes unknown'})
    if b['symbol']=='_CFRelease':
     arg=self.reg('x0');assert slot==0x1010a02e0
     if arg not in [0x1010b1a18]+[0x6d00000000+j*0x1000 for j in range(1,7)]:return self.stop('before_unmodeled_release_argument',{'argument':hex(arg),'binding':b})
     return self.api_return(a,raw,b,0xf0f0f0f012345678^self.identity_cfg['clobber_pattern'],{'arguments1':[hex(arg)],'lifetime_effect':'request only; reference count and actual lifetime unknown'})
    if a==0x100bab080:
     assert b['symbol']=='_CFStringGetLength'and slot==0x1010a0e88 and self.reg('x0')==0x6d00006000;return self.api_return(a,raw,b,self.identity_cfg['UTF16_length'],{'arguments1':['0x6d00006000'],'length_units':'UTF-16 code units; declared CFIndex result','object_contents':'opaque; no string bytes supplied'})
    if a==0x100bab0d0:
     assert b['symbol']=='_CFStringGetMaximumSizeForEncoding'and slot==0x1010a01b8 and self.reg('x0')==self.identity_cfg['UTF16_length']and self.reg('x1')==0x08000100;return self.api_return(a,raw,b,self.identity_cfg['maximum_bytes'],{'arguments2':[hex(self.reg('x0')),'0x8000100'],'return_premise':'declared maximum bytes; 3*length fixture, not an implemented CF algorithm'})
    if a==0x100bab11c:
     nb=self.identity_cfg['maximum_bytes']+1;assert b['symbol']=='_malloc'and slot==0x10109ff58 and self.reg('x0')==nb and nb<=769;ptr=P+0x39000 if self.identity_cfg['buffer_nonnull']else 0
     if ptr:self.owners[ptr]=nb;self.allocated[ptr]=nb;self.u.mem_write(ptr,bytes([self.identity_cfg['clobber_pattern']])*nb);self.defined.difference_update(range(ptr,ptr+nb))
     return self.api_return(a,raw,b,ptr,{'requested_bytes':nb,'uninitialized_owner':'reads rejected until source/API-defined'})
    if a==0x100b90f78:
     nb=self.identity_cfg['maximum_bytes']+1;ptr=P+0x39000;assert b['symbol']=='_CFStringGetCString'and slot==0x1010a12a8 and [self.reg('x'+str(j))for j in range(4)]==[0x6d00006000,ptr,nb,0x08000100]and self.allocated[ptr]==nb;self.defined.difference_update(range(ptr,ptr+nb));good=self.identity_cfg['conversion_success'];text=('e\u0301'if self.identity_cfg['text_fixture']=='combining'else '\u00e9'if self.identity_cfg['text_fixture']=='accent'else ''.join(chr(65+j%26)for j in range(self.identity_cfg['UTF16_length'])));data=text.encode('utf-8')+b'\0';assert len(text.encode('utf-16-le'))//2==self.identity_cfg['UTF16_length']and len(data)<=nb;writes=[]
     if good:self.u.mem_write(ptr,data);self.defined.update(range(ptr,ptr+len(data)));writes=[{'address':hex(ptr),'bytes_hex':data.hex()}]
     return self.api_return(a,raw,b,1 if good else 0,{'arguments4':['0x6d00006000',hex(ptr),hex(nb),'0x8000100'],'invalidated_range':{'address':hex(ptr),'size_bytes':nb},'writes':writes,'fixture_text':text,'return_premise':'declared conversion result/output, independent of preceding opaque native objects; undefined tail retained'})
    if a==0x100915450:
     ptr=self.reg('x0');assert b['symbol']=='_strlen'and slot==0x10109ffa8 and ptr==P+0x39000;data=bytearray()
     for j in range(self.allocated[ptr]):
      assert ptr+j in self.defined;v=bytes(self.u.mem_read(ptr+j,1))[0];data.append(v)
      if v==0:break
     assert data[-1]==0;return self.api_return(a,raw,b,len(data)-1,{'arguments1':[hex(ptr)],'read_prefix_hex':bytes(data).hex(),'return_units':'bytes before first NUL; bounded declared output scan'})
    if a==0x100b03b68:
     ptr=self.reg('x0');assert b['symbol']=='_free'and slot==0x10109ff30 and ptr==P+0x39000;nb=self.allocated.pop(ptr);self.owners.pop(ptr);self.defined.difference_update(range(ptr,ptr+nb));return self.api_return(a,raw,b,0xabcdef0012345678,{'arguments1':[hex(ptr)],'invalidated_range':{'address':hex(ptr),'size_bytes':nb},'lifetime_effect':'source free request; private owner retired; native allocator/lifetime unknown'})
    return self.stop('before_unmodeled_import',{'binding':b,'arguments8':[hex(self.reg('x'+str(j)))for j in range(8)]})
  if i.mnemonic=='bl':
   target=i.operands[0].imm;assert 0x100000000<=target<0x100e2c000;self.steps.append((a,raw.hex()));self.edges.append({'pc':hex(a),'target':hex(target),'kind':'bl','slot':None,'modifier':None});self.set('x30',a+4);self.ensure(target);self.set('pc',target);return
  return InitialRun.code(self,u,a,n,d)
 def run(self,limit=1000000):
  start=0x100ad6fcc;self.ensure(start);self.u.emu_start(start,0,count=limit);self.flush()
  if self.reason is None:self.stop('source_visit_limit')
  assert not self.arbitrary_heap_reads;cache=P+self.identity_context['parent_configuration']['heap_offset'];t={'cache_case_index':self.identity_context['cache_case_index'],'parent_payload_sha256':self.identity_context['parent_payload_sha256'],'configuration':self.identity_cfg,'entry_PC':hex(start),'entry_SP':hex(self.F),'entry_registers31':self.entry_identity_regs,'extension_fixtures':self.extension_fixtures,'steps':self.steps,'events':self.events,'edges':self.edges,'source_pool':self.source_pool,'used_fixups':[hex(a)for a in sorted(self.fix)],'API_models':self.api,'allocated_owners':{hex(a):n for a,n in self.allocated.items()},'owner_snapshots':{hex(a):bytes(self.u.mem_read(a,n)).hex()for a,n in self.allocated.items()},'cache_owner_address':hex(cache),'cache_owner_defined_mask36':[a in self.defined for a in range(cache,cache+36)],'boundary':self.boundary};raw=json.dumps(t,separators=(',',':')).encode();return {'cache_case_index':t['cache_case_index'],'configuration':self.identity_cfg,'source_visits':len(self.steps),'API_models_count':len(self.api),'boundary':self.boundary,'payload_zlib_base64':base64.b64encode(zlib.compress(raw)).decode(),'payload_sha256':hashlib.sha256(raw).hexdigest(),'native_target_executed':False,'full_goal_complete':False}
def configurations():
 for present in [False,True]:
  for length in ([0,1,64,256]if present else[0]):
   for nonnull in ([False,True]if present and length==64 else[True]):
    for good in ([False,True]if present and nonnull and length==64 else[True]):
     for text in (['ASCII','accent']if present and length==1 else['ASCII']):yield {'identity_present':present,'UTF16_length':length,'maximum_bytes':3*length,'buffer_nonnull':nonnull,'conversion_success':good,'text_fixture':text,'clobber_pattern':0x5a if present else 0xa5,'NZCV_after':0xa0000000 if present else 0x50000000}
def main():
 ctx=json.loads((ROOT/'daemon_identity_cache_context.json').read_text());rows=[]
 for c in ctx['contexts']:
  for cfg in configurations():
   r=Run(c,cfg).run();rows.append(r);print(json.dumps({'parent':r['cache_case_index'],'configuration':cfg,'visits':r['source_visits'],'boundary':{k:v for k,v in r['boundary'].items()if k!='registers31'}}),flush=True)
 deps=['daemon_identity_cache_context.json','probe_daemon_cache36.py','probe_daemon_object_initialization.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_identity_cache_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
