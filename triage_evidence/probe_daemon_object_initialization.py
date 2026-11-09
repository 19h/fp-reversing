#!/usr/bin/env python3
"""Original AEE->object initialization with source-shaped saved roots/cursor.
Runtime cache/mask/classifier/presence and allocation outcomes are explicit
private inputs. No native target, host API, IPC or hardware PAC executes.
O(cases*(source visits+effects)) time, O(one private RAM map+largest trace) space.
"""
import json,struct,hashlib,base64,zlib
from pathlib import Path
from collections import defaultdict,Counter
import unicorn as uc
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_MEM,ARM64_OP_REG,ARM64_EXT_SXTW,ARM64_EXT_SXTX
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from daemon_import_bindings import binding
from replay_daemon_object_creation import Run as BaseRun,P,SIZE,IMPORTS,OBJ
from recover_daemon_object_creation import sha
BUFFER48=P+0x28000;PUBLISHED=P+0x30000;INPUT=P+0x32000
PAGES=defaultdict(list)
for at,r in FIXUPS.items():PAGES[at&~4095].append((at,r))
ADDENDS={at:binding(at)['total_addend']for at,r in FIXUPS.items()if r['kind'].endswith('bind')}
class Run(BaseRun):
 def __init__(self,c):
  self.cfg=c;self.ctx=json.loads((ROOT/'daemon_object_initialization_context.json').read_text());self.events=[];self.pending=[];self.owners={};self.arbitrary_heap_reads=[];self.reason=None;self.global_defined=set();self.source_pool={};self.source_calls=[];self.reg_sources={};self.memory_sources={};self.previous_i=None;self.previous_event_start=0;self.previous_sources={};self.dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);self.dec.detail=True
  super().__init__({'kind':'allocation','marker':1,'nonnull':True,'pattern':c['pattern'],'placement':0x40000+c.get('placement',0),'controller':c.get('controller',0)});F=self.F;oldF=int(self.ctx['retained_SP'],16)
  for n,v in self.ctx['retained_common_registers'].items():
   if isinstance(v,dict)and'hex'in v:
    value=int.from_bytes(bytes.fromhex(v['hex']),'little');value=value-oldF+F if oldF<=value<oldF+0xe000 else value;self.set(n,value)
  self.set('sp',F)
  for row in self.ctx['source_frame_fields']:self.fixture(F+int(row['offset'],16),8,int(row['u64'],16))
  for o,n,v in [(0x2a48,8,INPUT),(0x2a50,4,c['decoded']^0x8b3dc651),(0x2a58,8,0x1122334455667788),(0x2a60,8,0x9988776655443322),(0x2a70,8,0x123456789abcdef0),(0x273c,4,0x471c)]:self.fixture(F+o,n,v)
  self.fixture(P+0x1000,8,0x0123456789abcdef);self.owners.update({(F-0x10000):0x10000+0xdf50,P+0x1000:8,PUBLISHED:512,INPUT:256})
  self.u.mem_write(PUBLISHED,bytes(((j*73+19)&255)if c['buffer_pattern']=='affine'else 0 if c['buffer_pattern']=='zero'else 255 for j in range(512)));self.defined.update(range(PUBLISHED,PUBLISHED+512));self.u.mem_write(INPUT,bytes((j*29+7)&255 for j in range(256)));self.defined.update(range(INPUT,INPUT+256))
  globals_=[(0x1010c8268,8,PUBLISHED),(0x1010c67d4,4,255),(0x1010c8254,1,1),(0x1010c4e18,4,c.get('controller',0)),(0x1010c4670,4,0x87654321)]
  provider=self.ctx['coherent_provider_snapshots'][c['provider_case']];self.u.mem_write(PUBLISHED,bytes.fromhex(provider['published_buffer512_hex']));globals_.extend([(0x1010c67dc,4,provider['index32']),(0x1010c8258,4,provider['counter32']),(0x1010c6800,8,int(provider['encoded_window_mask64'],16)),(0x1010ca2a8,8,int(provider['encoded_window_base64'],16))]);self.provider=provider;self.mutable_globals=set(range(0x1010c784c,0x1010c784c+2496))|set(range(0x1010c67dc,0x1010c67e0))|set(range(0x1010c8258,0x1010c825c))
  self.global_pages={a&~4095 for a,n,v in globals_};self.image_fixtures=[];self.import_defined=set();self.import_inputs={IMPORTS['IOKit/_kIOMainPortDefault']:(4,c.get('main_port',0),'IOKit/_kIOMainPortDefault'),IMPORTS['CoreFoundation/_kCFAllocatorDefault']:(8,c.get('allocator',0),'CoreFoundation/_kCFAllocatorDefault'),IMPORTS['CoreFoundation/_kCFAllocatorNull']:(8,c.get('null_allocator',0x6e00001000),'CoreFoundation/_kCFAllocatorNull')};self.import_pages={a&~4095 for a in self.import_inputs}
  for a,n,v in globals_:
   self.ensure(a,n);b=v.to_bytes(n,'little');self.u.mem_write(a,b);self.global_defined.update(range(a,a+n));self.image_fixtures.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'declared runtime state; pointer/mask source publications known, native preservation unknown'})
  state=bytes.fromhex(provider['state_bytes_hex']);self.global_pages.update([0x1010c7000,0x1010c8000]);self.ensure(0x1010c784c,2496);self.u.mem_write(0x1010c784c,state);self.global_defined.update(range(0x1010c784c,0x1010c784c+2496));self.image_fixtures.append({'address':'0x1010c784c','bytes_hex':state.hex(),'provenance':'coherent retained producer snapshot; native preservation unknown'})
  for a,(n,v,symbol)in self.import_inputs.items():self.ensure(a,n);self.u.mem_write(a,v.to_bytes(n,'little'));self.import_defined.update(range(a,a+n));self.image_fixtures.append({'address':hex(a),'bytes_hex':v.to_bytes(n,'little').hex(),'provenance':'declared imported-data ABI input; native value unknown','symbol':symbol})
  self.initial_fields=[{'address':hex(F+int(x['offset'],16)),'bytes_hex':x['bytes_hex']}for x in self.ctx['source_frame_fields']];self.entry_regs=[hex(self.reg('x'+str(j)))for j in range(31)];self.initial_SP=hex(F)
 def ensure(self,a,n=1):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if P<=pg<P+SIZE or pg in self.pages:continue
   if pg in getattr(self,'import_pages',set()):self.u.mem_map(pg,4096);self.u.mem_write(pg,bytes(4096));self.pages.add(pg);continue
   assert 0x100000000<=pg<0x102000000,('unmapped owner',hex(pg))
   try:raw=bytearray(IMAGE.read(pg,4096))
   except ValueError:
    assert pg in getattr(self,'global_pages',set()),('unknown image page',hex(pg));raw=bytearray(4096)
   for at,r in PAGES[pg]:
    target=r['target'];value=(IMPORTS[target]+ADDENDS.get(at,0))if isinstance(target,str)else target;raw[at-pg:at-pg+8]=struct.pack('<Q',value&((1<<64)-1))
   self.u.mem_map(pg,4096);self.u.mem_write(pg,bytes(raw));self.pages.add(pg)
 def stop(self,reason,detail=None):
  self.reason=reason;self.done=True;self.boundary={'pc':hex(self.reg('pc')),'kind':reason,'detail':detail,'SP':hex(self.reg('sp')),'registers31':[hex(self.reg('x'+str(j)))for j in range(31)]};self.u.emu_stop()
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def canonical(self,n):return 'x'+n[1:]if n.startswith('w')and n[1:].isdigit()else {'fp':'x29','lr':'x30','wsp':'sp'}.get(n,n)
 def finish_pointer_sources(self):
  i=self.previous_i
  if i is None:return
  effects=self.events[self.previous_event_start:];before=self.previous_sources;written={self.canonical(i.reg_name(v))for v in i.regs_access()[1]}
  for n in written:self.reg_sources.pop(n,None)
  for e in effects:
   if e['kind']=='write':
    a=int(e['address'],16);n=e['size_bytes']
    for at in list(self.memory_sources):
     if a<at+8 and at<a+n:self.memory_sources.pop(at)
  if i.mnemonic in ['ldr','ldur']and i.reg_name(i.operands[0].reg).startswith('x'):
   reads=[e for e in effects if e['kind']=='read'and e['size_bytes']==8]
   if len(reads)==1:
    a=int(reads[0]['address'],16);origin=a if a in FIXUPS else self.memory_sources.get(a)
    if origin is not None:self.reg_sources[self.canonical(i.reg_name(i.operands[0].reg))]=origin
  elif i.mnemonic=='mov'and len(i.operands)==2 and i.operands[1].type==ARM64_OP_REG:
   origin=before.get(self.canonical(i.reg_name(i.operands[1].reg)))
   if origin is not None:self.reg_sources[self.canonical(i.reg_name(i.operands[0].reg))]=origin
  elif i.mnemonic in ['str','stur']and i.reg_name(i.operands[0].reg).startswith('x'):
   origin=before.get(self.canonical(i.reg_name(i.operands[0].reg)));writes=[e for e in effects if e['kind']=='write'and e['size_bytes']==8]
   if origin is not None and len(writes)==1:self.memory_sources[int(writes[0]['address'],16)]=origin
  self.previous_i=None
 def read(self,u,t,a,n,v,d):
  b=bytes(u.mem_read(a,n));pc=hex(self.reg('pc'));e={'kind':'read','pc':pc,'address':hex(a),'size_bytes':n,'bytes_hex':b.hex()};self.events.append(e)
  if a in FIXUPS and n==8:self.fix.add(a);self.last_slot=a
  if P<=a<a+n<=P+SIZE and not all(x in self.defined for x in range(a,a+n)):self.arbitrary_heap_reads.append(e)
 def write(self,u,t,a,n,v,d):
  self.defined.update(range(a,a+n));e={'kind':'write','pc':hex(self.reg('pc')),'address':hex(a),'size_bytes':n};self.events.append(e);self.pending.append(e)
 def regname(self,n):return 0 if n in ['wzr','xzr']else self.reg(n)
 def preflight(self,i):
  op=next((x for x in i.operands if x.type==ARM64_OP_MEM),None)
  if op is None:return True
  m=i.mnemonic;load=m.startswith(('ldr','ldur','ldp','ldnp','ldar','ldax'));store=m.startswith(('str','stur','stp','stnp','stlr','stlx'));assert load or store,(m,i.op_str)
  a=self.regname(i.reg_name(op.mem.base))+op.mem.disp
  if op.mem.index:
   name=i.reg_name(op.mem.index);idx=self.regname(name)
   if op.ext in [ARM64_EXT_SXTW,ARM64_EXT_SXTX]:bits=32 if op.ext==ARM64_EXT_SXTW else 64;idx&=(1<<bits)-1;idx-=1<<bits if idx>>(bits-1)else 0
   a+=idx<<op.shift.value
  a&=(1<<64)-1;name=i.reg_name(i.operands[0].reg);n=1 if m.endswith('b')else 2 if m.endswith('h')else 4 if m.endswith('sw')or name.startswith('w')else 16 if name.startswith('q')else 8;n*=2 if m.startswith(('ldp','ldnp','stp','stnp'))else 1
  if P<=a<a+n<=P+SIZE:
   valid=any(h<=a<a+n<=h+nb for h,nb in self.owners.items());heap=any(h<=a<a+n<=h+nb for h,nb in self.allocated.items())
   if not valid:return self.stop('before_unowned_private_access',{'address':hex(a),'size_bytes':n,'instruction':m+' '+i.op_str})or False
   if load and not heap and not all(x in self.defined for x in range(a,a+n)):return self.stop('before_unknown_frame_read',{'address':hex(a),'size_bytes':n,'instruction':m+' '+i.op_str})or False
  elif a&~4095 in self.import_pages:
   if store or not all(x in self.import_defined for x in range(a,a+n)):return self.stop('before_unmodeled_imported_data',{'address':hex(a),'size_bytes':n,'instruction':m+' '+i.op_str})or False
  elif a&~4095 in self.global_pages:
   if(store and not all(x in self.mutable_globals for x in range(a,a+n)))or not all(x in self.global_defined for x in range(a,a+n)):return self.stop('before_unmodeled_runtime_global',{'address':hex(a),'size_bytes':n,'instruction':m+' '+i.op_str})or False
  else:
   if store:return self.stop('before_unowned_external_write',{'address':hex(a),'size_bytes':n})or False
   try:self.ensure(a,n)
   except(AssertionError,ValueError)as e:return self.stop('before_unknown_external_read',{'address':hex(a),'size_bytes':n,'reason':str(e)})or False
  return True
 def code(self,u,a,n,d):
  self.flush();self.finish_pointer_sources()
  if not 0x100000000<=a<0x100e2c000:return self.stop('before_external_code',{'target':hex(a)})
  raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4);i=next(self.dec.disasm(raw,a));m=i.mnemonic;self.source_pool[hex(a)]={'bytes_hex':raw.hex(),'mnemonic':m,'operands':i.op_str}
  if not self.preflight(i):return
  if m in ['braa','blraa','br','blr','ret','retab','retaa']:
   names=[x.strip()for x in i.op_str.split(',')];ret=m.startswith('ret');target=self.reg('x30')if ret else self.regname(names[0]);disc=self.regname(names[1])if len(names)>1 else None;call=m.startswith('bl');slot=self.reg_sources.get(self.canonical(names[0]))if not ret else None
   if not ret:
    r=FIXUPS.get(slot);word=int.from_bytes(IMAGE.read(slot,8),'little')if r else 0;expect=(IMPORTS[r['target']]+ADDENDS.get(slot,0))if r and isinstance(r['target'],str)else r['target']if r else None
    if not(r and expect==target and word>>63==1 and(word>>32)&65535==disc and(word>>49)&3==0 and(word>>48)&1==0):return self.stop('before_unresolved_auth_provenance',{'target':hex(target),'modifier':hex(disc)if disc is not None else None,'last_slot':hex(slot)if slot else None})
   if call and target in IMPORTS.values():
    specs={0x100c116b0:872,0x10094c6f8:48}
    if a not in specs or FIXUPS[slot]['target']!='libSystem/_malloc':return self.stop('before_unmodeled_import',{'symbol':FIXUPS[slot]['target'],'arguments8':[hex(self.reg('x'+str(j)))for j in range(8)]})
    extent=specs[a];assert self.reg('x0')==extent;ptr=OBJ if extent==872 else BUFFER48 if self.cfg['buffer_nonnull']else 0;before={n:self.reg(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]};self.api.append({'pc':hex(a),'binding':binding(slot),'requested_bytes':extent,'returned':hex(ptr),'preserved_GPR_SP':before,'native_call_executed':False})
    if ptr:self.owners[ptr]=extent;self.allocated[ptr]=extent
    for j in range(1,18):self.set('x'+str(j),((j+7)*0x143256789abcdef^self.cfg['pattern'])&((1<<64)-1))
    for j in list(range(18))+[30]:self.reg_sources.pop('x'+str(j),None)
    self.set('x0',ptr);self.set('x30',a+4);self.set('nzcv',0x50000000);assert all(self.reg(n)==v for n,v in before.items());self.steps.append((a,raw.hex()));self.set('pc',a+4);return
   if not 0x100000000<=target<0x100e2c000:return self.stop('before_unmapped_control_target',{'target':hex(target)})
   self.steps.append((a,raw.hex()));self.edges.append({'pc':hex(a),'target':hex(target),'modifier':hex(disc)if disc is not None else None,'slot':hex(slot)if not ret else None,'kind':m})
   if call:self.set('x30',a+4)
   self.ensure(target);self.set('pc',target);return
  self.steps.append((a,raw.hex()));self.previous_i=i;self.previous_event_start=len(self.events);self.previous_sources=self.reg_sources.copy()
  if m in ['pacibsp','paciasp','autibsp','autiasp','paciza']:self.set('pc',a+4);return
  assert m not in ['svc','hvc','smc','bl'],(hex(a),m)
 def run(self,limit=3000000):
  self.allocated={};start=0x100aee5c8;self.ensure(start);self.u.emu_start(start,0,count=limit);self.flush()
  if self.reason is None:self.stop('source_visit_limit')
  snapshots={hex(h):bytes(self.u.mem_read(h,n)).hex()for h,n in self.allocated.items()};trace={'configuration':self.cfg,'entry_PC':hex(start),'entry_SP':self.initial_SP,'entry_registers31':self.entry_regs,'image_fixtures':self.image_fixtures,'frame_fields':self.initial_fields,'steps':self.steps,'events':self.events,'source_pool':self.source_pool,'edges':self.edges,'api_models':self.api,'used_fixups':[hex(x)for x in sorted(self.fix)],'arbitrary_heap_reads':self.arbitrary_heap_reads,'allocated_owners':{hex(h):n for h,n in self.allocated.items()},'owner_snapshots':snapshots,'scratch48_hex':bytes(self.u.mem_read(self.F+0x39f0+48,48)).hex(),'cursor_after':hex(self.value(self.F+0x3620,8)),'boundary':self.boundary};raw=json.dumps(trace,separators=(',',':')).encode();return{'configuration':self.cfg,'source_visits':len(self.steps),'api_calls':len(self.api),'boundary':self.boundary,'payload_zlib_base64':base64.b64encode(zlib.compress(raw)).decode(),'payload_sha256':hashlib.sha256(raw).hexdigest(),'native_target_executed':False,'full_goal_complete':False}
def cases():
 for j,(d,pattern,nonnull,placement)in enumerate([(2,0,True,0),(200,255,True,0x100),(37,17,True,16),(37,93,False,0)]):yield {'decoded':d,'pattern':pattern,'buffer_pattern':'retained','buffer_nonnull':nonnull,'placement':placement,'provider_case':j}
def main():
 rows=[]
 for cfg in cases():
  r=Run(cfg).run();rows.append(r);print(json.dumps({'configuration':cfg,'source_visits':r['source_visits'],'api_calls':r['api_calls'],'boundary':{k:v for k,v in r['boundary'].items()if k!='registers31'}}),flush=True)
 deps=['daemon_object_initialization_context.json','replay_daemon_object_creation.py','daemon_receive_tools.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_initialization_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
