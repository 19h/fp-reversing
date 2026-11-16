#!/usr/bin/env python3
"""Original zero-wrapper and clear leaves in declared private aliases.
O(visits + RAM + journals) time/space. DC ZVA has an explicit logical64 B
effect; cache attributes/mapping/preemption helpers are no-RAM return models.
"""
import json,struct
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_kernel_magazine_bootstrap import Probe as Storage,THREAD
from probe_rpc502_vm_handoff import compressed,decode
import recover_kernel_physical_zero as R
ALIAS=P+0x40000;EXTENT=65536;CPU_INDEX=2
WINDOW_ALIAS=R.WINDOW_BASE+(CPU_INDEX<<16)

def cases():
 rows=[dict(mode='wrapper',route='direct',length=n,offset=o,attribute=a) for n,o,a in
  [(0,0,2),(1,3,2),(7,1,6),(8,7,11),(63,63,18),(64,1,22),(127,13,2),
   (128,31,2),(129,0,2),(4096,7,2),(16384,0,2),(16384,0,0),
   (17,5,23),(17,5,0x10002)]]
 rows.extend(dict(mode='wrapper',route='direct',length=65,offset=17,attribute=a) for a in range(24))
 rows.extend(dict(mode='wrapper',route='window',length=n,offset=o,attribute=a,nesting=d,deferred=f) for n,o,a,d,f in
  [(17,13,2,0,0),(16384,0,2,0,4),(16384,0,0,1,4),(16483,16380,2,0,4),(16483,16380,0,2,0)])
 rows.append(dict(mode='wrapper',route='window',length=17,offset=0,attribute=2,invalid_window=True))
 for mode in ['bzero','memset']:
  rows.extend(dict(mode=mode,length=n,offset=o,value=0x12345) for n,o in
   [(0,0),(1,1),(7,7),(8,1),(9,3),(15,15),(16,1),(17,15),(63,63),(64,1),(65,7),
    (127,15),(128,1),(129,63),(255,7),(256,0),(4096,1),(16384,0)])
 return rows

class Probe(Storage):
 def __init__(self,image,c,mutate=None):
  CPU.__init__(self,image,'selector',{'id':0});self.c=c;self.regions=[];self.mutate=mutate
  self.dcs=[];self.clear_entries=[];self.windows=0;self.initial=[];self.image_initial=[]
  self.allowed=[(R.ZERO,0xfffffe000be7b9b4),(R.BZERO,R.MEMSET),(R.MEMSET,0xfffffe000c648218)]
  for j in range(31):self.set(j,0x3030303000000000+j)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  self.fixture(THREAD+0x1b8,struct.pack('<H',CPU_INDEX));self.fixture(THREAD+0x1c8,struct.pack('<I',c.get('nesting',0)))
  self.fixture(THREAD+0x1c0,struct.pack('<Q',P+0x20000));self.fixture(P+0x2004c,bytes([c.get('deferred',0)]))
  self.fixture(ALIAS,bytes((j*17+41)&255 for j in range(EXTENT)))
  if c['mode']=='wrapper':
   self.entry=R.ZERO;self.physical=(0x300000 if c['route']=='window' else 0x100000)+c['offset']
   self.set(0,self.physical);self.set(1,c['length'])
   self.image_fixture(R.LOWER,struct.pack('<QQ',0x100000,0x200000),'Declared unsigned direct-map interval')
   if c['route']=='window':self.image_fixture(WINDOW_ALIAS,bytes((j*19+53)&255 for j in range(EXTENT)),'Declared CPU2 window aliases; no native physical equivalence')
  else:
   self.entry=R.BZERO if c['mode']=='bzero' else R.MEMSET;self.set(0,ALIAS+c['offset'])
   self.set(1,c['length'] if c['mode']=='bzero' else c['value']);self.set(2,c['length'])
  self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.before=bytes(self.u.mem_read(P,SIZE))
  if mutate is not None:self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def ensure(self,a,n=1):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if WINDOW_ALIAS<=pg<WINDOW_ALIAS+EXTENT:
    if pg not in self.pages:self.u.mem_map(pg,4096);self.u.mem_write(pg,bytes(4096));self.pages.add(pg)
   else:CPU.ensure(self,pg,4096)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('original_function_returned')
  if a in [0xfffffe000c62a2b0,0xfffffe000c63aec8]:return self.stop('before_original_diagnostic')
  if a==R.ATTR:return self.model(a,'declared_cache_attributes',self.c['attribute'])
  if a==R.DIRECT:return self.model(a,'declared_contiguous_direct_alias',ALIAS+self.reg(0)-0x100000)
  if a==R.WINDOW:
   index=4 if self.c.get('invalid_window') else self.windows;self.windows+=1
   return self.model(a,'declared_window_index',index)
  if a in [R.UNMAP,R.DEFER]:return self.model(a,'declared_window_unmap' if a==R.UNMAP else 'declared_deferred_preemption',0)
  if a in [R.BZERO,R.MEMSET]:self.clear_entries.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments3':[hex(self.reg(j)) for j in range(3)]})
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_uncaptured_code')
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4))
  i=next(self.image.k.cs.disasm(raw,a))
  if i.mnemonic=='dc':
   assert i.op_str.startswith('zva, x');j=int(i.op_str.split('x')[-1]);operand=self.reg(j);base=operand&~63
   assert P<=base<base+64<=P+SIZE or WINDOW_ALIAS<=base<base+64<=WINDOW_ALIAS+EXTENT
   event={'pc':hex(a),'source_visit_index':len(self.visits),'operand_register':j,'operand_value':hex(operand),
    'address':hex(base),'size_bytes':64,'before_hex':bytes(u.mem_read(base,64)).hex(),'after_hex':bytes(64).hex()}
   self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.dcs.append(event);u.mem_write(base,bytes(64));u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush()
  assert self.reason in ['original_function_returned','before_original_diagnostic'],self.boundary
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':'0x0',
   'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,
   'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'private_system_registers':[{'register':'TPIDR_EL1','value':hex(THREAD)}],
   'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in self.regions],
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,
   'logical_DC_ZVA_effects':self.dcs,'logical_DC_granule_bytes':64,'logical_envelopes':[],'string_leaf_inputs':[],
   'original_clear_entries':self.clear_entries,'boundary':self.boundary,'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,
   **{k:False for k in R.FALSE}}

def oracle(row):
 c=row['configuration'];checks=[];before=decode(row['initial_private_RAM']);after=decode(row['final_private_RAM']);want=bytearray(before)
 image={int(r['address'],16):bytearray.fromhex(r['bytes_hex']) for r in row['initial_image_fixtures']}
 expected_calls=[];expected_leaves=[];offset=c['offset'];length=c['length'];chunks=[]
 def check(label,p):assert p,(label,c);checks.append(label)
 if c['mode']=='wrapper':
  physical=(0x300000 if c['route']=='window' else 0x100000)+offset;left=length;index=0
  while left:
   expected_calls.append((R.ATTR,physical>>14))
   if c['route']=='direct':alias=ALIAS+physical-0x100000;chunk=left;expected_calls.append((R.DIRECT,physical))
   else:
    expected_calls.append((R.WINDOW,physical>>14))
    if c.get('invalid_window'):struct.pack_into('<I',want,THREAD-P+0x1c8,c.get('nesting',0)+1);break
    chunk=min(16384-(physical&16383),left);alias=WINDOW_ALIAS+(index<<14)+(physical&16383)
   chunks.append((alias,chunk));attr=c['attribute']&255
   if attr not in [2,6,11,18,22]:expected_leaves.append((R.MEMSET,[alias,0,chunk]))
   elif chunk!=16384:expected_leaves.append((R.BZERO,[alias,chunk,None]))
   if c['route']=='window':
    expected_calls.append((R.UNMAP,index))
    if c.get('nesting',0)==0 and c.get('deferred',0)&4:expected_calls.append((R.DEFER,None))
   physical+=chunk;left-=chunk;index+=1
  for alias,chunk in chunks:
   if ALIAS<=alias<ALIAS+EXTENT:want[alias-P:alias-P+chunk]=bytes(chunk)
   else:image[WINDOW_ALIAS][alias-WINDOW_ALIAS:alias-WINDOW_ALIAS+chunk]=bytes(chunk)
  check('exact_zero_or_invalid_window_boundary',row['boundary']['kind']==('before_original_diagnostic' if c.get('invalid_window') else 'original_function_returned'))
  check('cache_map_unmap_defer_order_and_input_arguments',len(expected_calls)==len(row['API_models']) and all(int(m['pc'],16)==pc and (arg is None or int(m['arguments8'][0],16)==arg) for m,(pc,arg) in zip(row['API_models'],expected_calls)))
  actual=[(int(e['pc'],16),list(map(lambda x:int(x,16),e['arguments3']))) for e in row['original_clear_entries']]
  check('exact_original_clear_leaf_selection_and_size',len(actual)==len(expected_leaves) and all(pc==epc and all(v is None or av==v for av,v in zip(args,eargs)) for (pc,args),(epc,eargs) in zip(actual,expected_leaves)))
 else:
  value=0 if c['mode']=='bzero' else c['value']&255;want[ALIAS-P+offset:ALIAS-P+offset+length]=bytes([value])*length
  check('no_mapping_or_cache_models_in_original_clear_leaf',not row['API_models'])
  if c['mode']=='memset':check('memset_returns_original_destination',int(row['boundary']['registers31'][0],16)==ALIAS+offset)
 check('entire_nonstack_private_RAM_and_all_payload_guards_exact',after[:SP-P-512]==want[:SP-P-512] and after[SP-P+256:]==want[SP-P+256:])
 actual={int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in row['final_image_globals']}
 check('all_declared_image_and_window_alias_bytes_exact',actual==image)
 if not c.get('invalid_window'):check('original_frame_and_all_nonvolatile_GP_restored',int(row['boundary']['SP'],16)==SP and all(row['boundary']['registers31'][j]==row['entry_registers31'][j] for j in range(19,31)))
 return checks
