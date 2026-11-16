#!/usr/bin/env python3
"""Original boot-record, nested context/pool/CPU and mapping components.
O(visits + journals + RAM) time/space; opaque/DT/lock/parser leaves explicit.
"""
import json,struct
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_kernel_magazine_bootstrap import Probe as Storage
from probe_rpc502_vm_handoff import compressed,decode
import recover_kernel_sptm_boot_inputs as R
C=R.C;T=C.T;THREAD=P+0x10000;CPUDATA=P+0x12000;TABLE=P+0x20000;COUNT=TABLE+0x100
DEVICE=P+0x24000;OUTPUT=P+0x28000;RESULT=P+0x2c000;ROOTVA=P+0x30000;HEADER=P+0x38000;RECORD=HEADER+0x1a0
BACKING=P+0x40000;BACKING_BYTES=0xa0000;ROOTPA=0x800000;BUMPA=0x900000;CPUPA=0xa00000
VA=0xfffffe0007d00000;DESC=0x0460000000400403;MAGIC=0xd00f000000000000;MASK=(1<<64)-1;OLD_HEAD=0x1234567800000000

def configuration(**kw):
 return dict(dict(mode='record',version=12,flag=0,count=64,cpu=0,bump_offset=0,memory_bytes=256<<20,status=0,transport_id=0),**kw)

def record_cases():return [configuration(version=v,flag=f) for v in [0,1,2,3,4,5,6,7,8,9,10,11,12,0xffffffff] for f in [0,1]]

def chain_cases():
 rows=[(64,0,0,256<<20,0,7,0),(128,1,3,16<<30,0,12,1),(513,2,0,64<<30,1,8,0),
  (256,1,7,0,2,6,0),(257,2,16380,256<<20,6,7,1),(1024,0,0,16<<30,0,0,0),
  (128,1,0,16<<30,0,0xffffffff,1),(1,0,0,256<<20,0,12,0),(63,2,0,0,0,3,1)]
 return [configuration(mode='chain',count=n,cpu=cpu,bump_offset=off,memory_bytes=mem,status=status,version=v,flag=flag,
  transport_id=0x123400000001 if j==6 else cpu) for j,(n,cpu,off,mem,status,v,flag) in enumerate(rows)]

def boot_record(c):
 raw=bytearray().join(struct.pack('<Q',0x1111000000000000+j*0x10101) for j in range(32));struct.pack_into('<I',raw,0,c['version'])
 for off,value in [(8,COUNT),(0x10,TABLE),(0x28,T.CPU_BASE),(0x30,T.CPU_BASE+49152),
  (0xa8,(0x123456789abcdef0&~64)|(c['flag']<<6))]:struct.pack_into('<Q',raw,off,value)
 return bytes(raw)

class Probe(Storage):
 def __init__(self,image,c,phase,parent=None,mutate=None):
  CPU.__init__(self,image,'selector',{'id':0});self.c=c;self.phase=phase;self.mutate=mutate;self.initial=[];self.image_initial=[];self.regions=[]
  self.dcs=[];self.events=[];self.clears=[];self.conversions=[];self.nested=[]
  e=json.loads(read(ROOT/(R.P+'_checks.json')));self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in e['functions']]
  if parent is not None:
   self.u.mem_write(P,decode(parent['final_private_RAM']))
   for row in parent['final_image_globals']:self.image_fixture(int(row['address'],16),bytes.fromhex(row['bytes_hex']),'Exact predecessor output transferred into a declared call epoch')
  else:
   assert phase in ['loader','boot'];self.fixture(THREAD,bytes(0x280));self.fixture(THREAD+0x1b8,struct.pack('<Q',(c['cpu']<<30)|c['cpu']));self.fixture(THREAD+0x1c8,struct.pack('<I',4));self.fixture(THREAD+0x1c0,struct.pack('<Q',CPUDATA));self.fixture(CPUDATA,bytes([0xa5])*4096)
   table=b''.join(struct.pack('<QQII',pa,va,pages,0) for pa,va,pages in [(ROOTPA,ROOTVA,1),(BUMPA,BACKING,40),(CPUPA,T.CPU_BASE,3)])
   self.fixture(TABLE,table);self.fixture(COUNT,struct.pack('<I',3));self.fixture(BACKING,bytes([0xa5])*BACKING_BYTES);self.fixture(ROOTVA,bytes([0x5a])*16384)
   self.fixture(RESULT,struct.pack('<QQ',DESC,0x123456789abcdef0));self.fixture(OUTPUT,bytes([0xa5])*32);self.fixture(DEVICE,bytes(0x400))
   for off,fmt,value in [(0x68,'I',c['count']),(0x330,'Q',0x1122334455667788),(0x338,'I',0x33445566),(0x340,'Q',0x2233445566778899),(0x348,'I',0x44556677)]:self.fixture(DEVICE+off,struct.pack('<'+fmt,value))
   self.fixture(SP+0x30,struct.pack('<Q',VA+123))
   topology=bytearray(image.k.read(R.TOPOBASE,3*136))
   for j in range(3):struct.pack_into('<I',topology,j*136+4,0x900+j)
   rows=[(R.GLOBALS,bytes([0 if c['mode']=='chain' else 0xa5])*R.GLOBAL_BYTES),
    (C.BOOTROOT,struct.pack('<Q',ROOTPA)),(C.ROOTPAIR,bytes(16)),(T.CTX,image.k.read(T.CTX,128)),(T.CPU_BASE,image.k.read(T.CPU_BASE,49152)),
    (C.BUMP,struct.pack('<Q',BUMPA+c['bump_offset'])),(R.MEMSIZE,struct.pack('<Q',c['memory_bytes'])),
    (0xfffffe0007f8b5e0,struct.pack('<Q',DEVICE)),(R.TOPOBASE,topology),(0xfffffe0007e6d0a0,bytes(40)),
    (0xfffffe0007ef81f0,bytes(16)),(0xfffffe000cb890a8,struct.pack('<Q',OLD_HEAD)+bytes(24)),
    (0xfffffe000ca93dd8,image.k.read(0xfffffe000ca93dd8,12)),(C.ASID_BITS,bytes(8)),(C.ASID_COUNT,bytes(8)),
    (0xfffffe000cb0c028,bytes(40)),(0xfffffe000cb0c320,bytes(8)),(0xfffffe000cb89010,bytes(48)),
    (0xfffffe0007e6ce10,bytes(2)),(T.TAG_FLAG,bytes(1))]
   for a,b in rows:self.image_fixture(a,b,'Original file state or declared boot/table/backing/topology input; native origin and ownership unproved')
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  for j in range(31):self.set(j,0x7070707000000000+j)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  if phase in ['loader','boot']:
   self.fixture(HEADER,struct.pack('<Q',MAGIC if not c.get('bad_magic') else MAGIC^1)+bytes(0x198));self.fixture(RECORD,boot_record(c))
   self.entry=R.BOOT_CALLER if phase=='loader' else R.BOOT;self.finish_PC=HALT;self.set(0,HEADER if phase=='loader' else 0 if c.get('null') else RECORD)
  elif phase=='root':self.entry=0xfffffe000be74108;self.finish_PC=0xfffffe000be74138
  elif phase=='context':self.entry=0xfffffe000be75444;self.finish_PC=0xfffffe000be7545c
  elif phase=='gate':
   self.entry=T.GATE;self.finish_PC=0xfffffe000be5b450
   for j,v in enumerate([T.CTX,VA,0x400000,3,0,0,1,1]):self.set(j,v)
   self.fixture(SP,bytes([0x23])+bytes(7))
  else:
   assert phase=='backend' and parent['phase']=='gate';self.entry=T.IMPL;self.finish_PC=HALT;descriptor=int(parent['boundary']['registers31'][0],16)
   for j,v in enumerate([T.CTX,OUTPUT,descriptor,0,OUTPUT+8,VA,1,0x23]):self.set(j,v)
   self.fixture(SP,struct.pack('<Q',OUTPUT+24))
  self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.before=bytes(self.u.mem_read(P,SIZE))
  if mutate is not None:self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def fixture(self,a,b):return CPU.fixture(self,a,bytes(b))
 def code(self,u,a,n,d):
  self.flush()
  if a==self.finish_PC:return self.stop('source_component_complete')
  if a in [0xfffffe000c62a2b0,0xfffffe000c63aec8]:return self.stop('before_original_diagnostic')
  if a in [0xfffffe000c660574,0xfffffe000c66057c]:return self.stop('before_original_WFE')
  if a in [R.POOL,R.DT,C.CPUINIT]:self.nested.append({'pc':hex(a),'source_visit_index':len(self.visits),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_PC':hex(self.reg(30)),'arguments2':[hex(self.reg(j)) for j in range(2)]})
  leaves={0xfffffe000bd037e0:('declared_lock_initialization_no_RAM_effect',0),0xfffffe000c5e48a4:('declared_boot_parser_absent_no_RAM_effect',0),
   0xfffffe000c620a08:('declared_capability_query_failure_no_RAM_effect',1),T.CHECK:('declared_validation_no_RAM_effect',0),
   0xfffffe000c662324:('declared_SecureDT_lookup_no_output_no_RAM_effect',0),0xfffffe000c662110:('declared_DT_property_absent_no_RAM_effect',0)}
  if a in leaves:return self.model(a,*leaves[a])
  if a in [C.IDENT,C.RESULT,T.WRAPPERS[1]]:
   block=T.CPU_BASE+self.c['cpu']*16384
   self.events.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j)) for j in range(8)],
    'thread_nesting':int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little'),
    'epoch_and_active_hex':bytes(u.mem_read(block+0x1270,16)).hex(),'transport_flag':bytes(u.mem_read(T.TRANSPORT_FLAG,1)).hex()})
   value=self.c['transport_id'] if a==C.IDENT else RESULT if a==C.RESULT else self.c['status']
   return self.model(a,'declared_SPTM_identifier' if a==C.IDENT else 'declared_SPTM_result_pointer' if a==C.RESULT else 'declared_opaque_mapping_status_no_RAM_effect',value)
  if a==C.Z.BZERO:self.clears.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments2':[hex(self.reg(j)) for j in range(2)]})
  if a in [C.P2V,C.V2P]:self.conversions.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments2':[hex(self.reg(j)) for j in range(2)]})
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_uncaptured_code')
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4));i=next(self.image.k.cs.disasm(raw,a))
  if i.mnemonic=='dc':
   assert i.op_str=='zva, x3';at=self.reg(3)&~63;assert BACKING<=at<at+64<=BACKING+BACKING_BYTES
   self.dcs.append({'pc':hex(a),'source_visit_index':len(self.visits),'address':hex(at),'before_hex':bytes(u.mem_read(at,64)).hex(),'after_hex':bytes(64).hex()})
   self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.mem_write(at,bytes(64));u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=60000);self.flush();assert self.reason is not None
  return {'configuration':self.c,'phase':self.phase,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':'0x0',
   'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,
   'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'private_system_registers':[{'register':'TPIDR_EL1','value':hex(THREAD)}],
   'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in self.regions],
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,
   'logical_envelopes':[],'string_leaf_inputs':[],'logical_DC_ZVA_effects':self.dcs,'original_clear_entries':self.clears,
   'transport_entries':self.events,'original_conversion_entries':self.conversions,'nested_source_entries':self.nested,
   'boundary':self.boundary,'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,**{k:False for k in R.FALSE}}

def published_fields():
 rows=[(off,off,4 if off==0x60 else 8,0) for off in [8,0x10,0x18,0x20,0x28,0x30,0x38,0x40,0x48,0x50,0x58,0x60,0x68,0x70,0x78]]
 for version,offsets in [(3,[0x80]),(4,[0x88]),(5,[0x90,0x98]),(6,[0xa0]),(7,[0xa8]),(8,[0xb0,0xb8,0xc0,0xc8]),(9,[0xd0]),(10,[0xd8]),(11,[0xe0,0xe8,0xf0]),(12,[0xf8])]:
  rows += [(off,off+(8 if off>=0xb0 else 0),4 if off in [0x98,0xb8,0xc8] else 8,version) for off in offsets]
 return rows

def allocation(c):
 units=((c['memory_bytes']>>24)&0xfffffffe);first=(units*0x6830d6e5)>>40;objects=(first*629)&0xffffffff
 pages=(((objects+629)&0xffffffff)*0x6830d6e5)>>40;page_bytes=(pages<<14)&0xffffffff
 old=BUMPA+c['bump_offset'];aligned=(old+16383)&~16383;pool_end=(aligned+page_bytes+16383)&~16383
 shared=pool_end;bitmap=shared+524288;budget=(((c['count']+63)&0xffffffff)>>3)&0x1ffffff8
 end=(bitmap+budget+16383)&~16383
 return dict(old=old,aligned=aligned,pages=pages,objects=objects,pool_end=pool_end,shared=shared,bitmap=bitmap,end=end)

def oracle(row):
 c=row['configuration'];phase=row['phase'];b=row['boundary'];checks=[];before=bytearray(decode(row['initial_private_RAM']));after=decode(row['final_private_RAM']);effective={}
 for f in row['initial_image_fixtures']:
  a=int(f['address'],16)
  for j,v in enumerate(bytes.fromhex(f['bytes_hex'])):effective[a+j]=v
 def put(a,n,v):
  raw=(v&((1<<(8*n))-1)).to_bytes(n,'little')
  if P<=a<a+n<=P+SIZE:before[a-P:a-P+n]=raw
  else:
   assert all(a+j in effective for j in range(n)),('untracked oracle region',hex(a),n)
   for j,v in enumerate(raw):effective[a+j]=v
 def check(label,p):assert p,(label,c,phase,b);checks.append(label)
 regs=list(map(lambda v:int(v,16),b['registers31']));initial=list(map(lambda v:int(v,16),row['entry_registers31']));models=row['API_models'];events=row['transport_entries'];conversions=[]
 if phase in ['loader','boot']:
  if c.get('bad_magic'):check('bad_loader_magic_stops_at_original_WFE_before_any_publication',b['pc']=='0xfffffe000c66057c' and not row['source_writes'][2:] and not models)
  elif c.get('null'):check('null_record_returns_raw2_without_global_publication',b['pc']==hex(HALT) and regs[0]==2)
  else:
   raw=boot_record(c)
   for src,dst,width,version in published_fields():
    if c['version']>=version:put(R.GLOBALS+dst,width,int.from_bytes(raw[src:src+width],'little'))
   if c['version']>=7:put(T.TRANSPORT_FLAG,1,c['flag'])
   put(R.GLOBALS,1,1)
   check('versioned_boot_record_returns_zero_and_restores_frame',b['pc']==hex(HALT) and regs[0]==0 and int(b['SP'],16)==SP and regs[19:30]==initial[19:30])
   check('boot_record_publication_has_no_leaf_return_models',not models)
 elif phase=='root':
  put(C.ROOTPAIR,8,ROOTPA);put(C.ROOTPAIR+8,8,ROOTVA);conversions=[(C.P2V,ROOTPA)]
  check('original_root_converter_returns_to_exact_ARM_cut',b['pc']=='0xfffffe000be74138' and not models)
 elif phase=='context':
  a=allocation(c);alias=lambda pa:BACKING+pa-BUMPA;block=T.CPU_BASE+c['cpu']*16384
  assert 0<a['pages']<=7 and BUMPA<=a['old']<=a['end']<=BUMPA+BACKING_BYTES
  for off,n,v in [(0,8,ROOTVA),(8,8,ROOTPA),(0x10,8,0xffff800000000000),(0x18,8,MASK),(0x20,8,C.GEOM),
   (0x30,8,0xfffffe000cb0c028),(0x38,8,0xfffffe000cb0c028),(0x40,16,0),(0x60,8,0),(0x68,4,1),
   (0x6c,2,0),(0x6e,1,0),(0x70,4,0x01010000),(0x74,1,0),(0x75,2,0x100)]:put(T.CTX+off,n,v)
  put(0xfffffe0007e6d0a0,4,629);put(0xfffffe0007e6d0a4,4,0x3b00)
  for dest,n,v in [(0xfffffe0007ef81f0,8,0x1122334455667788),(0xfffffe0007ef81f8,4,0x33445566),(0xfffffe0007e6d0a8,8,0x2233445566778899),(0xfffffe0007e6d0b0,4,0x44556677)]:put(dest,n,v)
  before[alias(a['old'])-P:alias(a['pool_end'])-P]=bytes(a['pool_end']-a['old']);head=OLD_HEAD
  for j in range(a['pages']):
   page=alias(a['aligned'])+j*16384;put(page+628*24,8,head);head=page
  put(0xfffffe000cb890a8,8,head);put(0xfffffe000cb890b0,4,629*a['pages']);put(0xfffffe000cb890b8,8,0);put(0xfffffe000cb890c0,8,0x11)
  put(C.SHARED,8,a['shared']);put(0xfffffe0007e6d0c0,8,a['bitmap']);put(CPUDATA+0x8e8,4,c['cpu'])
  for out,inp in [(0xe10,0x10),(0xe18,0x610),(0xe20,0xc10),(0xe28,0xc10),(0x1d70,0x1310)]:put(block+out,8,CPUPA+c['cpu']*16384+inp)
  put(block+0x1d78,2,c['transport_id']);put(block+8,8,alias(a['shared'])+((c['transport_id']&0xffffffff)<<15));put(block,8,RESULT)
  bitmap=alias(a['bitmap']);before[bitmap-P:alias(a['end'])-P]=bytes(a['end']-a['bitmap'])
  for j in range(c['count']):
   if j%256:before[bitmap-P+j//8]|=1<<(j&7)
  put(C.BUMP,8,a['end']);put(C.ASID_BITS,8,bitmap);put(C.ASID_COUNT,4,c['count']&~63)
  put(0xfffffe000cb0c028,8,T.CTX);put(0xfffffe000cb0c030,8,T.CTX);put(0xfffffe000cb0c320,8,(VA+123+0x1ffffff)&~0x1ffffff);put(0xfffffe000cb0c038,8,-0x13000000001)
  conversions=[(C.P2V,a['aligned']),(C.P2V,a['old'])]+[(C.V2P,block+off) for off in [0x10,0x610,0xc10,0xc10,0x1310]]+[(C.P2V,a['shared']+((c['transport_id']&0xffffffff)<<15)),(C.P2V,a['bitmap']),(C.P2V,a['bitmap'])]
  check('two_original_clears_cover_pool_and_bitmap_while_shared_reservation_is_preserved',[(int(e['arguments2'][0],16),int(e['arguments2'][1],16)) for e in row['original_clear_entries']]==[(alias(a['old']),a['pool_end']-a['old']),(bitmap,a['end']-a['bitmap'])] and after[alias(a['shared'])-P:alias(a['bitmap'])-P]==decode(row['initial_private_RAM'])[alias(a['shared'])-P:alias(a['bitmap'])-P])
  check('source_nested_pool_DT_CPU_order_and_CPU_tail_call_return',len(row['nested_source_entries'])==3 and [e['pc'] for e in row['nested_source_entries']]==list(map(hex,[R.POOL,R.DT,C.CPUINIT])) and row['nested_source_entries'][2]['return_PC']=='0xfffffe000be609bc')
  check('topology_and_full_identifier_wrapper_inputs',len(events)==2 and [int(e['arguments8'][0],16) for e in events]==[0x900+c['cpu'],c['transport_id']])
  if c['count']<64:check('small_count_diagnostic_occurs_after_original_pool_and_CPU_initialization',b['kind']=='before_original_diagnostic' and regs[0]==0xfffffe000705f996 and len(models)==7)
  else:
   put(C.ASID_COUNT+4,4,int((c['count']&~63)>256))
   for off,v in [(0,-2),(8,-1),(16,-1),(24,-1),(32,-1),(40,-1)]:put(0xfffffe000cb89010+off,8,v)
   put(0xfffffe000cb0c040,8,0);put(0xfffffe000cb0c048,8,0x11);put(0xfffffe0007e6ce10,1,1);put(0xfffffe0007e6ce11,1,0)
   check('complete_context_returns_after_original_nested_leaf_CPU_and_bitmap',b['pc']=='0xfffffe000be7545c' and len(models)==12)
 elif phase=='gate':
  put(SP-0x170+0xbe,2,0xc0);check('source_initialized_context_geometry_yields_original_descriptor',b['pc']=='0xfffffe000be5b450' and regs[0]==DESC)
  check('two_validations_receive_source_root_then_physical_page',len(models)==2 and [int(m['arguments8'][0],16) for m in models]==[ROOTPA,0x400000])
 else:
  block=T.CPU_BASE+c['cpu']*16384;put(block+0x1270,8,0);put(block+0x1278,8,1)
  if c['status']<2:put(OUTPUT,8,0x123456789abcdef0);put(OUTPUT+8,8,DESC)
  check('one_exact_mapping_request_and_first_epoch_publication',len(events)==1 and list(map(lambda v:int(v,16),events[0]['arguments8'][:4]))==[ROOTPA,VA,DESC,0] and events[0]['thread_nesting']==5 and events[0]['epoch_and_active_hex']==struct.pack('<QQ',1,1).hex())
  check('backend_returns_raw_status_and_restores_frame_nonvolatile_registers',b['pc']==hex(HALT) and regs[0]==c['status'] and int(b['SP'],16)==SP and regs[19:30]==initial[19:30])
 if events:check('all_transport_models_observe_original_boot_record_flag_publication',all(e['transport_flag']==bytes([c['flag'] if c['version']>=7 else 0]).hex() for e in events))
 check('every_original_conversion_entry_matches_independent_order_and_address',[(int(e['pc'],16),int(e['arguments2'][0],16)) for e in row['original_conversion_entries']]==conversions)
 check('all_recorded_global_bytes_match_independent_oracle',all(bytes.fromhex(r['bytes_hex'])==bytes(effective[int(r['address'],16)+j] for j in range(len(bytes.fromhex(r['bytes_hex'])))) for r in row['final_image_globals']))
 check('all_nonstack_private_RAM_matches_independent_byte_oracle',after[:SP-P-1024]==before[:SP-P-1024] and after[SP-P+1024:]==before[SP-P+1024:])
 return checks
