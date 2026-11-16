#!/usr/bin/env python3
"""Original root/context/CPU producers and exact declared-epoch consumers.
O(visits + journals + mapped RAM) time/space. Opaque transport returns and
boot/lock leaves are explicit; address converters execute original source.
"""
import json,struct
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_kernel_magazine_bootstrap import Probe as Storage
from probe_rpc502_vm_handoff import compressed,decode
import recover_kernel_mapping_context as R
T=R.T;THREAD=P+0x10000;CPUDATA=P+0x12000;TABLE=P+0x20000;COUNT=TABLE+0x100;TOPO=P+0x22000
OUTPUT=P+0x28000;RESULT=P+0x30000;BITMAP=P+0x40000;SHARED=P+0x60000;ROOTVA=P+0x80000
ROOTPA=0x800000;BUMPA=0x900000;CPUPA=0xa00000;SHAREDPA=0xb00000;VA=0xfffffe0007d00000
DESCRIPTOR=0x0460000000400403;MASK=(1<<64)-1

def configurations():
 return [dict(count=n,cpu=cpu,bump_offset=off,status=status,transport_id=cpu) for n,cpu,off,status in
  [(64,0,0,0),(128,1,3,0),(513,2,16380,0),(256,1,7,1),(257,2,0,2),(1024,0,0,6)]]+[
  dict(count=128,cpu=1,bump_offset=0,status=0,transport_id=0x123400000001),
  dict(count=1,cpu=0,bump_offset=0,status=0,transport_id=0),dict(count=63,cpu=0,bump_offset=0,status=0,transport_id=0),
  dict(count=128,cpu=1,bump_offset=0,status=0,transport_id=1,cpu_conversion_fail=True)]

class Probe(Storage):
 def __init__(self,image,c,phase,parent=None,mutate=None):
  CPU.__init__(self,image,'selector',{'id':0});self.c=c;self.phase=phase;self.mutate=mutate;self.initial=[];self.image_initial=[];self.regions=[];self.dcs=[];self.events=[];self.clears=[];self.conversions=[]
  e=json.loads(read(ROOT/(R.P+'_checks.json')));self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in e['functions']]
  if parent is not None:
   self.u.mem_write(P,decode(parent['final_private_RAM']))
   for row in parent['final_image_globals']:self.image_fixture(int(row['address'],16),bytes.fromhex(row['bytes_hex']),'Exact predecessor output transferred into a declared call epoch')
  else:
   assert phase=='root';self.fixture(THREAD,bytes(0x280));self.fixture(THREAD+0x1b8,struct.pack('<Q',(c['cpu']<<30)|c['cpu']));self.fixture(THREAD+0x1c8,struct.pack('<I',4));self.fixture(THREAD+0x1c0,struct.pack('<Q',CPUDATA));self.fixture(CPUDATA,bytes([0xa5])*4096)
   table=bytearray()
   for pa,va,pages in [(ROOTPA,ROOTVA,1),(BUMPA,BITMAP,4),(CPUPA,T.CPU_BASE,3),(SHAREDPA,SHARED,6)]:table+=struct.pack('<QQII',pa,va,pages,0)
   self.fixture(TABLE,table);self.fixture(COUNT,struct.pack('<I',4));self.fixture(TOPO,bytes(3*136))
   for j in range(3):self.fixture(TOPO+j*136+4,struct.pack('<I',0x900+j))
   self.fixture(BITMAP,bytes([0xa5])*65536);self.fixture(ROOTVA,bytes([0x5a])*16384);self.fixture(SHARED,bytes([0x3c])*98304)
   self.fixture(RESULT,struct.pack('<QQ',DESCRIPTOR,0x123456789abcdef0));self.fixture(OUTPUT,bytes([0xa5])*32)
   self.fixture(SP+0x30,struct.pack('<Q',VA+123))
   rows=[(R.BOOTROOT,struct.pack('<Q',ROOTPA)),(R.ROOTPAIR,bytes(16)),(T.CTX,image.k.read(T.CTX,128)),
    (T.CPU_BASE,image.k.read(T.CPU_BASE,49152)),(R.BUMP,struct.pack('<Q',BUMPA+c['bump_offset'])),
    (R.CONV_GLOBALS,bytes([1])+bytes(7)+struct.pack('<QQ',COUNT,TABLE)),
    (0xfffffe0007f8c740,struct.pack('<QQ',T.CPU_BASE,T.CPU_BASE+49152)),
    (0xfffffe0007f8b5e0,struct.pack('<Q',P+0x24000)),(R.TOPOLOGY,struct.pack('<Q',TOPO)),(R.SHARED,struct.pack('<Q',SHAREDPA)),
    (R.ASID_BITS,bytes(8)),(R.ASID_COUNT,bytes(8)),(0xfffffe000cb0c028,bytes(40)),(0xfffffe000cb0c320,bytes(8)),
    (0xfffffe000cb89010,bytes(48)),(0xfffffe0007e6ce10,bytes(2)),(T.TAG_FLAG,bytes(1))]
   self.fixture(P+0x24000,bytes(0x100));self.fixture(P+0x24068,struct.pack('<I',c['count']))
   for a,b in rows:self.image_fixture(a,b,'Original file-zero state or declared boot/range/topology input; native ownership unproved')
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  for j in range(31):self.set(j,0x6060606000000000+j)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  if phase=='root':self.entry=0xfffffe000be74108;self.finish_PC=0xfffffe000be74138
  elif phase=='context':self.entry=0xfffffe000be75444;self.finish_PC=0xfffffe000be7545c
  elif phase=='cpu':
   self.entry=R.CPUINIT;self.finish_PC=HALT;self.set(0,c['cpu'])
   if c.get('cpu_conversion_fail'):self.image_fixture(R.CONV_GLOBALS,bytes(1),'Declared feature change in this new call epoch exercises original VA-to-PA failure')
  elif phase=='gate':
   self.entry=T.GATE;self.finish_PC=0xfffffe000be5b450
   for j,v in enumerate([T.CTX,VA,0x400000,3,0,0,1,1]):self.set(j,v)
   self.fixture(SP,bytes([0x23])+bytes(7))
  else:
   assert phase=='backend' and parent['phase']=='gate';self.entry=T.IMPL;self.finish_PC=HALT
   desc=int(parent['boundary']['registers31'][0],16)
   for j,v in enumerate([T.CTX,OUTPUT,desc,0,OUTPUT+8,VA,1,0x23]):self.set(j,v)
   self.fixture(SP,struct.pack('<Q',OUTPUT+24))
  self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.before=bytes(self.u.mem_read(P,SIZE))
  if mutate is not None:self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def fixture(self,a,b):return CPU.fixture(self,a,bytes(b))
 def code(self,u,a,n,d):
  self.flush()
  if a==self.finish_PC:return self.stop('source_component_complete')
  if a in [0xfffffe000c62a2b0,0xfffffe000c63aec8]:return self.stop('before_original_diagnostic')
  if a==T.CHECK and self.phase=='gate':return self.model(a,'declared_validation_no_RAM_effect',0)
  leaves={0xfffffe000bd037e0:'declared_lock_initialization_no_RAM_effect',0xfffffe000be71258:'declared_initializer_leaf_no_RAM_effect',
   0xfffffe000c5e48a4:'declared_boot_parser_absent_no_RAM_effect',0xfffffe000c620a08:'declared_capability_query_failure_no_RAM_effect'}
  if a in leaves:return self.model(a,leaves[a],1 if a==0xfffffe000c620a08 else 0)
  if a in [R.IDENT,R.RESULT,T.WRAPPERS[1]]:
   block=T.CPU_BASE+self.c['cpu']*16384
   self.events.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j)) for j in range(8)],
    'thread_nesting':int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little'),
    'epoch_and_active_hex':bytes(u.mem_read(block+0x1270,16)).hex()})
   value=self.c['transport_id'] if a==R.IDENT else RESULT if a==R.RESULT else self.c['status']
   return self.model(a,'declared_SPTM_identifier' if a==R.IDENT else 'declared_SPTM_result_pointer' if a==R.RESULT else 'declared_opaque_mapping_status_no_RAM_effect',value)
  if a==R.Z.BZERO:self.clears.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments2':[hex(self.reg(j)) for j in range(2)]})
  if a in [R.P2V,R.V2P]:self.conversions.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments2':[hex(self.reg(j)) for j in range(2)]})
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_uncaptured_code')
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4));i=next(self.image.k.cs.disasm(raw,a))
  if i.mnemonic=='dc':
   assert i.op_str=='zva, x3';at=self.reg(3)&~63;assert BITMAP<=at<at+64<=BITMAP+65536
   self.dcs.append({'pc':hex(a),'source_visit_index':len(self.visits),'address':hex(at),'before_hex':bytes(u.mem_read(at,64)).hex(),'after_hex':bytes(64).hex()})
   self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.mem_write(at,bytes(64));u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=30000);self.flush();assert self.reason is not None
  return {'configuration':self.c,'phase':self.phase,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':'0x0',
   'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,
   'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'private_system_registers':[{'register':'TPIDR_EL1','value':hex(THREAD)}],
   'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in self.regions],
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,
   'logical_envelopes':[],'string_leaf_inputs':[],'logical_DC_ZVA_effects':self.dcs,'original_clear_entries':self.clears,
   'transport_entries':self.events,'original_conversion_entries':self.conversions,'boundary':self.boundary,'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,**{k:False for k in R.FALSE}}

def oracle(row):
 """Independent field/byte formulas, including every nonstack RAM byte."""
 c=row['configuration'];phase=row['phase'];b=row['boundary'];checks=[]
 before=bytearray(decode(row['initial_private_RAM']));after=decode(row['final_private_RAM']);effective={}
 for f in row['initial_image_fixtures']:
  a=int(f['address'],16)
  for j,v in enumerate(bytes.fromhex(f['bytes_hex'])):effective[a+j]=v
 def put(a,n,v):
  raw=(v&((1<<(8*n))-1)).to_bytes(n,'little')
  if P<=a<a+n<=P+SIZE:before[a-P:a-P+n]=raw
  else:
   assert all(a+j in effective for j in range(n)),('oracle untracked write',hex(a),n)
   for j,v in enumerate(raw):effective[a+j]=v
 def check(label,p):assert p,(label,c,phase,b);checks.append(label)
 regs=list(map(lambda v:int(v,16),b['registers31']));initial=list(map(lambda v:int(v,16),row['entry_registers31']))
 models=row['API_models'];events=row['transport_entries'];block=T.CPU_BASE+c['cpu']*16384
 expected_conversions=[]
 if phase=='root':
  put(R.ROOTPAIR,8,ROOTPA);put(R.ROOTPAIR+8,8,ROOTVA)
  check('original_root_conversion_returns_to_exact_ARM_source_cut',b['pc']=='0xfffffe000be74138' and not models)
  expected_conversions=[(R.P2V,ROOTPA)]
 elif phase=='context':
  for off,n,v in [(0,8,ROOTVA),(8,8,ROOTPA),(0x10,8,0xffff800000000000),(0x18,8,MASK),(0x20,8,R.GEOM),
   (0x30,8,0xfffffe000cb0c028),(0x38,8,0xfffffe000cb0c028),(0x40,16,0),(0x60,8,0),(0x68,4,1),
   (0x6c,2,0),(0x6e,1,0),(0x70,4,0x01010000),(0x74,1,0),(0x75,2,0x100)]:put(T.CTX+off,n,v)
  aligned=(c['bump_offset']+7)&~7;budget=(((c['count']+63)&0xffffffff)>>3)&0x1ffffff8
  end=(BUMPA+aligned+budget+16383)&~16383;length=end-(BUMPA+aligned);alias=BITMAP+aligned
  expected_conversions=[(R.P2V,BUMPA+aligned)]*2
  before[alias-P:alias-P+length]=bytes(length)
  for j in range(c['count']):
   if j%256:before[alias-P+j//8]|=1<<(j&7)
  put(R.BUMP,8,end);put(R.ASID_BITS,8,alias);put(R.ASID_COUNT,4,c['count']&~63)
  put(0xfffffe000cb0c028,8,T.CTX);put(0xfffffe000cb0c030,8,T.CTX)
  put(0xfffffe000cb0c320,8,(VA+123+0x1ffffff)&~0x1ffffff);put(0xfffffe000cb0c038,8,-0x13000000001)
  check('original_bzero_receives_exact_converted_alias_and_reserved_byte_extent',len(row['original_clear_entries'])==1 and list(map(lambda v:int(v,16),row['original_clear_entries'][0]['arguments2']))==[alias,length])
  if c['count']<64:
   check('count_rounddown_zero_reaches_exact_original_diagnostic',b['kind']=='before_original_diagnostic' and regs[0]==0xfffffe000705f996)
   check('only_initialization_leaves_precede_count_diagnostic',[m['symbol'] for m in models]==['declared_lock_initialization_no_RAM_effect','declared_initializer_leaf_no_RAM_effect'])
  else:
   put(R.ASID_COUNT+4,4,int((c['count']&~63)>256))
   for off,v in [(0,-2),(8,-1),(16,-1),(24,-1),(32,-1),(40,-1)]:put(0xfffffe000cb89010+off,8,v)
   put(0xfffffe000cb0c040,8,0);put(0xfffffe000cb0c048,8,0x11)
   put(0xfffffe0007e6ce10,1,1);put(0xfffffe0007e6ce11,1,0)
   check('complete_context_initializer_returns_to_original_ARM_caller',b['pc']=='0xfffffe000be7545c' and int(b['SP'],16)==SP)
   check('declared_initializer_leaf_and_parser_inventory',len(models)==7 and sum(m['symbol']=='declared_boot_parser_absent_no_RAM_effect' for m in models)==4)
 elif phase=='cpu':
  put(CPUDATA+0x8e8,4,c['cpu'])
  if c.get('cpu_conversion_fail'):
   expected_conversions=[(R.V2P,block+0x10)]
   check('original_disabled_converter_reaches_kvtophys_nofail_diagnostic',b['kind']=='before_original_diagnostic' and regs[0]==0xfffffe00070601b8 and not models and not events)
  else:
   expected_conversions=[(R.V2P,block+off) for off in [0x10,0x610,0xc10,0xc10,0x1310]]+[(R.P2V,SHAREDPA+((c['transport_id']&0xffffffff)<<15))]
   for out,inp in [(0xe10,0x10),(0xe18,0x610),(0xe20,0xc10),(0xe28,0xc10),(0x1d70,0x1310)]:put(block+out,8,CPUPA+c['cpu']*16384+inp)
   put(block+0x1d78,2,c['transport_id']);put(block+8,8,SHARED+((c['transport_id']&0xffffffff)<<15));put(block,8,RESULT)
   check('original_CPU_initializer_restores_frame_and_nonvolatile_registers',b['pc']==hex(HALT) and int(b['SP'],16)==SP and regs[19:30]==initial[19:30])
   check('identifier_uses_topology_field_and_result_pointer_uses_full_identifier',len(events)==2 and [int(e['arguments8'][0],16) for e in events]==[0x900+c['cpu'],c['transport_id']] and [e['pc'] for e in events]==[hex(R.IDENT),hex(R.RESULT)])
 elif phase=='gate':
  put(SP-0x170+0xbe,2,0xc0)
  check('original_admission_uses_source_initialized_geometry_and_returns_descriptor',b['pc']=='0xfffffe000be5b450' and regs[0]==DESCRIPTOR)
  check('two_declared_validations_receive_source_root_then_physical_page',len(models)==2 and [int(m['arguments8'][0],16) for m in models]==[ROOTPA,0x400000])
 else:
  put(block+0x1270,8,0);put(block+0x1278,8,1)
  if c['status']<2:put(OUTPUT,8,0x123456789abcdef0);put(OUTPUT+8,8,DESCRIPTOR)
  check('backend_receives_exact_root_virtual_descriptor_and_zero',len(events)==1 and list(map(lambda v:int(v,16),events[0]['arguments8'][:4]))==[ROOTPA,VA,DESCRIPTOR,0])
  check('backend_publishes_first_file_zero_epoch_and_nesting_before_transport',events[0]['thread_nesting']==5 and events[0]['epoch_and_active_hex']==struct.pack('<QQ',1,1).hex())
  check('backend_returns_raw_status_and_restores_frame_nonvolatile_registers',b['pc']==hex(HALT) and regs[0]==c['status'] and int(b['SP'],16)==SP and regs[19:30]==initial[19:30])
 check('original_conversion_entry_order_and_exact_address_arguments',[(int(e['pc'],16),int(e['arguments2'][0],16)) for e in row['original_conversion_entries']]==expected_conversions)
 check('every_recorded_global_byte_matches_independent_field_oracle',all(bytes.fromhex(r['bytes_hex'])==bytes(effective[int(r['address'],16)+j] for j in range(len(bytes.fromhex(r['bytes_hex'])))) for r in row['final_image_globals']))
 check('entire_nonstack_RAM_matches_independent_byte_oracle',after[:SP-P-1024]==before[:SP-P-1024] and after[SP-P+1024:]==before[SP-P+1024:])
 return checks
