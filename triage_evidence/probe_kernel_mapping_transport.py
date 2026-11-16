#!/usr/bin/env python3
"""Private original mapping components; opaque transport is a boundary/model.
O(visits + journals + mapped RAM) time/space; logical PAC/system reads only.
"""
import json,struct
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_kernel_magazine_bootstrap import Probe as Storage
from probe_rpc502_vm_handoff import compressed,decode
import recover_kernel_mapping_transport as R
THREAD=P+0x10000;GEOM=P+0x20000;ROWS=P+0x21000;OUT=P+0x30000;RESULT=P+0x31000;BITMAP=P+0x32000
VA=0xfffffe0007d00000;PA=0x400000;ROOT_PA=0x800000;MASK=(1<<64)-1

def cases():
 rows=[]
 for kind in ['valid','VA_unaligned','PA_unaligned','VA_below','VA_end','reserved_first','reserved_last','reserved_end','kernel_mode4','user_mode4_off','user_mode4_on','expand']:
  rows.append({'kind':'gate','scenario':kind})
 for kernel in [False,True]:
  for mode in [0,1,2,3,4,7]:
   for flag in [0,1]:
    if kernel and mode&4:continue
    rows.append({'kind':'descriptor','kernel':kernel,'mode':mode,'geometry_flag':flag,'nonzero_flag':1})
 for kernel in [False,True]:rows.append({'kind':'descriptor','kernel':kernel,'mode':3,'geometry_flag':1,'nonzero_flag':0})
 for cpu in [0,1,2]:
  for result in [0,1,2,6,7,0xffffffff]:rows.append({'kind':'implementation','cpu':cpu,'result':result,'bitmap':None})
 for bit in [0,2]:rows.append({'kind':'implementation','cpu':1,'result':0,'bitmap':bit})
 for j in range(3):
  for flag in [0,1]:
   for thread in [False,True]:rows.append({'kind':'wrapper','wrapper':j,'transport_flag':flag,'thread':thread,'depth':5})
 for thread,depth in [(False,0),(True,1),(True,4),(True,6)]:rows.append({'kind':'post','thread':thread,'depth':depth})
 return rows

def descriptor(c):
 # Independent selected-family arithmetic: kernel mode bit2 clear or user flags,
 # zero context+75/+76, PA outside the declared direct interval.
 mode=c['mode'];kernel=c.get('kernel',True);out=0xc0;value=3|(PA&0xfffffffff000)
 if c.get('nonzero_flag',1):value|=0x0400000000000000
 if mode&4:
  value|=0x0040000000000000 if kernel else 0
  value|=0x0010000000000000
 else:value|=0x0020000000000000
 if kernel:
  if not mode&2:value|=0x80;out=0x40
 else:
  if not c['geometry_flag']:value|=0x800
  value|=0x100 if mode==4 else 0x40 if not mode&2 else 0x80
  out=0x40 if not mode&2 else 0xc0
 return value|0x400,out

class Probe(Storage):
 def __init__(self,image,c,mutate=None):
  CPU.__init__(self,image,'selector',{'id':0});self.c=c;self.mutate=mutate;self.initial=[];self.image_initial=[];self.regions=[];self.system_reads=[];self.events=[]
  e=json.loads(read(ROOT/(R.P+'_checks.json')));self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in e['functions']]
  for j in range(31):self.set(j,0x5050505000000000+j)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD if c.get('thread',True) else 0)
  self.fixture(THREAD,bytes(0x280));self.fixture(THREAD+0x1b8,struct.pack('<Q',(c.get('cpu',0)<<30)|c.get('cpu',0)));self.fixture(THREAD+0x1c8,struct.pack('<I',c.get('depth',4)))
  context=bytearray(128);struct.pack_into('<QQQQ',context,8,ROOT_PA,VA,VA+16384,GEOM)
  geometry=bytearray(128);struct.pack_into('<Q',geometry,0,ROWS);struct.pack_into('<QQQQQ',geometry,0x10,0x40,0x80,0x100,0,0x0020000000000000);struct.pack_into('<Q',geometry,0x38,0x0010000000000000)
  struct.pack_into('<I',geometry,0x48,1);geometry[0x4c]=c.get('geometry_flag',0)
  self.fixture(GEOM,geometry);self.fixture(ROWS,bytes(128));self.fixture(ROWS+56+8,struct.pack('<QQ',0x3fff,14))
  self.fixture(OUT,bytes([0xa5])*32);self.fixture(RESULT,bytes(32));self.fixture(SP,bytes([0x23])+bytes(15))
  self.image_fixture(R.CTX,context,'Declared runtime context; original file context is zero-filled')
  self.image_fixture(0xfffffe0007ef81e0,struct.pack('<QQ',PA+16384,PA+32768),'Declared physical interval excluding selected PA')
  self.image_fixture(R.TAG_FLAG,bytes(1),'Declared tag0x23 fallback to category0x0b')
  kind=c['kind'];self.cpu_block=R.CPU_BASE+c.get('cpu',0)*16384
  if kind in ['gate','descriptor']:
   kernel=c.get('kernel',True);ctx=R.CTX if kernel else P+0x40000
   if not kernel:self.fixture(ctx,context)
   if kind=='descriptor':
    self.entry=R.DESC
    for j,v in enumerate([ctx,PA,c['mode'],0,c['nonzero_flag'],0,OUT]):self.set(j,v)
   else:
    s=c['scenario'];self.entry=R.GATE;va=VA;pa=PA;mode=3;options=1
    if s.startswith('user_'):
     ctx=P+0x40000;self.fixture(ctx,context);mode=4
     if s=='user_mode4_on':self.fixture(GEOM+0x4c,bytes([1]))
    if s=='VA_unaligned':va+=1
    if s=='PA_unaligned':pa+=1
    if s=='VA_below':va-=16384
    if s=='VA_end':va+=16384
    if s.startswith('reserved_'):
     va={'reserved_first':0xfffffecfffd00000,'reserved_last':0xfffffecfffdfc000,'reserved_end':0xfffffecfffe00000}[s]
     self.image_fixture(R.CTX+0x10,struct.pack('<QQ',0,MASK),'Declared broad bounds for reserved-window control')
    if s=='kernel_mode4':mode=4
    if s=='expand':options=2
    for j,v in enumerate([ctx,va,pa,mode,0,0,1,options]):self.set(j,v)
  elif kind=='implementation':
   self.entry=R.IMPL;self.desc=descriptor({'kernel':True,'mode':3})[0]
   if c['bitmap'] is not None:
    context[0x76]=3;struct.pack_into('<QQ',context,0x40,VA,16384);struct.pack_into('<Q',context,0x60,BITMAP)
    self.image_fixture(R.CTX,context,'Declared type3 context and one-page optional bitmap interval');self.fixture(BITMAP,struct.pack('<Q',c['bitmap']))
    if c['bitmap']&2:self.desc|=0x800
   block=bytearray(0x1280);struct.pack_into('<Q',block,0,RESULT);struct.pack_into('<Q',block,0x1278,7)
   self.image_fixture(self.cpu_block,block,'Declared current-CPU request epoch7, inactive marker and result pointer')
   self.fixture(RESULT,struct.pack('<QQ',self.desc,0x123456789abcdef0))
   for j,v in enumerate([R.CTX,OUT,self.desc&~(0x800 if c['bitmap']==2 else 0),0,OUT+8,VA,1,0x23]):self.set(j,v)
   self.fixture(SP,struct.pack('<Q',OUT+24))
  elif kind=='wrapper':
   self.entry=R.WRAPPERS[c['wrapper']];self.image_fixture(R.TRANSPORT_FLAG,bytes([c['transport_flag']]),'Declared transport selection byte')
   for j,v in enumerate([ROOT_PA,VA,descriptor({'kernel':True,'mode':3})[0],0]):self.set(j,v)
  else:assert kind=='post';self.entry=R.POST
  self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.before=bytes(self.u.mem_read(P,SIZE))
  if mutate is not None:self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def fixture(self,a,b):return CPU.fixture(self,a,bytes(b))
 def code(self,u,a,n,d):
  self.flush();kind=self.c['kind']
  if a==HALT:return self.stop('returned')
  if kind=='gate' and a in [0xfffffe000be5b450,R.EXPAND,0xfffffe000c62a2b0]:return self.stop('admission_boundary')
  if kind=='descriptor' and a==0xfffffe000c62a2b0:return self.stop('descriptor_diagnostic')
  if kind=='gate' and a==R.CHECK:return self.model(a,'declared_validation_no_RAM_effect',0)
  if kind=='implementation' and a==R.WRAPPERS[1]:
   self.events.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j)) for j in range(8)],
    'preemption_depth':int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little'),
    'epoch_and_active_hex':bytes(u.mem_read(self.cpu_block+0x1270,16)).hex()})
   return self.model(a,'declared_opaque_mapping_transport_no_RAM_effect',self.c['result'])
  if kind=='wrapper' and any(a in [w+32,w+40] for w in R.WRAPPERS):return self.stop('before_opaque_transport_word')
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_uncaptured_code')
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4));ii=list(self.image.k.cs.disasm(raw,a));assert len(ii)==1,(hex(a),raw.hex())
  i=ii[0]
  if i.mnemonic=='mrs' and ('s3_6_c15_c8_0' in i.op_str or 'daif' in i.op_str):
   dest=int(i.op_str.split(',')[0][1:]);value=0 if 's3_' in i.op_str else 0x80
   self.system_reads.append({'pc':hex(a),'source_visit_index':len(self.visits),'destination':dest,'value':hex(value),'register':i.op_str.split(', ')[1]})
   self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(dest,value);u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if a==self.mutate:
   self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=10000);self.flush();assert self.reason is not None
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':'0x0',
   'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,
   'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'private_system_registers':[{'register':'TPIDR_EL1','value':hex(THREAD if self.c.get('thread',True) else 0)}],
   'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in self.regions],
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,
   'logical_envelopes':[],'string_leaf_inputs':[],'logical_system_reads':self.system_reads,'transport_request_entries':self.events,
   'boundary':self.boundary,'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,**{k:False for k in R.FALSE}}

def oracle(row):
 c=row['configuration'];kind=c['kind'];checks=[];b=row['boundary'];regs=list(map(lambda x:int(x,16),b['registers31']));initial=list(map(lambda x:int(x,16),row['entry_registers31']))
 after=decode(row['final_private_RAM']);before=bytearray(decode(row['initial_private_RAM']))
 def get(a,n):return int.from_bytes(after[a-P:a-P+n],'little')
 def put(a,n,v):before[a-P:a-P+n]=(v&((1<<(8*n))-1)).to_bytes(n,'little')
 def check(label,p):assert p,(label,c,b);checks.append(label)
 if kind=='descriptor':
  if c['mode']==4 and not c['geometry_flag']:
   check('mode4_without_geometry_feature_stops_before_diagnostic',b['kind']=='descriptor_diagnostic' and get(OUT,2)==0);put(OUT,2,0)
  else:
   value,attrs=descriptor(c);check('descriptor_and_u16_attributes_match_independent_formula',b['kind']=='returned' and regs[0]==value and get(OUT,2)==attrs);put(OUT,2,attrs)
 elif kind=='gate':
  s=c['scenario'];check('exactly_two_validation_calls_with_root_then_PA',len(row['API_models'])==2 and [int(m['arguments8'][0],16) for m in row['API_models']]==[ROOT_PA,PA+(s=='PA_unaligned')])
  if s in ['VA_below','VA_end','user_mode4_off']:check('admission_raw_return_and_original_frame_restoration',b['kind']=='returned' and regs[0]==(2 if s=='user_mode4_off' else 1) and int(b['SP'],16)==SP)
  elif s=='expand':check('tail_expansion_preserves_original_frame_and_ninth_byte',b['pc']==hex(R.EXPAND) and int(b['SP'],16)==SP and regs[:3]==[R.CTX,VA,2] and get(SP,1)==0x23)
  elif s in ['VA_unaligned','PA_unaligned','reserved_first','reserved_last','kernel_mode4']:
   diagnostic={'VA_unaligned':0xfffffe000705ffcd,'PA_unaligned':0xfffffe000706006b,'reserved_first':0xfffffe000705fffa,'reserved_last':0xfffffe000705fffa,'kernel_mode4':0xfffffe0007060099}[s]
   check('admission_rejects_at_exact_original_diagnostic',b['pc']==hex(0xfffffe000c62a2b0) and regs[0]==diagnostic)
  else:
   kernel=s!='user_mode4_on';mode=3 if kernel else 4;value,attrs=descriptor({'kernel':kernel,'mode':mode,'geometry_flag':1 if not kernel else 0})
   check('admitted_gateway_executes_original_descriptor_and_returns_to_caller',b['pc']==hex(0xfffffe000be5b450) and regs[0]==value)
   put(SP-0x170+0xbe,2,attrs)
 elif kind=='implementation':
  cpu=c['cpu'];block=R.CPU_BASE+cpu*16384;value=descriptor({'kernel':True,'mode':3})[0]|(0x800 if c['bitmap']==2 else 0)
  event=row['transport_request_entries'];check('one_exact_root_VA_descriptor_zero_transport_request',len(event)==1 and list(map(lambda x:int(x,16),event[0]['arguments8'][:4]))==[ROOT_PA,VA,value,0])
  check('preemption_and_epoch_published_before_transport',event[0]['preemption_depth']==5 and event[0]['epoch_and_active_hex']==struct.pack('<QQ',8,8).hex())
  check('raw_status_propagates_and_frame_nonvolatile_registers_restore',b['kind']=='returned' and regs[0]==c['result'] and int(b['SP'],16)==SP and regs[19:30]==initial[19:30])
  check('preemption_depth_restored',get(THREAD+0x1c8,4)==4)
  if c['result']<2:put(OUT,8,0x123456789abcdef0);put(OUT+8,8,value)
  check('unsigned_status_below2_controls_two_result_copies',get(OUT,8)==(0x123456789abcdef0 if c['result']<2 else 0xa5a5a5a5a5a5a5a5) and get(OUT+8,8)==(value if c['result']<2 else 0xa5a5a5a5a5a5a5a5))
  # Context fixture overlap is deliberate and captured in order; check every byte
  # of each final recorded region using the effective last-writer initial state.
  effective={}
  for f in row['initial_image_fixtures']:
   a=int(f['address'],16)
   for j,v in enumerate(bytes.fromhex(f['bytes_hex'])):effective[a+j]=v
  for j,v in enumerate(struct.pack('<QQ',0,8)):effective[block+0x1270+j]=v
  check('active_marker_release_clear_epoch_increment_and_all_region_guards',all(bytes.fromhex(r['bytes_hex'])==bytes(effective[int(r['address'],16)+j] for j in range(len(bytes.fromhex(r['bytes_hex'])))) for r in row['final_image_globals']))
 elif kind=='wrapper':
  expected=R.WRAPPERS[c['wrapper']]+(40 if c['transport_flag'] else 32)
  check('flag_selects_exact_opaque_word_PC_and_raw_word',b['pc']==hex(expected) and b['kind']=='before_opaque_transport_word')
  check('selector_and_eight_input_registers_survive_original_prehelper',regs[:8]==initial[:8] and regs[16]==c['wrapper']+1)
  depth=c['depth']+int(c['thread']);check('prehelper_thread_nullable_and_nesting_increment',get(THREAD+0x1c8,4)==depth);put(THREAD+0x1c8,4,depth)
  check('opaque_word_not_in_executed_visits',hex(expected) not in {x['pc'] for x in row['source_visits']})
 else:
  depth=c['depth']-1 if c['thread'] else c['depth'];put(THREAD+0x1c8,4,depth)
  check('posthelper_decrements_nonnull_depth_and_preserves_results',b['kind']=='returned' and get(THREAD+0x1c8,4)==depth and regs[:8]==initial[:8] and regs[19:30]==initial[19:30] and int(b['SP'],16)==SP)
 if kind!='implementation':
  effective={}
  for f in row['initial_image_fixtures']:
   a=int(f['address'],16)
   for j,v in enumerate(bytes.fromhex(f['bytes_hex'])):effective[a+j]=v
  check('all_recorded_image_regions_remain_exact',all(bytes.fromhex(r['bytes_hex'])==bytes(effective[int(r['address'],16)+j] for j in range(len(bytes.fromhex(r['bytes_hex'])))) for r in row['final_image_globals']))
 # Stack scratch contains source frames. All nonstack private bytes remain exact.
 check('entire_nonstack_private_RAM_matches_independent_oracle',after[:SP-P-1024]==before[:SP-P-1024] and after[SP-P+1024:]==before[SP-P+1024:])
 return checks
