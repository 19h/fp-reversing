#!/usr/bin/env python3
"""Continuous original caller/policy/dispatcher/observer private execution.
O(visits + RAM + journals) time/space. Registered callbacks and boot helpers
return under explicit no-RAM models; their native bodies do not execute.
"""
import json,struct
from collections import Counter,defaultdict,deque
from hashlib import sha256
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_kernel_magazine_bootstrap import Probe as Leaves,THREAD
from probe_rpc502_vm_handoff import compressed,decode
from audit_startup_dispatch import machine,run
import recover_kernel_zone_boot_order as R
import recover_kernel_magazine_bootstrap as M
MEMORY=0xfffffe000cb29cb0;OUTPUT=0xfffffe000cae4dc0;INDIRECT=P+0xd0000

def sorted_table():
 e=json.loads(read(ROOT/'startup_dispatch_checks.json'));cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
 code={i.address:i for row in e['spans'] for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))}
 at=e['startup_section']['address'];raw=bytes.fromhex(e['logical_table_bytes_hex']);end=at+len(raw);v=machine(code)
 for j,b in enumerate(bytes([0xa5])*64+raw+bytes([0x5a])*64):v.memory[at-64+j]=b
 run(v,0xfffffe000c62f4e4,0xfffffe000c630240,8000000)
 out=bytes(v.memory[at+j] for j in range(len(raw)));chunks=lambda b:[b[j:j+24] for j in range(0,len(b),24)]
 assert Counter(chunks(raw))==Counter(chunks(out))
 keys=[struct.unpack_from('<II',b) for b in chunks(out)];assert keys==sorted(keys)
 assert bytes(v.memory[at-64+j] for j in range(64))==bytes([0xa5])*64 and bytes(v.memory[end+j] for j in range(64))==bytes([0x5a])*64
 source=defaultdict(deque)
 for row in e['records']:source[row['logical_bytes_hex']].append(row['address'])
 order=[]
 for j,b in enumerate(chunks(out)):
  phase,rank,callback,arg=struct.unpack('<IIQQ',b)
  order.append({'sorted_index':j,'cursor':hex(at+24*j),'original_record':source[b.hex()].popleft(),
   'phase32':phase,'rank32':rank,'callback':hex(callback),'argument':hex(arg)})
 return out,order,{'source_sort_visits':v.visits,'source_sort_calls':len(v.calls),'sorted_records':len(order),'sorted_table_sha256':sha256(out).hexdigest(),'sort_guard_bytes':128}

def cases():
 return [dict(last_cpu=0,boot_text='',memory_word=2<<30,descriptor_mode=0,rng='zero'),
  dict(last_cpu=1,boot_text='',memory_word=24<<30,descriptor_mode=1,rng='ones'),
  dict(last_cpu=9,boot_text='',memory_word=25<<30,descriptor_mode=0,rng='cycle'),
  dict(last_cpu=0,boot_text='zc_mag_size=16',memory_word=(1<<64)-1,descriptor_mode=1,rng='cycle'),
  dict(last_cpu=0xffffffff,boot_text='',memory_word=4<<30,descriptor_mode=0,rng='ones')]

def random_word(c,j):return 0 if c['rng']=='zero' else 0xffffffff if c['rng']=='ones' else (0xa5b6c700|((j-1)&7))

class Probe(Leaves):
 def __init__(self,image,c,table,order,mutate=None):
  CPU.__init__(self,image,'selector',{'id':0});self.mode='sequence';self.c=c;self.mutate=mutate;self.parent=None
  self.entry=R.CALLER;self.regions=[];self.envelopes=[];self.leaves=[];self.magazines=[];self.create_entries=[];self.events=[];self.rng=0;self.setups=0
  self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in json.loads(read(ROOT/(R.P+'_checks.json')))['functions'] if int(f['start'],16)!=M.BOOT]
  self.order=order;self.table_address=int(order[0]['cursor'],16);self.callback_targets={int(r['callback'],16) for r in order if r['phase32'] in [6,7]}
  first=next(r for r in order if r['phase32']>=6);self.initial_cursor=int(first['cursor'],16)
  count=(c['last_cpu']+1)&0xffffffff;assert count<=10
  for a,b,why in [
   (self.table_address,table,'Original source-sort output with logical format-8 targets'),
   (R.CURSOR,struct.pack('<Q',self.initial_cursor),'Declared already-completed sorted phase1..5 prefix'),
   (R.PHASE,struct.pack('<I',5),'Declared phase5 entry epoch'),(R.ANNOUNCED,struct.pack('<I',5),'Declared phase5 observer epoch'),
   (0xfffffe0007e64510,bytes(4),'Declared logging disabled'),
   (0xfffffe0007ef8bf0,struct.pack('<I',c['last_cpu']),'Declared maximum instance index'),
   (MEMORY,struct.pack('<Q',c['memory_word']),'One shared u64 input; policy consumes its high u32'),
   (OUTPUT,bytes([0x5a])*8,'Declared caller output sentinel'),(M.CAP,struct.pack('<H',8),'Original file-default capacity'),
   (M.COUNT,bytes(4),'Declared count before original policy'),(M.VIEW,bytes(8),'Declared unpublished view; callbacks are return models'),
   (0xfffffe0007f8b6e8,struct.pack('<Q',P+0x8000),'Declared boot-input structure'),
   (R.DESCRIPTORS-16,bytes((j*17+65)&255 for j in range(48*count+32)),'Descriptor input with 16-byte boundary guards'),
   (R.SECURITY,bytes((j*29+71)&255 for j in range(4*691)),'Metadata records0..690; only low u16 of1..689 may change'),
   (0xfffffe0007e6c9b8,struct.pack('<I',c['descriptor_mode']),'Explicit direct or indirect descriptor-helper mode'),
   (0xfffffe0007e6c9a8,struct.pack('<Q',INDIRECT),'Declared logical indirect helper; native target unknown'),
   (0xfffffe000cb88f48,struct.pack('<Q',P+0x11000),'Declared indirect helper context'),
   *[(a,bytes([0xa5])*128,'Callback-object input sentinel') for a,_,_ in R.OBJECTS]]:self.image_fixture(a,b,why)
  self.fixture(P+0x806c,c['boot_text'].encode()+bytes(1));self.fixture(THREAD+0x1b8,struct.pack('<H',max(count-1,0)))
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  for j in range(31):self.set(j,0x2020202000000000+j)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.before=bytes(self.u.mem_read(P,SIZE))
  if mutate is not None:self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def word(self,a,n):return int.from_bytes(bytes(self.u.mem_read(a,n)),'little')
 def event(self,kind,**extra):
  self.events.append({'kind':kind,'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits),
   'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'capacity_u16':self.word(M.CAP,2),'count_u32':self.word(M.COUNT,4),
   'phase_u32':self.word(R.PHASE,4),'cursor_u64':hex(self.word(R.CURSOR,8)),**extra})
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('original_startup_caller_returned')
  if a==M.POLICY:self.event('policy_entry')
  if a==0xfffffe000c634f20:self.event('policy_return')
  if a==R.DISPATCH:self.event('dispatch_entry',threshold_u32=self.reg(0)&0xffffffff)
  if a in [0xfffffe000c634fd4,0xfffffe000c635058]:self.event('dispatch_return')
  if a in self.callback_targets and self.reg(30)==0xfffffe000c630374:
   cursor=self.word(R.CURSOR,8);record=bytes(u.mem_read(cursor,24));phase,rank,target,arg=struct.unpack('<IIQQ',record)
   assert a==target and self.reg(0)==arg
   self.event('registered_callback',target=hex(a),argument=hex(arg),rank_u32=rank,record_phase_u32=phase)
   return self.model(a,'registered_callback_ordinary_return_no_RAM_effect',0)
  if a==0xfffffe000be577f0:
   value=random_word(self.c,self.rng+1);self.rng+=1;return self.model(a,'declared_metadata_word_source',value)
  if a in [0xfffffe000be57bec,INDIRECT]:
   ptr=R.DESCRIPTORS+48*self.setups;self.setups+=1
   if a==INDIRECT:assert [self.reg(j) for j in range(4)]==[P+0x11000,max(((self.c['last_cpu']+1)&0xffffffff)-1,0),16,ptr]
   else:assert [self.reg(j) for j in range(2)]==[ptr,16]
   return self.model(a,'declared_descriptor_helper_no_RAM_effect',0)
  if a in R.HELPERS:return self.model(a,'declared_'+R.HELPERS[a]+'_no_RAM_effect',0)
  return Leaves.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=200000);self.flush();assert self.reason=='original_startup_caller_returned',self.boundary
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':'0x0',
   'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,
   'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'private_system_registers':[{'register':'TPIDR_EL1','value':hex(THREAD)}],
   'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in self.regions],
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_envelopes':self.envelopes,
   'string_leaf_inputs':self.leaves,'sequence_events':self.events,'boundary':self.boundary,'initial_cursor':hex(self.initial_cursor),
   'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,**{k:False for k in R.FALSE}}

def oracle(row,order):
 c=row['configuration'];initial={int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in row['initial_image_fixtures']};wanted=dict(initial)
 actual={int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in row['final_image_globals']};checks=[]
 def check(name,value):assert value,(name,c);checks.append(name)
 def put(a,n,v):
  for base,b in list(wanted.items()):
   if base<=a<a+n<=base+len(b):
    out=bytearray(b);out[a-base:a-base+n]=(v&((1<<(8*n))-1)).to_bytes(n,'little');wanted[base]=bytes(out);return
  raise AssertionError(('unowned oracle write',hex(a),n))
 count=(c['last_cpu']+1)&0xffffffff;present=any(t.split('=',1)[0]=='zc_mag_size' for t in c['boot_text'].split())
 capacity=8 if present else 14 if count>=10 else 10 if c['memory_word']>>32 else 8
 put(M.COUNT,4,count);put(M.CAP,2,capacity)
 for j in range(count):
  at=R.DESCRIPTORS+48*j;put(at+0x10,4,0);put(at+0x18,8,0);put(at+0x20,8,17)
 check('descriptor_bytes_exact_including_guards_and_untouched_fields',actual[R.DESCRIPTORS-16]==wanted[R.DESCRIPTORS-16])
 for j in range(1,690):
  old=int.from_bytes(initial[R.SECURITY][4*j:4*j+2],'little');r=random_word(c,j)
  new=(old&0xdf00)|((r&1)<<13)|((old+((r&6)>>1))&0xff);put(R.SECURITY+4*j,2,new)
 check('all_689_metadata_low_halfwords_and_upper_halfword_guards_exact',actual[R.SECURITY]==wanted[R.SECURITY])
 for a,target,flags in R.OBJECTS:
  b=bytearray(128);struct.pack_into('<I',b,0x40,flags);struct.pack_into('<Q',b,0x58,target);wanted[a]=bytes(b)
  check('callback_object_'+hex(a)+'_all_128_bytes_exact',actual[a]==wanted[a])
 check('single_shared_u64_input_high_word_controls_small_count_capacity',int.from_bytes(actual[M.CAP],'little')==capacity and actual[MEMORY]==initial[MEMORY])
 v=c['memory_word'];q=v>>30;lo=q&0xffffffff;signed=lo-(1<<32) if lo&(1<<31) else lo
 factor=((35-lo)&0xffffffff) if signed<25 else 10
 product=(factor*v)&((1<<64)-1);output=(((product>>2)*0x28f5c28f5c28f5c3)>>64)>>2;put(OUTPUT,8,output)
 check('caller_sizing_arithmetic_exact_with_W_register_truncation_and_mul_wrap',actual[OUTPUT]==wanted[OUTPUT])
 eligible=[r for r in order if r['phase32'] in [6,7]];callbacks=[e for e in row['sequence_events'] if e['kind']=='registered_callback']
 check('exact_sorted_phase6_phase7_callback_cursors_targets_arguments',[(e['cursor_u64'],e['record_phase_u32'],e['rank_u32'],e['target'],e['argument']) for e in callbacks]==[(r['cursor'],r['phase32'],r['rank32'],r['callback'],r['argument']) for r in eligible])
 check('every_callback_observes_completed_policy_and_predecessor_phase',all(e['count_u32']==count and e['capacity_u16']==capacity and e['phase_u32']==e['record_phase_u32']-1 for e in callbacks))
 mag=next(e for e in callbacks if int(e['target'],16)==M.BOOT)
 specs=json.loads(read(ROOT/(R.P+'_checks.json')))['selected_IPC_specifications'];ipc={s['specification_address'] for s in specs}
 selected=[e for e in callbacks if e['argument'] in ipc]
 check('unique_magazine_registration_precedes_each_selected_IPC_registration',len(selected)==3 and all(mag['source_visit_index']<e['source_visit_index'] for e in selected))
 stages=[e['kind'] for e in row['sequence_events'] if e['kind']!='registered_callback']
 check('one_continuous_caller_policy_then_dispatch6_then_dispatch7',stages==['policy_entry','policy_return','dispatch_entry','dispatch_return','dispatch_entry','dispatch_return'] and [e['threshold_u32'] for e in row['sequence_events'] if e['kind']=='dispatch_entry']==[6,7])
 cursor=int(eligible[-1]['cursor'],16)+24;put(R.CURSOR,8,cursor);put(R.PHASE,4,7);put(R.ANNOUNCED,4,7)
 check('all_image_regions_exact',actual==wanted)
 before=decode(row['initial_private_RAM']);after=decode(row['final_private_RAM'])
 check('all_private_RAM_outside_explicit_stack_window_preserved',before[:SP-P-1024]==after[:SP-P-1024] and before[SP-P+256:]==after[SP-P+256:])
 check('caller_stack_and_nonvolatile_GP_restored',int(row['boundary']['SP'],16)==SP and all(row['boundary']['registers31'][j]==row['entry_registers31'][j] for j in range(19,31)))
 rng=[m for m in row['API_models'] if m['symbol']=='declared_metadata_word_source'];helpers=[m for m in row['API_models'] if m['symbol']=='declared_descriptor_helper_no_RAM_effect']
 check('exact_metadata_source_and_descriptor_helper_counts',len(rng)==689 and len(helpers)==count)
 return checks
