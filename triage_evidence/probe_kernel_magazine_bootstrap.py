#!/usr/bin/env python3
"""Capacity policy, original dynamic zone creation and cache installation.
O(visits + private RAM + journals) time/space. String/storage/lock/PAC models
are explicit; no native boot, allocator, synchronization or IPC executes.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_rpc502_vm_handoff import compressed,decode
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
import recover_kernel_magazine_bootstrap as R
THREAD=P+0x10000;CACHE=P+0x20000;MAGAZINES=P+0x60000;STATS=P+0x88000;ZONE=R.ARRAY+24*192

def policies():
 rows=[{'last_cpu':last,'feature':flag,'boot_text':''} for last in [0,8,9,11,0xfffffffe,0xffffffff] for flag in [0,1]]
 for text in ['other=1','zc_mag_size','zc_mag_size=16','zc_mag_size=0','zc_mag_size=garbage',
  'zc_mag_size=0xffff','zc_mag_size_extra=1','xzc_mag_size=1','-zc_mag_size',
  ' \tzc_mag_size=3 other=4','other=4 zc_mag_size=99','zc_mag_size=8 zc_mag_size=garbage']:
  rows.append({'last_cpu':11,'feature':1,'boot_text':text})
 rows.extend([{'last_cpu':0,'feature':1,'boot_text':'zc_mag_size=99','initial_capacity':k} for k in [0,16,4094,4095,65535]])
 return rows

class Probe(CPU):
 def __init__(self,im,mode,c,parent=None,mutate=None):
  super().__init__(im,'selector',{'id':0});self.mode=mode;self.c=c;self.parent=parent;self.mutate=mutate
  self.initial=[];self.image_initial=[];self.regions=[];self.envelopes=[];self.leaves=[];self.magazines=[];self.create_entries=[]
  self.allowed=[(R.POLICY,0xfffffe000c6321a8),(R.BOOT,0xfffffe000c632708),(R.CREATE,0xfffffe000bd77b94),
   (R.CACHEINIT,0xfffffe000bd77ce4),(R.PARSER,0xfffffe000c5e4ca8),(R.NUMBER,0xfffffe000c5e4f88)]
  if parent is not None:
   self.u.mem_write(P,decode(parent['final_private_RAM']))
   for row in parent['final_image_globals']:self.image_fixture(int(row['address'],16),bytes.fromhex(row['bytes_hex']),'Exact predecessor output transfer')
  if mode=='policy':
   self.entry=R.POLICY;self.image_fixture(0xfffffe0007ef8bf0,struct.pack('<I',c['last_cpu']),'Declared maximum-index input')
   self.image_fixture(0xfffffe000cb29cb4,struct.pack('<I',c['feature']),'Declared policy feature word')
   self.image_fixture(R.CAP,struct.pack('<H',c.get('initial_capacity',8)),'Original file default8 or explicit controlled entry epoch')
   self.image_fixture(R.COUNT,bytes(4),'Declared pre-policy count word')
   self.image_fixture(0xfffffe0007f8b6e8,struct.pack('<Q',P+0x8000),'Declared readable boot-input structure')
   self.fixture(P+0x806c,c['boot_text'].encode()+bytes(1))
  elif mode=='publish':
   self.entry=0xfffffe000c6325ec
   for a,b,why in [(R.MAGZONE,bytes(192),'Declared fresh dynamic slot40'),(0xfffffe000caeb45a,struct.pack('<H',40),'Declared reserved fixed-slot count40'),
    (0xfffffe000cb7f2c8,bytes(2),'Declared created-zone count0'),(0xfffffe0007f8b5f0,bytes(4),'Declared phase0 preserves original name'),
    (0xfffffe000caeb600,struct.pack('<Q',0xfffffe000caeb600),'Declared ready slot2 statistics allocator'),
    (0xfffffe0007e6a840,bytes(4),'Declared selected zone40 security metadata'),(R.VIEW,bytes(8),'Declared unpublished magazine view')]:self.image_fixture(a,b,why)
  else:
   assert mode=='cache';self.entry=R.CACHEINIT
   zone=bytearray(192);struct.pack_into('<QQ',zone,0,ZONE,P+0x90000);struct.pack_into('<H',zone,0x34,256)
   self.image_fixture(ZONE,zone,'Declared source-compatible IPC zone geometry for a new cache-initialization epoch')
   self.image_fixture(0xfffffe0007e66e38,struct.pack('<I',0x100000),'Declared cache budget')
   self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD);self.fixture(THREAD+0x1b8,bytes(2));self.fixture(THREAD+0x1c8,bytes(4))
   self.set(0,ZONE)
  self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  for j in range(31):self.set(j,0x2020202000000000+j)
  if mode=='cache':self.set(0,ZONE)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.before=bytes(self.u.mem_read(P,SIZE))
  if mutate is not None:self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def image_fixture(self,a,b,why):
  self.ensure(a,len(b));self.u.mem_write(a,bytes(b));self.image_initial.append({'address':hex(a),'bytes_hex':bytes(b).hex(),'provenance':why});self.regions.append((a,len(b)))
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or any(lo<=a<a+n<=lo+k for lo,k in self.regions),(hex(a),n)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def cstring(self,a):
  b=bytearray()
  for j in range(4096):
   self.ensure(a+j);x=bytes(self.u.mem_read(a+j,1))
   if x==bytes(1):return bytes(b)
   b+=x
  raise AssertionError('unterminated declared string')
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('cache_initializer_returned')
  if self.mode=='policy' and a in [0xfffffe000c6320f8,0xfffffe000c631ffc]:return self.stop('capacity_policy_prefix_complete')
  if self.mode=='publish' and a==0xfffffe000c632660:return self.stop('magazine_view_published_and_floor_updated')
  if a in [0xfffffe000c62a2b0,0xfffffe000c633e40]:return self.stop('before_creator_diagnostic')
  if a==R.CREATE:self.create_entries.append({'arguments5':[hex(self.reg(j)) for j in range(5)],'source_visit_index':len(self.visits)})
  if a in [0xfffffe000bc9dbf0,0xfffffe000bc9db70]:
   left=self.cstring(self.reg(0));right=self.cstring(self.reg(1)) if a==0xfffffe000bc9dbf0 else None
   if right is None:result=len(left)
   else:
    n=self.reg(2);l=(left+bytes(1))[:n];r=(right+bytes(1))[:n];result=(l>r)-(l<r)
   self.leaves.append({'pc':hex(a),'left_hex':left.hex(),'right_hex':right.hex() if right is not None else None,'return_u64':hex(result&((1<<64)-1))})
   return self.model(a,'declared_strncmp' if right is not None else 'declared_strlen',result&((1<<64)-1))
  if a==0xfffffe000bd71a20:
   assert self.reg(0)==0xfffffe000caeb600 and (self.reg(1),self.reg(2)) in [(32,7),(64,0x3f)]
   return self.model(a,'declared_zero_statistics_storage' if self.reg(1)==32 else 'declared_zero_percpu_cache_storage',STATS if self.reg(1)==32 else CACHE)
  if a==0xfffffe000bd75c64:
   assert self.mode=='cache' and [self.reg(j) for j in range(3)]==[R.MAGZONE,STATS,0x8004]
   extent=int.from_bytes(bytes(self.u.mem_read(R.MAGZONE+0x34,2)),'little');ptr=MAGAZINES+len(self.magazines)*extent
   assert bytes(self.u.mem_read(ptr,extent))==bytes(extent)
   self.magazines.append({'pointer':hex(ptr),'extent_bytes':extent});return self.model(a,'declared_zero_magazine_storage_matching_source_zone_extent',ptr)
  if a in [0xfffffe000bd0bfa4,0xfffffe000bd0c2cc,0xfffffe000bd0aab4,0xfffffe000bd0ab18]:return self.model(a,'declared_registry_or_zone_lock_no_RAM_effect',0)
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_uncaptured_bootstrap_code')
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4))
  i=next(self.image.k.cs.disasm(raw,a))
  if i.mnemonic in ['pacia','pacda','blraa']:
   row={'pc':hex(a),'mnemonic':i.mnemonic,'source_visit_index':len(self.visits),'registers31':[hex(self.reg(j)) for j in range(31)]};self.envelopes.append(row);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
   if i.mnemonic=='blraa':
    reg=i.op_str.split(',')[0];target=self.reg(int(reg[1:]));self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,target)
   else:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
   return
  if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=100000);self.flush()
  assert self.reason in ['capacity_policy_prefix_complete','magazine_view_published_and_floor_updated','cache_initializer_returned','before_creator_diagnostic'],self.boundary
  regions=list(dict.fromkeys(self.regions))
  return {'mode':self.mode,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':'0x0',
   'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,
   'initial_image_fixtures':self.image_initial,'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in regions],
   'private_system_registers':[{'register':'TPIDR_EL1','value':hex(THREAD)}] if self.mode=='cache' else [],
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,
   'logical_envelopes':self.envelopes,'string_leaf_inputs':self.leaves,'raw_magazine_returns':self.magazines,'creator_entries':self.create_entries,
   'boundary':self.boundary,'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,
   'capacity_u16':int.from_bytes(bytes(self.u.mem_read(R.CAP,2)),'little'),'cpu_count_u32':int.from_bytes(bytes(self.u.mem_read(R.COUNT,4)),'little'),
   'view_pointer_u64':int.from_bytes(bytes(self.u.mem_read(R.VIEW,8)),'little') if self.mode!='policy' else None,
   **{k:False for k in R.FALSE}}

def oracle(row,parent=None):
 mode=row['mode'];c=row['configuration'];before=decode(row['initial_private_RAM']);after=decode(row['final_private_RAM']);expected=bytearray(before);checks=[]
 initial={int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in row['initial_image_fixtures']}
 actual={int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in row['final_image_globals']};wanted=dict(initial)
 def put(a,n,v):
  b=(v&((1<<(8*n))-1)).to_bytes(n,'little')
  for at,old in list(wanted.items()):
   if at<=a<a+n<=at+len(old):z=bytearray(old);z[a-at:a-at+n]=b;wanted[at]=bytes(z);return
  raise AssertionError(('unowned expected image write',hex(a),n))
 def check(name,p):assert p,(name,c,mode);checks.append(name)
 if mode=='policy':
  count=(c['last_cpu']+1)&0xffffffff;present=any(token.split('=',1)[0]=='zc_mag_size' for token in c['boot_text'].split())
  capacity=c.get('initial_capacity',8) if present else 14 if count>=10 else 10 if c['feature'] else c.get('initial_capacity',8)
  put(R.COUNT,4,count);put(R.CAP,2,capacity)
  check('exact_source_policy_count_capacity',row['cpu_count_u32']==count and row['capacity_u16']==capacity)
  check('original_presence_parser_not_whole_return_model',all(m['symbol'] in ['declared_strncmp','declared_strlen'] for m in row['API_models']))
 elif mode=='publish':
  capacity=row['capacity_u16'];extent=16+8*capacity;admit=extent<=32768
  check('exact_creator_request',len(row['creator_entries'])==1 and [int(v,16) for v in row['creator_entries'][0]['arguments5']]==[0xfffffe000705354e,extent,0x2000000002000020,0xffff,0])
  check('creator_extent_admission',row['boundary']['kind']==('magazine_view_published_and_floor_updated' if admit else 'before_creator_diagnostic'))
  if admit:
   # All fields come from the source creator's declared fresh slot/phase.
   zone=bytearray(192);struct.pack_into('<QQQ',zone,0,R.MAGZONE,STATS,0xfffffe000705354e)
   multiplier=0xffffffff//extent+1;span=extent
   if (extent+7)&0x3ff8:
    span=16384
    if 16384%extent:
     p16=(16384%extent)*100//16384;p32=(32768%extent)*100//32768
     span=32768 if p16>p32 else 16384
     if extent>4096 and min(p16,p32)>(49152%extent)*100//49152:span=49152
   used=span//extent;tail=span%extent
   struct.pack_into('<QIHHHH',zone,0x28,multiplier,multiplier&0xffffffff,extent,tail,span>>14,used)
   struct.pack_into('<I',zone,0x3c,0x600);struct.pack_into('<I',zone,0x60,0x144);struct.pack_into('<I',zone,0x80,0x144);struct.pack_into('<I',zone,0x84,0xffffffff)
   struct.pack_into('<Q',zone,0x58,R.MAGZONE+0x50);floor=(row['cpu_count_u32']*2)&0xfffe;struct.pack_into('<I',zone,0xb0,floor)
   wanted[R.MAGZONE]=bytes(zone);put(0xfffffe000caeb45a,2,41);put(0xfffffe000cb7f2c8,2,1);put(R.VIEW,8,R.MAGZONE)
   # High flag61 republishes the original zero security class; bit5 sets zone flag0x200.
   check('source_created_magazine_view_and_extent',row['view_pointer_u64']==R.MAGZONE and actual[R.MAGZONE]==zone)
   check('source_capacity_unchanged_across_creator',parent is not None and row['capacity_u16']==parent['capacity_u16'])
 else:
  capacity=row['capacity_u16'];count=row['cpu_count_u32'];extent=16+8*capacity;zone=bytearray(initial[ZONE]);bound=min(0x100000//(capacity*256),32767) if capacity else 0
  struct.pack_into('<H',zone,0x7e,bound);struct.pack_into('<Q',zone,0x40,CACHE)
  wanted[ZONE]=bytes(zone)
  for j in range(count):
   cache=CACHE+(j<<14);current=MAGAZINES+(2*j)*extent;spare=current+extent
   struct.pack_into('<IHHQQIIQQ',expected,cache-P,0x144,0,0,current+16,spare+16,0,0,0,cache+0x20)
  check('two_source_typed_magazines_per_cpu',row['raw_magazine_returns']==[{'pointer':hex(MAGAZINES+j*extent),'extent_bytes':extent} for j in range(2*count)])
  check('source_created_view_retained_at_cache_requests',all([int(v,16) for v in m['arguments8'][:3]]==[R.MAGZONE,STATS,0x8004] for m in row['API_models'] if m['symbol'].startswith('declared_zero_magazine_storage')))
  check('source_capacity_unchanged_across_cache_initialization',parent is not None and row['capacity_u16']==parent['capacity_u16'])
  check('ordinary_cache_frame_and_GP_custody',int(row['boundary']['SP'],16)==SP and all(row['boundary']['registers31'][j]==row['entry_registers31'][j] for j in range(19,31)))
 check('all_image_regions_exact',actual==wanted)
 if mode!='policy':check('all_private_RAM_outside_stack_guard_exact',after[:SP-P-512]==expected[:SP-P-512] and after[SP-P+256:]==expected[SP-P+256:])
 else:check('policy_preserves_boot_input_and_nonstack_RAM',after[:SP-P-512]==before[:SP-P-512] and after[SP-P+256:]==before[SP-P+256:])
 return checks
