#!/usr/bin/env python3
"""Original ready-page allocator and creator/cache storage joins.
O(visits + journals + mapped state) time/space. Ready metadata/backing and
locks are declared; no refill, native allocation, ownership or IPC occurs.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_kernel_magazine_bootstrap import Probe as Leaves,THREAD
from probe_rpc502_vm_handoff import compressed,decode
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
import recover_kernel_permanent_storage as R
import recover_kernel_magazine_bootstrap as M
PAGE=0xfffffe0007d00000;INDEX=(PAGE>>14)&0xffffffff;META=P+0x10000;METABASE=META-16*INDEX
STATS=P+0x50000;MAGAZINES=P+0x70000;IPC=M.ARRAY+24*192

def cases():
 return [dict(request=32,mask=7),dict(request=64,mask=63,cpu=2),dict(request=9,mask=5,offset=3,used=3),
  dict(request=(1<<64)-1,mask=7),dict(request=1,mask=0,offset=17,used=17),
  dict(request=64,mask=63,offset=16320,used=16320),
  dict(request=64,mask=63,offset=16320,used=16320,chain=True),
  dict(request=64,mask=63,offset=16320,used=16320,full_tail=True),
  dict(request=64,mask=63,offset=16380,used=16380,chain=True,second_offset=16320,second_used=16320),
  dict(request=32,mask=7,offset=16380,used=16380,chain=True,second_offset=3,second_used=3),
  dict(request=32,mask=7,empty=True),dict(request=64,mask=63,offset=16380,used=16380),
  dict(request=32,mask=7,free=0,statistics=(1<<64)-16)]

def signed32(v):return v-(1<<32) if v&(1<<31) else v
def head_code(offset):return ((R.ZONE+offset-R.HEADBASE+4)>>2)&0xffffffff

class Probe(Leaves):
 def __init__(self,image,mode,c,parent=None,mutate=None):
  CPU.__init__(self,image,'selector',{'id':0});self.mode=mode;self.c=c;self.parent=parent;self.mutate=mutate
  self.regions=[];self.envelopes=[];self.leaves=[];self.magazines=[];self.create_entries=[];self.events=[];self.allocations=[]
  self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in json.loads(read(ROOT/(R.P+'_checks.json')))['functions']]
  if parent is not None:
   self.u.mem_write(P,decode(parent['final_private_RAM']))
   for row in parent['final_image_globals']:
    a=int(row['address'],16);b=bytes.fromhex(row['bytes_hex'])
    if P<=a<a+len(b)<=P+SIZE:self.regions.append((a,len(b)))
    else:self.image_fixture(a,b,'Exact predecessor source output; declared new-call epoch')
  for j in range(31):self.set(j,0x2020202000000000+j)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  self.cpu=c.get('cpu',0);self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  self.fixture(THREAD+0x1b8,struct.pack('<H',self.cpu))
  if mode=='setup':
   self.entry=[R.SETUP1,R.SETUP2][c['setup']];self.setup_zone=M.ARRAY+192*(c['setup']+1)
   self.tracked(self.setup_zone,bytes((j*13+29)&255 for j in range(192)),'Declared callback destination with byte guards')
   self.set(0,R.RECORDS[c['setup']]);self.set(1,self.setup_zone)
  else:
   if parent is None:self.ready(c)
   if mode=='direct':self.entry=R.ALLOC;self.set(0,R.ZONE);self.set(1,c['request']);self.set(2,c['mask'])
   elif mode=='publish':
    self.entry=0xfffffe000c6325ec
    for a,b in [(M.MAGZONE,bytes(192)),(0xfffffe000caeb45a,struct.pack('<H',40)),(0xfffffe000cb7f2c8,bytes(2)),
     (0xfffffe0007f8b5f0,bytes(4)),(0xfffffe0007e6a840,bytes(4)),(M.VIEW,bytes(8))]:self.tracked(a,b,'Declared fresh magazine slot and creation epoch')
   else:
    assert mode=='cache' and parent is not None;self.entry=M.CACHEINIT
    zone=bytearray(192);struct.pack_into('<QQ',zone,0,IPC,P+0x90000);struct.pack_into('<H',zone,0x34,256)
    self.tracked(IPC,zone,'Declared IPC zone geometry; actual constructor outside this new-call join')
    self.tracked(0xfffffe0007e66e38,struct.pack('<I',0x100000),'Declared cache budget');self.set(0,IPC)
  self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.before=bytes(self.u.mem_read(P,SIZE))
  if mutate is not None:self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def tracked(self,a,b,why):
  if P<=a<a+len(b)<=P+SIZE:self.fixture(a,bytes(b));self.regions.append((a,len(b)))
  else:self.image_fixture(a,bytes(b),why)
 def ready(self,c):
  zone=bytearray(192);struct.pack_into('<QQ',zone,0,R.ZONE,STATS)
  struct.pack_into('<III',zone,0x9c,0 if c.get('empty') else INDEX,INDEX+2 if c.get('full_tail') else 0,0)
  struct.pack_into('<I',zone,0xa8,c.get('free',100000));self.tracked(R.ZONE,zone,'Declared ready slot2; native producer/refill not executed')
  meta=bytearray(bytes([0xa5])*16+bytes(48)+bytes([0x5a])*16)
  for j in range(3):
   used=c.get('used',0) if j==0 else c.get('second_used',0) if j==1 else 16384
   off=c.get('offset',0) if j==0 else c.get('second_offset',0) if j==1 else 16384
   nxt=INDEX+1 if j==0 and c.get('chain') else 0
   prev=head_code(0x9c) if j==0 else INDEX if j==1 else head_code(0xa0)
   struct.pack_into('<HHIII',meta,16+16*j,0x1234,used,off,nxt,prev)
  self.tracked(META-16,meta,'Declared16 B metadata records with guards and queue encodings')
  self.tracked(R.METABASE,struct.pack('<Q',METABASE),'Declared metadata translation base')
  for j in range(3):self.tracked(STATS+(j<<14),struct.pack('<QQ',c.get('statistics',0)+j,0x5544332211000000+j),'Declared per-CPU accounting and untouched guard')
  self.tracked(PAGE,bytes((j*17+41)&255 for j in range(3*16384)),'Declared nonzero raw backing; no native producer or zero-initialization premise')
  self.tracked(M.CAP,struct.pack('<H',c.get('capacity',8)),'Declared capacity; policy source established separately')
  self.tracked(M.COUNT,struct.pack('<I',c.get('count',1)),'Declared logical numbering bound')
 def word(self,a,n):return int.from_bytes(bytes(self.u.mem_read(a,n)),'little')
 def code(self,u,a,n,d):
  self.flush()
  if self.allocations and a==self.allocations[-1]['return_pc']:
   call=self.allocations.pop();self.events.append({'kind':'permanent_return','source_visit_index':len(self.visits),
    'pc':hex(a),'entry_event_index':call['event_index'],'result':hex(self.reg(0))})
  if a==HALT:return self.stop('original_function_returned')
  if a==R.REFILL:return self.stop('before_original_refill',{'arguments2':[hex(self.reg(j)) for j in range(2)]})
  if a in [0xfffffe000c633728,0xfffffe000c62a2b0,0xfffffe000c633e40]:return self.stop('before_original_diagnostic')
  if self.mode=='publish' and a==0xfffffe000c632660:return self.stop('source_view_publication_cut_complete')
  if a==R.ALLOC:
   event={'kind':'permanent_entry','source_visit_index':len(self.visits),'pc':hex(a),'arguments3':[hex(self.reg(j)) for j in range(3)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))}
   self.allocations.append({'return_pc':self.reg(30),'event_index':len(self.events)});self.events.append(event)
  if a==M.CREATE:self.create_entries.append({'arguments5':[hex(self.reg(j)) for j in range(5)],'source_visit_index':len(self.visits)})
  if a==0xfffffe000bd75c64:
   view=self.word(M.VIEW,8);st=self.word(view+8,8)
   assert [self.reg(j) for j in range(3)]==[view,st,0x8004]
   extent=self.word(view+0x34,2);ptr=MAGAZINES+len(self.magazines)*extent
   assert bytes(u.mem_read(ptr,extent))==bytes(extent)
   self.magazines.append({'pointer':hex(ptr),'extent_bytes':extent,'source_view':hex(view),'source_statistics':hex(st)})
   return self.model(a,'declared_zero_typed_magazine_storage',ptr)
  if a in [0xfffffe000bd0bfa4,0xfffffe000bd0c2cc,0xfffffe000bd0aab4,0xfffffe000bd0ab18]:return self.model(a,'declared_lock_no_RAM_effect',0)
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_uncaptured_code')
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4))
  i=next(self.image.k.cs.disasm(raw,a))
  if i.mnemonic in ['pacia','pacda','blraa']:
   self.envelopes.append({'pc':hex(a),'mnemonic':i.mnemonic,'source_visit_index':len(self.visits),'registers31':[hex(self.reg(j)) for j in range(31)]});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
   if i.mnemonic=='blraa':self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,self.reg(int(i.op_str.split(',')[0][1:])))
   else:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
   return
  if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush()
  assert self.reason in ['original_function_returned','before_original_refill','source_view_publication_cut_complete'],self.boundary
  return {'mode':self.mode,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':'0x0',
   'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,
   'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'private_system_registers':[{'register':'TPIDR_EL1','value':hex(THREAD)}],
   'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in dict.fromkeys(self.regions)],
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_envelopes':self.envelopes,
   'string_leaf_inputs':self.leaves,'permanent_events':self.events,'raw_magazine_returns':self.magazines,'creator_entries':self.create_entries,
   'boundary':self.boundary,'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,**{k:False for k in R.FALSE}}

def oracle(row,parent=None):
 c=row['configuration'];mode=row['mode'];regions={r['address'] for r in row['final_image_globals']}
 initial={int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in row['initial_private_fixtures']+row['initial_image_fixtures'] if r['address'] in regions}
 if parent:
  for r in parent['final_image_globals']:initial.setdefault(int(r['address'],16),bytes.fromhex(r['bytes_hex']))
 want=dict(initial);actual={int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in row['final_image_globals']};checks=[];mask64=(1<<64)-1
 def get(a,n):
  for lo,b in want.items():
   if lo<=a<a+n<=lo+len(b):return int.from_bytes(b[a-lo:a-lo+n],'little')
  raise AssertionError(('unowned oracle load',hex(a),n))
 def put(a,n,v):
  found=False
  for lo,b in list(want.items()):
   if lo<=a<a+n<=lo+len(b):out=bytearray(b);out[a-lo:a-lo+n]=(v&((1<<(8*n))-1)).to_bytes(n,'little');want[lo]=bytes(out);found=True
  assert found,('unowned oracle store',hex(a),n)
 def check(name,p):assert p,(name,mode,c);checks.append(name)
 def allocation(request,mask):
  size=(request+mask)&mask64&(~mask&mask64);index=get(R.ZONE+0x9c,4)
  while index:
   record=METABASE+16*index;off=get(record+4,4)
   if ((size+off)&mask64)<=16384:break
   index=get(record+8,4)
  if not index:return None
  aligned=((off+mask)&mask64)&(~mask&mask64);put(record+4,4,(aligned+size)&0xffff);used=(get(record+2,2)+size)&0xffff;put(record+2,2,used)
  put(R.ZONE+0xa8,4,get(R.ZONE+0xa8,4)-size);st=get(R.ZONE+8,8)+(c.get('cpu',0)<<14);put(st,8,get(st,8)+size)
  if used>=16376:
   next_index=get(record+8,4);previous=get(record+12,4)
   if next_index:put(METABASE+16*next_index+12,4,previous)
   if signed32(previous)>=1:previous_address=R.HEADBASE-4+4*previous
   else:previous_address=METABASE+16*previous+8
   put(previous_address,4,next_index)
   old=get(R.ZONE+0xa0,4);put(record+8,4,old)
   if old:put(METABASE+16*old+12,4,index)
   put(record+12,4,head_code(0xa0));put(R.ZONE+0xa0,4,index)
  return ((signed32(index)<<14)+(aligned&0xffff))&mask64
 expected_return=None
 if mode=='setup':
  zone=M.ARRAY+192*(c['setup']+1);put(zone+0x3c,4,get(zone+0x3c,4)|0x100);put(zone+0x34,2,1)
  check('setup_exact_flag_and_extent_with_all_guard_bytes',actual==want)
 elif mode=='direct':
  expected_return=allocation(c['request'],c['mask']);check('exact_ready_page_or_refill_boundary',row['boundary']['kind']==('before_original_refill' if expected_return is None else 'original_function_returned'))
  if expected_return is not None:check('signed_page_index_plus_aligned_low16_offset_return',int(row['boundary']['registers31'][0],16)==expected_return)
  check('exact_metadata_queue_accounting_and_all_guards',actual==want)
  check('ready_allocator_preserves_entire_nonzero_raw_payload',actual[PAGE]==initial[PAGE])
 elif mode=='publish':
  statistics=allocation(32,7);k=get(M.CAP,2);extent=16+8*k;zone=bytearray(192);struct.pack_into('<QQQ',zone,0,M.MAGZONE,statistics,0xfffffe000705354e)
  multiplier=0xffffffff//extent+1;span=16384
  if 16384%extent:
   p16=(16384%extent)*100//16384;p32=(32768%extent)*100//32768;span=32768 if p16>p32 else 16384
   if extent>4096 and min(p16,p32)>(49152%extent)*100//49152:span=49152
  struct.pack_into('<QIHHHH',zone,0x28,multiplier,multiplier&0xffffffff,extent,span%extent,span>>14,span//extent)
  for at,value in [(0x3c,0x600),(0x60,0x144),(0x80,0x144),(0x84,0xffffffff),(0xb0,(get(M.COUNT,4)*2)&0xfffe)]:struct.pack_into('<I',zone,at,value)
  struct.pack_into('<Q',zone,0x58,M.MAGZONE+0x50);want[M.MAGZONE]=bytes(zone);put(0xfffffe000caeb45a,2,41);put(0xfffffe000cb7f2c8,2,1);put(M.VIEW,8,M.MAGZONE)
  check('creator_uses_original_permanent_statistics_return',actual[M.MAGZONE]==zone)
  check('publication_preserves_entire_nonzero_raw_statistics_backing',actual[PAGE]==initial[PAGE])
 else:
  cache=allocation(64,63);k=get(M.CAP,2);count=get(M.COUNT,4);extent=16+8*k;bound=min(0x100000//(k*256),32767) if k else 0
  put(IPC+0x7e,2,bound);put(IPC+0x40,8,cache);put(IPC+0x78,4,0);put(IPC+0x70,8,0);put(IPC+0x6c,4,0)
  view=get(M.VIEW,8);statistics=get(view+8,8)
  for j in range(count):
   at=cache+(j<<14);current=MAGAZINES+2*j*extent;spare=current+extent
   for off,n,v in [(0,4,0x144),(8,8,current+16),(16,8,spare+16),(24,8,0),(32,8,0),(40,8,at+32)]:put(at+off,n,v)
  check('cache_publishes_source_permanent_return_and_exact_percpu_fields',actual[IPC]==want[IPC] and actual[PAGE]==want[PAGE])
  check('typed_magazine_requests_reuse_source_created_view_statistics_and_extent',row['raw_magazine_returns']==[{'pointer':hex(MAGAZINES+j*extent),'extent_bytes':extent,'source_view':hex(view),'source_statistics':hex(statistics)} for j in range(2*count)])
  check('statistics_payload_remains_nonzero_source_input',actual[PAGE][:32]==initial[PAGE][:32] and any(actual[PAGE][:32]))
  check('cache_magazine_counts_retain_nonzero_backing_in_every_CPU_slot',all(actual[PAGE][cache-PAGE+(j<<14)+4:cache-PAGE+(j<<14)+8]==initial[PAGE][cache-PAGE+(j<<14)+4:cache-PAGE+(j<<14)+8] and all(int.from_bytes(actual[PAGE][cache-PAGE+(j<<14)+off:cache-PAGE+(j<<14)+off+2],'little')!=0 for off in [4,6]) for j in range(count)))
  check('statistics_to_cache_alignment_gap_preserved',actual[PAGE][32:64]==initial[PAGE][32:64])
 check('all_recorded_regions_exact',actual==want)
 expected=bytearray(decode(row['initial_private_RAM']));after=decode(row['final_private_RAM'])
 for a,b in want.items():
  if P<=a<a+len(b)<=P+SIZE:expected[a-P:a-P+len(b)]=b
 check('whole_nonstack_private_RAM_exact',expected[:SP-P-1024]==after[:SP-P-1024] and expected[SP-P+256:]==after[SP-P+256:])
 if row['boundary']['kind']=='original_function_returned':check('original_SP_and_nonvolatile_GP_restored',int(row['boundary']['SP'],16)==SP and all(row['boundary']['registers31'][j]==row['entry_registers31'][j] for j in range(19,31)))
 entries=[e for e in row['permanent_events'] if e['kind']=='permanent_entry'];returns=[e for e in row['permanent_events'] if e['kind']=='permanent_return']
 check('permanent_body_is_source_not_API_model',not any(int(m['pc'],16)==R.ALLOC for m in row['API_models']))
 check('one_source_permanent_entry_per_storage_consumer',len(entries)==(0 if mode=='setup' else 1) and len(returns)==(0 if mode=='setup' or row['boundary']['kind']=='before_original_refill' else 1))
 return checks
