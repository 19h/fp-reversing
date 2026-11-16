#!/usr/bin/env python3
"""Continuous original refill cut with explicit page/pmap/lock leaf models.
O(visits + journals + mapped RAM) time/space. Virtual aliases are declared;
no native page ownership, mapping, exclusion or full-refill execution.
"""
import json,struct
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_kernel_physical_zero import Probe as Zero,THREAD
from probe_rpc502_vm_handoff import compressed,decode
import recover_kernel_refill_publication as R
import recover_kernel_physical_zero as Z
import recover_kernel_permanent_storage as PS
import recover_kernel_magazine_bootstrap as M
from probe_kernel_permanent_storage import PAGE,INDEX,META,METABASE,STATS,head_code
OBJECTS=P+0x60000;LEDGER=P+0x90000;REFSTATS=P+0xa0000;PHYSICAL=0x400000
MAPOBJ=0xfffffe000cb81140;TOTAL=0xfffffe000cadd728

def cases():
 return [dict(pages=n,cpu=n-1,capacity={1:8,2:10,3:14}[n],percpu=True,object_route=route,pmap_return=0) for n in [1,2,3] for route in ['interval','stored_PFN']]+[
  dict(pages=1,cpu=0,percpu=True,object_route='interval',pmap_return=0,retry=True),
  dict(pages=1,cpu=0,percpu=True,object_route='stored_PFN',pmap_return=5),
  dict(pages=3,cpu=2,percpu=False,object_route='interval',pmap_return=0)]

class Probe(Zero):
 def fixture(self,a,b):return CPU.fixture(self,a,bytes(b))
 def __init__(self,image,c,mutate=None):
  CPU.__init__(self,image,'selector',{'id':0});self.c={**c,'attribute':0};self.regions=[];self.mutate=mutate
  self.dcs=[];self.clear_entries=[];self.windows=0;self.initial=[];self.image_initial=[];self.events=[];self.acquired=0;self.pmap_calls=0
  self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in json.loads(read(ROOT/(R.P+'_checks.json')))['functions']]
  for j in range(31):self.set(j,0x4040404000000000+j)
  self.set(30,HALT);self.set(19,PS.ZONE);self.set(24,0);self.set(29,SP+0x1c0)
  self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0);self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  zone=bytearray(192);struct.pack_into('<QQ',zone,0,PS.ZONE,STATS);struct.pack_into('<HHH',zone,0x34,1,0,c['pages']);struct.pack_into('<I',zone,0x3c,0x140 if c['percpu'] else 0x100)
  self.image_fixture(PS.ZONE,zone,'Declared permanent slot2 with empty queues and no ready backing')
  self.image_fixture(PS.METABASE,struct.pack('<Q',METABASE),'Declared translation base for original metadata insertion')
  meta=bytearray(bytes([0xa5])*16+bytes([0x5a])*48+bytes([0xa5])*16);struct.pack_into('<H',meta,16,0x400)
  self.fixture(META-16,meta);self.regions.append((META-16,len(meta)))
  self.image_fixture(PAGE,bytes((j*17+41)&255 for j in range(49152)),'Declared nonzero physical-clear aliases and prospective permanent virtual storage; native equivalence unproved')
  objects=bytearray(192)
  for j in range(3):struct.pack_into('<I',objects,64*j+0x3c,(PHYSICAL>>14)+j)
  self.fixture(OBJECTS,objects);self.regions.append((OBJECTS,len(objects)))
  self.fixture(THREAD+0x1b8,struct.pack('<H',c['cpu']));self.fixture(THREAD+0x4e8,struct.pack('<Q',LEDGER))
  ledger=bytearray(64);struct.pack_into('<Q',ledger,0x18,97);self.fixture(LEDGER,ledger);self.regions.append((LEDGER,64))
  for j in range(3):
   self.fixture(STATS+(j<<14),bytes(16));self.regions.append((STATS+(j<<14),16))
   self.fixture(REFSTATS+(j<<14),struct.pack('<QQ',29+j,0xaabbccddeeff0011));self.regions.append((REFSTATS+(j<<14),16))
  low=OBJECTS if c['object_route']=='interval' else OBJECTS+0x1000
  fixtures=[(0xfffffe0007ef8e80,struct.pack('<Q',low)),(0xfffffe0007ef8e78,struct.pack('<Q',low+192)),
   (0xfffffe0007ef8000,struct.pack('<I',PHYSICAL>>14)),(Z.LOWER,struct.pack('<QQ',PHYSICAL,PHYSICAL+49152)),
   (MAPOBJ,bytes(128)),(0xfffffe000cb0bf88,bytes(1)),(0xfffffe0007e6a7a0+8,bytes(1)),
   (0xfffffe0007ef8fc0,struct.pack('<I',0x10)),(0xfffffe000caa5090,struct.pack('<Q',REFSTATS)),
   (TOTAL,struct.pack('<Q',123)),(M.CAP,struct.pack('<H',c.get('capacity',8))),
   (M.COUNT,struct.pack('<I',c.get('count',c['pages'])))]
  for a,b in fixtures:self.image_fixture(a,b,'Declared source-cut environmental input or guarded global')
  for off,b in [(0xd0,struct.pack('<QQ',PAGE,2)),(0xcc,struct.pack('<I',2)),(0xa4,struct.pack('<I',0x200)),
   (0xb0,bytes(4)),(0xb4,bytes(4)),(0x9c,struct.pack('<II',3,0)),(0xc0,struct.pack('<Q',THREAD))]:self.fixture(SP+off,b)
  self.entry=R.ENTRY;self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.before=bytes(self.u.mem_read(P,SIZE))
  if mutate is not None:self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def code(self,u,a,n,d):
  self.flush()
  if a==R.END:return self.stop('source_refill_metadata_publication_complete')
  if a==0xfffffe000be100ec:
   result=OBJECTS+64*self.acquired;self.acquired+=1;assert self.acquired<=self.c['pages'] and self.reg(0)==2
   return self.model(a,'declared_page_object_acquisition',result)
  if a==Z.DIRECT:return self.model(a,'declared_physical_clear_alias',PAGE+self.reg(0)-PHYSICAL)
  if a==R.PMAP:
   result=6 if self.c.get('retry') and self.pmap_calls==0 else self.c['pmap_return'];self.pmap_calls+=1
   ninth=bytes(u.mem_read(u.reg_read(ar.UC_ARM64_REG_SP),1))[0]
   self.model(a,'declared_lower_pmap_result_no_RAM_effect',result);self.models[-1]['argument9_byte']=ninth;return
  if a in [0xfffffe000be0d098,0xfffffe000be0f308,0xfffffe000be2f16c,0xfffffe000bde9b90,0xfffffe000bd0a630,0xfffffe000bd0aab4]:
   return self.model(a,'declared_page_list_or_lock_no_RAM_effect',0)
  if a in [Z.ZERO,R.CONSUME,R.MAP,R.INSERT,R.ACCOUNT]:self.events.append({'pc':hex(a),'source_visit_index':len(self.visits),
   'arguments8':[hex(self.reg(j)) for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
  return Zero.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=30000);self.flush();assert self.reason=='source_refill_metadata_publication_complete',self.boundary
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':'0x0',
   'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,
   'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'private_system_registers':[{'register':'TPIDR_EL1','value':hex(THREAD)}],
   'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in self.regions],
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,
   'logical_DC_ZVA_effects':self.dcs,'logical_DC_granule_bytes':64,'logical_envelopes':[],'string_leaf_inputs':[],
   'original_clear_entries':self.clear_entries,'original_publication_entries':self.events,'boundary':self.boundary,
   'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,**{k:False for k in R.FALSE}}

def oracle(row):
 c=row['configuration'];n=c['pages'];cpu=c['cpu'];checks=[]
 regions={r['address'] for r in row['final_image_globals']}
 want={int(r['address'],16):bytearray.fromhex(r['bytes_hex']) for r in row['initial_private_fixtures']+row['initial_image_fixtures'] if r['address'] in regions}
 private=bytearray(decode(row['initial_private_RAM']));after=decode(row['final_private_RAM'])
 def check(label,p):assert p,(label,c);checks.append(label)
 def putbytes(a,b):
  found=False
  for start,old in want.items():
   if start<=a<a+len(b)<=start+len(old):old[a-start:a-start+len(b)]=b;found=True
  assert found,('unowned oracle write',hex(a),len(b))
  if P<=a<a+len(b)<=P+SIZE:private[a-P:a-P+len(b)]=b
 def put(a,size,value):putbytes(a,(value&((1<<(8*size))-1)).to_bytes(size,'little'))
 putbytes(PAGE,bytes(n*16384))
 logical=1 if c['percpu'] else n
 putbytes(META,struct.pack('<HHIII',0x402|(logical<<12),0,0,0,head_code(0x9c)))
 for j in range(1,n):putbytes(META+16*j,struct.pack('<HBBIQ',0xf402 if c['percpu'] else 0xe402,j,n-j,0,0))
 for offset,value in [(0x9c,INDEX),(0xa8,logical*16384),(0xac,logical*16384),(0x8c,logical),(0x88,logical)]:put(PS.ZONE+offset,4,value)
 put(TOTAL,8,123+n);put(LEDGER+0x18,8,97+n);put(REFSTATS+(cpu<<14),8,29+cpu+n)
 for j in range(n):put(OBJECTS+j*64+0x2a,1,2);put(OBJECTS+j*64+0x2d,1,0x50)
 actual={int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in row['final_image_globals']}
 check('exact_metadata_ready_queue_all_counters_and_all_guarded_regions',actual==want)
 check('entire_nonstack_private_RAM_matches_independent_state_oracle',after[:SP-P-512]==private[:SP-P-512] and after[SP-P+512:]==private[SP-P+512:])
 def entries(pc):return [list(map(lambda x:int(x,16),r['arguments8'])) for r in row['original_publication_entries'] if int(r['pc'],16)==pc]
 check('original_zero_calls_cover_each_acquired_PFN_in_acquisition_order',[r[:2] for r in entries(Z.ZERO)]==[[PHYSICAL+j*16384,16384] for j in range(n)])
 check('original_list_consumer_receives_exact_LIFO_head_and_virtual_extent',[r[:8] for r in entries(R.CONSUME)]==[[MAPOBJ,PAGE,PAGE,n*16384,OBJECTS+(n-1)*64,0x200,12,3]])
 check('original_page_mapping_adapter_visits_reverse_object_order',[r[:7] for r in entries(R.MAP)]==[[MAPOBJ,PAGE,j*16384,OBJECTS+(n-1-j)*64,3,0,0x23] for j in range(n)])
 check('original_metadata_inserter_receives_exact_zero_old_count_and_new_pages',[r[:6] for r in entries(R.INSERT)]==[[PS.ZONE,PAGE,0,0,n,0]])
 check('original_accounting_helper_receives_ledger_flags_and_page_count',[r[:3] for r in entries(R.ACCOUNT)]==[[LEDGER,0x10,n]])
 models=[r for r in row['API_models'] if int(r['pc'],16)==R.PMAP];expected=[]
 for j in range(n):
  request=[0xfffffe000cb0bf18,PAGE+j*16384,PHYSICAL+(n-1-j)*16384,3,0,0,1,1]
  expected.append((request,6 if c.get('retry') and j==0 else c['pmap_return']))
  if c.get('retry') and j==0:expected.append((request[:7]+[0],c['pmap_return']))
 check('lower_pmap_exact_virtual_physical_arguments_attributes_and_retry_results',len(models)==len(expected) and all(list(map(lambda x:int(x,16),m['arguments8']))==args and int(m['return_value'],16)==result and m['argument9_byte']==0x23 for m,(args,result) in zip(models,expected)))
 check('all_payload_clears_execute_original_memset_without_DC_or_clear_return_model',len(row['original_clear_entries'])==n and all(int(e['pc'],16)==Z.MEMSET and [int(x,16) for x in e['arguments3']]==[PAGE+j*16384,0,16384] for j,e in enumerate(row['original_clear_entries'])) and not row['logical_DC_ZVA_effects'])
 check('selected_refill_cut_has_original_SP_at_metadata_publication_boundary',int(row['boundary']['SP'],16)==SP and row['boundary']['pc']==hex(R.END))
 return checks

def correspondence(row):
 zero=[e for e in row['original_publication_entries'] if int(e['pc'],16)==Z.ZERO];links=[]
 for m in row['API_models']:
  if int(m['pc'],16)!=R.PMAP:continue
  va,pa=map(lambda x:int(x,16),m['arguments8'][1:3]);matches=[e for e in zero if int(e['arguments8'][0],16)==pa]
  assert len(matches)==1 and matches[0]['source_visit_index']<m['before_source_visit_index']
  links.append({'lower_pmap_before_source_visit_index':m['before_source_visit_index'],'virtual_request':hex(va),'physical_request':hex(pa),
   'earlier_zero_source_visit_index':matches[0]['source_visit_index'],'declared_zero_alias':hex(PAGE+pa-PHYSICAL),'length_bytes':16384,
   'lower_pmap_return':m['return_value'],'native_mapping_effect_established':False})
 return links

def cache_oracle(row,parent):
 from probe_kernel_permanent_storage import IPC,MAGAZINES
 c=row['configuration'];cpu=c['cpu'];checks=[];private=bytearray(decode(row['initial_private_RAM']));after=decode(row['final_private_RAM'])
 regions={r['address'] for r in row['final_image_globals']}
 initial={int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in parent['final_image_globals']}
 initial.update({int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in row['initial_private_fixtures']+row['initial_image_fixtures'] if r['address'] in regions})
 want={a:bytearray(b) for a,b in initial.items()};actual={int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in row['final_image_globals']}
 def check(label,p):assert p,(label,c);checks.append(label)
 def get(a,n):return next(int.from_bytes(b[a-at:a-at+n],'little') for at,b in want.items() if at<=a<a+n<=at+len(b))
 def put(a,n,value):
  b=(value&((1<<(n*8))-1)).to_bytes(n,'little');found=False
  for at,old in want.items():
   if at<=a<a+n<=at+len(old):old[a-at:a-at+n]=b;found=True
  assert found,('unowned cache oracle write',hex(a),n)
  if P<=a<a+n<=P+SIZE:private[a-P:a-P+n]=b
 capacity=get(M.CAP,2);count=get(M.COUNT,4);extent=16+8*capacity;cache=PAGE+64
 put(META+4,4,128);put(META+2,2,96);put(PS.ZONE+0xa8,4,get(PS.ZONE+0xa8,4)-64);put(STATS+(cpu<<14),8,get(STATS+(cpu<<14),8)+64)
 for at,n,value in [(IPC+0x7e,2,min(0x100000//(capacity*256),32767)),(IPC+0x40,8,cache),(IPC+0x78,4,0),(IPC+0x70,8,0),(IPC+0x6c,4,0)]:put(at,n,value)
 for j in range(count):
  at=cache+(j<<14);current=MAGAZINES+2*j*extent;spare=current+extent
  for off,n,value in [(0,4,0x144),(8,8,current+16),(16,8,spare+16),(24,8,0),(32,8,0),(40,8,at+32)]:put(at+off,n,value)
 check('all_cache_metadata_statistics_and_guarded_region_bytes_exact',actual==want)
 check('all_nonstack_private_RAM_exact',after[:SP-P-1024]==private[:SP-P-1024] and after[SP-P+256:]==private[SP-P+256:])
 check('source_produced_statistics_payload_and_alignment_gap_remain_zero',actual[PAGE][:64]==bytes(64))
 check('both_magazine_counts_are_zero_in_every_source_initialized_CPU_slot',all(actual[PAGE][64+(j<<14)+4:64+(j<<14)+8]==bytes(4) for j in range(count)))
 check('source_typed_magazine_requests_use_published_view_and_zeroed_statistics',row['raw_magazine_returns']==[{'pointer':hex(MAGAZINES+j*extent),'extent_bytes':extent,'source_view':hex(M.MAGZONE),'source_statistics':hex(PAGE)} for j in range(2*count)])
 entries=[e for e in row['permanent_events'] if e['kind']=='permanent_entry'];returns=[e for e in row['permanent_events'] if e['kind']=='permanent_return']
 check('one_original_permanent_allocation_returns_PAGE_plus64',len(entries)==len(returns)==1 and int(returns[0]['result'],16)==cache and not any(int(m['pc'],16)==PS.ALLOC for m in row['API_models']))
 check('original_cache_SP_and_nonvolatile_GP_restored',int(row['boundary']['SP'],16)==SP and all(row['boundary']['registers31'][j]==row['entry_registers31'][j] for j in range(19,31)))
 return checks
