#!/usr/bin/env python3
"""Bulk return components and original-fill-produced slot-array handoffs.
O(visits + private RAM/journals) time/space. Original bulk/followup executes;
outer locking, wake builder, magazine zeroing/retirement and PAC are models.
"""
import json,struct
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_rpc502_vm_handoff import compressed,decode
from probe_kernel_zone_bitmap_release import Probe as Setup,ZONE,META,BITMAP,ELEMENT_PAGE,THREAD,STATS,G,MASK
from probe_kernel_zone_refill import Probe as FillProbe,CACHE as FILLCACHE,PAGE as FILLPAGE,BITMAP as FILLBITMAP,INDEX as FILLINDEX
import recover_kernel_magazine_bulk_return as R
ARRAY=P+0x90000;OTHER=P+0x94000;PAIR=P+0x95000;OTHER_STATS=P+0x96000;TABLE=P+0x70000

class Producer(FillProbe):
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000bd76294:return self.stop('before_refill_consumes_original_filled_slots')
  return super().code(u,a,n,d)

def produce(image,parent,used):
 src=json.loads(read(ROOT/'kernel_zone_refill_source.json'))
 row=Producer(image,{'mode':'page','used':used},src,parent).run()
 assert row['boundary']['kind']=='before_refill_consumes_original_filled_slots'
 ram=decode(row['final_private_RAM']);count=int.from_bytes(ram[FILLCACHE-P+4:FILLCACHE-P+6],'little')
 array=int.from_bytes(ram[FILLCACHE-P+8:FILLCACHE-P+16],'little')
 assert count==min(16,64-used)
 assert ram[array-P:array-P+count*8]==b''.join((FILLPAGE+(used+j)*256).to_bytes(8,'little') for j in range(count))
 assert int.from_bytes(ram[META-P+2:META-P+4],'little')==used+count
 assert int.from_bytes(bytes.fromhex(row['final_zone192_hex'])[0xa8:0xac],'little')==64-used-count
 bitmap=((1<<64)-1)^((1<<(used+count))-1)
 assert int.from_bytes(ram[FILLBITMAP-P:FILLBITMAP-P+8],'little')==bitmap
 z=bytes.fromhex(row['final_zone192_hex'])
 assert int.from_bytes(z[0x9c:0xa0],'little')==(FILLINDEX if used+count<64 else 0)
 if used+count==64:assert int.from_bytes(z[0xa0:0xa4],'little')==FILLINDEX
 row['produced_slot_array']={'address':hex(array),'count':count,'bytes_hex':ram[array-P:array-P+count*8].hex(),
  'before_fill_used':used,'before_fill_available':64-used,'before_fill_bitmap':hex(((1<<64)-1)^((1<<used)-1))}
 return row

def configurations():
 rows=[]
 for inline in [False,True]:
  for count,n in [(1,1),(2,1),(63,1),(64,1),(2,2),(32,16)]:rows.append({'inline':inline,'count':count,'n':n})
  for index,extent,n,count in [(31,256,2,32),(63,128,2,64),(127,128,1,128)]:
   rows.append({'inline':inline,'index':index,'extent':extent,'n':n,'count':count})
  rows.extend([{'inline':inline,'count':1,'n':1,'next':True,'dest':True},
   {'inline':inline,'count':1,'n':1,'prev':'metadata','next':True,'dest':True},
   {'inline':inline,'count':64,'n':2,'prev':'metadata','next':True,'dest':True},
   {'inline':inline,'count':2,'n':1,'followup':True},
   {'inline':inline,'count':0,'n':1},
   {'inline':inline,'count':2,'n':1,'already_set':True},
   {'inline':inline,'count':2,'n':0},
   {'inline':inline,'count':2,'n':1,'extended':True,'index':64}])
 for fault in ['range','zone','alignment']:rows.append({'fault':fault,'n':1,'count':2})
 for fault in ['next_backlink','prev_backlink','destination_backlink']:
  rows.append({'fault':fault,'n':1,'count':64,'next':True,'dest':True})
 for used in [16,63]:
  for mode in ['bulk','prefill']:rows.append({'producer_used':used,'mode':mode,'n':min(16,64-used),'count':used+min(16,64-used),'followup':mode=='bulk'})
 return rows

class Probe(Setup):
 def __init__(self,image,parent,c,producer=None,mutate=None):
  super().__init__(image,parent,c);self.c=c;self.producer=producer;self.external_effects=[];self.followups=[];self.bulk_entries=[]
  self.n=c.get('n',1);self.prefill=c.get('mode')=='prefill';self.array=ARRAY;self.zone=ZONE
  if producer is not None:
   self.u.mem_write(P,decode(producer['final_private_RAM']))
   for row in producer['final_image_globals']:
    a=int(row['address'],16);b=bytes.fromhex(row['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b)
   self.overlays=[]
   self.array=int(producer['produced_slot_array']['address'],16)
   self.val(FILLCACHE+4,2,0,'Declared ownership handoff: detach the source-filled current slots before bulk return')
   self.val(0xfffffe0007e66e50,8,FILLPAGE,'Declared bulk object range lower bound for original produced arena')
   self.val(0xfffffe0007e66e58,8,FILLPAGE+16384,'Declared bulk object range upper bound for original produced arena')
   flags=int.from_bytes(bytes(self.u.mem_read(ZONE+0x3c,4)),'little')
   self.val(ZONE+0x3c,4,flags|16 if c.get('followup') else flags&~16,'Declared followup bit for the new bulk-call epoch')
  else:
   pointers=[self.element+j*self.extent for j in range(self.n)]
   self.patch(self.array,b''.join(x.to_bytes(8,'little') for x in pointers),'Declared finite bulk slot array')
   capacity=(32768 if self.extended else 16384)//self.extent;selected=[self.index+j for j in range(self.n)]
   assert not selected or selected[-1]<capacity
   occupied=set(selected)
   for j in range(capacity):
    if len(occupied)>=min(c.get('count',2),capacity):break
    occupied.add(j)
   width=32 if c.get('inline') else 64
   for j in range((capacity+width-1)//width):
    bits=sum(1<<(b%width) for b in range(j*width,min(capacity,(j+1)*width)) if b not in occupied)
    if c.get('already_set') and self.index//width==j:bits|=1<<(self.index%width)
    at=META+16*j+4 if c.get('inline') else BITMAP+8*j
    self.val(at,width//8,bits,'Declared coherent free bits outside the supplied allocated slots')
   self.val(ZONE+0xa8,4,capacity-min(c.get('count',2),capacity),'Declared initial available-object count')
  self.val(0xfffffe0007f213e0,8,0,'Declared no observers for original followup traversal')
  self.val(0xfffffe0007e66df8,8,TABLE,'Declared wake-table root for original followup hash')
  self.val(0xfffffe0007e66e00,4,8,'Declared wake-table count')
  self.node=self.array-16
  if self.prefill:
   assert producer is not None
   self.val(self.node,8,0,'Declared single full magazine after ownership handoff')
   self.patch(ZONE+0x48,struct.pack('<IIQQ',1,0,self.node,self.node),'Declared shared full-magazine inventory handoff')
   self.val(ZONE+0x7c,2,0,'Declared prefill path bypasses per-CPU drain in this joined component')
   self.val(0xfffffe0007e6a248,2,self.n,'Declared coherent bulk capacity from the source-produced slot count')
   self.val(0xfffffe0007e66f58,8,PAIR,'Declared magazine-object retirement view')
   self.patch(PAIR,struct.pack('<QQ',OTHER,OTHER_STATS),'Declared distinct magazine allocation zone/accounting pair')
   self.val(OTHER+0x34,2,16+8*self.n,'Declared magazine extent matching its complete source-produced slot array')
  self.entry=R.PREFILL if self.prefill else R.BULK
  self.allowed=[(R.BULK,R.END),(R.FOLLOW,0xfffffe000bd75c64),(R.PREFILL,0xfffffe000bd7332c)]
  self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  for j in range(31):self.set(j,0x1010101000000000+j)
  for j,v in enumerate([ZONE] if self.prefill else [ZONE,self.n,self.array]):self.set(j,v)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j)) for j in range(31)]
  self.before=bytes(self.u.mem_read(P,SIZE));self.zone_before=bytes(self.u.mem_read(ZONE,192));self.mutate=mutate
  self.global_snapshot={hex(a):bytes(self.u.mem_read(a,n)).hex() for a,n in [(0xfffffe0007e66e50,16),(0xfffffe0007e66f00,8),(0xfffffe0007e66e70,8)]}
  if mutate is not None:self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def effect(self,a,b,why):
  old=bytes(self.u.mem_read(a,len(b)));self.u.mem_write(a,b)
  self.external_effects.append({'before_source_visit_index':len(self.visits),'address':hex(a),'before_hex':old.hex(),'after_hex':b.hex(),'reason':why,'native_effect_executed':False})
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('bulk_component_returned')
  if a in [0xfffffe000c633aa0,0xfffffe000c633728,0xfffffe000c633c7c,0xfffffe000c6338dc]:return self.stop('before_bulk_diagnostic')
  if a==R.BULK:self.bulk_entries.append({'arguments3':[hex(self.reg(j)) for j in range(3)],'before_source_visit_index':len(self.visits)})
  if a==R.FOLLOW:self.followups.append({'zone':hex(self.reg(0)),'before_source_visit_index':len(self.visits)})
  if a==0xfffffe000bd6e22c:return self.model(a,'declared_wake_wrapper_no_RAM_effect',0)
  if a==0xfffffe000bd0ae78:
   assert self.reg(0)==ZONE+0x60;return self.model(a,'declared_prefill_lock_no_RAM_effect',0)
  if a==0xfffffe000c6480c0:
   assert self.prefill and [self.reg(j) for j in range(2)]==[self.node,16+8*self.n]
   self.effect(self.node,bytes(16+8*self.n),'Declared magazine-object bzero semantic model');return self.model(a,'declared_magazine_bzero',0)
  if a==0xfffffe000bd74fcc:
   assert self.prefill and [self.reg(j) for j in range(4)]==[OTHER,OTHER_STATS,self.node,16+8*self.n]
   return self.model(a,'declared_magazine_object_retirement_no_RAM_effect',0xffffffff)
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_uncaptured_bulk_code')
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4))
  if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=50000);self.flush()
  assert self.reason in ['bulk_component_returned','before_bulk_diagnostic'],self.boundary
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_registers31':self.entry_regs,
   'array':hex(self.array),'node':hex(self.node),'initial_private_RAM':compressed(self.before),
   'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'initial_zone192_hex':self.zone_before.hex(),
   'final_zone192_hex':bytes(self.u.mem_read(ZONE,192)).hex(),'metadata_globals':self.global_snapshot,
   'source_producer':self.producer,'ownership_and_epoch_overlays':self.overlays,'source_visits':self.visits,
   'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'declared_model_RAM_writes':self.external_effects,
   'bulk_entries':self.bulk_entries,'followups':self.followups,'boundary':self.boundary,
   'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate is not None else None,**{n:False for n in R.FALSE}}

def oracle(row):
 c=row['configuration'];n=c.get('n',1);prefill=c.get('mode')=='prefill';array=int(row['array'],16);node=int(row['node'],16)
 before=decode(row['initial_private_RAM']);after=decode(row['final_private_RAM']);expected=bytearray(before)
 zone=bytearray.fromhex(row['initial_zone192_hex']);actual_zone=bytes.fromhex(row['final_zone192_hex']);checks=[]
 def data(a,k):
  return bytes(zone[a-ZONE:a-ZONE+k]) if ZONE<=a<a+k<=ZONE+192 else bytes(expected[a-P:a-P+k])
 def get(a,k=4):return int.from_bytes(data(a,k),'little')
 def put(a,k,v):
  b=(v&((1<<(8*k))-1)).to_bytes(k,'little')
  if ZONE<=a<a+k<=ZONE+192:zone[a-ZONE:a-ZONE+k]=b
  else:assert P<=a<a+k<=P+SIZE,(hex(a),k);expected[a-P:a-P+k]=b
 def check(name,p):assert p,(name,c);checks.append(name)
 glob=row['metadata_globals'];bounds=bytes.fromhex(glob['0xfffffe0007e66e50']);lo=int.from_bytes(bounds[:8],'little');hi=int.from_bytes(bounds[8:],'little')
 root=int.from_bytes(bytes.fromhex(glob['0xfffffe0007e66f00']),'little');bitmap=int.from_bytes(bytes.fromhex(glob['0xfffffe0007e66e70']),'little')
 if prefill:
  put(ZONE+0x48,4,0);put(ZONE+0x50,8,get(node,8));put(ZONE+0x58,8,ZONE+0x50)
  put(ZONE+0x64,4,0);put(node,8,0);put(ZONE+0x62,1,get(ZONE+0x62,1)+1)
 diagnostic=None;completed=0;followups=0;extent=get(ZONE+0x34,2)
 for j in range(n):
  pointer=get(array+j*8,8);put(array+j*8,8,0)
  if not lo<=pointer<hi:diagnostic=0xfffffe000c633aa0;break
  meta=(root+((pointer>>10)&0xffffffff0))&MASK;header=get(meta,2)
  if 0xfffffe000caeb480+(header&0x3ff)*192!=ZONE:diagnostic=0xfffffe000c633aa0;break
  disp=((pointer&0x3fff)-get(ZONE+0x36,2))&MASK
  if header&0xf000==0xe000:
   extra=get(meta+2,1);disp=(disp+(extra<<14))&MASK;meta=(meta-16*extra)&MASK
  product=(get(ZONE+0x28,8)*disp)&MASK;index=product>>32
  if (index&0xffffffff)*extent!=disp:diagnostic=0xfffffe000c633aa0;break
  header=get(meta,2);inline=bool(header&0x800);width=4 if inline else 8
  at=meta+(product>>37)*16+4 if inline else bitmap+(get(meta+4)&0xfffffff)*8+(product>>38)*8
  mask=1<<(index&(31 if inline else 63));word=get(at,width)
  if word&mask:diagnostic=0xfffffe000c633c7c;break
  put(at,width,word|mask);count=get(meta+2,2);put(meta+2,2,count-1)
  if count==0:diagnostic=0xfffffe000c6338dc;break
  dest=ZONE+0x98 if count==1 else ZONE+0x9c if extent*((count&0x7fff)+1)>((header<<2)&0x3c000) else None
  if dest is not None:
   ident=(((meta-root)&MASK)>>4)&0xffffffff;nextid=get(meta+8);previd=get(meta+12)
   if nextid:
    following=(root+nextid*16)&MASK
    if get(following+12)!=ident:diagnostic=0xfffffe000c633728;break
    put(following+12,4,previd)
   predecessor=(G-4+previd*4)&MASK if 0<previd<0x80000000 else (root+previd*16+8)&MASK
   if get(predecessor)!=ident:diagnostic=0xfffffe000c633728;break
   put(predecessor,4,nextid);put(meta+8,8,0);head=get(dest);put(meta+8,4,head)
   sentinel=(dest-G+4)//4
   if head:
    first=(root+head*16)&MASK
    if get(first+12)!=sentinel:diagnostic=0xfffffe000c633728;break
    put(first+12,4,ident)
   put(meta+12,4,sentinel);put(dest,4,ident)
   if count==1:put(ZONE+0x90,4,get(ZONE+0x90)+(header>>12))
  if get(ZONE+0x3c)&16:
   followups+=1;put(ZONE+0x3c,4,get(ZONE+0x3c)&~16)
  completed+=1
 if diagnostic is None:
  put(ZONE+0xa8,4,get(ZONE+0xa8)+n)
  if prefill:
   for j in range(16+8*n):put(node+j,1,0)
 check('exact_return_or_partial_diagnostic',row['boundary']['kind']=='bulk_component_returned' if diagnostic is None else row['boundary']['kind']=='before_bulk_diagnostic' and int(row['boundary']['pc'],16)==diagnostic)
 check('original_bulk_entry_arguments',len(row['bulk_entries'])==1 and [int(v,16) for v in row['bulk_entries'][0]['arguments3']]==[ZONE,n,array])
 check('source_followup_count_and_zone',len(row['followups'])==followups and all(int(x['zone'],16)==ZONE for x in row['followups']))
 event=ZONE+32;a=((event^(event>>31))*0x7fb5d329728ea185)&MASK;b=((a^(a>>27))*0x81dadef4bc2dd44d)&MASK
 queue=TABLE+((b^(b>>33))&7)*24;wake=[m for m in row['API_models'] if m['symbol']=='declared_wake_wrapper_no_RAM_effect']
 check('original_followup_hash_and_wake_request_ABI',len(wake)==followups and all([int(v,16) for v in m['arguments8'][:5]]==[queue,event,0,0,0xffffffff] for m in wake))
 check('whole_zone192_exact',actual_zone==zone)
 stack_lo,stack_hi=SP-P-512,SP-P+256
 check('all_private_RAM_outside_stack_guard_exact',after[:stack_lo]==expected[:stack_lo] and after[stack_hi:]==expected[stack_hi:])
 check('no_bulk_or_followup_return_model',all(m['symbol'] not in ['declared_node_preparation_no_RAM_effect','declared_followup_no_RAM_effect'] for m in row['API_models']))
 if diagnostic is None:
  check('ordinary_SP_and_saved_GPs',int(row['boundary']['SP'],16)==SP and all(row['boundary']['registers31'][j]==row['entry_registers31'][j] for j in [*range(19,30),30]))
  if prefill:check('prefill_source_progress_result',int(row['boundary']['registers31'][0],16)==1)
 if row['source_producer'] is not None:
  p=row['source_producer'];f=p['produced_slot_array'];count=int.from_bytes(after[META-P+2:META-P+4],'little')
  check('source_produced_slot_bytes_unchanged_at_bulk_admission',before[array-P:array-P+n*8].hex()==f['bytes_hex'])
  check('fill_bulk_used_count_roundtrip',count==f['before_fill_used'])
  check('fill_bulk_available_count_roundtrip',int.from_bytes(actual_zone[0xa8:0xac],'little')==f['before_fill_available'])
  # The original fill producer uses the external one-word bitmap at
  # its own recorded root; this is independent of the standalone fixture.
  check('fill_bulk_bitmap_roundtrip',int.from_bytes(after[bitmap-P:bitmap-P+8],'little')==int(f['before_fill_bitmap'],16))
  check('bulk_processed_exact_source_produced_count',completed==n)
 return checks
