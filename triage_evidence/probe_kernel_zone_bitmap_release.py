#!/usr/bin/env python3
"""Private original-byte release/unlock components with a separate queue oracle.
O(source visits + RAM + journals) time/space. External calls do not modify RAM
in this declared model; PAC/AUT use logical identity, never native execution.
"""
import struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_rpc502_vm_handoff import compressed,decode
from probe_kernel_retirement_magazines import ZONE,CACHE,STATS,THREAD,PENDING
import recover_kernel_zone_bitmap_release as R
MASK=(1<<64)-1;G=0xfffffe000ca8c000;META=P+0xc0000;BITMAP=P+0xb8000
ELEMENT_PAGE=0xfffffe1000000000;NEXT=META+0x100;PREV=META+0x200;DEST=META+0x300

def configurations():
 out=[]
 for inline in [False,True]:
  for count in [1,2,63,64,0,0x8000]:
   for prev in ['sentinel','metadata']:
    out.append({'inline':inline,'count':count,'prev':prev,'next':count%2==0,'dest':count%2==1})
  for index,extent in [(31,256),(32,256),(63,256),(64,128),(127,128)]:
   out.append({'inline':inline,'index':index,'extent':extent,'count':2})
  for prev in ['sentinel','metadata']:
   out.append({'inline':inline,'count':64,'prev':prev,'next':False,'dest':True})
  out.append({'inline':inline,'count':64,'next':False,'dest':True,'fault':'destination_backlink'})
  out.extend([{'inline':inline,'extended':True,'index':64,'count':1,'next':True,'dest':True},
   {'inline':inline,'already_set':True}, {'inline':inline,'followup':True,'count':1},
   {'inline':inline,'nest':2}, {'inline':inline,'pending':4}, {'inline':inline,'nest':0}])
 for why in ['range','zone','alignment','next_backlink','prev_backlink','destination_backlink']:
  out.append({'fault':why,'count':1,'next':True,'dest':True})
 for c in [{'contended':True,'phase':0},{'contended':True,'phase':255},
  {'contended':True,'phase':0,'cache':True},{'contended':True,'phase':0,'limit':0},
  {'acquire_monitor':7,'unlock_monitor':9},{'entry':'retirement','nest':0},
  {'entry':'retirement','nest':0,'pending':4},{'entry':'helper_null','nest':0}]:out.append(c)
 return out

class Probe(CPU):
 def __init__(self,im,parent,c,mutate=None):
  super().__init__(im,'selector',{'id':0});self.kind=R.P;self.c=c;self.initial=[];self.image_initial=[];self.overlays=[];self.auth=[]
  self.entry=R.ENTRY if c.get('entry','release')=='release' else 0xfffffe000bd74fcc
  self.allowed=[(R.ENTRY,R.END),(R.UNLOCK,R.UNLOCK_END)]
  if self.entry!=R.ENTRY:self.allowed.append((0xfffffe000bd74fcc,R.ENTRY))
  self.transfer={'path':'kernel_zone_startup_profiles.json','case':7,**parent['final_private_RAM']}
  self.u.mem_write(P,decode(self.transfer))
  for row in parent['final_image_globals']:
   a=int(row['address'],16);b=bytes.fromhex(row['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append(dict(row))
  def patch(a,b,why):
   self.ensure(a,len(b));self.overlays.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why});self.u.mem_write(a,b)
  self.patch=patch
  def val(a,n,v,why):patch(a,(v&((1<<(8*n))-1)).to_bytes(n,'little'),why)
  self.val=val;self.extent=c.get('extent',256);self.index=c.get('index',3);self.extended=c.get('extended',False)
  assert self.index*self.extent//16384==(1 if self.extended else 0)
  self.element=ELEMENT_PAGE+self.index*self.extent+(1 if c.get('fault')=='alignment' else 0)
  self.root=(META-((ELEMENT_PAGE>>10)&0xffffffff0))&MASK
  self.ident=((META-self.root)&MASK)>>4;assert self.ident<2**32 and self.ident>=2**31
  self.ids={a:(((a-self.root)&MASK)>>4)&0xffffffff for a in [META,NEXT,PREV,DEST]}
  self.source_cell=ZONE+0x94;self.source_sentinel=(self.source_cell-G+4)//4
  self.dest_cell=ZONE+(0x98 if c.get('count',2)==1 else 0x9c);self.dest_sentinel=(self.dest_cell-G+4)//4
  self.next=self.ids[NEXT] if c.get('next') else 0
  self.prev=self.ids[PREV] if c.get('prev')=='metadata' else self.source_sentinel
  self.dest=self.ids[DEST] if c.get('dest') else 0
  patch(META-0x100,bytes(0x2000),'Declared private metadata arena in a new release epoch')
  header=24|(0x2000 if self.extended else 0x1000)|(0x800 if c.get('inline') else 0)
  self.header=header;val(META,2,header,'Declared ID24 leading metadata and bitmap layout')
  val(META+2,2,c.get('count',2),'Declared outstanding metadata count')
  val(META+4,4,0,'Declared external bitmap word-index0')
  val(META+8,4,self.next,'Declared source forward index')
  val(META+12,4,self.prev,'Declared source predecessor index or sentinel')
  if self.extended:val(META+16,4,(24|0xe000)|(1<<16),'Declared continuation metadata with one-page back-displacement')
  val(NEXT+12,4,self.ident+(1 if c.get('fault')=='next_backlink' else 0),'Declared next-node reciprocal source index')
  val(PREV+8,4,self.ident+(1 if c.get('fault')=='prev_backlink' else 0),'Declared previous-node reciprocal source index')
  val(self.source_cell,4,self.ident+(1 if c.get('fault')=='prev_backlink' and c.get('prev')!='metadata' else 0),'Declared old sentinel head')
  val(self.dest_cell,4,self.dest,'Declared destination queue head')
  val(DEST+12,4,self.dest_sentinel+(1 if c.get('fault')=='destination_backlink' else 0),'Declared destination reciprocal sentinel')
  val(ZONE+0x28,8,(0xffffffff//self.extent)+1,'Creator-equivalent u64 quotient multiplier')
  val(ZONE+0x30,4,(0xffffffff//self.extent)+1,'Creator-equivalent u32 displacement multiplier')
  val(ZONE+0x34,2,self.extent,'Declared element extent')
  val(ZONE+0x36,2,0,'Declared zero tail displacement')
  val(ZONE+0x3c,4,16 if c.get('followup') else 0,'Declared followup bit4')
  val(ZONE+0x40,8,CACHE if c.get('cache') or c.get('entry')=='helper_null' else 0,'Declared raw cache slot')
  val(ZONE+0x60,4,0,'Declared helper shared lock word')
  val(ZONE+0x48,24,0,'Declared empty helper shared depot')
  val(ZONE+0x7c,2,0,'Declared no local quota for helper-null path')
  val(ZONE+0x80,4,0x10000 if c.get('contended') else 0,'Declared release lock ticket/owner snapshot')
  val(ZONE+0x84,4,c.get('limit',2),'Declared event comparison limit')
  val(ZONE+0x8c,4,1,'Declared event comparison value')
  val(ZONE+0x74,4,0,'Declared event counter0')
  val(ZONE+0x90,4,7,'Declared empty-span counter7')
  val(ZONE+0xa8,4,0xffffffff,'Declared release event counter at modular boundary')
  val(0xfffffe0007e66e50,8,ELEMENT_PAGE+(32768 if c.get('fault')=='range' else 0),'Declared lower point bound')
  val(0xfffffe0007e66e58,8,ELEMENT_PAGE+65536,'Declared upper point bound')
  val(0xfffffe0007e66f00,8,self.root,'Declared biased metadata root')
  val(0xfffffe0007e66e70,8,BITMAP,'Declared external bitmap root')
  if c.get('fault')=='zone':val(META,2,(header&~0x3ff)|25,'Declared mismatching zone header')
  val(0xfffffe000cb115b0,4,c.get('acquire_monitor',0),'Declared acquire monitor handle')
  val(0xfffffe000cb0bc50,4,c.get('unlock_monitor',0),'Declared release monitor handle')
  val(0xfffffe000ca92380,1,c.get('phase',0),'Declared phase byte')
  val(THREAD+0x1b8,2,0,'Declared CPU0')
  val(THREAD+0x1c0,8,PENDING,'Declared pending-object pointer')
  val(THREAD+0x1c8,4,c.get('nest',1),'Declared entry nesting')
  val(PENDING+0x4c,1,c.get('pending',0),'Declared pending bitfield')
  val(STATS+8,8,0,'Declared fresh extent accounting')
  patch(BITMAP,b'\xa5'*256,'Declared external bitmap backing')
  self.bit_width=32 if c.get('inline') else 64
  self.bit_address=(META+16*(self.index//32)+4) if c.get('inline') else BITMAP+8*(self.index//64)
  self.mask=1<<(self.index%self.bit_width);self.bit_before=0xaaaaaaaaaaaaaaaa&((1<<self.bit_width)-1)&~self.mask
  if c.get('already_set'):self.bit_before|=self.mask
  val(self.bit_address,self.bit_width//8,self.bit_before,'Declared selected bitmap word')
  if c.get('entry')=='helper_null':
   from probe_kernel_retirement_magazines import CAP,CAPADDR,CURRENT,CONSUMER
   val(CAPADDR,2,CAP,'Declared full helper magazine capacity')
   patch(CACHE+4,struct.pack('<HHQQ',CAP,CAP,CONSUMER+16,CURRENT+16),'Declared both-full magazines')
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  for j in range(31):self.set(j,0x1010101000000000+j)
  for j,value in enumerate([ZONE,self.element] if self.entry==R.ENTRY else [ZONE,STATS,self.element,self.extent]):self.set(j,value)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j)) for j in range(31)]
  self.initial_zone=bytes(self.u.mem_read(ZONE,192)).hex();self.mutate=mutate
  if mutate is not None:
   self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or ZONE<=a<a+n<=ZONE+192,(hex(a),n)
  row={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(row);self.pending.append(row)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('original_release_returned')
  if a==0xfffffe000be8663c:return self.stop('before_original_pending_continuation')
  if a in [0xfffffe000c633aa0,0xfffffe000c633728,0xfffffe000c633c7c,0xfffffe000c6338dc,0xfffffe000c63aec8]:return self.stop('before_original_diagnostic')
  if a==0xfffffe000bd75b54:
   assert self.reg(0)==ZONE;return self.model(a,'declared_followup_no_RAM_effect',0)
  if a==0xfffffe000bd0abac:
   assert self.reg(0)==ZONE+0x80 and self.reg(2)==0xfffffe0007e63658;return self.model(a,'declared_contention_no_RAM_effect',0)
  if a==0xfffffe000beda010:
   assert [self.reg(j) for j in range(6)]==[self.c.get('acquire_monitor',0),ZONE+0x80,0,0,0,0];return self.model(a,'declared_acquire_monitor_no_RAM_effect',0)
  if a==0xfffffe000bd0ab80:
   assert self.reg(0)==ZONE+0x80;return self.model(a,'declared_unlock_monitor_no_RAM_effect',0)
  if a==0xfffffe000bd75c64:
   assert self.c.get('entry')=='helper_null' and self.reg(2)==5;return self.model(a,'declared_raw_magazine_allocator_null',0)
  if not any(x<=a<z for x,z in self.allowed):return self.stop('before_uncaptured_code')
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4))
  ins=next(self.image.k.cs.disasm(raw,a))
  if ins.mnemonic=='autda':
   self.auth.append({'pc':hex(a),'raw_pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'assumed_identity':True})
   self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if a==self.mutate:
   self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=30000);self.flush()
  assert self.reason in ['original_release_returned','before_original_pending_continuation','before_original_diagnostic'],self.boundary
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,
   'initial_state_transfer':self.transfer,'initial_image_globals':self.image_initial,'overlays':self.overlays,
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,
   'logical_authentication':self.auth,'boundary':self.boundary,'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'initial_zone192_hex':self.initial_zone,'final_zone192_hex':bytes(self.u.mem_read(ZONE,192)).hex(),
   'fixture':{'root':hex(self.root),'metadata':hex(META),'element':hex(self.element),'index':self.index,'extent':self.extent,
    'header':self.header,'metadata_id':self.ident,'source_next':self.next,'source_prev':self.prev,'destination_head':self.dest,
    'source_head_cell':hex(self.source_cell),'destination_head_cell':hex(self.dest_cell),'destination_sentinel':self.dest_sentinel,
    'bitmap_address':hex(self.bit_address),'bitmap_width':self.bit_width,'bitmap_before':hex(self.bit_before),'bitmap_mask':hex(self.mask),
    'neighbor_ids':{hex(a):v for a,v in self.ids.items()}},
   'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate is not None else None,**{n:False for n in R.FALSE}}

def oracle(row):
 c=row['configuration'];f=row['fixture'];ram=decode(row['final_private_RAM']);zone=bytes.fromhex(row['final_zone192_hex'])
 def data(a,n):return zone[a-ZONE:a-ZONE+n] if ZONE<=a<a+n<=ZONE+192 else ram[a-P:a-P+n]
 def u(a,n=4):return int.from_bytes(data(a,n),'little')
 checks=[]
 def check(name,p):assert p,(name,c);checks.append(name)
 count=c.get('count',2);fault=c.get('fault');bit_before=int(f['bitmap_before'],16);mask=int(f['bitmap_mask'],16);bit_addr=int(f['bitmap_address'],16)
 early=fault in ['range','zone','alignment'] or c.get('already_set')
 if early:diagnostic=0xfffffe000c633c7c if c.get('already_set') else 0xfffffe000c633aa0
 elif count==0:diagnostic=0xfffffe000c6338dc
 elif fault in ['next_backlink','prev_backlink','destination_backlink']:diagnostic=0xfffffe000c633728
 elif c.get('nest',1)==0 and c.get('entry','release')=='release':diagnostic=0xfffffe000c63aec8
 else:diagnostic=None
 check('exact_boundary',int(row['boundary']['pc'],16)==diagnostic if diagnostic else row['boundary']['kind']==('before_original_pending_continuation' if c.get('pending',0)&4 and c.get('nest',1)+(c.get('entry','release')!='release')==1 else 'original_release_returned'))
 check('bitmap_exact_word',u(bit_addr,f['bitmap_width']//8)==(bit_before if early else bit_before^mask))
 check('count_store_before_underflow_check',u(META+2,2)==(count if early else (count-1)&0xffff))
 transitioned=not early and count!=0 and (count==1 or f['extent']*((count&0x7fff)+1)>((f['header']<<2)&0x3c000))
 completed=diagnostic is None or diagnostic==0xfffffe000c63aec8
 if transitioned and completed:
  dest=int(f['destination_head_cell'],16);prev=f['source_prev'];ids=f['neighbor_ids'];nextid=f['source_next'];ident=f['metadata_id']
  check('old_predecessor_relinked',u(PREV+8 if c.get('prev')=='metadata' else int(f['source_head_cell'],16))==nextid)
  if nextid:check('old_successor_relinked',u(NEXT+12)==prev)
  check('new_head_is_metadata_id',u(dest)==ident)
  check('new_metadata_links',u(META+8)==f['destination_head'] and u(META+12)==f['destination_sentinel'])
  if f['destination_head']:check('destination_backlink_relinked',u(DEST+12)==ident)
 if completed:
  check('empty_span_counter',u(ZONE+0x90)==7+((f['header']>>12) if count==1 else 0))
  check('release_event_mod32',u(ZONE+0xa8)==0)
  check('owner_byte_increment_preserves_ticket',u(ZONE+0x80)==(0x1010000 if c.get('contended') else 0x1000000)+0x10000)
  initial=c.get('nest',1)+(c.get('entry','release')!='release')
  check('thread_nesting',u(THREAD+0x1c8)==(initial-1 if initial else 0))
  check('entry_extent_accounting',u(STATS+8,8)==(f['extent'] if c.get('entry','release')!='release' else 0))
  if diagnostic is None:
   check('SP_and_nonvolatile_GPs',int(row['boundary']['SP'],16)==SP and all(row['boundary']['registers31'][j]==row['entry_registers31'][j] for j in [19,20,21,22,29,30]))
  check('followup_request',sum(m['symbol']=='declared_followup_no_RAM_effect' for m in row['API_models'])==int(c.get('followup',False)))
 expected_event=int(c.get('contended',False) and c.get('phase',0)==0 and not c.get('cache',False) and c.get('limit',2)>1)
 check('contention_event_gate',u(ZONE+0x74)==expected_event)
 if diagnostic in [0xfffffe000c633aa0,0xfffffe000c633c7c]:check('diagnostic_zone_element_ABI',[int(x,16) for x in row['boundary']['registers31'][:2]]==[ZONE,int(f['element'],16)])
 if diagnostic==0xfffffe000c6338dc:check('underflow_diagnostic_ABI',[int(x,16) for x in row['boundary']['registers31'][:3]]==[ZONE,META,0xfffffe0007053a00])
 check('opaque_element_not_read_or_written',not any(ELEMENT_PAGE<=int(x['address'],16)<ELEMENT_PAGE+65536 for x in row['source_reads']+row['source_writes']))
 # Independently reconstruct every non-stack byte, including partial stores
 # before diagnostic requests. The saved stack is checked by ABI restoration
 # above; its transient spill contents are not a semantic output assertion.
 expected=bytearray(decode(row['initial_state_transfer']));ez=bytearray.fromhex(row['initial_zone192_hex'])
 for p in row['overlays']:
  a=int(p['address'],16);b=bytes.fromhex(p['after_hex'])
  if P<=a<a+len(b)<=P+SIZE:expected[a-P:a-P+len(b)]=b
 def put(a,n,v):
  buf,off=(ez,a-ZONE) if ZONE<=a<a+n<=ZONE+192 else (expected,a-P)
  buf[off:off+n]=(v&((1<<(n*8))-1)).to_bytes(n,'little')
 def get(a,n=4):
  buf,off=(ez,a-ZONE) if ZONE<=a<a+n<=ZONE+192 else (expected,a-P)
  return int.from_bytes(buf[off:off+n],'little')
 if c.get('entry','release')!='release':
  put(THREAD+0x1c8,4,c.get('nest',1)+1);put(STATS+8,8,f['extent'])
 if c.get('entry')=='helper_null':put(ZONE+0x60,4,0x1010000)
 put(ZONE+0x80,4,get(ZONE+0x80)+0x1000000);put(ZONE+0x74,4,expected_event)
 if not early:
  put(bit_addr,f['bitmap_width']//8,bit_before^mask);put(META+2,2,count-1)
  if transitioned:
   ids=f['neighbor_ids'];nextid=f['source_next'];prev=f['source_prev'];ident=f['metadata_id']
   if fault!='next_backlink':
    if nextid:put(NEXT+12,4,prev)
    if fault!='prev_backlink':
     put(PREV+8 if c.get('prev')=='metadata' else int(f['source_head_cell'],16),4,nextid)
     put(META+8,8,0);put(META+8,4,f['destination_head'])
     if fault!='destination_backlink':
      if f['destination_head']:put(DEST+12,4,ident)
      put(META+12,4,f['destination_sentinel']);put(int(f['destination_head_cell'],16),4,ident)
      if count==1:put(ZONE+0x90,4,7+(f['header']>>12))
 if completed:
  put(ZONE+0xa8,4,0);put(ZONE+0x82,1,get(ZONE+0x82,1)+1)
  nest=get(THREAD+0x1c8)
  if nest:put(THREAD+0x1c8,4,nest-1)
 stack_lo,stack_hi=SP-P-0x100,SP-P+0x100
 check('all_nonstack_private_RAM_exact',ram[:stack_lo]==expected[:stack_lo] and ram[stack_hi:]==expected[stack_hi:])
 check('entire_zone192_exact',zone==ez)
 return checks
