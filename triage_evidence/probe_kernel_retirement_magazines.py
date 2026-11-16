#!/usr/bin/env python3
"""Execute original retirement/helper bytes in private CPU/RAM components.
O(source visits+RAM+journals) time/space; ordinary external calls have no RAM
effects by explicit model. PAC/AUT identity is logical, never native proof.
"""
import struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_rpc502_vm_handoff import compressed,decode
import recover_kernel_retirement_magazines as R

ZONE=0xfffffe000caec680;CACHE=P+0xb2000;STATS=P+0xb1000;THREAD=P+0x2c000
PENDING=P+0xb4000;ELEMENT=P+0xd0000;META=P+0xc0000
CURRENT=P+0x80000;CONSUMER=P+0x80400;NEW=P+0x80800;CLOCK=P+0x80c00
CAP=16;CAPADDR=0xfffffe0007e6a248
LF=[P+0x82000+0x100*i for i in range(8)];LE=[P+0x84000+0x100*i for i in range(8)]
SF=[P+0x86000+0x100*i for i in range(8)];SE=[P+0x88000+0x100*i for i in range(8)]

def configurations():
 return [
  {'se':1},{'se':2,'sf':2},{'se':2,'sf':2,'security12':True},
  {'allocation':True},{'allocation':False},
  {'quota':2,'le':1},{'quota':2,'lf':4,'le':1},
  {'quota':2,'se':2},{'quota':2,'lf':4,'sf':2,'se':4},
  {'quota':4,'lf':4,'sf':2,'se':4},
  {'quota':2,'allocation':True},{'quota':2,'allocation':False},
  {'quota':1,'lf':1,'se':1,'clock':True},
  {'quota':4,'lf':4,'sf':2,'se':4,'clock':True,'comparison':1},
  {'quota':4,'lf':4,'sf':2,'se':4,'clock':True,'comparison':0},
  {'quota':4,'lf':4,'sf':2,'se':4,'clock':True,'comparison':0xffffffff},
  {'quota':2,'lf':2,'sf':1,'se':2,'clock':True,'epoch':2**64-1},
  {'quota':2,'lf':2,'sf':1,'se':2,'clock':True,'epoch':5010},
  {'se':1,'contended':True,'phase':0},
  {'quota':2,'se':2,'contended':True,'phase':255},
  {'se':1,'monitor':7},{'se':1,'monitor':7,'drain':True},
  {'quota':2,'le':1,'monitor':7},
  {'quota':2,'allocation':True,'monitor':7,'contended':True},
  {'se':1,'clock':True,'clock_mark':36},
  {'quota':2,'se':2,'monitor':7},
  {'se':1,'security12':True}]

class Probe(CPU):
 def __init__(self,im,e,parent,c):
  super().__init__(im,'selector',{'id':0});self.kind=R.P;self.c=c;self.initial=[];self.image_initial=[]
  self.overlays=[];self.auth=[];self.frames=[];self.helper_returns=[];self.atomic=[]
  self.entry=0xfffffe000bd74fcc;self.allowed=[(self.entry,R.END)]
  self.transfer={'path':'kernel_zone_startup_profiles.json','case':7,**parent['final_private_RAM']}
  self.u.mem_write(P,decode(self.transfer))
  for row in parent['final_image_globals']:
   a=int(row['address'],16);b=bytes.fromhex(row['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b)
   self.image_initial.append(dict(row))
  def patch(a,b,why):
   self.ensure(a,len(b));self.overlays.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why});self.u.mem_write(a,b)
  self.patch=patch
  patch(CAPADDR,struct.pack('<H',CAP),'Declared coherent entry capacity16')
  patch(CACHE+4,struct.pack('<HHQQ',CAP,CAP,CONSUMER+16,CURRENT+16),'Declared both-full active consumer/producer magazines')
  self.start_lists={'local_full':LF[:c.get('lf',0)],'local_empty':LE[:c.get('le',0)],
   'shared_full':SF[:c.get('sf',0)],'shared_empty':SE[:c.get('se',0)]}
  self.markers={a:1000+i for i,a in enumerate(LF)}|{a:5000+i for i,a in enumerate(SF)}
  self.markers[CURRENT]=40
  for name,owner,off in [('local',CACHE,0x20),('shared',ZONE,0x50)]:
   full=self.start_lists[name+'_full'];empty=self.start_lists[name+'_empty'];nodes=full+empty
   for i,a in enumerate(nodes):patch(a,struct.pack('<QQ',nodes[i+1] if i+1<len(nodes) else 0,self.markers.get(a,0)), 'Declared distinct '+name+' inventory node')
   base=owner+(0x18 if name=='local' else 0x48)
   patch(base,struct.pack('<IIQQ',len(full),len(empty),nodes[0] if nodes else 0,full[-1] if full else owner+off),'Declared full-prefix/empty-suffix partition')
  for a,marker in [(CURRENT,40),(CONSUMER,80)]:
   raw=struct.pack('<QQ',0x1111222233334444,marker)+b''.join(struct.pack('<Q',ELEMENT+0x2000+256*i) for i in range(CAP))
   patch(a,raw,'Declared opaque active magazine entries; no native allocation identities')
  patch(NEW,b'\xa5'*(16+8*CAP),'Declared allocator-return storage, without an implicit zeroing effect')
  patch(CACHE+0x30,struct.pack('<Q',CLOCK if c.get('clock') else 0),'Declared optional sequence-marker object')
  patch(CLOCK,struct.pack('<QQ',c.get('epoch',0),c.get('clock_mark',0)),'Declared marker object fields')
  patch(ZONE+0x7c,struct.pack('<H',c.get('quota',0)),'Declared active local quota')
  patch(ZONE+0x60,struct.pack('<I',0x10000 if c.get('contended') else 0),'Declared shared lock-word snapshot')
  patch(ZONE+0x6c,struct.pack('<I',100),'Declared empty-depot low-water sample')
  patch(ZONE+0x3c,struct.pack('<I',16 if c.get('drain') else 0),'Declared zone followup bit4')
  patch(ZONE+0x74,bytes(4),'Declared event-counter snapshot0')
  patch(ZONE+0x84,struct.pack('<I',2),'Declared zone comparison bound2')
  patch(ZONE+0x8c,struct.pack('<I',1),'Declared zone comparison current1')
  patch(0xfffffe0007e6a7a0+4*24,struct.pack('<I',(1<<12) if c.get('security12') else 0),'Declared zone-security entry')
  patch(0xfffffe000cb0bc50,struct.pack('<I',c.get('monitor',0)),'Declared unlock-monitor handle')
  patch(0xfffffe000cb115b0,struct.pack('<I',c.get('monitor',0)),'Declared acquire-monitor handle')
  patch(0xfffffe000ca92380,bytes([c.get('phase',0)]),'Declared phase byte')
  patch(THREAD+0x1b8,bytes(2),'Declared CPU0')
  patch(THREAD+0x1c0,struct.pack('<Q',PENDING),'Declared pending pointer')
  patch(THREAD+0x1c8,bytes(4),'Declared fresh retirement nesting0')
  patch(PENDING,bytes(80),'Declared no pending continuation')
  patch(STATS,bytes(32),'Declared fresh retirement accounting')
  patch(ELEMENT,b'\x3c'*256,'Declared opaque element bytes, not a native allocation')
  patch(META,struct.pack('<HH',24,0)+bytes(12),'Declared coherent ID24 page metadata')
  patch(0xfffffe0007e66e50,struct.pack('<QQ',ELEMENT,ELEMENT+16384),'Declared point-admission interval')
  patch(0xfffffe0007e66f00,struct.pack('<Q',META-((ELEMENT>>10)&0xffffffff0)),'Declared biased metadata root')
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  for j in range(31):self.set(j,0x1010101000000000+j)
  for j,v in enumerate([ZONE,STATS,ELEMENT,256]):self.set(j,v)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j)) for j in range(31)]
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or ZONE<=a<a+n<=ZONE+192,(hex(a),n)
  row={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n}
  self.writes.append(row);self.pending.append(row)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('original_retirement_returned')
  if a==0xfffffe000bd756f8:return self.stop('before_original_deeper_release')
  if a in [0xfffffe000c6336f8,0xfffffe000c633aa0,0xfffffe000c63aec8]:return self.stop('before_original_error')
  if a==R.HELPER:self.frames.append({'source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j)) for j in range(4)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
  if a==0xfffffe000bd75150:self.helper_returns.append({'source_visit_index':len(self.visits),'X0':hex(self.reg(0)),'count_u16':int.from_bytes(bytes(u.mem_read(CACHE+6,2)),'little'),'slot_pointer':hex(int.from_bytes(bytes(u.mem_read(CACHE+16,8)),'little')),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
  if a in [0xfffffe000bd0ae78,0xfffffe000bd0ab80]:
   assert self.reg(0) in [CACHE,ZONE+0x60,ZONE+0x80]
   return self.model(a,'declared_lock_call_no_RAM_effect',0)
  if a==0xfffffe000bd0abac:
   assert self.reg(0)==ZONE+0x60 and self.reg(2)==0xfffffe0007e63658
   return self.model(a,'declared_contention_call_no_RAM_effect',0)
  if a==0xfffffe000beda010:
   assert [self.reg(j) for j in range(6)]==[self.c.get('monitor',0),ZONE+0x60,0,0,0,0]
   return self.model(a,'declared_instrumentation_call_no_RAM_effect',0)
  if a==0xfffffe000bd75b54:
   assert self.reg(0)==ZONE;return self.model(a,'declared_zone_followup_no_RAM_effect',0)
  if a==0xfffffe000bd37700:
   assert self.reg(0)==CLOCK and self.reg(4)==0
   return self.model(a,'declared_marker_comparison_no_RAM_effect',self.c.get('comparison',1))
  if a==0xfffffe000bd75c64:
   assert self.reg(30) in [0xfffffe000bd7545c,0xfffffe000bd7569c] and self.reg(2)==5
   view=int.from_bytes(bytes(u.mem_read(0xfffffe0007e66f58,8)),'little')
   assert [self.reg(j) for j in range(2)]==list(struct.unpack('<QQ',bytes(u.mem_read(view,16))))
   return self.model(a,'declared_raw_magazine_allocator_result',NEW if self.c.get('allocation',False) else 0)
  if not any(x<=a<z for x,z in self.allowed):return self.stop('before_uncaptured_code')
  raw=bytes(u.mem_read(a,4));ins=next(self.image.k.cs.disasm(raw,a))
  if ins.mnemonic=='autda':
   assert raw==self.image.k.read(a,4);self.auth.append({'pc':hex(a),'raw_pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'assumed_identity':True})
   self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=30000);self.flush();assert self.reason in ['original_retirement_returned','before_original_deeper_release'],self.boundary
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,
   'initial_state_transfer':self.transfer,'initial_image_globals':self.image_initial,'overlays':self.overlays,
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,
   'logical_data_authentication':self.auth,'helper_calls':self.frames,'helper_returns':self.helper_returns,
   'boundary':self.boundary,'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'final_zone192_hex':bytes(self.u.mem_read(ZONE,192)).hex(),'start_lists':self.start_lists,
   **{n:False for n in R.FALSE}}

def oracle(row):
 c=row['configuration'];q=c.get('quota',0);start={n:list(v) for n,v in row['start_lists'].items()}
 lf,le,sf,se=[start[n] for n in ['local_full','local_empty','shared_full','shared_empty']]
 low=100;marker=c.get('clock_mark',0);epoch=c.get('epoch',0);compared=False;comparison_arguments=None
 stamps={a:1000+i for i,a in enumerate(LF)}|{a:5000+i for i,a in enumerate(SF)}
 shared_entered=not q or not le
 def cas(value):
  nonlocal marker
  if marker==(value-4)&(2**64-1):marker=value
 if q:
  if not le:
   if len(lf)>=q:
    keep=0 if c.get('clock') else q//2;spill=lf[:len(lf)-keep];lf=lf[len(lf)-keep:]
    sf+=spill
    if c.get('clock'):
     cas(stamps[spill[-1]])
     if q!=1 and sf:
      delta=(stamps[sf[0]]-epoch)&(2**64-1);signed=delta if delta<2**63 else delta-2**64
      if signed>=1:compared=True;comparison_arguments=[CLOCK,stamps[sf[0]],epoch,marker,0]
      if signed<1 or c.get('comparison',1)!=0:
       take=q//2;assert len(sf)>=take;lf+=sf[:take];sf=sf[take:]
   take=min(q-len(lf),len(se));assert take>=0
   if take:le=se[:take];se=se[take:];low=min(low,len(se))
  new=le.pop(0) if le else NEW if c.get('allocation') else 0
  if new:lf.append(CURRENT)
 else:
  new=se.pop(0) if se else NEW if c.get('allocation') else 0
  if new:
   if new!=NEW:low=min(low,len(se))
   if c.get('clock'):cas(40)
   sf=([CURRENT]+sf) if c.get('security12') else (sf+[CURRENT])
 ram=decode(row['final_private_RAM']);zone=bytes.fromhex(row['final_zone192_hex'])
 def data(a,n):return zone[a-ZONE:a-ZONE+n] if ZONE<=a<a+n<=ZONE+192 else ram[a-P:a-P+n]
 def u(a,n=8):return int.from_bytes(data(a,n),'little')
 checks=[]
 def check(label,value):assert value,(label,c);checks.append(label)
 check('helper_request_ABI',len(row['helper_calls'])==1 and [int(x,16) for x in row['helper_calls'][0]['arguments4']]==[ZONE,CACHE,ELEMENT,256] and int(row['helper_calls'][0]['SP'],16)==SP-48)
 for full,empty,owner,base,head in [(lf,le,CACHE,0x18,0x20),(sf,se,ZONE,0x48,0x50)]:
  nodes=full+empty;check('inventory_counts_'+hex(owner),u(owner+base,4)==len(full) and u(owner+base+4,4)==len(empty))
  check('inventory_head_'+hex(owner),u(owner+head)==(nodes[0] if nodes else 0))
  check('inventory_boundary_'+hex(owner),u(owner+head+8)==(full[-1] if full else owner+head))
  for i,a in enumerate(nodes):check('next_'+hex(a),u(a)==(nodes[i+1] if i+1<len(nodes) else 0))
 check('returned_cache_or_zero',len(row['helper_returns'])==1 and int(row['helper_returns'][0]['X0'],16)==(CACHE if new else 0) and int(row['helper_returns'][0]['SP'],16)==SP-48)
 if new:
  check('helper_zeroes_producer_count',row['helper_returns'][0]['count_u16']==0)
  check('helper_installs_slot_array',int(row['helper_returns'][0]['slot_pointer'],16)==new+16)
  check('caller_publishes_one_pointer',u(CACHE+6,2)==1 and u(CACHE+16)==new+16 and u(new+16)==ELEMENT)
  check('new_header_second_word_zero',u(new+8)==0)
  check('header_first_word_provenance',u(new)==(0xa5a5a5a5a5a5a5a5 if new==NEW else 0))
  check('caller_frame_and_nonvolatile_restored',row['boundary']['kind']=='original_retirement_returned' and int(row['boundary']['SP'],16)==SP and all(row['boundary']['registers31'][j]==row['entry_registers31'][j] for j in range(19,31)))
 else:
  check('deeper_request_preserves_full_producer',u(CACHE+6,2)==CAP and u(CACHE+16)==CURRENT+16 and row['boundary']['kind']=='before_original_deeper_release' and list(map(lambda x:int(x,16),row['boundary']['registers31'][:2]))==[ZONE,ELEMENT] and int(row['boundary']['SP'],16)==SP)
 check('consumer_active_buffer_unchanged',u(CACHE+4,2)==CAP and u(CACHE+8)==CONSUMER+16)
 check('low_water_exact',u(ZONE+0x6c,4)==low)
 check('sequence_marker_CAS_exact',u(CLOCK+8)==marker)
 check('comparison_request_exact',sum(m['symbol']=='declared_marker_comparison_no_RAM_effect' for m in row['API_models'])==int(compared))
 if compared:
  model=next(m for m in row['API_models'] if m['symbol']=='declared_marker_comparison_no_RAM_effect')
  check('comparison_ABI_exact',[int(x,16) for x in model['arguments8'][:5]]==comparison_arguments)
 check('event_phase_exact',u(ZONE+0x74,4)==int(shared_entered and c.get('contended',False) and c.get('phase',0)==0))
 check('accounting_and_nesting',u(STATS+8)==256 and u(THREAD+0x1c8,4)==(0 if new else 1))
 check('opaque_element_bytes_preserved',data(ELEMENT,256)==b'\x3c'*256)
 return {'passed':checks,'new_producer_header':hex(new),'local_full':list(map(hex,lf)),'local_empty':list(map(hex,le)),
  'shared_full':list(map(hex,sf)),'shared_empty':list(map(hex,se)),'marker_compared':compared,'native_effects_established':False}
