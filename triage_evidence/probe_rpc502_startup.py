#!/usr/bin/env python3
"""Original startup callback followed by RPC502 in the same guarded guest.

Entry45053c is an original registered startup callback,not a claim of complete
process startup. Declared malloc/entropy/time/opaque-lock outputs;no readiness,
parser PC,frame,register or branch intervention. Bounded quanta resume at the
current guest PC. Compressed per-quantum observer journals bound retained
working memory;guest image,heap,stack and logical API state are preserved.
No native target/API/IDB operation. O(B+V+E+S) time/space including stored
compressed journals;general observer journals reset per quantum. Inherited
specialized body/callback/store observers retain their bounded full sequence.
"""
import base64,copy,hashlib,json,struct,zlib
from pathlib import Path
from array import array
from probe_rpc502_body import BodyProbe,ROOT,SOURCE,IMAGE,ar,uc,STACK
from daemon_rpc502_probe import HALT

INIT=0x10045053c;READY=0x1010c5798;INIT_STATUS=0x1010b6360
POINTS={0x10046c750,0x100a03424,0x100a03450,0x100a5c3cc,0x100a5c3ec,0x1009757d0}

class StartupProbe(BodyProbe):
 def __init__(self,raw,fixture):
  self.startup_fixture=fixture;self.execution_phase='startup';self.init_returned=False;self.phase_chunks=[];self.startup_events=[];self.rng_calls=0;self.time_outputs=[];self.global_reads=[];self.startup_points=[];self.original_stage_owners={};self.quantum=fixture.get('quantum_instructions',500000);self.startup_snapshot=None
  assert 10000<=self.quantum<=2000000
  super().__init__(raw,fixture)
  self.u.emu_start=self.worker_start
 def model_event(self,name,**kw):
  self.steps+=1;event={'kind':'startup_declared_API_model','phase':self.execution_phase,'name':name,'site':hex(self.reg(30)-4),'return_pc':hex(self.reg(30)),'step':self.steps,'args':[hex(self.reg(j))for j in range(8)],'native_API_executed':False,**kw};self.records.append(event);return event
 def hook(self,u,a,n,d):
  self.flush();name=self.imports.get(a)
  if self.execution_phase=='startup'and a==HALT:
   self.steps+=1;self.init_returned=True;self.startup_events.append({'kind':'original_callback_return','step':self.steps,'LR_trampoline':hex(a),'return_X0_not_interpreted_as_void_status':hex(self.reg(0))});return self.stop('original_startup_callback_returned')
  if a in POINTS:
   sp=u.reg_read(ar.UC_ARM64_REG_SP);self.startup_points.append({'pc':hex(a),'phase':self.execution_phase,'step':self.steps,'sp':hex(sp),'registers':[hex(self.reg(j))for j in range(29)],'ready_hex':self.observe(READY,1),'init_status_hex':self.observe(INIT_STATUS,4),'frame_prefix450_hex':self.observe(sp,0x450)})
  if name=='libSystem/_malloc'and self.reg(0)>65536:
   size=self.reg(0);assert size<=0x400000 and len(self.heap_allocations)<32
   if self.startup_fixture.get('arena_malloc_NULL'):
    self.model_event(name,result='0x0',requested_size_bytes=size);return self.return_model(0)
   pages=(size+4095)&~4095;ptr=self.heap_next;self.heap_next+=pages+4096;u.mem_map(ptr,pages);u.mem_write(ptr,b'\xa5'*size);self.heap_allocations.append({'address':ptr,'size':size,'mapped':pages,'initialized':bytearray(size),'allocation_pc':self.reg(30)-4});self.model_event(name,result=hex(ptr),requested_size_bytes=size,initial_bytes='a5 poison;unwritten reads blocked');return self.return_model(ptr)
  if name=='libSystem/_arc4random':
   values=self.startup_fixture.get('arc4random_u32',[0x12345678,0x89abcdef,0xfedcba98]);assert values and all(0<=v<=0xffffffff for v in values);value=values[self.rng_calls%len(values)];self.rng_calls+=1;self.model_event(name,result_u32=hex(value),ordinal=self.rng_calls,sequence_wrap_explicit=self.rng_calls>len(values));return self.return_model(value)
  if name=='libSystem/_gettimeofday':
   p=self.reg(0);assert self.reg(1)==0;status=self.startup_fixture.get('gettimeofday_result',0);sec=self.startup_fixture.get('tv_sec',1760000000);usec=self.startup_fixture.get('tv_usec',123456);assert 0<=usec<1000000;event=self.model_event(name,result_signed32=status,output_pointer=hex(p),tv_sec=sec,tv_usec=usec,padding_not_written=True)
   record={'pointer':p,'known':bytearray(16),'phase':self.execution_phase,'reads':[]};self.time_outputs.append(record)
   if status==0:
    b=struct.pack('<qi',sec,usec);u.mem_write(p,b);record['known'][:12]=bytes([1])*12;event['declared_output_hex']=b.hex()
   return self.return_model(status)
  if name=='libSystem/_pthread_rwlock_init':
   p=self.reg(0);assert self.reg(1)==0;owner=next(v for v in self.heap_allocations if v['address']<=p and p+200<=v['address']+v['size']);off=p-owner['address'];status=self.startup_fixture.get('startup_rwlock_init_result',0);self.model_event(name,result_signed32=status,object_pointer=hex(p),object_extent_bytes=200,owner=hex(owner['address']),owner_extent_bytes=owner['size'],before_bytes_hex=self.observe(p,200),before_known_mask_hex=bytes(owner['initialized'][off:off+200]).hex(),opaque_native_bytes_not_synthesized=True);self.rwlocks[p]={'initialized':status==0,'readers':0,'writer':False};return self.return_model(status)
  return super().hook(u,a,n,d)
 def read_hook(self,u,access,a,n,value,d):
  if a<=READY<a+n:self.global_reads.append({'phase':self.execution_phase,'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'address':hex(a),'size_bytes':n,'bytes_hex':self.observe(a,n)})
  for obj in self.time_outputs:
   p=obj['pointer']
   if obj['phase']==self.execution_phase and a<p+16 and a+n>p:
    record={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'address':hex(a),'size_bytes':n,'bytes_hex':self.observe(a,n)};obj['reads'].append(record)
    if a<p or a+n>p+16 or not all(obj['known'][a-p:a-p+n]):return self.stop('unknown_timeval_output_read',**record)
  return super().read_hook(u,access,a,n,value,d)
 def write_hook(self,u,access,a,n,value,d):
  for obj in self.time_outputs:
   p=obj['pointer']
   if obj['phase']==self.execution_phase:
    lo=max(a,p);hi=min(a+n,p+16)
    if lo<hi:obj['known'][lo-p:hi-p]=bytes([1])*(hi-lo)
  return super().write_hook(u,access,a,n,value,d)
 def checkpoint(self,phase):
  self.flush();seq=array('Q',self.visit_pcs);assert seq.itemsize==8
  data={'phase':phase,'ordinal':len(self.phase_chunks),'steps_total':self.steps,'source_visit_count':len(seq),'ordered_source_bytes_sha256':self.source_hash.hexdigest(),'source_visits_zlib_base64':base64.b64encode(zlib.compress(seq.tobytes())).decode(),'records':self.records,'image_writes':self.writes,'stack_stores':self.stack_stores,'owner_stores':self.owner_stores,'original_fixup_reads':list(self.fixup_reads.values()),'PC_after_quantum':hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),'SP_after_quantum':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'registers_after_quantum':[hex(self.reg(j))for j in range(29)],'ready_hex':self.observe(READY,1),'status_hex':self.observe(INIT_STATUS,4),'stop_reason':self.stop_reason}
  raw=json.dumps(data,separators=(',',':')).encode();self.phase_chunks.append({'phase':phase,'source_visits':len(seq),'payload_zlib_base64':base64.b64encode(zlib.compress(raw)).decode()});self.visit_pcs=[];self.source_hash=hashlib.sha256();self.records=[];self.writes=[];self.stack_stores=[];self.owner_stores=[];self.fixup_reads={}
  print('QUANTUM',phase,len(self.phase_chunks),self.steps,len(seq),data['PC_after_quantum'],self.stop_reason,flush=True)
 def worker_start(self,begin,until,timeout=0,count=0):
  assert begin==0x100422d48 and count==200000 and timeout==0
  cap=self.startup_fixture.get('worker_instruction_budget',16000000);assert 0<cap<=64000000
  used=0
  while used<cap and self.stop_reason is None:
   quantum=min(self.quantum,cap-used)
   uc.Uc.emu_start(self.u,begin,until,count=quantum);used+=quantum
   if self.stop_reason is None and used<cap:self.checkpoint('worker');begin=self.u.reg_read(ar.UC_ARM64_REG_PC)
 def run(self):
  if self.startup_fixture.get('execute_startup',True):
   for j in range(8):self.setreg(j,0)
   self.setreg(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0x78000);begin=INIT;cap=self.startup_fixture.get('startup_instruction_budget',32000000);assert 0<cap<=64000000
   used=0
   while used<cap and self.stop_reason is None:
    quantum=min(self.quantum,cap-used)
    try:uc.Uc.emu_start(self.u,begin,0,count=quantum)
    except uc.UcError as e:self.stop_reason='unicorn_error';self.records.append({'kind':'engine_error','message':str(e),'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC))})
    used+=quantum;self.checkpoint('startup');begin=self.u.reg_read(ar.UC_ARM64_REG_PC)
   if not self.init_returned:
    self.stop_reason=self.stop_reason or'startup_instruction_budget';return self.snapshot_without_worker()
   self.stop_reason=None
   self.startup_snapshot={'heap_owners':[{'address':hex(e['address']),'size_bytes':e['size'],'allocation_pc':hex(e['allocation_pc']),'bytes_hex':self.observe(e['address'],e['size']),'known_mask_hex':bytes(e['initialized']).hex()}for e in self.heap_allocations],'descriptor_base':'0x1010b5ef0','descriptor60_hex':self.observe(0x1010b5ef0,0x60),'readiness_hex':self.observe(READY,1),'status_hex':self.observe(INIT_STATUS,4),'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP))}
   if int.from_bytes(self.u.mem_read(INIT_STATUS,4),'little')!=0x8b3dc651:
    self.stop_reason='startup_status_rejected';return self.snapshot_without_worker()
  self.startup_events.append({'kind':'worker_ABI_fixture_entry','step':self.steps,'ready_hex':self.observe(READY,1),'init_status_hex':self.observe(INIT_STATUS,4),'stack_carried_from_startup':True});self.execution_phase='worker'
  r=super().run();return self.finish(r)
 def snapshot_without_worker(self):
  self.flush();r={'steps':self.steps,'stop_reason':self.stop_reason,'records':self.records,'original_visit_count':len(self.visit_pcs),'original_ordered_bytes_sha256':self.source_hash.hexdigest(),'original_visits_zlib_base64':base64.b64encode(zlib.compress(array('Q',self.visit_pcs).tobytes())).decode(),'owner_stores':self.owner_stores,'original_fixup_reads':list(self.fixup_reads.values()),'native_target_executed':False,'target_host_ipc_files_or_system_calls_executed':False,'idb_mutated':False,'core_argument_calls':self.core_calls,'core_argument_reads':self.core_reads};return self.finish(r)
 def finish(self,r):
  owners=[{'address':hex(e['address']),'size_bytes':e['size'],'bytes_hex':self.observe(e['address'],e['size']),'known_mask_hex':bytes(e['initialized']).hex(),'allocation_pc':hex(e['allocation_pc'])}for e in self.heap_allocations];r.update(scope=__doc__,stack_initialization='Private stack initially zero-filled; original startup stores carried into worker; worker ABI argument slots explicitly seeded; observer bytes do not prove definedness.',generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),startup_fixture=self.startup_fixture,startup_returned=self.init_returned,startup_snapshot=self.startup_snapshot,startup_chunks=self.phase_chunks,startup_events=self.startup_events,readiness_reads=self.global_reads,readiness_points=self.startup_points,timeval_observations=[{**e,'pointer':hex(e['pointer']),'known':bytes(e['known']).hex()}for e in self.time_outputs],final_owned_regions=owners,final_readiness_hex=self.observe(READY,1),final_startup_status_hex=self.observe(INIT_STATUS,4),native_target_executed=False,full_goal_complete=False);return r
