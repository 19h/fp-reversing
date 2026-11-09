#!/usr/bin/env python3
"""Private original-ISA CF Mach-port lifetime sequences and cleanup flag sweep.
Explicit component entries, allocator/CF collection/retention, lock/dispatch/Mach
results and logical PAC. No native target effects. O(V+J+H*R), O(S+J+R).
"""
import json,struct,hashlib,zlib,base64
import unicorn as U
from unicorn import arm64_const as A
from bootpolicy_cache_reader import CS
from recover_cf_mach_port_retirement import *
B=0x6800000000;RAM=0x40000;PORT=B+0x1000;CTX=B+0x2000;INFO=B+0x2800;SOURCE=B+0x3000;ARRAY=B+0x4000;RECORDS=B+0x4800;ALLOC=B+0x5000;MONITOR=B+0x8000;CANCEL_BLOCK=B+0x9000;EVENT_BLOCK=B+0xa000;TASK=B+0xb000;CANARY=B+0xb100;TYPE=B+0xc000;QUEUE=B+0xc100;HALT=B+0x100;RETAIN_INFO=B+0x110;RELEASE_INFO=B+0x120;INVALID_CB=B+0x130
def pack(a,b):return{'address':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'zlib_base64':base64.b64encode(zlib.compress(b,9)).decode()}
class Engine:
 def __init__(self,s,cfg):
  self.s=s;self.cfg=cfg;self.u=U.Uc(U.UC_ARCH_ARM64,U.UC_MODE_ARM);self.u.ctl_set_cpu_model(A.UC_CPU_ARM64_MAX);self.ins={int(i['ea'],16):i for f in s['functions']for i in f['instructions']};self.stubs={int(x['address'],16):x['exact_exports'][0]for x in s['stubs']};self.lower={int(x['address'],16):x['role']for x in s['boundaries']};self.pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in s['pages']};self.mutable=[]
  for a,b in self.pages.items():
   rw=a>=0x1ed890000 and a<0x1ed892000 or a==0x1e01c8000
   self.u.mem_map(a,4096,U.UC_PROT_ALL if rw else U.UC_PROT_READ|U.UC_PROT_EXEC);self.u.mem_write(a,b)
   if rw:self.mutable.append(a)
  self.u.mem_map(B,RAM);self.initial=[];self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.events=[];self.entries=[];self.frames=[];self.locks=set();self.registry=[];self.records={};self.allocs=0;self.cancel_block=None;self.event_block=None;self.created=False;self.action=None;self.phase_index=-1;self.current=None
  for a,b in[(0x1ed891742,b'\x02'),(0x1e01c88a8,struct.pack('<Q',CANARY)),(CANARY,struct.pack('<Q',0x123456789abcdef0)),(0x1e01c8b30,struct.pack('<Q',TASK)),(TASK,struct.pack('<I',0x103)),(0x1ed890e90,struct.pack('<Q',ARRAY)),(0x1ed890e30,b'\xff'*8),(0x1ed890e28,struct.pack('<Q',RECORDS)),(0x1ed890e08,b'\xff'*8),(0x1ed890e10,struct.pack('<Q',QUEUE)),(0x1e01c8738,struct.pack('<Q',TYPE)),(0x1e01c8888,struct.pack('<Q',B+0xd000)),(PORT+128,b'\xa5'),(CTX,struct.pack('<5Q',0,INFO if cfg.get('context')else 0,RETAIN_INFO if cfg.get('context')else 0,RELEASE_INFO if cfg.get('context')else 0,0)),(CTX+40,b'\xaa\xa5')]:self.fixture(a,b)
  if cfg.get('seed_object'):
   raw=bytearray(128);struct.pack_into('<Q',raw,8,0x2400|cfg.get('ownership',0));struct.pack_into('<II',raw,16,cfg.get('initial_state',0),cfg.get('name',0x303));self.fixture(PORT,raw)
   if cfg.get('registry_seed'):self.registry=[PORT]
  self.u.hook_add(U.UC_HOOK_CODE,self.code);self.u.hook_add(U.UC_HOOK_MEM_READ,self.read);self.u.hook_add(U.UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(U.UC_HOOK_MEM_INVALID,self.bad)
 def fixture(self,a,b):self.initial.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(a,bytes(b))
 def reg(self,j):return self.u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))
 def setreg(self,j,v):self.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v&0xffffffffffffffff)
 def frame(self):return{'pc':hex(self.u.reg_read(A.UC_ARM64_REG_PC)),'SP':hex(self.u.reg_read(A.UC_ARM64_REG_SP)),'NZCV':hex(self.u.reg_read(A.UC_ARM64_REG_NZCV)),'X31':[hex(self.reg(j))for j in range(31)],'Q32':[hex(self.u.reg_read(getattr(A,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]}
 def state(self):return{'object128_hex':bytes(self.u.mem_read(PORT,128)).hex(),'registry':[hex(v)for v in self.registry],'records':{hex(k):hex(v)for k,v in self.records.items()},'record_bytes':{hex(v):bytes(self.u.mem_read(v,8)).hex()for v in self.records.values()},'locks':[hex(v)for v in sorted(self.locks)],'cancel_block':hex(self.cancel_block)if self.cancel_block else None,'event_block':hex(self.event_block)if self.event_block else None}
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def read(self,u,access,a,n,v,d):self.reads.append({'visit':self.current,'address':hex(a),'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,access,a,n,v,d):
  e={'visit':self.current,'address':hex(a),'size_bytes':n,'before_hex':bytes(u.mem_read(a,n)).hex(),'low_value':hex(v&((1<<min(64,n*8))-1))};self.writes.append(e);self.pending.append(e)
 def bad(self,u,access,a,n,v,d):raise AssertionError(('unmapped/protected',self.cfg['label'],hex(u.reg_read(A.UC_ARM64_REG_PC)),access,hex(a),n))
 def api(self,a,name):
  x=[self.reg(j)for j in range(8)];value=0;patch=[];meta={};before=self.frame();prior=self.state()
  if name in('_os_unfair_lock_lock','_os_unfair_lock_unlock'):
   if name.endswith('_lock'):assert x[0]not in self.locks;self.locks.add(x[0])
   else:assert x[0]in self.locks;self.locks.remove(x[0])
  elif name=='_mach_port_allocate':assert x[:2]==[0x103,1];value=self.cfg.get('allocate_status',0);patch=[]if value else[(x[2],struct.pack('<I',self.cfg.get('name',0x303)))]
  elif name=='_mach_port_insert_right':assert x[:4]==[0x103,self.cfg.get('name',0x303),self.cfg.get('name',0x303),20];value=self.cfg.get('insert_status',0)
  elif name=='_mach_port_type':assert x[:2]==[0x103,self.cfg.get('name',0x303)];value=self.cfg.get('type_status',0);patch=[]if value else[(x[2],struct.pack('<I',self.cfg.get('types',0x30000)))]
  elif name in('_mach_port_mod_refs','_mach_port_deallocate'):assert x[0]==0x103;meta={'task_u32':x[0]&0xffffffff,'name_u32':x[1]&0xffffffff};value=self.cfg.get('cleanup_status',0)
  elif name=='runtime_create':
   assert x[:4]==[0,36,112,0];value=0 if self.cfg.get('runtime_fail')else PORT
   if value:raw=bytearray(128);struct.pack_into('<Q',raw,8,0x2400);patch=[(PORT,raw)];self.created=True
  elif name=='CF_retain':value=x[0]
  elif name=='CF_release':pass
  elif name=='ObjC_type_check':assert x[:2]==[36,PORT]
  elif name=='array_count':assert x[0]==ARRAY;value=len(self.registry)
  elif name=='array_value':assert x[0]==ARRAY and x[1]<len(self.registry);value=self.registry[x[1]]
  elif name=='array_append':assert x[:2]==[ARRAY,PORT];self.registry.append(PORT)
  elif name=='array_remove':assert x[0]==ARRAY and x[1]<len(self.registry);self.registry.pop(x[1])
  elif name=='_malloc_type_calloc':assert x[:2]==[1,8];value=ALLOC+32*self.allocs;self.allocs+=1;patch=[(value,bytes(8)+b'\xa5')]
  elif name=='_free':meta={'free_request':hex(x[0])}
  elif name=='set_value':assert x[0]==RECORDS;key=int.from_bytes(bytes(self.u.mem_read(x[1],5)),'little');value=self.records.get(key,0);meta={'key40':hex(key)}
  elif name=='set_add':
   assert x[0]==RECORDS;key=int.from_bytes(bytes(self.u.mem_read(x[1],5)),'little');assert key not in self.records;self.records[key]=x[1];flags=bytes(self.u.mem_read(x[1]+5,1))[0];assert not flags&1;patch=[(x[1]+5,bytes([flags|1]))];meta={'key40':hex(key),'declared_record_retain_effect':True}
  elif name=='set_remove':
   assert x[0]==RECORDS;key=int.from_bytes(bytes(self.u.mem_read(x[1],5)),'little');assert key in self.records;v=self.records.pop(key);meta={'key40':hex(key),'declared_record_release_free_request':hex(v)}
  elif name=='_dispatch_source_create':assert x[:4]==[TYPE,self.cfg.get('name',0x303),1,QUEUE];value=0 if self.cfg.get('monitor_null')else MONITOR
  elif name in('_dispatch_source_set_cancel_handler','_dispatch_source_set_event_handler'):
   assert x[0]==MONITOR;cancel=name.endswith('cancel_handler');size=44 if cancel else 36;at=CANCEL_BLOCK if cancel else EVENT_BLOCK;raw=bytes(self.u.mem_read(x[1],size));patch=[(at,raw)];meta={'copied_bytes':size,'invoke':hex(struct.unpack_from('<Q',raw,16)[0]),'source_block':hex(x[1]),'copy':hex(at)}
   if cancel:self.cancel_block=at
   else:self.event_block=at
  elif name in('_dispatch_resume','_dispatch_release','_dispatch_channel_cancel'):assert x[0]==MONITOR
  elif name=='source_invalidate_request':assert x[0]==SOURCE;meta={'original_source_body_executed':False}
  elif name=='context_retain':assert x[0]==INFO;value=INFO
  elif name=='context_release':assert x[0]==INFO;assert PORT+0x68 not in self.locks
  elif name=='invalidation_callback':assert x[:2]==[PORT,INFO if self.cfg.get('context')else 0];assert PORT+0x68 not in self.locks
  elif name=='log_object':value=B+0xe000
  elif name=='_os_log_type_enabled':value=0
  else:raise AssertionError(('unknown lower boundary',hex(a),name,[hex(v)for v in x]))
  e={'pc':hex(a),'name':name,'arguments8':[hex(v)for v in x],'before':before,'state_before':prior,'result':hex(value&0xffffffffffffffff),'patches':[],**meta};self.events.append(e)
  for at,b in patch:e['patches'].append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':bytes(b).hex()});self.u.mem_write(at,bytes(b))
  ret=self.reg(30)
  for j in range(18):self.setreg(j,0x8b3dc651^((j+1)*0x123456789abcdef))
  self.setreg(0,value);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000);self.u.reg_write(A.UC_ARM64_REG_PC,ret);e['after']=self.frame();e['state_after']=self.state()
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:u.emu_stop();return
  callbacks={RETAIN_INFO:'context_retain',RELEASE_INFO:'context_release',INVALID_CB:'invalidation_callback'}
  if a in callbacks:return self.api(a,callbacks[a])
  if a not in self.ins:
   name=self.stubs.get(a,self.lower.get(a));assert name,('uncaptured code',hex(a));return self.api(a,name)
  i=self.ins[a];raw=bytes(u.mem_read(a,4));expected=next(bytes.fromhex(f['bytes'])[a-int(f['start'],16):a-int(f['start'],16)+4]for f in self.s['functions']if int(f['start'],16)<=a<int(f['end'],16));assert raw==expected;self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if a in FUNCS:self.frames.append({'visit':self.current,'frame':self.frame(),'state':self.state()})
  op=i['mnemonic'];oper=i['operands']
  if op in('pacibsp','paciasp','autibsp','autiasp','paciza','pacia','pacda','autia','autiza','autda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
  elif op in('retab','retaa'):u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
  elif op in('blraa','blraaz','braa','braaz'):
   target=self.reg(int(oper.split(',')[0].strip()[1:]))
   if op.startswith('blr'):self.setreg(30,a+4)
   u.reg_write(A.UC_ARM64_REG_PC,target)
  else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac')),(hex(a),op)
 def run(self):
  name=self.cfg.get('name',0x303)
  for j,action in enumerate(self.cfg['actions']):
   self.action=action;self.phase_index=j;patch=[]
   if action=='create':at=CREATE;args=[0,0x100425f78,CTX,CTX+40]
   elif action=='wrap':at=WITH;args=[0,name,0x100425f78,CTX,CTX+40]
   elif action=='wrap_again':at=WITH;args=[0,name,0x11112222,CTX+0x80,CTX+40]
   elif action=='invalidate':at=INVALID;args=[PORT]
   elif action=='destroy':at=DESTROY;args=[PORT]
   elif action=='cancel':assert self.cancel_block;at=struct.unpack('<Q',self.u.mem_read(self.cancel_block+16,8))[0];args=[self.cancel_block]
   elif action=='intent':at=INTENT;args=[self.cfg.get('client',0),name]
   elif action=='record':at=RECORD;args=[self.cfg.get('client',0),name,self.cfg.get('send',1),self.cfg.get('receive',1)]
   elif action=='dead':at=DEAD;args=[self.cfg.get('client',0),name]
   elif action=='source_invalid':at=0x18477a448;args=[self.cfg.get('client',0),name]
   elif action=='ns_interest':at=NS_INTEREST;args=[self.cfg.get('client',0),name]
   elif action=='ns_record':at=NS_RECORD;args=[self.cfg.get('client',0),name,self.cfg.get('ns_send',1),self.cfg.get('ns_receive',1)]
   elif action=='cleanup':at=CLEAN;args=[name|(self.cfg.get('client',0)<<32)|(self.cfg['flags']<<40)|(self.cfg.get('opaque_tail',0)<<48)]
   elif action=='attach':
    for addr,raw in[(PORT+0x20,struct.pack('<Q',INVALID_CB if self.cfg.get('callback')else 0)),(PORT+0x28,struct.pack('<Q',SOURCE if self.cfg.get('cached_source')else 0))]:patch.append({'address':hex(addr),'before_hex':bytes(self.u.mem_read(addr,len(raw))).hex(),'after_hex':raw.hex()});self.u.mem_write(addr,raw)
    self.entries.append({'action':action,'patches':patch,'state':self.state()});continue
   else:raise AssertionError(action)
   # Explicit component calls preserve the private memory epoch, not a native caller.
   for k in range(31):self.setreg(k,0x1111000000000000+k)
   for k in range(32):self.u.reg_write(getattr(A,'UC_ARM64_REG_Q'+str(k)),k|(k<<64))
   self.u.reg_write(A.UC_ARM64_REG_SP,B+0x3f000);self.u.reg_write(A.UC_ARM64_REG_NZCV,0);self.setreg(30,HALT)
   for k,v in enumerate(args):self.setreg(k,v)
   self.u.reg_write(A.UC_ARM64_REG_PC,at);e={'action':action,'entry':self.frame(),'state_before':self.state(),'visit_start':len(self.visits),'event_start':len(self.events)};self.entries.append(e)
   self.u.emu_start(at,HALT+4,count=20000);self.flush();assert self.u.reg_read(A.UC_ARM64_REG_PC)==HALT;assert not self.locks
   e.update(returned=self.frame(),state_after=self.state(),visit_end=len(self.visits),event_end=len(self.events))
  return{'config':self.cfg,'initial':self.initial,'source_visits':self.visits,'reads':self.reads,'writes':self.writes,'lower_events':self.events,'entries':self.entries,'original_entry_frames':self.frames,'final_state':self.state(),'final_regions':[pack(B,bytes(self.u.mem_read(B,RAM)))]+[pack(a,bytes(self.u.mem_read(a,4096)))for a in sorted(self.mutable)]}
def configs():
 out=[]
 for label,kind,types,acts,more in[
  ('borrowed_receive','wrap',0x20000,['invalidate','destroy'],{}),
  ('owned_cached_reuse','create',0x30000,['wrap_again','invalidate','destroy','cancel'],{'context':True}),
  ('owned_cancel_before_destroy','create',0x30000,['invalidate','cancel','destroy'],{}),
  ('owned_destroy_before_cancel','create',0x30000,['invalidate','destroy','cancel'],{}),
  ('owned_destroy_live','create',0x30000,['destroy','cancel'],{}),
  ('borrowed_send_monitor','wrap',0x10000,['invalidate','destroy','cancel'],{}),
  ('borrowed_send_once_monitor','wrap',0x40000,['invalidate','cancel','destroy'],{}),
  ('monitor_null_pending','create',0x30000,['invalidate','destroy'],{'monitor_null':True}),
  ('context_and_source','create',0x30000,['attach','invalidate','invalidate','destroy','cancel'],{'context':True,'callback':True,'cached_source':True}),
  ('insert_failure','create',0x30000,[],{'insert_status':5}),
  ('allocate_failure','create',0x30000,[],{'allocate_status':3}),
  ('runtime_failure','create',0x30000,[],{'runtime_fail':True}),
  ('high_name','create',0x30000,['destroy','cancel'],{'name':0x80000303}),
  ('cleanup_error_status','create',0x30000,['destroy','cancel'],{'cleanup_status':5}),
 ]:out.append({'label':label,'types':types,'actions':[kind]+acts,**more})
 for order in(['intent','record','source_invalid'],['intent','source_invalid','record'],['intent','record','dead','source_invalid'],['record'],['intent','ns_interest','ns_record','source_invalid'],['intent','ns_interest','source_invalid','ns_record']):out.append({'label':'_'.join(order),'actions':order})
 for send in range(2):
  for receive in range(2):
   for order in(['intent','record','source_invalid'],['intent','source_invalid','record']):out.append({'label':'mask_'+str(send)+str(receive)+'_'+'_'.join(order),'actions':order,'send':send,'receive':receive})
 for state in(1,2,3):out.append({'label':'preexisting_state_'+str(state),'actions':['invalidate','destroy'],'seed_object':True,'initial_state':state,'ownership':6})
 for f in range(256):out.append({'label':'cleanup_flags_'+str(f),'flags':f,'opaque_tail':0xa55a,'client':0x73,'name':0x80000303,'actions':['cleanup']})
 return out
if __name__=='__main__':
 s=json.loads((ROOT/(P+'_source.json')).read_text());rows=[]
 for cfg in configs():
  try:r=Engine(s,cfg).run()
  except Exception as e:print('FAILED',cfg['label'],type(e).__name__,str(e),flush=True);raise
  rows.append(r)
  if not cfg['label'].startswith('cleanup_flags_'):print(cfg['label'],len(r['source_visits']),len(r['lower_events']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','recover_'+P+'.py']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'original_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
