#!/usr/bin/env python3
"""Continue restored initialization through two declared clock ABI results.
O(restored bytes+new visits+effects) time/space per case. Parent source effects
are restored, not reexecuted. Native clock, errno, vector state and PAC unknown.
"""
import json,struct,hashlib,base64,zlib
from pathlib import Path
from capstone.arm64_const import ARM64_OP_MEM,ARM64_EXT_SXTW,ARM64_EXT_SXTX
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from daemon_import_bindings import binding
from recover_daemon_object_creation import sha
from probe_daemon_object_initialization import Run as Parent,P,SIZE,OBJ,IMPORTS
from capture_daemon_object_clock import memory_width
MASK=(1<<64)-1
class Run(Parent):
 def __init__(self,context,outcome):
  super().__init__(context['configuration']);self.context=context;self.outcome=outcome;self.allocated={int(a,16):n for a,n in context['allocated_owners'].items()};self.owners.update(self.allocated)
  for row in context['source_memory_groups']:
   a=int(row['address'],16);b=bytes.fromhex(row['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b);self.defined.update(range(a,a+len(b)))
   if 0x100000000<=a<0x102000000:self.global_defined.update(range(a,a+len(b)))
  for a,h in context['owner_snapshots'].items():assert bytes(self.u.mem_read(int(a,16),len(h)//2)).hex()==h
  for j,v in enumerate(context['boundary']['registers31']):self.set('x'+str(j),int(v,16))
  self.set('sp',int(context['boundary']['SP'],16));self.reg_sources={n:int(a,16)for n,a in context['register_pointer_origins'].items()};self.memory_sources={int(a,16):int(v,16)for a,v in context['memory_pointer_origins'].items()};self.new_fixtures=[];lock=outcome['lock_cell64'];self.ensure(0x1010c67c0,8);self.u.mem_write(0x1010c67c0,lock.to_bytes(8,'little'));self.global_defined.update(range(0x1010c67c0,0x1010c67c8));self.new_fixtures.append({'address':'0x1010c67c0','bytes_hex':lock.to_bytes(8,'little').hex(),'provenance':'declared lock cell'});self.owners[P+0x6000]=200
  for address in [0x1010c4e18,0x1010c4670]:
   old=int.from_bytes(self.u.mem_read(address,4),'little');value=(outcome['controller_upper32']<<32)|old;self.u.mem_write(address,value.to_bytes(8,'little'));self.new_fixtures.append({'address':hex(address),'bytes_hex':value.to_bytes(8,'little').hex(),'provenance':'known lower32 plus declared upper32'});self.global_defined.update(range(address,address+8));self.mutable_globals.update(range(address,address+8))
  self.new_source_cells={0x1010c5040,0x1010b66a8,0x1010b6738};self.global_pages.update(a&~4095 for a in self.new_source_cells)
  for address in sorted(self.new_source_cells):
   self.ensure(address,8);self.u.mem_write(address,outcome['auxiliary_state64'].to_bytes(8,'little'));self.new_fixtures.append({'address':hex(address),'bytes_hex':outcome['auxiliary_state64'].to_bytes(8,'little').hex(),'provenance':'declared auxiliary state'});self.global_defined.update(range(address,address+8));self.mutable_globals.update(range(address,address+8))
  mode=outcome['registry_mode'];count=0 if mode=='empty'else 2;array=0 if count==0 else P+0x34000
  for address,nb,value in [(0x1010ca2b0,4,count),(0x1010c9288,8,array),(0x1010c6840,8,0)]:
   self.global_pages.add(address&~4095);self.ensure(address,nb);self.u.mem_write(address,value.to_bytes(nb,'little'));self.new_fixtures.append({'address':hex(address),'bytes_hex':value.to_bytes(nb,'little').hex(),'provenance':'declared registry state'});self.global_defined.update(range(address,address+nb));self.mutable_globals.update(range(address,address+nb))
  if count:
   query=int.from_bytes(self.u.mem_read(self.F+0x3588,8),'little');keys=[query if mode=='match_first'else query^1,query if mode=='match_last'else query^2];raw=b''.join(struct.pack('<4Q',key,0x44440000+j,0,0x55550000+j)for j,key in enumerate(keys));self.u.mem_write(array,raw);self.defined.update(range(array,array+len(raw)));self.owners[array]=len(raw);self.new_fixtures.append({'address':hex(array),'bytes_hex':raw.hex(),'provenance':'declared two-entry raw-key/head table'})
  self.clock_calls=0;self.steps=[];self.events=[];self.pending=[];self.edges=[];self.api=[];self.fix=set();self.source_pool={};self.reason=None;self.done=False;self.previous_i=None;self.arbitrary_heap_reads=[];self.entry_clock_regs=[hex(self.reg('x'+str(j)))for j in range(31)]
 def write(self,u,t,a,n,v,d):
  super().write(u,t,a,n,v,d)
  if a in self.new_source_cells:self.global_defined.update(range(a,a+n));self.mutable_globals.update(range(a,a+n))
 def finish_pointer_sources(self):
  i=self.previous_i;before=self.previous_sources.copy();effects=self.events[self.previous_event_start:]if i is not None else[];super().finish_pointer_sources()
  if i is None or i.mnemonic not in ['ldp','stp']or not all(i.reg_name(o.reg).startswith('x')for o in i.operands[:2]):return
  kind='read'if i.mnemonic=='ldp'else'write';es=[e for e in effects if e['kind']==kind];assert sum(e['size_bytes']for e in es)==16;first=int(es[0]['address'],16);assert [int(e['address'],16)for e in es]in [[first],[first,first+8]]
  for j,o in enumerate(i.operands[:2]):
   name=self.canonical(i.reg_name(o.reg));address=first+8*j;origin=(address if address in FIXUPS else self.memory_sources.get(address))if kind=='read'else before.get(name)
   if origin is not None:
    if kind=='read':self.reg_sources[name]=origin
    else:self.memory_sources[address]=origin
 def preflight(self,i):
  reads,writes=i.regs_access();vectors=[i.reg_name(v)for v in reads if i.reg_name(v).startswith(('q','v','d','s'))and i.reg_name(v)[1:].isdigit()]
  if vectors:return self.stop('before_unmodeled_vector_read',{'registers':vectors})or False
  op=next((x for x in i.operands if x.type==ARM64_OP_MEM),None)
  if op is not None and i.mnemonic in ['str','stur']:
   a=(self.regname(i.reg_name(op.mem.base))+op.mem.disp)&MASK
   if not op.mem.index and a in self.new_source_cells:
    assert memory_width(i)==8;self.ensure(a,8);return True
  if not super().preflight(i):return False
  op=next((x for x in i.operands if x.type==ARM64_OP_MEM),None)
  if op is not None and i.mnemonic.startswith(('ldr','ldur','ldp','ldnp','ldar','ldax')):
   a=self.regname(i.reg_name(op.mem.base))+op.mem.disp
   if op.mem.index:
    idx=self.regname(i.reg_name(op.mem.index))
    if op.ext in [ARM64_EXT_SXTW,ARM64_EXT_SXTX]:bits=32 if op.ext==ARM64_EXT_SXTW else 64;idx&=(1<<bits)-1;idx-=1<<bits if idx>>(bits-1)else 0
    a+=idx<<op.shift.value
   a&=MASK;n=memory_width(i)
   if P<=a<a+n<=P+SIZE and not all(x in self.defined for x in range(a,a+n)):return self.stop('before_undefined_private_read',{'address':hex(a),'size_bytes':n,'instruction':i.mnemonic+' '+i.op_str})or False
  return True
 def code(self,u,a,n,d):
  sync={0x10043e508:('_pthread_once',0x10109fe80,0x8489),0x100442650:('_pthread_once',0x10109fe80,0x8489),0x100361df4:('_pthread_rwlock_wrlock',0x1010a0a00,0x4c4d),0x100208efc:('_pthread_rwlock_unlock',0x1010a0d78,0x5431)}
  if a in sync:
   self.flush();self.finish_pointer_sources();raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4);i=next(self.dec.disasm(raw,a));name,expected,div=sync[a];reg=i.op_str.split(',')[0].strip();slot=self.reg_sources[reg];b=binding(slot);word=int(b['word'],16);assert slot==expected and b['symbol']==name and b['authenticated']and b['total_addend']==0 and self.reg(reg)==IMPORTS['libSystem/'+name]and self.reg('x17')==div and (word>>32)&65535==div and(word>>48)&7==0;args=[self.reg('x'+str(j))for j in range(8)];before={n:self.reg(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]}
   if name=='_pthread_once':assert args[:2]==[0x1010b8cd0,0x10040ebd4];effects={'address':hex(args[0]),'size_bytes':16,'kind':'invalidate_opaque_once_control','callback_execution':'already-completed premise; no callback invoked'};status=0
   else:assert args[0]==P+0x6000;effects={'address':hex(args[0]),'size_bytes':200,'kind':'invalidate_opaque_lock_object'};status=self.outcome['primitive_status32']
   start=int(effects['address'],16);nb=effects['size_bytes'];self.defined.difference_update(range(start,start+nb));self.global_defined.difference_update(range(start,start+nb))
   if start<0x102000000:self.global_pages.update(range(start&~4095,((start+nb-1)&~4095)+4096,4096))
   o=self.outcome
   for j in range(1,18):self.set('x'+str(j),(((j+13)*0x143256789abcdef)^o['clobber_pattern'])&MASK)
   for j in list(range(18))+[30]:self.reg_sources.pop('x'+str(j),None)
   ret=((o['return_upper32']&0xffffffff)<<32)|(status&0xffffffff);self.set('x0',ret);self.set('x30',a+4);self.set('nzcv',o['NZCV_after']);assert all(self.reg(n)==v for n,v in before.items());self.api.append({'pc':hex(a),'binding':b,'arguments8':[hex(x)for x in args],'status32':status,'outcome':o,'opaque_effect':effects,'preserved_GPR_SP':before,'returned_X0':hex(ret),'native_call_executed':False});self.steps.append((a,raw.hex()));self.source_pool[hex(a)]={'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str};self.fix.add(slot);self.set('pc',a+4);return
  if (a==0x100bad4c8 and self.clock_calls==0)or(a==0x10087cbe0 and self.clock_calls==1):
   self.flush();self.finish_pointer_sources();raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4);i=next(self.dec.disasm(raw,a));target_reg='x9'if a==0x100bad4c8 else'x8';slot=self.reg_sources[target_reg];b=binding(slot);assert slot==0x10109ff20 and b['symbol']=='_gettimeofday'and b['authenticated']and b['total_addend']==0;assert self.reg(target_reg)==IMPORTS['libSystem/_gettimeofday']and self.reg('x17')==0x9298;assert (int(b['word'],16)>>32)&65535==0x9298 and (int(b['word'],16)>>48)&7==0
   pointer=self.reg('x0');assert pointer==self.F+0x3ca0 and self.reg('x1')==0;assert any(h<=pointer<pointer+16<=h+nb for h,nb in self.owners.items());before={n:self.reg(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]};o=self.outcome;sample={'seconds':o.get('first_seconds',o['seconds']),'microseconds':o.get('first_microseconds',o['microseconds']),'status32':o.get('first_status32',o['status32'])}if self.clock_calls==0 else{k:o[k]for k in ['seconds','microseconds','status32']};sec=(sample['seconds']&MASK).to_bytes(8,'little');usec=(sample['microseconds']&0xffffffff).to_bytes(4,'little');self.u.mem_write(pointer,sec+usec);self.defined.update(range(pointer,pointer+12));self.defined.difference_update(range(pointer+12,pointer+16))
   for j in range(1,18):self.set('x'+str(j),(((j+7)*0x143256789abcdef)^o['clobber_pattern'])&MASK)
   for j in list(range(18))+[30]:self.reg_sources.pop('x'+str(j),None)
   ret=((o['return_upper32']&0xffffffff)<<32)|(sample['status32']&0xffffffff);self.set('x0',ret);self.set('x30',a+4);self.set('nzcv',o['NZCV_after']);assert all(self.reg(n)==v for n,v in before.items());self.api.append({'pc':hex(a),'binding':b,'arguments2':[hex(pointer),'0x0'],'outcome':o,'sample':sample,'writes':[{'address':hex(pointer),'bytes_hex':sec.hex()},{'address':hex(pointer+8),'bytes_hex':usec.hex()}],'padding4':'invalidated; implementation writes unknown','preserved_GPR_SP':before,'returned_X0':hex(ret),'native_call_executed':False});self.clock_calls+=1;self.steps.append((a,raw.hex()));self.source_pool[hex(a)]={'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str};self.fix.add(slot);self.set('pc',a+4);return
  return super().code(u,a,n,d)
 def run(self,limit=200000):
  start=0x100bad4c8;self.ensure(start);self.u.emu_start(start,0,count=limit);self.flush()
  if self.reason is None:self.stop('source_visit_limit')
  assert not self.arbitrary_heap_reads
  t={'parent_case_index':self.context['parent_case_index'],'parent_payload_sha256':self.context['parent_payload_sha256'],'outcome':self.outcome,'entry_PC':hex(start),'entry_SP':hex(self.F),'entry_registers31':self.entry_clock_regs,'extension_fixtures':self.new_fixtures,'steps':self.steps,'events':self.events,'edges':self.edges,'source_pool':self.source_pool,'used_fixups':[hex(a)for a in sorted(self.fix)],'API_models':self.api,'allocated_owners':{hex(a):n for a,n in self.allocated.items()},'owner_snapshots':{hex(a):bytes(self.u.mem_read(a,n)).hex()for a,n in self.allocated.items()},'boundary':self.boundary,'arbitrary_heap_reads':self.arbitrary_heap_reads};raw=json.dumps(t,separators=(',',':')).encode();return {'parent_case_index':t['parent_case_index'],'outcome':self.outcome,'source_visits':len(self.steps),'API_models_count':len(self.api),'boundary':self.boundary,'payload_zlib_base64':base64.b64encode(zlib.compress(raw)).decode(),'payload_sha256':hashlib.sha256(raw).hexdigest(),'native_target_executed':False,'full_goal_complete':False}
def outcomes():
 for name,sec,usec,status,upper,clobber,nzcv in [('zero',0,0,0,0,0,0x50000000),('reference',1700000000,123456,0,0x12345678,255,0xa0000000),('negative_seconds',-1,999999,0,0xffffffff,17,0),('int32_failure_declared_outputs',0x100000001,42,-1,0x87654321,93,0xf0000000)]:yield {'name':name,'seconds':sec,'microseconds':usec,'status32':status,'return_upper32':upper,'clobber_pattern':clobber,'NZCV_after':nzcv,'first_seconds':-sec,'first_microseconds':1,'first_status32':-1 if status==0 else 0}
def main():
 contexts=json.loads((ROOT/'daemon_object_clock_context.json').read_text());rows=[]
 for ctx in contexts['contexts']:
  for outcome in ({**o,'lock_cell64':lock,'controller_upper32':[0,0xffffffff,0x12345678,0x87654321][j],'auxiliary_state64':((j+1)*0x123456789abcdef)&MASK,'primitive_status32':0 if j%2==0 else 22,'registry_mode':mode}for j,o in enumerate(outcomes())for lock in [0,P+0x6000]for mode in ['empty','miss','match_first','match_last']):
   r=Run(ctx,outcome).run();rows.append(r);print(json.dumps({k:r[k]for k in ['parent_case_index','source_visits','API_models_count']}|{'outcome':outcome['name'],'boundary':{k:v for k,v in r['boundary'].items()if k!='registers31'}}),flush=True)
 deps=['daemon_object_clock_context.json','probe_daemon_object_initialization.py','capture_daemon_object_clock.py','daemon_import_bindings.py'];r={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_clock_profiles.json').write_text(json.dumps(r,indent=2)+'\n')
if __name__=='__main__':main()
