#!/usr/bin/env python3
"""Original serialized-tree APIs and topology composition in private RAM.
O(visits + journals + mapped bytes + serialized fixture bytes) time/space.
No native firmware, system instruction, receiver or target IPC execution.
"""
import bisect
from unicorn import arm64_const as ar
import recover_kernel_secure_dt_execution as R
from probe_kernel_cpu_topology_handoff import Probe as Parent,TREE,TREE_SIZE,SP,P,HALT,rid,MASK,node,scalar,description
from probe_kernel_boot_cpu_identity import Probe as Base
from recover_kernel_boot_header_handoff import logical
B=R.B;K=B.B;LIMIT=100000;WORK=P+0x6000
SOURCE_APIS=[R.INIT,B.LOOKUP,B.PROPERTY,B.ITERATE,B.FIND,R.SKIP,R.STRCMP]
def tree_node(name,properties=(),children=()):
 return {'properties':[['name',description(name.encode()+bytes(1))],*[[k,v] for k,v in properties]],'children':list(children)}
def fixture(c):
 children=[tree_node('unused', [('odd',description(b'abc'))], [tree_node('nested-unused')])]
 if c.get('cpus_present',True):children.append(tree_node('cpus', [('pad',description(b'xy'))], [tree_node('cpu'+str(j), [(k,v) for k,v in p.items() if v is not None]) for j,p in enumerate(c['nodes'])]))
 if c.get('io_found'):children.append(tree_node('bridge',[],[tree_node('arm-io',[('chip-revision',c['chip'])] if c.get('chip') is not None else [])]))
 children.append(tree_node('last'))
 return tree_node('device-tree',[('model',description(b'private-fixture'+bytes(1))),('odd',description(b'12345'))],children)
def serialize(root):
 out=bytearray();index={}
 def visit(n,path):
  at=TREE+len(out);index[path]=at;props=n['properties'];out.extend(len(props).to_bytes(4,'little')+len(n['children']).to_bytes(4,'little'))
  for key,p in props:
   raw=bytes.fromhex(p['bytes_hex']);assert p['size_bytes']==len(raw);name=key.encode();assert len(name)<32 and bytes(1) not in name
   out.extend(name+bytes(32-len(name))+len(raw).to_bytes(4,'little')+raw+bytes((-len(raw))%4))
  for child in n['children']:
   name=bytes.fromhex(child['properties'][0][1]['bytes_hex']).rstrip(bytes(1)).decode();visit(child,(path.rstrip('/')+'/'+name))
 visit(root,'/');assert len(out)<TREE_SIZE;return bytes(out),index
class Probe(Parent):
 def __init__(self,image,c,mutate=None):
  super().__init__(image,c,None);self.mutate=mutate;self.native_entries=[];self.tree_call_returns=[];self.active_calls=[];self.api_returns=[];self.init_checkpoint=None;self.stage='tree_initializer';self.step=0
  self.blob,self.node_index=serialize(fixture(c));self.put(TREE,bytes(TREE_SIZE));self.put(TREE,self.blob);self.put(R.GLOBALS,bytes(32));self.put(R.CURSOR,bytes(8))
  for a in [R.INIT,R.SKIP,R.STRCMP]:
   end=image.k.starts[bisect.bisect_left(image.k.starts,a)+1]
   for pg in range(a&~4095,(end+4095)&~4095,4096):self.map(pg)
  self.operations=c.get('operations',[])
  for j,op in enumerate(self.operations):
   for i,key in enumerate(['path','key','value']):
    if key in op:self.put(WORK+0x400+j*0x200+i*0x80,op[key].encode()+bytes(1))
  self.put(WORK,bytes([0xa5])*0x200);self.start=R.INIT;self.u.reg_write(rid(0),TREE);self.u.reg_write(rid(1),len(self.blob));self.u.reg_write(rid(30),HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP)
  if mutate is not None:self.put(mutate,bytes.fromhex('1f2003d5'))
  self.initial_system=dict(self.system);self.initial_registers=self.regs();self.initial_SP=SP;self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
 def call(self,a,next_pc,kind,args=()):
  before=self.regs();epoch={'PC':hex(a),'next_PC':hex(next_pc),'kind':kind,'registers':list(map(hex,before)),'system':dict(self.system),'writes_completed':len(self.writes),'before_visit':len(self.visits),'arguments':list(map(hex,args)),
   'contract':'Same complete private RAM; explicit new call frame/arguments; native caller and intervening startup not executed'}
  self.epochs.append(epoch);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(rid(30),HALT)
  for j,v in enumerate(args):self.u.reg_write(rid(j),v)
  self.u.reg_write(ar.UC_ARM64_REG_PC,next_pc)
 def next_operation(self):
  j=self.step;op=self.operations[j];base=WORK+0x400+j*0x200;target=self.node_index.get(op.get('node','/'),0)
  if op['kind']=='lookup':entry=B.LOOKUP;args=[target if op.get('relative') else 0,base,WORK]
  elif op['kind']=='property':entry=B.PROPERTY;args=[target,base+0x80,WORK,WORK+8,TREE,len(self.blob)]
  elif op['kind']=='skip':entry=R.SKIP;args=[target]
  else:raise AssertionError(op)
  self.call(HALT,entry,'explicit_tree_API_call',args);self.step+=1
 def code(self,u,a,n,d):
  self.finish()
  while self.active_calls and a==int(self.native_entries[self.active_calls[-1]]['return_PC'],16) and u.reg_read(ar.UC_ARM64_REG_SP)==int(self.native_entries[self.active_calls[-1]]['entry_SP'],16):
   self.tree_call_returns.append({'entry_index':self.active_calls.pop(),'before_visit':len(self.visits),'return_value':hex(self.regs()[0])})
  if a==HALT and self.stage=='tree_initializer':
   self.init_checkpoint={'PC':hex(a),'before_visit':len(self.visits),'global_bytes_hex':bytes(u.mem_read(R.GLOBALS,32)).hex(),'registers':list(map(hex,self.regs()))}
   if self.operations:self.stage='API';self.next_operation()
   else:self.stage='enumeration';self.call(a,0xfffffe000c639cb8,'tree_initializer_to_main_cut')
   return
  if a==HALT and self.stage=='API':
   self.api_returns.append({'operation':self.step-1,'PC':hex(a),'before_visit':len(self.visits),'registers':list(map(hex,self.regs())),'workspace_hex':bytes(u.mem_read(WORK,0x200)).hex()})
   if self.step<len(self.operations):self.next_operation();return
  if a==0xfffffe000c639cbc:
   self.boot_snapshots.append({'PC':hex(a),'before_visit':len(self.visits),'record_pointer':hex(int.from_bytes(u.mem_read(K.RECORD_PTR,8),'little')),'system':dict(self.system)});self.stage='post_enumeration_helper'
  if a==0xfffffe000c639cc0:self.main_snapshots.append({'PC':hex(a),'before_visit':len(self.visits),'system':dict(self.system)});self.stage='bootstrap'
  if a==0xfffffe000c639dd8:self.stage='caller';self.call(a,K.CALLER,'bootstrap_to_CPU_caller_cut');return
  if a in [HALT,K.TAIL,K.PANIC] or a==0xfffffe000be83d2c and self.regs()[8]==0:
   self.stop={'PC':hex(a),'registers':list(map(hex,self.regs()))};u.emu_stop();return
  if a==B.STACKFAIL:raise AssertionError('original_stack_guard_failed')
  if a==B.PARSE:
   regs=self.regs();key=self.text(regs[1]);options=self.c.get('options',{});present=key in options;writes=[]
   if present and regs[3]:writes=[(regs[2],options[key].to_bytes(regs[3],'little'))]
   self.model(a,'declared_boot_option_output',int(present),writes);return
  if a==B.WRAPPER:
   self.wrapper_calls.append({'PC':hex(a),'physical_reg_low32':hex(self.regs()[0]),'before_visit':len(self.visits)});self.model(a,'declared_selector0e_wrapper_no_RAM_return');return
  if a in [K.SPTM,K.CACHE,K.CONFIG]:self.model(a,{K.SPTM:'declared_SPTM_CPU_initializer_no_RAM',K.CACHE:'declared_cache_initializer_no_RAM',K.CONFIG:'declared_CPU_context_initializer_no_RAM'}[a]);return
  if a==B.COMPARE:self.comparisons.append({'PC':hex(a),'arguments3':list(map(hex,self.regs()[:3])),'before_visit':len(self.visits)})
  if a in SOURCE_APIS:
   self.active_calls.append(len(self.native_entries));self.native_entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':list(map(hex,self.regs()[:6])),'return_PC':hex(self.regs()[30]),'before_visit':len(self.visits)})
  original=self.im.k.read(a,4);raw=original if a!=self.mutate else bytes.fromhex('1f2003d5');i=next(self.im.k.cs.disasm(raw,a));self.current=len(self.visits);self.visits.append({'PC':hex(a),'bytes_hex':raw.hex()});assert len(self.visits)<LIMIT
  if a==K.COPY:self.copies.append({'PC':hex(a),'arguments3':list(map(hex,self.regs()[:3])),'return_PC':hex(self.regs()[30]),'visit':self.current})
  if i.mnemonic in ['mrs','msr']:
   before=dict(self.system);left,right=i.op_str.split(', ')
   if i.mnemonic=='mrs':u.reg_write(getattr(ar,'UC_ARM64_REG_'+left.upper()),self.system[right])
   else:self.system[left]=0 if right=='xzr' else u.reg_read(getattr(ar,'UC_ARM64_REG_'+right.upper()))
   self.events.append({'visit':self.current,'PC':hex(a),'kind':'logical_system','mnemonic':i.mnemonic,'operands':i.op_str,'before':before,'after':dict(self.system)});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if i.mnemonic in ['pacibsp','autibsp','pacda','retab']:
   self.events.append({'visit':self.current,'PC':hex(a),'kind':'logical_PAC','mnemonic':i.mnemonic,'operands':i.op_str});u.reg_write(ar.UC_ARM64_REG_PC,self.regs()[30] if i.mnemonic=='retab' else a+4)
 def run(self):
  self.u.emu_start(self.start,0,count=LIMIT);self.finish();assert self.stop is not None
  return {'configuration':self.c,'start':hex(self.start),'mutated_PC':hex(self.mutate) if self.mutate else None,'fixture_extent_bytes':len(self.blob),'fixture_node_addresses':{k:hex(v) for k,v in self.node_index.items()},
   'initial_system':self.initial_system,'initial_registers':list(map(hex,self.initial_registers)),'initial_SP':hex(self.initial_SP),'initial_pages':[{'address':hex(pg),'bytes_hex':raw.hex()} for pg,raw in sorted(self.initial_pages.items())],
   'source_visits':self.visits,'reads':self.reads,'writes':self.writes,'logical_effects':self.events,'declared_models':self.models,'original_copy_entries':self.copies,'epochs':self.epochs,'original_comparison_entries':self.comparisons,'declared_selector0e_calls':self.wrapper_calls,
   'source_boot_record_snapshots':self.boot_snapshots,'source_main_continuation_checkpoints':self.main_snapshots,'original_tree_API_entries':self.native_entries,'original_tree_call_returns':self.tree_call_returns,'tree_initializer_return':self.init_checkpoint,'tree_API_returns':self.api_returns,
   'boundary':self.stop,'final_system':self.system,'final_pages':[{'address':hex(pg),'bytes_hex':bytes(self.u.mem_read(pg,4096)).hex()} for pg in sorted(self.pages)]}
def cases():
 rows=[]
 def add(label,nodes,**extra):rows.append(dict(label=label,phase='serialized_tree',nodes=nodes,**extra))
 add('one_running_CPU',[node(0x100)])
 add('three_clusters_and_recursive_IO_scan',[node(4,b'stopped'),node(0x102),node(0x201,b'stopped',0x4d)],io_found=True,chip=scalar(0x1234,2))
 add('reserved_last_slot',[node(0,b'stopped'),node(0x100,b'stopped'),node(0x201)],options={'cpus':1})
 add('mask_and_running',[node(0,b'stopped'),node(0x101),node(0x202,b'stopped')],options={'cpus':2,'cpumask':4})
 add('prefixes_and_PM_merge',[node(0x100),node(0x101,b'run',0x4d),node(0x102,b'runningX',0x50)])
 add('sixteen_CPUs',[node(i,b'stopped') for i in range(15)]+[node(15)])
 add('empty_CPUs',[])
 add('missing_CPUs_root_fallback',[node(0x100)],cpus_present=False)
 add('zero_CPU_limit',[node(0x100)],options={'cpus':0})
 full={'die-id':scalar(0x1234,2),'soc-die-id':scalar(0x123456789abcdef0,8),'l2-cache-size':scalar(0xff,1),'l2-cache-id':scalar(0x2345,2),'l3-cache-size':scalar(0x12345678,4),'l3-cache-id':scalar(0xffff123456789abc,8),'cpu-uttdbg-reg':description(bytes(range(16))),'cpu-impl-reg':description(bytes(range(16,32))),'coresight-reg':description(bytes(range(32,48))),'acc-impl-reg':description(bytes(range(48,64))),'cpm-impl-reg':description(bytes(range(64,80))),'die-cluster-id':scalar(0xaabbccdd),'cluster-core-id':scalar(0x123456789abcdef0,8),'cluster-power-down':scalar(1,8)}
 add('all_properties_and_nested_chip',[node(2,**full),node(0x100,b'stopped',0x45)],io_found=True,chip=scalar(0x12345678),options={'cluster_power':7,'siq_realtime_thread_mode':3})
 add('API_lookup_property_and_subtree',[node(0x100)],io_found=True,chip=scalar(7),operations=[{'kind':'lookup','path':'/'},{'kind':'lookup','path':'/cpus'},{'kind':'lookup','path':'/cpus/cpu0'},{'kind':'lookup','path':'cpu0','relative':True,'node':'/cpus'},{'kind':'lookup','path':'/bridge/arm-io'},{'kind':'lookup','path':'/absent'},{'kind':'property','node':'/cpus/cpu0','key':'reg'},{'kind':'property','node':'/cpus/cpu0','key':'absent'},{'kind':'property','node':'/','key':'odd'},{'kind':'skip','node':'/unused'},{'kind':'skip','node':'/cpus'}])
 return rows
