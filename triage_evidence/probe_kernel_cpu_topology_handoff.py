#!/usr/bin/env python3
"""Original full enumerator/comparison with declared environmental outputs.
O(visits + journals + mapped bytes + fixture properties) time/space.
Native tree parsing, opaque receiver and startup continuity unexecuted.
"""
import bisect
from unicorn import arm64_const as ar
from recover_kernel_boot_header_handoff import logical
from probe_kernel_boot_cpu_identity import Probe as Parent,P,SP,HALT,rid,MASK
import recover_kernel_cpu_topology_handoff as R
B=R.B;TREE=P+0x10000;TREE_SIZE=0x20000;ROOT_NODE=TREE+0x40;IO_NODE=TREE+0x80
CHILD=TREE+0x100;BOOTARGS=B.ARGS;MAIN_CUT=0xfffffe000c639cc0
KEYS=['state','reg','die-id','soc-die-id','l2-cache-size','l2-cache-id','l3-cache-size','l3-cache-id','cpu-uttdbg-reg','cpu-impl-reg','coresight-reg','cluster-type','cluster-power-down','acc-impl-reg','cpm-impl-reg','die-cluster-id','cluster-core-id']
def prop_slot(index,key):return TREE+0x4000+index*0x800+KEYS.index(key)*64+3
def description(raw,length=None):return {'bytes_hex':raw.hex(),'size_bytes':len(raw) if length is None else length}
def scalar(value,n=4):return description(value.to_bytes(n,'little'))
def node(reg_value,state_bytes=b'running',kind=0x50,**properties):
 p={'state':description(state_bytes),'reg':scalar(reg_value),'cluster-type':scalar(kind,1)};p.update(properties);return p

class Probe(Parent):
 def __init__(self,image,c,mutate=None):
  super().__init__(image,dict(phase='caller',boot=True,ordinal=0,magic=0),None)
  self.c=c;self.mutate=mutate;self.iterator_index=0;self.wrapper_calls=[];self.comparisons=[];self.boot_snapshots=[];self.main_snapshots=[];self.stage='enumeration'
  self.u.mem_map(TREE,TREE_SIZE)
  for pg in range(TREE,TREE+TREE_SIZE,4096):self.pages[pg]=bytes(4096)
  for a in R.FUNCTIONS:
   end=image.k.starts[bisect.bisect_left(image.k.starts,a)+1]
   for pg in range(a&~4095,(end+4095)&~4095,4096):self.map(pg)
  for a,n in [(B.CPU,0xa40),(B.THREAD,0x5c0),(B.GLOBALS,0xa4),(B.ARRAY-4,16*136+4),(B.CLUSTERS,3*88)]:self.put(a,logical(image,a,n))
  self.put(B.THREAD,bytes([0xa5])*0x5c0)
  for offset,value,n in [(0,TREE,8),(8,TREE_SIZE,8),(16,TREE+TREE_SIZE,8),(24,int(c.get('tree_initialized',True)),4)]:self.put(0xfffffe0007f8b508+offset,value.to_bytes(n,'little'))
  self.put(0xfffffe0007f8b6e8,BOOTARGS.to_bytes(8,'little'))
  self.put(B.ARGS+8,(0xfffffe0007000000).to_bytes(8,'little')+(0x80000000).to_bytes(8,'little'))
  self.put(0xfffffe000cacb000,(0x123456789abcdef0).to_bytes(8,'little'))
  for index,properties in enumerate(c['nodes']):
   for key,p in properties.items():
    if p is not None:self.put(prop_slot(index,key),bytes.fromhex(p['bytes_hex']))
  if c.get('chip') is not None:self.put(TREE+0x3000,bytes.fromhex(c['chip']['bytes_hex']))
  self.system.update(tpidr_el0=0xfeed123456789abc,tpidrro_el0=0xabcdef0123456789,s3_4_c15_c10_4=0xaaaaaaaa55555555)
  self.start=0xfffffe000c639cb8 if c.get('join_main',True) else B.ENUM;self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(rid(30),HALT)
  if mutate is not None:self.put(mutate,bytes.fromhex('1f2003d5'))
  self.initial_system=dict(self.system);self.initial_registers=self.regs();self.initial_SP=SP;self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
 def text(self,a):
  for pg in range(a&~4095,(a+80+4095)&~4095,4096):self.map(pg)
  return bytes(self.u.mem_read(a,80)).split(bytes(1))[0].decode('ascii')
 def epoch(self,a,next_pc,kind):
  self.epochs.append({'PC':hex(a),'next_PC':hex(next_pc),'kind':kind,'registers':list(map(hex,self.regs())),'system':dict(self.system),
   'writes_completed':len(self.writes),'before_visit':len(self.visits),'contract':'Same complete private RAM; explicit new call SP/LR; intervening original startup calls not executed'})
  self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(rid(30),HALT);self.u.reg_write(ar.UC_ARM64_REG_PC,next_pc)
 def code(self,u,a,n,d):
  self.finish()
  if a==0xfffffe000c639cbc and self.stage=='enumeration' and self.c.get('join_main',True):
   self.boot_snapshots.append({'PC':hex(a),'before_visit':len(self.visits),'record_pointer':hex(int.from_bytes(u.mem_read(B.RECORD_PTR,8),'little')),'system':dict(self.system)})
   self.stage='post_enumeration_helper'
  if a==MAIN_CUT:
   self.main_snapshots.append({'PC':hex(a),'before_visit':len(self.visits),'system':dict(self.system)});self.stage='bootstrap'
  if a==0xfffffe000c639dd8:
   self.stage='caller';self.epoch(a,B.CALLER,'bootstrap_to_CPU_caller_cut');return
  if a==0xfffffe000be83d2c and self.regs()[8]==0:
   self.stop={'PC':hex(a),'registers':list(map(hex,self.regs())),'kind':'before_original_null_boot_record_load'};u.emu_stop();return
  if a==R.STACKFAIL:
   self.stop={'PC':hex(a),'registers':list(map(hex,self.regs())),'kind':'before_original_stack_check_failure'};u.emu_stop();return
  if a==R.PARSE:
   regs=self.regs();key=self.text(regs[1]);options=self.c.get('options',{});present=key in options;writes=[]
   if present and regs[3]:writes=[(regs[2],options[key].to_bytes(regs[3],'little'))]
   self.model(a,'declared_boot_option_output',int(present),writes);return
  if a==R.LOOKUP:
   regs=self.regs();assert self.text(regs[1])=='/cpus';found=self.c.get('lookup_found',True)
   self.model(a,'declared_CPU_node_lookup_output',int(found),[(regs[2],ROOT_NODE.to_bytes(8,'little'))] if found else []);return
  if a==R.ITERATE:
   regs=self.regs();index=self.iterator_index;found=index<len(self.c['nodes']);self.iterator_index+=1
   self.model(a,'declared_child_iterator_output',int(found),[(regs[1],(CHILD+index*32).to_bytes(8,'little'))] if found else []);return
  if a==R.PROPERTY:
   regs=self.regs();key=self.text(regs[1]);at=regs[0];descriptor=None;slot=None
   if at==IO_NODE:
    assert key=='chip-revision';descriptor=self.c.get('chip');slot=TREE+0x3000
   else:
    assert CHILD<=at<CHILD+len(self.c['nodes'])*32 and (at-CHILD)%32==0
    index=(at-CHILD)//32;descriptor=self.c['nodes'][index].get(key);slot=prop_slot(index,key)
   writes=[] if descriptor is None else [(regs[2],slot.to_bytes(8,'little')),(regs[3],descriptor['size_bytes'].to_bytes(4,'little'))]
   self.model(a,'declared_tree_property_output',int(descriptor is not None),writes);return
  if a==R.FIND:
   regs=self.regs();assert self.text(regs[0])=='name' and self.text(regs[1])=='arm-io';found=self.c.get('io_found',False)
   self.model(a,'declared_named_IO_node_output',int(found),[(regs[2],IO_NODE.to_bytes(8,'little'))] if found else []);return
  if a==R.WRAPPER:
   self.wrapper_calls.append({'PC':hex(a),'physical_reg_low32':hex(self.regs()[0]),'before_visit':len(self.visits)})
   self.model(a,'declared_selector0e_wrapper_no_RAM_return');return
  if a==R.COMPARE:self.comparisons.append({'PC':hex(a),'arguments3':list(map(hex,self.regs()[:3])),'before_visit':len(self.visits)})
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row.update(original_comparison_entries=self.comparisons,declared_selector0e_calls=self.wrapper_calls,source_boot_record_snapshots=self.boot_snapshots,source_main_continuation_checkpoints=self.main_snapshots);return row

def cases():
 rows=[]
 def add(label,nodes,**extra):rows.append(dict(label=label,phase='topology',nodes=nodes,**extra))
 add('one_running_CPU',[node(0x100)])
 add('three_physical_clusters_running_middle',[node(0x004,b'stopped'),node(0x102,b'running',0x45),node(0x201,b'stopped',0x4d)])
 add('reserved_last_slot_for_running',[node(0x000,b'stopped'),node(0x100,b'stopped'),node(0x201)],options={'cpus':1})
 add('masked_running_is_still_admitted',[node(0x000,b'stopped'),node(0x101),node(0x202,b'stopped')],options={'cpus':2,'cpumask':4})
 add('prefix_matches_overwrite_boot_pointer_and_merge_PM',[node(0x100),node(0x101,b'run',0x4d),node(0x102,b'runningX',0x50,**{'state':description(b'runningX',7)})])
 add('zero_length_state_comparison',[node(0x200,**{'state':description(b'',0)})],join_main=False)
 add('nonmatching_state_no_boot_pointer',[node(0x000,b'runningX')],join_main=False)
 add('missing_state_diagnostic',[node(0x100,**{'state':None})],join_main=False)
 add('missing_mandatory_reg_diagnostic',[node(0x100,**{'reg':None})],join_main=False)
 add('invalid_scalar_width_diagnostic',[node(0x100,**{'die-id':description(bytes(3))})],join_main=False)
 add('invalid_pair_width_diagnostic',[node(0x100,**{'cpu-uttdbg-reg':description(bytes(8))})],join_main=False)
 full={'die-id':scalar(0x1234,2),'soc-die-id':scalar(0x123456789abcdef0,8),'l2-cache-size':scalar(0xff,1),'l2-cache-id':scalar(0x2345,2),'l3-cache-size':scalar(0x12345678,4),'l3-cache-id':scalar(0xffff123456789abc,8),
  'cpu-uttdbg-reg':description(bytes(range(16))),'cpu-impl-reg':description(bytes(range(16,32))),'coresight-reg':description(bytes(range(32,48))),
  'acc-impl-reg':description(bytes(range(48,64))),'cpm-impl-reg':description(bytes(range(64,80))),'die-cluster-id':scalar(0xaabbccdd),'cluster-core-id':scalar(0x123456789abcdef0,8),'cluster-power-down':scalar(1,8)}
 add('all_properties_and_option_override',[node(0x002,**full),node(0x100,b'stopped',0x45)],io_found=True,chip=scalar(0x12345678),options={'enable_skstb':1,'cluster_power':7})
 add('invalid_chip_width_diagnostic',[node(0x100)],io_found=True,chip=description(bytes(3)),join_main=False)
 add('empty_iterator',[ ],join_main=False)
 add('zero_CPU_limit',[node(0x100)],options={'cpus':0},join_main=False)
 add('sixteen_CPUs_boot_ordinal15',[node(i,b'stopped') for i in range(15)]+[node(15)])
 add('lookup_absent_explicit_iterator_contract',[node(0x200)],lookup_found=False)
 add('uninitialized_tree_empty_iterator',[],tree_initialized=False,join_main=False)
 add('incompatible_cluster_types',[node(0x100),node(0x101,b'stopped',0x45)])
 add('reverse_MP_cluster_merge',[node(0x100,b'running',0x4d),node(0x101,b'stopped',0x50)])
 add('absent_cluster_type_defaults_to_zero',[node(0x200,**{'cluster-type':None})])
 add('post_enumeration_control3',[node(0x100)],options={'siq_realtime_thread_mode':3})
 add('post_enumeration_control4_diagnostic',[node(0x100)],options={'siq_realtime_thread_mode':4})
 return rows
