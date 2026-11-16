#!/usr/bin/env python3
"""Independent topology formulas, state-cut materialization and fresh replay.
O(visits + journals + mapped bytes + fixture properties) time/space.
No executor import; all environmental outputs remain private contracts.
"""
from unicorn import arm64_const as ar
from replay_kernel_boot_cpu_identity import Replay as Parent,oracle as thread_oracle,pages,get,put,P,SP,HALT,MASK,regno
import recover_kernel_cpu_topology_handoff as R
B=R.B;TREE=P+0x10000;TREE_SIZE=0x20000;ROOT_NODE=TREE+0x40;IO_NODE=TREE+0x80;CHILD=TREE+0x100
KEYS=['state','reg','die-id','soc-die-id','l2-cache-size','l2-cache-id','l3-cache-size','l3-cache-id','cpu-uttdbg-reg','cpu-impl-reg','coresight-reg','cluster-type','cluster-power-down','acc-impl-reg','cpm-impl-reg','die-cluster-id','cluster-core-id']
class Diagnostic(Exception):pass
def state_at(row,end):
 memory=pages(row['initial_pages']);effects=[]
 for index,w in enumerate(row['writes']):
  if w['visit']<end:effects.append((w['visit'],1,index,w))
 for index,m in enumerate(row['declared_models']):
  if m['before_visit']<end:
   for j,w in enumerate(m['api_writes']):effects.append((m['before_visit'],0,index*4+j,w))
 for _,_,_,w in sorted(effects):
  raw=bytes.fromhex(w['after_hex']);put(memory,int(w['address'],16),len(raw),raw)
 return memory
def oracle(row):
 c=row['configuration'];memory=pages(row['initial_pages']);checks=[];system=dict(row['initial_system']);expected_calls=[];admitted=[];boot=None;groups={};coremax={};count=0
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def w(a,n,value):put(memory,a,n,value)
 def ok(label,predicate):assert predicate,('semantic_oracle',label);checks.append(label)
 def scalar(p,default=0):
  if p is None:
   if default==MASK:raise Diagnostic('mandatory_property_absent')
   return default
  size=p['size_bytes']
  if size not in [1,2,4,8]:raise Diagnostic('invalid_scalar_width')
  return int.from_bytes((bytes.fromhex(p['bytes_hex'])+bytes(8))[:size],'little')
 def pair(p,address):
  if p is None:return
  if p['size_bytes']!=16:raise Diagnostic('invalid_pair_width')
  w(address,16,(bytes.fromhex(p['bytes_hex'])+bytes(16))[:16])
 def bounded_equal(p):
  data=bytes.fromhex(p['bytes_hex'])+bytes(16);target=b'running'+bytes(16)
  for left,right in zip(data[:p['size_bytes']],target[:p['size_bytes']]):
   if left!=right:return False
   if left==0:return True
  return True
 ok('initial_counters_and_runtime_boot_pointer_absent',u(B.GLOBALS,16)==0 and u(B.RECORD_PTR,16)==0)
 options=c.get('options',{});limit=options.get('cpus',16);mask=options.get('cpumask',MASK)
 if 'cpus' in options and 'cpumask' in options:w(B.ARRAY-4,1,0)
 if 'cpus' in options or 'cpumask' in options:w(B.ARRAY-3,1,1)
 for a in [0xfffffe0007ef8c78,0xfffffe0007ef8c80,0xfffffe0007ef8c88]:w(a,8,MASK)
 diagnostic=None
 try:
  for node_index,p in enumerate(c['nodes']):
   if p.get('state') is None:raise Diagnostic('state_absent')
   running=bounded_equal(p['state']);bit=mask&1;mask>>=1
   if running and not bit:w(B.ARRAY-4,1,0)
   if not running and not bit:continue
   if not running and count>=((limit-1)&0xffffffff) and boot is None:continue
   if count>=limit:break
   ordinal=count;at=B.ARRAY+count*136;count+=1;w(B.GLOBALS,4,count);w(at,4,ordinal);w(B.GLOBALS+4,4,max(u(B.GLOBALS+4,4),ordinal))
   die=scalar(p.get('die-id'))&0xffffffff;w(at+0xc,4,die);w(0xfffffe0007ef8bfc,4,max(u(0xfffffe0007ef8bfc,4),die))
   soc=scalar(p.get('soc-die-id'))&0xffffffff;w(at+0x10,4,soc);w(0xfffffe0007ef8c00,4,max(u(0xfffffe0007ef8c00,4),soc))
   physical=scalar(p.get('reg'),MASK)&0xffffffff;w(at+4,4,physical)
   for key,offset in [('l2-cache-size',0x1c),('l2-cache-id',0x20),('l3-cache-size',0x24),('l3-cache-id',0x28)]:w(at+offset,4,scalar(p.get(key))&0xffffffff)
   for key,offset in [('cpu-uttdbg-reg',0x50),('cpu-impl-reg',0x38),('coresight-reg',0x68)]:pair(p.get(key),at+offset)
   kind={0x50:2,0x45:1,0x4d:3}.get(scalar(p.get('cluster-type'))&0xffffffff,0);w(at+0x14,4,kind)
   if scalar(p.get('cluster-power-down')):w(0xfffffe0007ef8c58,4,1)
   pertype=0xfffffe0007ef8c30+kind*4;w(pertype,4,(u(pertype,4)+1)&0xffffffff)
   affinity=(physical>>8)&255;cluster=groups.get(affinity,len(groups));w(at+8,4,cluster);ct=B.CLUSTERS+88*cluster
   type_mask=0xfffffe0007ef8c2c;w(type_mask,4,u(type_mask,4)|(1<<kind))
   if u(ct+8,4):
    old=u(ct+4,4)
    if old!=kind:
     merged=4 if {old,kind}=={2,3} or old==4 and kind in [2,3] else 0xffffffff
     w(ct+4,4,merged)
   else:
    w(B.GLOBALS+8,4,u(B.GLOBALS+8,4)+1);w(B.GLOBALS+12,4,max(u(B.GLOBALS+12,4),cluster))
    for off,value in [(0,cluster),(4,kind),(0xc,ordinal),(0x18,die),(0x1c,soc)]:w(ct+off,4,value)
    groups[affinity]=cluster;pertype=0xfffffe0007ef8c44+kind*4;w(pertype,4,(u(pertype,4)+1)&0xffffffff)
    for key,offset in [('acc-impl-reg',0x30),('cpm-impl-reg',0x48)]:pair(p.get(key),ct+offset)
   coremax[affinity]=max(coremax.get(affinity,0),physical&255)
   value=scalar(p.get('die-cluster-id'),affinity)&0xffffffff;w(at+0x78,4,value);w(ct+0x20,4,value)
   w(at+0x7c,4,scalar(p.get('cluster-core-id'),physical&255)&0xffffffff);w(at+0x80,1,255)
   w(ct+8,4,u(ct+8,4)+1);w(ct+0x10,8,u(ct+0x10,8)|(1<<(ordinal&63)))
   if running:boot=ordinal;w(B.RECORD_PTR,8,at);w(B.RECORD_PTR+8,8,ct)
   expected_calls.append(physical);admitted.append({'node_index':node_index,'ordinal':ordinal,'physical_reg':physical,'cluster_index':cluster,'running_comparison':running})
  position=0
  for affinity in range(3):
   if affinity in groups:w(0xfffffe0007ef8c78+affinity*8,8,position);position+=coremax[affinity]+1
  chip=255
  if c.get('tree_initialized',True):
   w(0xfffffe000cba40e8,8,TREE)
   if c.get('io_found',False) and c.get('chip') is not None:chip=scalar(c['chip'])&0xffffffff
  w(0xfffffe0007ef8c28,4,chip)
  if 'enable_skstb' in options or 'enable_skstsct' in options:w(0xfffffe0007ef8c58,4,0)
  if 'cluster_power' in options:w(0xfffffe0007ef8c58,4,options['cluster_power'])
  if boot is not None:
   at=B.ARRAY+boot*136;system.update(tpidr_el0=(boot&4095)|((u(at+8,4)&255)<<12),tpidrro_el0=0)
 except Diagnostic as error:diagnostic=str(error)
 ok('selector0e_calls_follow_completed_admitted_records',[int(x['physical_reg_low32'],16) for x in row['declared_selector0e_calls']]==expected_calls)
 expected_pc=B.PANIC if diagnostic else (0xfffffe000be83d2c if boot is None else HALT)
 joined=bool(row['source_boot_record_snapshots'])
 if joined:
  ok('original_topology_return_to_main_callsite',diagnostic is None and boot is not None and len(row['source_boot_record_snapshots'])==1)
  first=row['source_boot_record_snapshots'][0];actual=state_at(row,first['before_visit']);ok('source_topology_registers_at_handoff',first['system']==system)
 else:
  actual=pages(row['final_pages']);ok('topology_diagnostic_null_stop_or_original_return',int(row['boundary']['PC'],16)==expected_pc);ok('topology_final_system_values',row['final_system']==system)
 byte_count=0
 for pg in memory:
  if pg==P+0xe000:continue
  ok('topology_nonstack_page_'+hex(pg),memory[pg]==actual[pg]);byte_count+=4096
 nested=None;post_bytes=0;control=None
 if joined:
  control=options.get('siq_realtime_thread_mode',u(R.CONTROL,4))
  if 'siq_realtime_thread_mode' in options:w(R.CONTROL,4,control)
  if control>=4:
   diagnostic='post_enumeration_control_out_of_range';ok('post_helper_diagnostic_before_system_write',int(row['boundary']['PC'],16)==B.PANIC and not row['source_main_continuation_checkpoints'] and not row['epochs'] and row['final_system']==system);actual=pages(row['final_pages'])
  else:
   system['s3_4_c15_c10_4']=0;ok('original_post_helper_return_enters_bootstrap_source',len(row['source_main_continuation_checkpoints'])==1 and len(row['epochs'])==1)
   checkpoint=row['source_main_continuation_checkpoints'][0];ok('post_helper_logical_system_result',checkpoint['system']==system);actual=state_at(row,checkpoint['before_visit'])
  for pg in memory:
   if pg==P+0xe000:continue
   ok('post_helper_nonstack_page_'+hex(pg),memory[pg]==actual[pg]);post_bytes+=4096
 if joined and control<4:
  at=B.ARRAY+boot*136;synthetic=dict(row);synthetic.update(configuration=dict(phase='bootstrap',ordinal=boot,physical=u(at+4,4),cluster=u(at+8,4),virt_base=0xfffffe0007000000,phys_base=0x80000000),
   initial_pages=[{'address':hex(pg),'bytes_hex':bytes(raw).hex()} for pg,raw in sorted(memory.items())],initial_system=system,
   epochs=row['epochs'],declared_models=[m for m in row['declared_models'] if int(m['PC'],16) in [B.SPTM,B.CACHE,B.CONFIG]])
  nested=thread_oracle(synthetic)
 return {'checks':checks,'independent_topology_nonstack_bytes_checked':byte_count,'independent_post_helper_nonstack_bytes_checked':post_bytes,'completed_admitted_records':admitted,
  'selected_boot_ordinal':boot,'diagnostic_reason':diagnostic,'post_helper_control_value':control,'thread_handoff_oracle':nested}

class Replay(Parent):
 def __init__(self,image,row):
  super().__init__(image,row);self.iterator=0;self.comparisons=[];self.wrapper_calls=[];self.boot_snapshots=[];self.main_snapshots=[]
 def text(self,a):return bytes(self.u.mem_read(a,80)).split(bytes(1))[0].decode('ascii')
 def code(self,u,a,n,d):
  self.finish()
  if a==0xfffffe000c639cbc:
   self.boot_snapshots.append({'PC':hex(a),'before_visit':self.seq,'record_pointer':hex(int.from_bytes(u.mem_read(B.RECORD_PTR,8),'little')),'system':dict(self.system)})
  if a==0xfffffe000c639cc0:self.main_snapshots.append({'PC':hex(a),'before_visit':self.seq,'system':dict(self.system)})
  if self.epoch<len(self.row['epochs']) and a==int(self.row['epochs'][self.epoch]['PC'],16):
   e=self.row['epochs'][self.epoch];assert e['before_visit']==self.seq and e['writes_completed']==self.wi and e['system']==self.system and e['registers']==list(map(hex,self.regs()))
   assert e['kind']=='bootstrap_to_CPU_caller_cut' and a==0xfffffe000c639dd8 and int(e['next_PC'],16)==B.CALLER
   self.epoch+=1;u.reg_write(ar.UC_ARM64_REG_SP,SP);u.reg_write(regno(30),HALT);u.reg_write(ar.UC_ARM64_REG_PC,int(e['next_PC'],16));return
  if self.mi<len(self.row['declared_models']) and a==int(self.row['declared_models'][self.mi]['PC'],16) and a in [R.PARSE,R.LOOKUP,R.ITERATE,R.PROPERTY,R.FIND,R.WRAPPER]:
   m=self.row['declared_models'][self.mi];before=self.regs();c=self.row['configuration'];expected=[];result=0
   assert m['before_visit']==self.seq and m['registers_before']==list(map(hex,before)) and m['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP))
   if a==R.PARSE:
    assert m['name']=='declared_boot_option_output' and before[0]==B.ARGS+0x6c
    name=self.text(before[1]);assert name in ['cpus','cpumask','enable_skstb','enable_skstsct','cluster_power','siq_realtime_thread_mode'];options=c.get('options',{});result=int(name in options)
    size={'cpus':4,'cpumask':8,'enable_skstb':0,'enable_skstsct':0,'cluster_power':4,'siq_realtime_thread_mode':4}[name];assert before[3:5]==[size,0]
    if name=='siq_realtime_thread_mode':assert before[2]==R.CONTROL
    if result and size:expected=[(before[2],options[name].to_bytes(size,'little'))]
   elif a==R.LOOKUP:
    assert m['name']=='declared_CPU_node_lookup_output' and before[0]==0 and self.text(before[1])=='/cpus' and before[2]==SP-0xd0
    result=int(c.get('lookup_found',True))
    if result:expected=[(before[2],ROOT_NODE.to_bytes(8,'little'))]
   elif a==R.ITERATE:
    assert m['name']=='declared_child_iterator_output' and before[:2]==[SP-0x100,SP-0xd8]
    root=ROOT_NODE if c.get('lookup_found',True) else TREE;state=(root.to_bytes(8,'little')*2+bytes(24)) if c.get('tree_initialized',True) else bytes(40)
    assert bytes(u.mem_read(before[0],40))==state
    result=int(self.iterator<len(c['nodes']))
    if result:expected=[(before[1],(CHILD+self.iterator*32).to_bytes(8,'little'))]
    self.iterator+=1
   elif a==R.PROPERTY:
    assert m['name']=='declared_tree_property_output';name=self.text(before[1]);node=before[0]
    if node==IO_NODE:assert name=='chip-revision';p=c.get('chip');slot=TREE+0x3000
    else:
     index=(node-CHILD)//32;assert 0<=index<len(c['nodes']) and node==CHILD+index*32 and name in KEYS
     p=c['nodes'][index].get(name);slot=TREE+0x4000+index*0x800+KEYS.index(name)*64+3
    result=int(p is not None)
    if result:
     raw=bytes.fromhex(p['bytes_hex']);assert bytes(u.mem_read(slot,len(raw)))==raw
     expected=[(before[2],slot.to_bytes(8,'little')),(before[3],p['size_bytes'].to_bytes(4,'little'))]
    assert before[4:6]==[TREE,TREE_SIZE]
   elif a==R.FIND:
    assert m['name']=='declared_named_IO_node_output' and self.text(before[0])=='name' and self.text(before[1])=='arm-io'
    result=int(c.get('io_found',False))
    if result:expected=[(before[2],IO_NODE.to_bytes(8,'little'))]
   else:
    assert m['name']=='declared_selector0e_wrapper_no_RAM_return'
    self.wrapper_calls.append({'PC':hex(a),'physical_reg_low32':hex(before[0]),'before_visit':self.seq})
   assert len(expected)==len(m['api_writes'])
   for w,(at,data) in zip(m['api_writes'],expected):
    assert w=={'address':hex(at),'before_hex':bytes(u.mem_read(at,len(data))).hex(),'after_hex':data.hex()};u.mem_write(at,data)
   for j in range(18):u.reg_write(regno(j),result if j==0 else ((j+1)*0x123456789abcdef^(self.mi+1)*0x8b3dc651)&MASK)
   u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000 if self.mi%2==0 else 0)
   assert m['registers_after']==list(map(hex,self.regs())) and m['return_value']==hex(result) and m['NZCV_after']==hex(u.reg_read(ar.UC_ARM64_REG_NZCV))
   self.mi+=1;u.reg_write(ar.UC_ARM64_REG_PC,before[30]);return
  if a==R.COMPARE:self.comparisons.append({'PC':hex(a),'arguments3':list(map(hex,self.regs()[:3])),'before_visit':self.seq})
  return super().code(u,a,n,d)
 def run(self):
  counts=super().run();assert self.comparisons==self.row['original_comparison_entries'] and self.wrapper_calls==self.row['declared_selector0e_calls'] and self.boot_snapshots==self.row['source_boot_record_snapshots'] and self.main_snapshots==self.row['source_main_continuation_checkpoints']
  return {**counts,'original_comparison_entries_checked':len(self.comparisons),'declared_selector0e_calls_checked':len(self.wrapper_calls),'source_boot_record_handoffs_checked':len(self.boot_snapshots),'original_post_helper_returns_checked':len(self.main_snapshots)}
