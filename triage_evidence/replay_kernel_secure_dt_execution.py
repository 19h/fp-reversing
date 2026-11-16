#!/usr/bin/env python3
"""Independent serialized-tree decoder, record formulas and fresh replay.
No executor import. O(visits + journals + mapped bytes + tree bytes) space;
phase materialization adds O(journals log journals) time. No native claim.
"""
from unicorn import arm64_const as ar
from replay_kernel_boot_cpu_identity import pages,get,put,oracle as thread_oracle,P,SP,HALT,MASK,regno
from replay_kernel_cpu_topology_handoff import Replay as Parent,state_at,Diagnostic
import recover_kernel_secure_dt_execution as R
B=R.B.B;TREE=P+0x10000;WORK=P+0x6000;LIMIT=100000
def topology_oracle(row,parsed):
 c=dict(row['configuration']);c['nodes']=parsed['CPU_properties'];memory=pages(row['initial_pages']);checks=[];system=dict(row['initial_system']);expected_calls=[];admitted=[];boot=None;groups={};coremax={};count=0
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
 w(R.GLOBALS,8,TREE);w(R.GLOBALS+8,8,row['fixture_extent_bytes']);w(R.GLOBALS+16,8,TREE+row['fixture_extent_bytes']);w(R.GLOBALS+24,4,1)
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
   w(0xfffffe000cba40e8,8,parsed['named_scan_final_cursor'])
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
  control=options.get('siq_realtime_thread_mode',u(R.B.CONTROL,4))
  if 'siq_realtime_thread_mode' in options:w(R.B.CONTROL,4,control)
  if control>=4:
   diagnostic='post_enumeration_control_out_of_range';ok('post_helper_diagnostic_before_system_write',int(row['boundary']['PC'],16)==B.PANIC and not row['source_main_continuation_checkpoints'] and not row['epochs'] and row['final_system']==system);actual=pages(row['final_pages'])
  else:
   system['s3_4_c15_c10_4']=0;ok('original_post_helper_return_enters_bootstrap_source',len(row['source_main_continuation_checkpoints'])==1 and len(row['epochs'])==2)
   checkpoint=row['source_main_continuation_checkpoints'][0];ok('post_helper_logical_system_result',checkpoint['system']==system);actual=state_at(row,checkpoint['before_visit'])
  for pg in memory:
   if pg==P+0xe000:continue
   ok('post_helper_nonstack_page_'+hex(pg),memory[pg]==actual[pg]);post_bytes+=4096
 if joined and control<4:
  at=B.ARRAY+boot*136;synthetic=dict(row);synthetic.update(configuration=dict(phase='bootstrap',ordinal=boot,physical=u(at+4,4),cluster=u(at+8,4),virt_base=0xfffffe0007000000,phys_base=0x80000000),
   initial_pages=[{'address':hex(pg),'bytes_hex':bytes(raw).hex()} for pg,raw in sorted(memory.items())],initial_system=system,
   epochs=row['epochs'][1:],declared_models=[m for m in row['declared_models'] if int(m['PC'],16) in [B.SPTM,B.CACHE,B.CONFIG]])
  nested=thread_oracle(synthetic)
 return {'checks':checks,'independent_topology_nonstack_bytes_checked':byte_count,'independent_post_helper_nonstack_bytes_checked':post_bytes,'completed_admitted_records':admitted,
  'selected_boot_ordinal':boot,'diagnostic_reason':diagnostic,'post_helper_control_value':control,'thread_handoff_oracle':nested}
def decode(row):
 memory=pages(row['initial_pages']);end=TREE+row['fixture_extent_bytes'];nodes={};order=[];checks=[]
 def read(a,n):assert TREE<=a<=a+n<=end;return get(memory,a,n)
 def node(a,path):
  start=a;count=int.from_bytes(read(a,4),'little');children=int.from_bytes(read(a+4,4),'little');a+=8;props=[]
  for _ in range(count):
   raw=read(a,32);assert bytes(1) in raw;name=raw.split(bytes(1))[0].decode('ascii');size=int.from_bytes(read(a+32,4),'little');value=read(a+36,size)
   props.append({'key':name,'value':value,'size':size,'data':a+36,'next':a+36+((size+3)//4)*4});a=props[-1]['next']
  current={'start':start,'properties':props,'children':[]};nodes[path]=current;order.append(current)
  for _ in range(children):
   # Every selected fixture supplies its first property as the node name.
   assert read(a+8,32).split(bytes(1))[0]==b'name';n=int.from_bytes(read(a+40,4),'little');name=read(a+44,n).split(bytes(1))[0].decode('ascii')
   child_path=path.rstrip('/')+'/'+name;child_end=node(a,child_path);current['children'].append(nodes[child_path]);a=child_end
  current['end']=a;return a
 assert node(TREE,'/')==end
 assert {k:hex(v['start']) for k,v in nodes.items()}==row['fixture_node_addresses']
 def props(n):return {p['key']:{'bytes_hex':p['value'].hex(),'size_bytes':p['size']} for p in reversed(n['properties'])}
 root=nodes.get('/cpus',nodes['/']);cpu=[props(n) for n in root['children']]
 scan=end
 for n in order:
  match=next((p for p in n['properties'] if p['key']=='name' and p['value'].split(bytes(1))[0]==b'arm-io'),None)
  if match is not None:scan=match['next'];break
 return {'nodes':nodes,'order':order,'CPU_properties':cpu,'named_scan_final_cursor':scan,'serialized_bytes':end-TREE,'node_count':len(nodes),'property_count':sum(len(n['properties']) for n in order)}
def oracle(row):
 parsed=decode(row);initial=pages(row['initial_pages']);checks=[];api=API_oracle(row,parsed)
 def ok(label,predicate):assert predicate,('semantic_oracle',label);checks.append(label)
 expected=pages(row['initial_pages'])
 for at,n,v in [(R.GLOBALS,8,TREE),(R.GLOBALS+8,8,row['fixture_extent_bytes']),(R.GLOBALS+16,8,TREE+row['fixture_extent_bytes']),(R.GLOBALS+24,4,1)]:put(expected,at,n,v)
 checkpoint=row['tree_initializer_return'];actual=state_at(row,checkpoint['before_visit'])
 ok('original_initializer_returns_before_explicit_call_epoch',row['epochs'][0]['PC']==hex(HALT) and row['epochs'][0]['before_visit']==checkpoint['before_visit'])
 ok('original_initializer_publishes_exact_base_size_end_and_flag',get(actual,R.GLOBALS,32)==get(expected,R.GLOBALS,32) and checkpoint['global_bytes_hex']==get(expected,R.GLOBALS,32).hex())
 ok('no_modeled_tree_API_returns',not {int(m['PC'],16) for m in row['declared_models']}&{R.INIT,R.B.LOOKUP,R.B.PROPERTY,R.B.ITERATE,R.B.FIND,R.SKIP,R.STRCMP})
 if not row['configuration'].get('operations'):
  topology=topology_oracle(row,parsed);checks+=topology['checks']
  return {'checks':checks,'original_API_contracts':api,'independent_initializer_bytes_checked':32,'tree':{k:v for k,v in parsed.items() if k not in ['nodes','order','CPU_properties']},'topology':{k:v for k,v in topology.items() if k!='checks'}}
 bytes_checked=0;returns=row['tree_API_returns'];ops=row['configuration']['operations'];ok('all_explicit_API_calls_return',len(returns)==len(ops))
 for index,(op,result) in enumerate(zip(ops,returns)):
  found=None;target=parsed['nodes'].get(op.get('node','/'));kind=op['kind'];status=0xffffffff
  if kind=='lookup':
   # This fixture domain has nonempty components <=63 B and at most one leading slash.
   path=op['path'];base=op.get('node','/') if op.get('relative') else '/';path=base.rstrip('/')+'/'+path.lstrip('/');path=path.rstrip('/') or '/';found=parsed['nodes'].get(path)
   if found is not None:put(expected,WORK,8,found['start']);status=1
  elif kind=='property':
   found=next((p for p in target['properties'] if p['key']==op['key']),None)
   if found is not None:put(expected,WORK,8,found['data']);put(expected,WORK+8,4,found['size']);status=1
  elif kind=='skip':status=target['end']
  else:raise AssertionError(kind)
  ok('API_return_'+str(index),int(result['registers'][0],16)==status)
  ok('API_workspace_'+str(index),result['workspace_hex']==get(expected,WORK,0x200).hex())
  actual=state_at(row,result['before_visit'])
  for pg in expected:
   if pg==P+0xe000:continue
   ok('API_nonstack_'+str(index)+'_'+hex(pg),expected[pg]==actual[pg]);bytes_checked+=4096
 ok('API_final_halt',int(row['boundary']['PC'],16)==HALT and row['final_system']==row['initial_system'])
 return {'checks':checks,'original_API_contracts':api,'independent_initializer_bytes_checked':32,'independent_API_nonstack_bytes_checked':bytes_checked,'tree':{k:v for k,v in parsed.items() if k not in ['nodes','order','CPU_properties']},'topology':None}
class Replay(Parent):
 def __init__(self,image,row):
  super().__init__(image,row);self.native_entries=[];self.tree_call_returns=[];self.active_calls=[];self.api_returns=[];self.init_checkpoint=None;self.stage='tree_initializer'
 def code(self,u,a,n,d):
  self.finish()
  while self.active_calls and a==int(self.native_entries[self.active_calls[-1]]['return_PC'],16) and u.reg_read(ar.UC_ARM64_REG_SP)==int(self.native_entries[self.active_calls[-1]]['entry_SP'],16):
   self.tree_call_returns.append({'entry_index':self.active_calls.pop(),'before_visit':self.seq,'return_value':hex(self.regs()[0])})
  if a==HALT:
   if self.init_checkpoint is None:
    self.init_checkpoint={'PC':hex(a),'before_visit':self.seq,'global_bytes_hex':bytes(u.mem_read(R.GLOBALS,32)).hex(),'registers':list(map(hex,self.regs()))};self.stage='API' if self.row['configuration'].get('operations') else 'enumeration'
   elif self.stage=='API':self.api_returns.append({'operation':len(self.api_returns),'PC':hex(a),'before_visit':self.seq,'registers':list(map(hex,self.regs())),'workspace_hex':bytes(u.mem_read(WORK,0x200)).hex()})
  if self.epoch<len(self.row['epochs']):
   e=self.row['epochs'][self.epoch]
   if a==int(e['PC'],16) and self.seq==e['before_visit']:
    assert e['writes_completed']==self.wi and e['system']==self.system and e['registers']==list(map(hex,self.regs()))
    assert e['kind'] in ['explicit_tree_API_call','tree_initializer_to_main_cut','bootstrap_to_CPU_caller_cut']
    self.epoch+=1;u.reg_write(ar.UC_ARM64_REG_SP,SP);u.reg_write(regno(30),HALT)
    for j,v in enumerate(e['arguments']):u.reg_write(regno(j),int(v,16))
    u.reg_write(ar.UC_ARM64_REG_PC,int(e['next_PC'],16));return
  if a in [R.INIT,R.B.LOOKUP,R.B.PROPERTY,R.B.ITERATE,R.B.FIND,R.SKIP,R.STRCMP]:
   self.active_calls.append(len(self.native_entries));self.native_entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':list(map(hex,self.regs()[:6])),'return_PC':hex(self.regs()[30]),'before_visit':self.seq})
  return super().code(u,a,n,d)
 def run(self):
  self.u.emu_start(int(self.row['start'],16),0,count=LIMIT);self.finish();assert self.stopped
  assert (self.ri,self.wi,self.mi,self.ei,self.epoch)==tuple(len(self.row[k]) for k in ['reads','writes','declared_models','logical_effects','epochs'])
  assert self.system==self.row['final_system'] and self.copy_entries==self.row['original_copy_entries']
  assert self.comparisons==self.row['original_comparison_entries'] and self.wrapper_calls==self.row['declared_selector0e_calls'] and self.boot_snapshots==self.row['source_boot_record_snapshots'] and self.main_snapshots==self.row['source_main_continuation_checkpoints']
  assert self.tree_call_returns==self.row['original_tree_call_returns'] and not self.active_calls
  assert self.native_entries==self.row['original_tree_API_entries'] and self.api_returns==self.row['tree_API_returns'] and self.init_checkpoint==self.row['tree_initializer_return']
  for pg,raw in pages(self.row['final_pages']).items():assert bytes(self.u.mem_read(pg,4096))==raw
  return {'source_visits_checked':self.seq,'reads_checked':self.ri,'writes_checked':self.wi,'declared_models_checked':self.mi,'logical_effects_checked':self.ei,'same_RAM_epochs_checked':self.epoch,'whole_mapped_bytes_checked':len(self.row['final_pages'])*4096,'original_tree_API_entries_checked':len(self.native_entries),'original_tree_call_returns_checked':len(self.tree_call_returns),'original_tree_API_returns_checked':len(self.api_returns),'tree_initializer_returns_checked':1}
def API_oracle(row,parsed):
 """Validate each nested API call against decoded records and journal state.
 O(J log J + A + string/property work) time, O(J + A + M) space.
 """
 memory=pages(row['initial_pages']);nodes={n['start']:n for n in parsed['order']};events=[];checks=[];obligations={};hist={}
 def ok(label,p):assert p,('semantic_oracle',label);checks.append(label)
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def string(a):
  raw=bytearray()
  for j in range(256):
   v=u(a+j,1)
   if v==0:return bytes(raw)
   raw.append(v)
  raise AssertionError('fixture_string_not_terminated')
 for j,w in enumerate(row['writes']):events.append((w['visit'],2,j,'write',w))
 for j,m in enumerate(row['declared_models']):
  for k,w in enumerate(m['api_writes']):events.append((m['before_visit'],2,j*4+k,'write',w))
 for j,e in enumerate(row['original_tree_API_entries']):events.append((e['before_visit'],1,j,'entry',e))
 for j,e in enumerate(row['original_tree_call_returns']):events.append((e['before_visit'],0,j,'return',e))
 for _,_,index,kind,e in sorted(events,key=lambda x:x[:3]):
  if kind=='write':raw=bytes.fromhex(e['after_hex']);put(memory,int(e['address'],16),len(raw),raw);continue
  if kind=='return':
   expected,out=obligations.pop(e['entry_index']);ok('API_status_'+str(e['entry_index']),int(e['return_value'],16)==expected)
   for j,(at,raw) in enumerate(out):ok('API_output_'+str(e['entry_index'])+'_'+str(j),get(memory,at,len(raw))==raw)
   continue
  a=int(e['PC'],16);args=list(map(lambda x:int(x,16),e['arguments6']));hist[hex(a)]=hist.get(hex(a),0)+1;out=[]
  def output(at,n,value):out.append((at,value.to_bytes(n,'little') if isinstance(value,int) else value))
  if a==R.INIT:
   status=0 # Native void-like leaf leaves X0 equal to its incoming base.
   status=args[0];output(R.GLOBALS,8,args[0]);output(R.GLOBALS+8,8,args[1]);output(R.GLOBALS+16,8,args[0]+args[1]);output(R.GLOBALS+24,4,int(args[0]!=0))
  elif a==R.STRCMP:
   x,y=string(args[0])+bytes(1),string(args[1])+bytes(1);status=0
   for left,right in zip(x,y):
    if left!=right:status=((left if left<128 else left-256)-(right if right<128 else right-256))&0xffffffff;break
  elif a==R.SKIP:status=nodes[args[0]]['end']
  elif a==R.B.PROPERTY:
   ok('property_bounds_'+str(index),args[4:6]==[TREE,row['fixture_extent_bytes']]);n=nodes.get(args[0]);name=string(args[1]);p=next((p for p in n['properties'] if p['key'].encode()==name),None) if n else None
   status=1 if p else 0xffffffff;output(args[2],8,p['data'] if p else u(args[2],8));output(args[3],4,p['size'] if p else u(args[3],4))
  elif a==R.B.LOOKUP:
   root=nodes[args[0] or TREE];path=string(args[1]).decode('ascii');parts=path[1:] if path.startswith('/') else path;cur=root;status=1
   for part in parts.rstrip('/').split('/') if parts.rstrip('/') else []:
    cur=next((n for n in cur['children'] if next((p['value'].split(bytes(1))[0].decode('ascii') for p in n['properties'] if p['key']=='name'),None)==part),None)
    if cur is None:status=0xffffffff;break
   output(args[2],8,cur['start'] if cur else u(args[2],8))
  elif a==R.B.ITERATE:
   raw=bytearray(get(memory,args[0],40));root=nodes[u(args[0]+8,8)];ordinal=u(args[0]+32,8)
   if ordinal>=len(root['children']):status=0;output(args[1],8,0)
   else:
    status=1;child=root['children'][ordinal]['start'];raw[32:40]=(ordinal+1).to_bytes(8,'little');raw[16:24]=child.to_bytes(8,'little');output(args[1],8,child)
   output(args[0],40,bytes(raw))
  elif a==R.B.FIND:
   root=nodes[u(R.CURSOR,8)];key=string(args[0]);value=string(args[1]) if args[1] else None;match=None;cursor=root['end']
   for n in parsed['order']:
    if not root['start']<=n['start']<root['end']:continue
    p=next((p for p in n['properties'] if p['key'].encode()==key and (value is None or p['value'].split(bytes(1))[0]==value)),None)
    if p:match=n;cursor=p['next'];break
   status=1 if match else 0xffffffff;output(args[2],8,match['start'] if match else u(args[2],8));output(R.CURSOR,8,cursor)
  else:raise AssertionError(hex(a))
  obligations[index]=(status,out)
 ok('all_original_API_calls_returned',not obligations and len(row['original_tree_API_entries'])==len(row['original_tree_call_returns']))
 return {'checks':checks,'API_calls':len(row['original_tree_API_entries']),'entry_histogram':hist}
