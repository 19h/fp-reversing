#!/usr/bin/env python3
"""Independent prefix, topology, thread formulas and whole-state source replay.
O(visits+journals+RAM) space; timeline sorting O(J log J). No executor import.
"""
from hashlib import sha256
from unicorn import arm64_const as ar
from probe_rpc502_vm_handoff import decode as uncompress
from replay_kernel_boot_cpu_identity import pages,get,put
import replay_kernel_platform_environment_execution as B
from replay_kernel_vm_mig import Replay as Core
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
import json
import recover_kernel_bootstrap_state_composition as R
K=R.K;T=R.T;P=B.P;SIZE=B.SIZE;SP=B.SP;MASK=(1<<64)-1
NEW_APIS=[K.ENUM,K.SCALAR,K.SETTER,T.POST]
LEAVES={**B.LEAVES,T.WRAPPER:'declared_selector0e_wrapper_no_RAM_return'}

def prefix_row(row):
 c=row['pre_enumeration_checkpoint'];end=c['before_visit'];out=dict(row)
 for key in ['source_visits']:out[key]=row[key][:end]
 for key in ['source_reads','source_writes']:out[key]=[w for w in row[key] if w['source_visit_index']<end]
 out['API_models']=[m for m in row['API_models'] if m['before_source_visit_index']<end]
 out['logical_effects']=[m for m in row['logical_effects'] if m['before_visit']<end]
 out['original_API_entries']=[m for m in row['original_API_entries'] if m['before_visit']<end]
 out['original_API_returns']=[m for m in row['original_API_returns'] if m['before_visit']<=end]
 out.update(final_private_RAM=c['private_RAM'],final_image_globals=c['image_globals'],final_system=c['system'],final_vectors=c['vectors'],boundary={'pc':c['PC'],'kind':'original_main_reaches_CPU_enumeration_call','registers31':c['registers31'],'SP':c['SP'],'NZCV':c['NZCV']})
 return out

def copy_contracts(row,old):
 memory=pages(old['initial_pages']);events=[];pending={};checks=[];calls=0;copied=0
 for j,w in enumerate(row['source_writes']):events.append((w['source_visit_index'],2,j,'write',w))
 for j,e in enumerate(row['original_API_entries']):
  if int(e['PC'],16) in [K.COPY,R.B.E.STRLCPY]:events.append((e['before_visit'],1,j,'entry',e))
 for j,e in enumerate(row['original_API_returns']):
  if int(row['original_API_entries'][e['entry_index']]['PC'],16) in [K.COPY,R.B.E.STRLCPY]:events.append((e['before_visit'],0,j,'return',e))
 def ok(label,p):assert p,('copy_contract',label);checks.append(label)
 for _,_,index,kind,e in sorted(events,key=lambda x:x[:3]):
  if kind=='write':raw=bytes.fromhex(e['after_hex']);put(memory,int(e['address'],16),len(raw),raw);continue
  if kind=='entry':
   a,b,n=[int(x,16) for x in e['arguments6'][:3]];assert 0<=n<=1472;calls+=1
   if int(e['PC'],16)==K.COPY:expected=get(memory,b,n);result=a
   else:
    text=bytearray()
    for j in range(512):
     v=get(memory,b+j,1)
     if v==b'\0':break
     text+=v
    else:raise AssertionError('unterminated_private_string')
    result=len(text);expected=bytes(text[:max(n-1,0)])+b'\0' if n else b''
   pending[index]=(a,expected,result);continue
  a,raw,result=pending.pop(e['entry_index']);ok('return_'+str(e['entry_index']),int(e['return_value'],16)==result);ok('destination_'+str(e['entry_index']),get(memory,a,len(raw))==raw);copied+=len(raw)
 ok('all_copy_calls_returned',not pending)
 return {'checks':checks,'calls':calls,'destination_bytes_checked':copied}

def oracle(row,e):
 prefix=B.oracle(prefix_row(row),json.loads(read(ROOT/(R.B.P+'_checks.json'))));old=B.legacy(row);tree=B.decode_tree(old);tree_checks=B.tree_contracts(old,tree);option_checks=B.option_oracle(old);copies=copy_contracts(row,old)
 memory=pages(old['initial_pages']);cut=row['pre_enumeration_checkpoint'];checks=[];system=dict(cut['system']);compared=0
 raw=uncompress(cut['private_RAM'])
 for j in range(0,SIZE,4096):memory[P+j]=bytearray(raw[j:j+4096])
 for region in cut['image_globals']:put(memory,int(region['address'],16),len(bytes.fromhex(region['bytes_hex'])),bytes.fromhex(region['bytes_hex']))
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def w(a,n,v):put(memory,a,n,v)
 def ok(label,p):assert p,('composition_contract',label,row['configuration']['label']);checks.append(label)
 for r in cut['additional_image_globals']:ok('additional_storage_unmodified_before_enumeration_'+r['address'],get(memory,int(r['address'],16),len(bytes.fromhex(r['bytes_hex']))).hex()==r['bytes_hex'])
 def compare(snapshot,label):
  nonlocal compared
  for r in snapshot['image_globals']+snapshot.get('additional_image_globals',[]):
   a=int(r['address'],16);raw=bytes.fromhex(r['bytes_hex']);ok(label+'_'+r['address'],get(memory,a,len(raw))==raw);compared+=len(raw)
  ok(label+'_system',snapshot['system']==system)
 def final_snapshot():return {'image_globals':row['final_image_globals'],'system':row['final_system']}
 text=get(memory,K.ARGS+0x6c,256);options={}
 for key,width in [('cpus',4),('cpumask',8),('enable_skstb',0),('enable_skstsct',0),('cluster_power',4),('siq_realtime_thread_mode',4)]:
  found,value=B.parse(text,key.encode(),width,0,bytes(width))
  if found:options[key]=int.from_bytes(value,'little') if width else 1
 def scalar(node,key,default=0):
  p=next((p for p in node['properties'] if p['key']==key),None)
  if p is None:return default
  assert len(p['value']) in [1,2,4,8];return int.from_bytes(p['value'],'little')
 def pair(node,key,address):
  p=next((p for p in node['properties'] if p['key']==key),None)
  if p:assert len(p['value'])==16;w(address,16,p['value'])
 def running(node):
  p=next(p for p in node['properties'] if p['key']=='state');data=p['value'];reference=b'running\0';assert len(data)<=8
  for x,y in zip(data,reference):
   if x!=y:return False
   if x==0:return True
  return True
 limit=options.get('cpus',16);mask=options.get('cpumask',MASK);count=0;boot=None;groups={};coremax={};admitted=[];expected_calls=[]
 ok('original_counter_and_boot_pointer_initializers',u(K.GLOBALS,16)==0 and u(K.RECORD_PTR,16)==0)
 if 'cpus' in options and 'cpumask' in options:w(K.ARRAY-4,1,0)
 if 'cpus' in options or 'cpumask' in options:w(K.ARRAY-3,1,1)
 for a in [0xfffffe0007ef8c78,0xfffffe0007ef8c80,0xfffffe0007ef8c88]:w(a,8,MASK)
 zero_pointer=False
 for index,node in enumerate(tree['nodes']['/cpus']['children']):
  match=running(node);bit=mask&1;mask>>=1
  if match and not bit:w(K.ARRAY-4,1,0)
  if not match and not bit:continue
  if not match and count>=((limit-1)&0xffffffff) and boot is None:continue
  if count>=limit:break
  ordinal=count;at=u(K.GLOBALS+0x1c,8)+136*ordinal;count+=1;w(K.GLOBALS,4,count)
  if at==0:zero_pointer=True;break
  assert at==K.ARRAY+136*ordinal and ordinal<16;w(at,4,ordinal);w(K.GLOBALS+4,4,max(u(K.GLOBALS+4,4),ordinal))
  die=scalar(node,'die-id')&0xffffffff;soc=scalar(node,'soc-die-id')&0xffffffff;physical=scalar(node,'reg',MASK)&0xffffffff
  for address,value in [(at+0xc,die),(at+0x10,soc),(at+4,physical)]:w(address,4,value)
  w(0xfffffe0007ef8bfc,4,max(u(0xfffffe0007ef8bfc,4),die));w(0xfffffe0007ef8c00,4,max(u(0xfffffe0007ef8c00,4),soc))
  for key,offset in [('l2-cache-size',0x1c),('l2-cache-id',0x20),('l3-cache-size',0x24),('l3-cache-id',0x28)]:w(at+offset,4,scalar(node,key)&0xffffffff)
  for key,offset in [('cpu-uttdbg-reg',0x50),('cpu-impl-reg',0x38),('coresight-reg',0x68)]:pair(node,key,at+offset)
  kind={0x50:2,0x45:1,0x4d:3}.get(scalar(node,'cluster-type')&0xffffffff,0);w(at+0x14,4,kind)
  if scalar(node,'cluster-power-down'):w(0xfffffe0007ef8c58,4,1)
  a=0xfffffe0007ef8c30+kind*4;w(a,4,(u(a,4)+1)&0xffffffff)
  affinity=(physical>>8)&255;assert affinity<3;cluster=groups.get(affinity,len(groups));ct=u(K.GLOBALS+0x24,8)+88*cluster;assert ct==K.CLUSTERS+88*cluster
  w(at+8,4,cluster);w(0xfffffe0007ef8c2c,4,u(0xfffffe0007ef8c2c,4)|(1<<kind))
  if u(ct+8,4):
   prior=u(ct+4,4)
   if prior!=kind:w(ct+4,4,4 if {prior,kind}=={2,3} or prior==4 and kind in [2,3] else 0xffffffff)
  else:
   w(K.GLOBALS+8,4,u(K.GLOBALS+8,4)+1);w(K.GLOBALS+12,4,max(u(K.GLOBALS+12,4),cluster));groups[affinity]=cluster
   for offset,value in [(0,cluster),(4,kind),(0xc,ordinal),(0x18,die),(0x1c,soc)]:w(ct+offset,4,value)
   a=0xfffffe0007ef8c44+kind*4;w(a,4,(u(a,4)+1)&0xffffffff)
   for key,offset in [('acc-impl-reg',0x30),('cpm-impl-reg',0x48)]:pair(node,key,ct+offset)
  coremax[affinity]=max(coremax.get(affinity,0),physical&255);diecluster=scalar(node,'die-cluster-id',affinity)&0xffffffff
  w(at+0x78,4,diecluster);w(ct+0x20,4,diecluster);w(at+0x7c,4,scalar(node,'cluster-core-id',physical&255)&0xffffffff);w(at+0x80,1,255)
  w(ct+8,4,u(ct+8,4)+1);w(ct+0x10,8,u(ct+0x10,8)|(1<<(ordinal&63)))
  if match:boot=ordinal;w(K.RECORD_PTR,8,at);w(K.RECORD_PTR+8,8,ct)
  expected_calls.append(physical);admitted.append({'node_index':index,'ordinal':ordinal,'physical_reg':physical,'cluster_index':cluster,'running':match})
 if not zero_pointer:
  position=0
  for affinity in range(3):
   if affinity in groups:w(0xfffffe0007ef8c78+affinity*8,8,position);position+=coremax[affinity]+1
  w(0xfffffe000cba40e8,8,tree['named_scan_final_cursor']);arm=tree['nodes'].get('/bridge/arm-io');w(0xfffffe0007ef8c28,4,scalar(arm,'chip-revision',255)&0xffffffff if arm else 255)
  if 'enable_skstb' in options or 'enable_skstsct' in options:w(0xfffffe0007ef8c58,4,0)
  if 'cluster_power' in options:w(0xfffffe0007ef8c58,4,options['cluster_power'])
  if boot is not None:
   at=K.ARRAY+136*boot;system.update(tpidr_el0=(boot&4095)|((u(at+8,4)&255)<<12),tpidrro_el0=0)
 ok('wrapper_calls_are_zero_extended_stored_reg32',[int(c['arguments8'][0],16) for c in row['declared_selector0e_calls']]==expected_calls)
 control=None;thread=False
 if zero_pointer:
  ok('unchanged_zero_page_stops_before_first_null_record_store',row['boundary']['pc']=='0xfffffe000be83324' and int(row['boundary']['registers31'][26],16)==0 and row['original_enumeration_return'] is None)
 elif boot is None:ok('no_selected_boot_record_stops_before_dereference',row['boundary']['pc']=='0xfffffe000be83d2c' and int(row['boundary']['registers31'][8],16)==0 and row['original_enumeration_return'] is None)
 else:
  compare(row['original_enumeration_return'],'enumeration_return');ok('original_enumeration_return_restores_main_frame',row['original_enumeration_return']['SP']==cut['SP'])
  control=options.get('siq_realtime_thread_mode',u(T.CONTROL,4))
  if 'siq_realtime_thread_mode' in options:w(T.CONTROL,4,control)
  if control>=4:ok('post_helper_diagnostic_precedes_system_write',row['boundary']['pc']==hex(K.PANIC) and row['original_post_helper_return'] is None)
  else:
   system['s3_4_c15_c10_4']=0;compare(row['original_post_helper_return'],'post_helper_return');ok('post_helper_return_restores_main_frame',row['original_post_helper_return']['SP']==cut['SP']);thread=True
   at=K.ARRAY+136*boot;ordinal=u(at,4);w(0xfffffe0007f8b4f0,4,ordinal);w(K.CPU,2,ordinal&65535)
   for offset,value in [(0x10,0xfffffe000cbb4000),(0x20,0xfffffe000cbbc000)]:w(K.CPU+offset,16,value.to_bytes(8,'little')*2)
   w(K.CPU_MAP+16*ordinal+8,8,K.CPU);w(K.CPU_MAP+16*ordinal,8,(u(K.ARGS+16,8)+K.CPU-u(K.ARGS+8,8))&MASK)
   template=bytearray(get(memory,K.TEMPLATE,1472));template[0x328:0x338]=bytes(16);w(K.TEMPLATE,1472,template);w(K.THREAD,1472,template)
   w(K.THREAD+0x214,2,0x5f);w(K.SLOT,8,K.THREAD);w(K.THREAD+0x518,4,0xfffff);w(K.THREAD+0x1b8,8,ordinal&65535);w(K.THREAD+0x1c0,8,K.CPU);w(K.THREAD+0x1c8,4,0);w(K.CPU+0x30,8,K.THREAD)
   system.update(tpidr_el1=K.THREAD,tpidr_el0=(system['tpidr_el0']&0xffff000000000000)|(u(K.CPU+0xa38,8)&0xffffffffffff),tpidrro_el0=u(K.THREAD+0x148,8),contextidr_el1=u(K.THREAD+0x510,8))
   thread_copies=[entry for entry in row['original_API_entries'] if entry['PC']==hex(K.COPY) and int(entry['arguments6'][2],16)==1472]
   ok('one_original_1472_byte_template_copy',len(thread_copies)==1 and thread_copies[0]['arguments6'][:3]==list(map(hex,[K.THREAD,K.TEMPLATE,1472])))
   ok('source_thread_low16_is_selected_admission_ordinal',u(K.THREAD+0x1b8,8)==boot and u(K.THREAD+0x1b8,8)>>16==0)
   ok('stop_before_later_main_callback_setup',row['boundary']['pc']=='0xfffffe000c639dd8')
 compare(final_snapshot(),'final_region')
 before=uncompress(cut['private_RAM']);after=uncompress(row['final_private_RAM']);ok('continuation_preserves_nonstack_private_bytes',before[:SP-P-0x1000]==after[:SP-P-0x1000] and before[SP-P+0x100:]==after[SP-P+0x100:])
 ok('no_call_frame_epoch_or_generic_initializer','epochs' not in row and not any(v['pc']==hex(R.B.E.GENERIC) for v in row['source_visits']))
 ok('declared_returns_only_registration_and_selector0e',all(int(m['pc'],16) in LEAVES and m['symbol']==LEAVES[int(m['pc'],16)] for m in row['API_models']))
 return {'checks':checks,'prefix_contracts':prefix,'tree_API_contracts':tree_checks,'option_API_contracts':option_checks,'copy_contracts':copies,'derived_options':options,'admitted_records':admitted,'selected_boot_ordinal':boot,'post_helper_control':control,'source_thread_setup_complete':thread,'prior_zero_page_null_store_boundary':zero_pointer,'whole_mutable_checkpoint_bytes_checked':compared,'private_nonstack_bytes_checked':SIZE-0x1100}

class Replay(B.Replay):
 def __init__(self,image,row):
  super().__init__(image,row);self.additional_checkpoints=0
  for r in row['initial_image_pages']:
   a=int(r['address'],16);self.ensure(a,4096);assert bytes(self.u.mem_read(a,4096)).hex()==r['bytes_hex']
 def composition_checkpoint(self,c):
  self.checkpoint(c)
  for r in c['additional_image_globals']:assert bytes(self.u.mem_read(int(r['address'],16),len(bytes.fromhex(r['bytes_hex'])))).hex()==r['bytes_hex'];self.counts['whole_checkpoint_additional_image_bytes_checked']+=len(bytes.fromhex(r['bytes_hex']))
  assert c['vectors']==[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)];self.additional_checkpoints+=1
 def code(self,u,a,n,d):
  self.finish()
  while self.active and self.entries[self.active[-1]]['return_PC']==hex(a) and self.entries[self.active[-1]]['entry_SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   self.returns.append({'entry_index':self.active.pop(),'before_visit':self.seq,'return_value':hex(self.reg(0))})
  for pc,key in [(0xfffffe000c639cb8,'pre_enumeration_checkpoint'),(0xfffffe000c639cbc,'original_enumeration_return'),(0xfffffe000c639cc0,'original_post_helper_return')]:
   if a==pc:self.composition_checkpoint(self.p[key])
  if a in NEW_APIS:
   self.active.append(len(self.entries));self.entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':[hex(self.reg(j)) for j in range(6)],'return_PC':hex(self.reg(30)),'before_visit':self.seq})
  if self.mi<len(self.models) and a==int(self.models[self.mi]['pc'],16):
   m=self.models[self.mi];assert a in LEAVES and m['symbol']==LEAVES[a] and m['return_value']=='0x0'
   for j in range(18):assert int(m['after_registers31'][j],16)==(0 if j==0 else (((j+1)*0x123456789abcdef)^((self.mi+1)*0x8b3dc651))&MASK)
   assert int(m['after_NZCV'],16)==(0xf0000000 if (self.mi+1)&1 else 0)
   return Core.code(self,u,a,n,d)
  if self.seq<len(self.p['source_visits']):
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic=='pacda':
    assert raw==self.image.k.read(a,4) and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()}
    event={'PC':hex(a),'kind':'pacda','operands':i.op_str,'before_visit':self.seq,'system_before':dict(self.system),'system_after':dict(self.system),'X16':hex(self.reg(16)),'X17':hex(self.reg(17))};assert event==self.p['logical_effects'][len(self.logical)];self.logical.append(event)
    self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_effects_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  entry=int(self.p['entry_PC'],16);self.ensure(entry);self.u.emu_start(entry,0,count=len(self.p['source_visits'])+len(self.models)+10);self.finish()
  assert self.seq==len(self.p['source_visits']) and self.mi==len(self.models) and self.counts['final_boundaries_checked']==1
  assert self.entries==self.p['original_API_entries'] and self.returns==self.p['original_API_returns'] and self.active==self.p['unfinished_API_entry_indices']
  assert self.additional_checkpoints==1+int(self.p['original_enumeration_return'] is not None)+int(self.p['original_post_helper_return'] is not None) and self.checkpoints==self.additional_checkpoints+2
  assert self.logical==self.p['logical_effects'] and self.system==self.p['final_system']
  assert bytes(self.u.mem_read(P,SIZE))==uncompress(self.p['final_private_RAM']);self.counts['whole_private_bytes_checked']+=SIZE
  assert {hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}==self.p['final_page_sha256'];self.counts['whole_image_page_bytes_checked']+=len(self.pages)*4096
  for j,value in enumerate(self.p['final_vectors']):assert value==hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))));self.counts['vector_registers_checked']+=1
  self.counts['original_API_entries_and_returns_checked']+=len(self.returns);self.counts['unfinished_original_API_entries_checked']+=len(self.active);return dict(self.counts)
