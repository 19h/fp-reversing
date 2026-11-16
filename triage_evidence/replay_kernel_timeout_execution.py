#!/usr/bin/env python3
"""Independent sequential timeout formulas and fresh original replay.
Linear journals/RAM construction; API timeline O(J log J). No executor import.
"""
import bisect,json,struct
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_rpc502_vm_handoff import decode as uncompress
from replay_kernel_boot_cpu_identity import pages,get,put
from replay_kernel_boot_option_execution import parse
from replay_kernel_vm_mig import Replay as Core
import replay_kernel_uuid_formatter_execution as U
import recover_kernel_timeout_execution as R
B=U.B;P=U.P;SIZE=U.SIZE;SP=U.SP;MASK=(1<<64)-1

def prefix(row):
 c=row['phase_two_entry_checkpoint'];end=c['before_visit'];out=dict(row);out['source_visits']=row['source_visits'][:end]
 for k in ['source_reads','source_writes']:out[k]=[v for v in row[k] if v['source_visit_index']<end]
 for k,field in [('API_models','before_source_visit_index'),('logical_effects','before_visit'),('original_call_entries','source_visit_index'),('original_API_entries','before_visit'),('callback_entries','before_visit')]:out[k]=[v for v in row[k] if v[field]<end]
 for k in ['original_API_returns','callback_returns']:out[k]=[v for v in row[k] if v['before_visit']<=end]
 returned={v['entry_index'] for v in out['original_API_returns']};out.update(final_private_RAM=c['private_RAM'],final_image_globals=c['image_globals']+c['additional_image_globals']+c['registry_image_globals']+c['phase_one_image_globals'],final_system=c['system'],final_vectors=c['vectors'],final_page_sha256=c['mapped_page_sha256'],unfinished_API_entry_indices=[j for j in range(len(out['original_API_entries'])) if j not in returned],boundary={'pc':c['PC'],'kind':'before_first_phase_two_callback_BLRAA','registers31':c['registers31'],'SP':c['SP'],'NZCV':c['NZCV']});return out

def helper_contracts(row):
 memory=pages(row['initial_image_pages']);raw=uncompress(row['initial_private_RAM'])
 for j in range(0,SIZE,4096):memory[P+j]=bytearray(raw[j:j+4096])
 events=[];pending={};checks=[];calls=[];probes=[v for v in row['logical_effects'] if v.get('scope')=='original_timeout_stack_probe'];probe_index=0;read_indices=[v['source_visit_index'] for v in row['source_reads']];assert read_indices==sorted(read_indices)
 def ok(label,p):assert p,('timeout_helper_contract',label,row['configuration']['label']);checks.append(label)
 def string(a):
  out=bytearray()
  while get(memory,a+len(out),1)!=b'\0':out+=get(memory,a+len(out),1);assert len(out)<256
  return bytes(out)
 for j,w in enumerate(row['source_writes']):events.append((w['source_visit_index'],2,j,'write',w))
 for j,v in enumerate(row['original_API_entries']):
  if int(v['PC'],16) in [R.ZERO,R.CONCAT,R.STACK_STUB]:events.append((v['before_visit'],1,j,'entry',v))
 for j,v in enumerate(row['original_API_returns']):
  if int(row['original_API_entries'][v['entry_index']]['PC'],16) in [R.ZERO,R.CONCAT,R.STACK_STUB]:events.append((v['before_visit'],0,j,'return',v))
 for _,_,index,kind,v in sorted(events,key=lambda x:x[:3]):
  if kind=='write':b=bytes.fromhex(v['after_hex']);put(memory,int(v['address'],16),len(b),b);continue
  if kind=='return':
   q=pending.pop(v['entry_index']);target=q['target']
   if target==R.STACK_STUB:
    reads=row['source_reads'][bisect.bisect_left(read_indices,q['before']):bisect.bisect_left(read_indices,v['before_visit'])];ok('stack_probe_exact_one_private_byte_'+str(index),len(reads)==1 and reads[0]['address']==hex(q['SP']-q['size']) and reads[0]['size_bytes']==1)
   else:
    ok('bounded_helper_output_'+str(index),get(memory,q['destination'],len(q['expected']))==q['expected'])
    if target==R.CONCAT:ok('strlcat_attempted_length_'+str(index),int(v['return_value'],16)==q['result'])
   calls.append(q['receipt']);continue
  args=[int(x,16) for x in v['arguments6']];target=int(v['PC'],16);q={'target':target,'before':v['before_visit']}
  if target==R.STACK_STUB:
   effect=probes[probe_index];probe_index+=1;size=int(effect['probe_size_X9'],16);sp=int(v['entry_SP'],16);ok('selected_stack_probe_size_'+str(index),effect['before_visit']+1==v['before_visit'] and 0<size<4096 and P<=sp-size<sp<=P+SIZE);q.update(SP=sp,size=size,receipt={'target':hex(target),'probe_bytes':size,'read_address':hex(sp-size)})
  elif target==R.ZERO:
   dst,n=args[:2];ok('selected_bzero_private_extent_'+str(index),P<=dst<dst+n<=P+SIZE);q.update(destination=dst,expected=bytes(n),receipt={'target':hex(target),'destination':hex(dst),'size_bytes':n})
  else:
   dst,src,n=args[:3];source=string(src);before=get(memory,dst,n);length=before.find(b'\0');length=n if length<0 else length;take=min(len(source),max(0,n-length-1));expected=before if length==n else before[:length]+source[:take]+b'\0'+before[length+take+1:];q.update(destination=dst,expected=expected,result=length+len(source),receipt={'target':hex(target),'destination':hex(dst),'capacity_bytes':n,'source_text':source.decode(),'attempted_length':length+len(source)})
  pending[index]=q
 ok('all_selected_helpers_returned',not pending and probe_index==len(probes));return {'checks':checks,'calls':calls}

def oracle(row,e):
 row=B.hydrate(row);prior=U.oracle(prefix(row),json.loads(read(ROOT/(R.B.P+'_checks.json'))));cut=row['phase_two_entry_checkpoint'];memory=pages(row['initial_image_pages']);ram=uncompress(cut['private_RAM']);checks=[];results=[];compared=0
 for j in range(0,SIZE,4096):memory[P+j]=bytearray(ram[j:j+4096])
 groups=['image_globals','additional_image_globals','registry_image_globals','phase_one_image_globals','timeout_image_globals']
 for group in groups:
  for r in cut[group]:put(memory,int(r['address'],16),len(bytes.fromhex(r['bytes_hex'])),bytes.fromhex(r['bytes_hex']))
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def w(a,n,v):put(memory,a,n,v&MASK if n==8 else v)
 def ok(label,p):assert p,('timeout_contract',label,row['configuration']['label']);checks.append(label)
 options=get(memory,R.B.B.B.B.K.ARGS+0x6c,256)
 def parsed(key,n):
  status,raw=parse(options,key.encode(),n,0,bytes(n));return status,int.from_bytes(raw,'little')
 def prop(path,key,n):
  data=row['configuration'].get('machine_timeouts' if path=='/machine-timeouts' else 'chosen_timeouts',{}).get(key)
  if data is None:return None
  value,width=data;ok('admitted_tree_width_'+path+'_'+key,width==n);return value
 freq=u(0xfffffe000ca8c000,4);ok('nonzero_produced_timebase',freq>0)
 def convert(value):return max(1,(value//1000)*freq//1_000_000_000)
 descriptors={int(d['address'],16):d for d in e['timeout_descriptors']};records=bytes.fromhex(next(r['bytes_hex'] for r in cut['registry_image_globals'] if r['address']==hex(R.B.B.B.BASE)))
 for j,c in enumerate(row['callback_entries'][392:],392):
  phase,rank,target,arg=struct.unpack('<IIQQ',records[24*j:24*j+24]);ok('entry_'+str(j),c['sorted_index']==j and c['cursor']==hex(R.B.B.B.BASE+24*j) and (phase,rank,hex(target),hex(arg))==(c['phase_u32'],c['rank_u32'],c['target'],c['argument']) and phase==2);w(0xfffffe0007f8b5f0,4,1)
  if target in [R.ORDINARY,R.SPECIAL]:
   d=descriptors[arg];name=d['name'];dst=int(d['destination_pointer']['target'],16);disabled=not d['special_W2_bit0'] and u(0xfffffe0007e63ff8,8)==MASK
   if disabled:value=0;record={'name':name,'disabled_by_watchdog':True,'published_u64':value}
   else:
    value=d['default_u64'];overridden=False;scale=1
    for path in ['/machine-timeouts','/chosen/machine-timeouts']:
     found=prop(path,name,8)
     if found is not None:value=found;overridden=True
    status,boot=parsed('ml-timeout-'+name,8)
    if status:value=boot;overridden=True
    for path in ['/machine-timeouts','/chosen/machine-timeouts']:
     found=prop(path,name+'-scale',4)
     if found is not None:scale=found
    status,boot=parsed('ml-timeout-'+name+'-scale',8)
    if status:scale=boot
    cached=u(0xfffffe000cb62710,1)==1
    if cached:global_scale=u(0xfffffe000cb62718,8)
    else:
     global_scale=1
     for path in ['/machine-timeouts','/chosen/machine-timeouts']:
      found=prop(path,'global-scale',4)
      if found is not None:global_scale=found;w(0xfffffe000cb62710,1,1);w(0xfffffe000cb62718,8,found)
     status,boot=parsed('ml-timeout-global-scale',8)
     if status:global_scale=boot;w(0xfffffe000cb62710,1,1);w(0xfffffe000cb62718,8,boot)
    scale_product=(scale*global_scale)&MASK;input_value=value
    if overridden and value!=0:
     ok('selected_override_conversion_domain_'+name,value<1<<32 and d['divisor_u64']==0);value=convert(value)
    value=min(MASK,value*scale_product);record={'name':name,'disabled_by_watchdog':False,'input_u64':input_value,'overridden':overridden,'local_scale_u64':scale,'global_scale_u64':global_scale,'global_scale_was_cached':cached,'wrapped_scale_product_u64':scale_product,'published_u64':value}
   w(dst,8,value);results.append(record)
  else:
   ok('last_phase_two_family_is_lock_preparation',target==R.LOCK and arg==0);status,us=parsed('slto_us',4)
   if status:lock=us*freq//1_000_000;w(0xfffffe0007ef8240,8,lock);microseconds=us
   else:
    lock=u(0xfffffe0007ef8240,8);q,r=divmod(lock,freq);nanoseconds=(q*1_000_000_000+r*1_000_000_000//freq)&MASK;microseconds=nanoseconds//1000
   w(0xfffffe000cb0c4f8,8,microseconds);status,us=parsed('tlto_us',4)
   if status:w(0xfffffe0007ef8248,8,us*freq//1_000_000)
   elif lock:w(0xfffffe0007ef8248,8,lock>>1)
   status,us=parsed('mtxspin',8)
   if status:w(0xfffffe0007ef8250,8,min(us,62500)*freq//1_000_000)
   value=u(0xfffffe0007ef8250,8);w(0xfffffe000cb0c500,8,value);w(0xfffffe000cb0c508,8,value);status,max_wfe=parsed('max_wfe_us',8);results.append({'name':'lock_preparation','slto_ticks':u(0xfffffe0007ef8240,8),'slto_microseconds_word':microseconds,'tlto_ticks':u(0xfffffe0007ef8248,8),'mtxspin_ticks':value,'max_wfe_option_present':bool(status),'max_wfe_stack_value':max_wfe if status else 500,'max_wfe_value_published':False})
  ret=row['callback_returns'][j];ok('return_SP_'+str(j),ret['SP']==c['SP'])
  for r in ret['observed_regions']:
   raw=bytes.fromhex(r['bytes_hex']);ok('callback_output_'+str(j)+'_'+r['address'],get(memory,int(r['address'],16),len(raw))==raw);compared+=len(raw)
  w(R.B.B.B.CURSOR,8,R.B.B.B.BASE+24*(j+1))
 ok('all402_callbacks_returned',len(row['callback_entries'])==len(row['callback_returns'])==402)
 w(0xfffffe0007f8b5f0,4,2);w(R.B.B.B.LAST_PHASE,4,3);state=R.B.B.B.EVENT_STATE;ok('fourth_trace_slot_available',u(state,1)==0 and u(state+4,4)==3);event=R.B.B.B.EVENTS+192;thread=row['final_system']['tpidr_el1'];stamp=(row['final_system']['s3_4_c15_c10_6']+u(u(thread+0x1c0,8)+0x58,8))&MASK;w(event,8,stamp);w(event+8,32,b'locks\0'.ljust(32,b'\0'));w(event+40,8,0);w(event+48,4,0x07020010);w(state+4,4,4);w(state+8,1,0)
 for r in row['final_image_globals']:
  raw=bytes.fromhex(r['bytes_hex']);ok('final_global_'+r['address'],get(memory,int(r['address'],16),len(raw))==raw);compared+=len(raw)
 ok('phase_three_prepared_not_called',row['phase_three_dispatch_boundary']=={'cursor':'0xfffffe000cbec780','phase_u32':3,'rank_u32':0,'target':'0xfffffe000c62d618','argument':'0x0'} and row['boundary']['pc']==hex(R.DISPATCH));before=uncompress(cut['private_RAM']);after=uncompress(row['final_private_RAM']);ok('nonstack_private_RAM_preserved',before[:SP-P-0x1000]==after[:SP-P-0x1000] and before[SP-P+0x100:]==after[SP-P+0x100:]);ok('system_state_retained',row['final_system']==cut['system'])
 full_options=B.option_contracts(row);old=B.B.B.B.legacy(row);tree=B.B.B.B.decode_tree(old);full_tree=B.B.B.B.tree_contracts(old,tree);helpers=helper_contracts(row);copies=B.B.B.copy_contracts(row,old)
 return {'checks':checks,'prior_formatter_contracts':prior,'timeout_results':results,'full_option_API_contracts':full_options,'full_tree_API_contracts':full_tree,'full_copy_API_contracts':copies,'helper_contracts':helpers,'mutable_bytes_compared':compared,'private_nonstack_bytes_checked':SIZE-0x1100,'produced_timebase_frequency_word':freq,'phase_three_callback_invoked':False}

class Replay(U.Replay):
 def composition_checkpoint(self,c):
  super().composition_checkpoint(c)
  for r in c.get('timeout_image_globals',[]):
   raw=bytes.fromhex(r['bytes_hex']);assert bytes(self.u.mem_read(int(r['address'],16),len(raw)))==raw;self.counts['whole_checkpoint_timeout_bytes_checked']+=len(raw)
 def code(self,u,a,n,d):
  self.finish()
  if self.seq==len(self.p['source_visits']):return Core.code(self,u,a,n,d)
  while self.active and self.entries[self.active[-1]]['return_PC']==hex(a) and self.entries[self.active[-1]]['entry_SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   self.returns.append({'entry_index':self.active.pop(),'before_visit':self.seq,'return_value':hex(self.reg(0))})
  if a==R.DISPATCH and self.callback_index>=392:
   if self.callback_index==392:
    c=self.p['phase_two_entry_checkpoint'];self.composition_checkpoint(c);actual={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)};wanted=c['mapped_page_sha256'];assert wanted.keys()<=actual.keys() and all(actual[p]==h for p,h in wanted.items())
    for p in actual.keys()-wanted.keys():assert bytes(u.mem_read(int(p,16),4096))==self.image.logical_page(int(p,16));self.counts['phase_two_eager_original_page_bytes_checked']+=4096
   c=self.p['callback_entries'][self.callback_index];cursor=int.from_bytes(u.mem_read(R.B.B.B.CURSOR,8),'little');phase,rank,target,arg=struct.unpack('<IIQQ',u.mem_read(cursor,24));assert c['before_visit']==self.seq and c['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)) and c['cursor']==hex(cursor)==hex(R.B.B.B.BASE+24*self.callback_index) and (phase,rank,hex(target),hex(arg))==(c['phase_u32'],c['rank_u32'],c['target'],c['argument']) and phase==2 and self.reg(8)==target and self.reg(0)==arg and self.reg(17)==0x2abe
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert raw==self.image.k.read(a,4) and i.mnemonic=='blraa' and i.op_str=='x8, x17';event={'PC':hex(a),'kind':'blraa','scope':'original_registry_callback','operands':i.op_str,'before_visit':self.seq,'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(target),'modifier_X17':hex(self.reg(17)),'argument_X0':hex(arg)};self.callback_index+=1;self.counts['callback_entries_checked']+=1;return self.transfer(a,raw,event,target)
  if R.COMMON<=a<0xfffffe000bd11150:
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic=='blraa' and i.op_str=='x16, x17':
    assert raw==self.image.k.read(a,4) and self.reg(16)==R.STACK_STUB and self.reg(17)==0xfffffe0007f95e28;event={'PC':hex(a),'kind':'blraa','scope':'original_timeout_stack_probe','operands':i.op_str,'before_visit':self.seq,'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(self.reg(16)),'modifier_X17':hex(self.reg(17)),'probe_size_X9':hex(self.reg(9))};return self.transfer(a,raw,event,R.STACK_STUB)
  if a in R.APIS:
   self.active.append(len(self.entries));self.entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':[hex(self.reg(j)) for j in range(6)],'return_PC':hex(self.reg(30)),'before_visit':self.seq})
  return super().code(u,a,n,d)
 def transfer(self,a,raw,event,target):
  assert self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()} and event==self.p['logical_effects'][len(self.logical)];self.logical.append(event);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_effects_checked']+=1;self.u.reg_write(ar.UC_ARM64_REG_X30,a+4);self.u.reg_write(ar.UC_ARM64_REG_PC,target)
 def run(self):
  entry=int(self.p['entry_PC'],16);self.ensure(entry);self.u.emu_start(entry,0,count=len(self.p['source_visits'])+len(self.models)+10);self.finish()
  assert self.seq==len(self.p['source_visits']) and self.mi==len(self.models) and self.counts['final_boundaries_checked']==1
  assert self.entries==self.p['original_API_entries'] and self.returns==self.p['original_API_returns'] and self.active==self.p['unfinished_API_entry_indices']
  assert self.additional_checkpoints==12 and self.checkpoints==14 and self.callback_index==self.callback_return_index==402
  assert self.logical==self.p['logical_effects'] and self.system==self.p['final_system'] and bytes(self.u.mem_read(P,SIZE))==uncompress(self.p['final_private_RAM']);self.counts['whole_private_bytes_checked']+=SIZE
  assert {hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}==self.p['final_page_sha256'];self.counts['whole_image_page_bytes_checked']+=len(self.pages)*4096
  for j,v in enumerate(self.p['final_vectors']):assert v==hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))));self.counts['vector_registers_checked']+=1
  self.counts['original_API_entries_and_returns_checked']+=len(self.returns);self.counts['unfinished_original_API_entries_checked']+=len(self.active);return dict(self.counts)
