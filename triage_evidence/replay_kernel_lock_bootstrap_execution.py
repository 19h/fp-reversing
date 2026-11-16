#!/usr/bin/env python3
"""Independent lock formulas and fresh source-instruction replay.
Linear journal/RAM construction; no import of the phase-three executor.
"""
import json,struct
from collections import Counter
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from replay_kernel_boot_cpu_identity import pages,get,put
from probe_rpc502_vm_handoff import decode as uncompress
from replay_kernel_vm_mig import Replay as Core
import replay_kernel_timeout_execution as B
import recover_kernel_lock_bootstrap_execution as R
P=B.P;SIZE=B.SIZE;SP=B.SP;MASK=(1<<64)-1

def prefix(row):
 c=row['phase_three_entry_checkpoint'];end=c['before_visit'];out=dict(row);out['source_visits']=row['source_visits'][:end]
 for k in ['source_reads','source_writes']:out[k]=[v for v in row[k] if v['source_visit_index']<end]
 for k,field in [('API_models','before_source_visit_index'),('logical_effects','before_visit'),('original_call_entries','source_visit_index'),('original_API_entries','before_visit'),('callback_entries','before_visit')]:out[k]=[v for v in row[k] if v[field]<end]
 for k in ['original_API_returns','callback_returns']:out[k]=[v for v in row[k] if v['before_visit']<=end]
 returned={v['entry_index'] for v in out['original_API_returns']};out.update(final_private_RAM=c['private_RAM'],final_image_globals=sum([c[k] for k in ['image_globals','additional_image_globals','registry_image_globals','phase_one_image_globals','timeout_image_globals']],[]),final_system=c['system'],final_vectors=c['vectors'],final_page_sha256=c['mapped_page_sha256'],unfinished_API_entry_indices=[j for j in range(len(out['original_API_entries'])) if j not in returned],boundary={'pc':c['PC'],'kind':'before_first_phase_three_callback_BLRAA','registers31':c['registers31'],'SP':c['SP'],'NZCV':c['NZCV']},phase_three_dispatch_boundary={'cursor':'0xfffffe000cbec780','phase_u32':3,'rank_u32':0,'target':hex(R.FIRST),'argument':'0x0'});return out

def oracle(row,e):
 row=B.B.hydrate(row);cut=row['phase_three_entry_checkpoint'];prior=B.oracle(prefix(row),json.loads(read(ROOT/(R.B.P+'_checks.json'))));memory=pages(row['initial_image_pages']);checks=[];results=[];compared=0
 for k in ['image_globals','additional_image_globals','registry_image_globals','phase_one_image_globals','timeout_image_globals','lock_image_globals']:
  for r in cut[k]:raw=bytes.fromhex(r['bytes_hex']);put(memory,int(r['address'],16),len(raw),raw)
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def w(a,n,v):put(memory,a,n,v&((1<<(n*8))-1))
 def ok(label,p):assert p,('lock_contract',label,row['configuration']['label']);checks.append(label)
 def count(group,off):
  w(group+off,4,u(group+off,4)+1)
  if u(group+4,4)&0x80000000:
   old=u(group,4);ok('reference_increment_in_range_'+hex(group)+'_'+str(len(results)),1<=old<0x0fffffff);w(group,4,old+1)
 def mutex(dst,group,attr):
  w(dst,4,0x22000000|(u(group+4,4)&0xffffff));w(dst+4,4,0);w(dst+8,8,0x80000000 if u(attr or 0xfffffe0007e63610,1)&1 else 0);count(group,0x10)
 def group(dst,name,flags):
  put(memory,dst,0x148,bytes(0x148));w(dst,4,1);text=name.encode();ok('group_name_capacity_'+hex(dst),len(text)<64);put(memory,dst+0x18,len(text)+1,text+b'\0')
  for bit,offsets in [(16,[0x60,0x78,0xa8,0xc0,0xf0,0x108,0x120,0x138]),(17,[0x90,0xd8])]:
   if flags&(1<<bit):
    for off in offsets:w(dst+off,4,1)
  ok('static_bank_binding_'+hex(dst),u(R.REGISTRY,8)==R.BANK and u(R.REGISTRY+0x60,8)==R.BITMAP and u(R.REGISTRY+0xe0,4)<1024)
  bitmap=int.from_bytes(get(memory,R.BITMAP,128),'little');ok('free_static_id_'+hex(dst),bitmap!=0);idx=(bitmap&-bitmap).bit_length()-1;ok('id_u16_'+hex(dst),idx<=0xffff);put(memory,R.BITMAP,128,(bitmap&~(1<<idx)).to_bytes(128,'little'));w(R.REGISTRY+0xdc,4,u(R.REGISTRY+0xdc,4)+1);w(R.REGISTRY+0xe0,4,idx+1);w(R.BANK+8*idx,8,dst);w(dst+4,4,idx|flags);return idx
 ds={d['registry_index']:d for d in e['descriptors']};records=bytes.fromhex(next(v['bytes_hex'] for v in cut['registry_image_globals'] if v['address']==hex(R.B.B.B.B.BASE)))
 ok('phase_three_gate_is2',u(0xfffffe0007f8b5f0,4)==2)
 for j,c in enumerate(row['callback_entries'][402:],402):
  phase,rank,t,a=struct.unpack('<IIQQ',records[24*j:24*j+24]);ok('entry_'+str(j),c['sorted_index']==j and (phase,rank,hex(t),hex(a))==(c['phase_u32'],c['rank_u32'],c['target'],c['argument']) and phase==3);d=next(x for x in e['descriptors'] if x['target']==hex(t) and x['argument']==hex(a));record={'sorted_index':j,'target':hex(t),'argument':hex(a)}
  if t==R.FIRST:
   f=u(0xfffffe0007e63698,4);common=u(0xfffffe0007e635c8,4);combined=common|((f<<15)&0x10000)|((f<<14)&0x20000)|((f&1)<<18)
   if f&0xb:w(0xfffffe0007e635c8,4,combined)
   w(0xfffffe0007e63610,4,f&1);record['group_id']=group(0xfffffe000cb60590,'Compatibility APIs',combined);w(R.BANK,8,0)
  elif t==R.GROUP:record.update(group_id=group(int(d['destination'],16),d['name'],u(0xfffffe0007e635c8,4)|d['flags_u32']),name=d['name'])
  elif t==R.ATTR:w(int(d['destination'],16),4,(u(0xfffffe0007e63610,4)|d['set_mask_u32'])&~d['clear_mask_u32'])
  elif t in [R.MUTEX,R.RW,R.SPIN,R.TICKET,R.PLAIN]:
   dst=int(d['destination'],16);g=int(d['pointers'][1]['target'],16) if t in [R.MUTEX,R.RW,R.SPIN] and d['pointers'][1] else 0;attr=int(d['pointers'][2]['target'],16) if t in [R.MUTEX,R.RW] and d['pointers'][2] else 0
   if t==R.MUTEX:mutex(dst,g,attr)
   elif t==R.RW:
    flags=u(attr or 0xfffffe0007e63610,4);put(memory,dst,8,bytes.fromhex(e['constants'][1]['bytes_hex']));w(dst+8,2,0);w(dst+10,2,(0 if flags&0x10000 else 2)|(0 if flags&0x20000 else 0x40));w(dst+12,4,0);count(g,0x14)
   elif t==R.TICKET:put(memory,dst,8,bytes.fromhex(e['constants'][0]['bytes_hex']));w(dst+8,8,0x144)
   else:w(dst,8,0);w(dst+8,8,0x11);count(g,8) if g else None
  elif t==R.REGLOCK:mutex(a+0xc0,0xfffffe000caad718,0)
  elif t==R.FIXED:mutex(0xfffffe000cb2a5e0,0xfffffe000caaf868,0)
  else:
   ok('late_global_branch',t==R.LATE and a==0xfffffe000cac6e18);base=0xfffffe000cac4200
   for off,n,value in [(8,8,a),(0x10,4,9),(0x14,4,0x144),(0x18,8,0),(0x20,8,0),(0x28,1,1),(0x38,8,0),(0x50,8,base+0x48),(0x58,8,base+0x48),(0x60,8,base+0x48),(0x70,8,0),(0x78,8,base+0x70)]:w(base+off,n,value)
  ret=row['callback_returns'][j];ok('return_SP_'+str(j),ret['sorted_index']==j and ret['SP']==c['SP'])
  for v in ret['observed_regions']:
   raw=bytes.fromhex(v['bytes_hex']);ok('output_'+str(j)+'_'+v['address'],get(memory,int(v['address'],16),len(raw))==raw);compared+=len(raw)
  results.append(record)
 for r in cut['lock_image_globals']:
  a=int(r['address'],16);n=len(bytes.fromhex(r['bytes_hex']));actual=next((bytes.fromhex(v['bytes_hex'])[a-int(v['address'],16):a-int(v['address'],16)+n] for v in row['final_image_globals'] if int(v['address'],16)<=a<a+n<=int(v['address'],16)+len(bytes.fromhex(v['bytes_hex']))),None);ok('final_lock_interval_'+hex(a),actual==get(memory,a,n));compared+=n
 ok('all1029_callbacks_returned',len(row['callback_entries'])==len(row['callback_returns'])==1029);ok('291_group_ids_consumed',u(R.REGISTRY+0xdc,4)==u(R.REGISTRY+0xe0,4)==291 and u(R.BANK,8)==0);ok('same_declared_models',row['API_models']==prefix(row)['API_models']);ok('system_state_preserved',row['final_system']==cut['system']);ok('post_phase_three_stop',row['boundary']['pc']==hex(R.STOP) and row['post_phase_three_dispatch_boundary']=={'call_PC':hex(R.STOP),'target':hex(R.FRONTIER),'kind':'original_main_direct_BL_after_phase_three_return'})
 return {'checks':checks,'prior_timeout_contracts':prior,'callback_results':results,'mutable_bytes_compared':compared,'groups_initialized':291,'static_group_capacity':1024,'unconsumed_static_group_ids':733,'phase_three_callbacks':627}

class Replay(B.Replay):
 def code(self,u,a,n,d):
  self.finish()
  if self.seq==len(self.p['source_visits']):return Core.code(self,u,a,n,d)
  if a==R.DISPATCH and self.callback_index>=402:
   if self.callback_index==402:
    cut=self.p['phase_three_entry_checkpoint'];self.composition_checkpoint(cut)
    for r in cut['lock_image_globals']:
     raw=bytes.fromhex(r['bytes_hex']);assert bytes(u.mem_read(int(r['address'],16),len(raw)))==raw;self.counts['whole_checkpoint_lock_bytes_checked']+=len(raw)
   c=self.p['callback_entries'][self.callback_index];cursor=int.from_bytes(u.mem_read(R.B.B.B.B.CURSOR,8),'little');phase,rank,target,arg=struct.unpack('<IIQQ',u.mem_read(cursor,24));assert c['before_visit']==self.seq and c['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)) and c['cursor']==hex(cursor)==hex(R.B.B.B.B.BASE+24*self.callback_index) and (phase,rank,hex(target),hex(arg))==(c['phase_u32'],c['rank_u32'],c['target'],c['argument']) and phase==3 and self.reg(8)==target and self.reg(0)==arg and self.reg(17)==0x2abe
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);event={'PC':hex(a),'kind':'blraa','scope':'original_registry_callback','operands':'x8, x17','before_visit':self.seq,'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(target),'modifier_X17':hex(self.reg(17)),'argument_X0':hex(arg)};self.callback_index+=1;self.counts['callback_entries_checked']+=1;return self.transfer(a,raw,event,target)
  return super().code(u,a,n,d)
 def run(self):
  entry=int(self.p['entry_PC'],16);self.ensure(entry);self.u.emu_start(entry,0,count=len(self.p['source_visits'])+len(self.models)+10);self.finish();assert self.seq==len(self.p['source_visits']) and self.mi==len(self.models) and self.counts['final_boundaries_checked']==1
  assert self.entries==self.p['original_API_entries'] and self.returns==self.p['original_API_returns'] and self.active==self.p['unfinished_API_entry_indices'];assert self.callback_index==self.callback_return_index==1029
  assert self.logical==self.p['logical_effects'] and self.system==self.p['final_system'] and bytes(self.u.mem_read(P,SIZE))==uncompress(self.p['final_private_RAM']);self.counts['whole_private_bytes_checked']+=SIZE
  assert {hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}==self.p['final_page_sha256'];self.counts['whole_image_page_bytes_checked']+=len(self.pages)*4096
  for j,v in enumerate(self.p['final_vectors']):assert v==hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))));self.counts['vector_registers_checked']+=1
  return dict(self.counts)
