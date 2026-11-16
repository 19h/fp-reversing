#!/usr/bin/env python3
"""Independent post-lock timer formulas and fresh CPU replay.
Linear journal/RAM work; no executor import or replacement return values.
"""
import json
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from replay_kernel_boot_cpu_identity import pages,get,put
from replay_kernel_boot_option_execution import parse
from replay_kernel_tunable_batch_execution import option_contracts
from replay_kernel_vm_mig import Replay as Core
from probe_rpc502_vm_handoff import decode as uncompress
import replay_kernel_lock_bootstrap_execution as B
import recover_kernel_longterm_bootstrap_execution as R
P=B.P;SIZE=B.SIZE;MASK=(1<<64)-1
GROUPS=['image_globals','additional_image_globals','registry_image_globals','phase_one_image_globals','timeout_image_globals','lock_image_globals']

def prefix(row):
 c=row['longterm_entry_checkpoint'];end=c['before_visit'];out=dict(row);out['source_visits']=row['source_visits'][:end]
 for k in ['source_reads','source_writes']:out[k]=[v for v in row[k] if v['source_visit_index']<end]
 for k,field in [('API_models','before_source_visit_index'),('logical_effects','before_visit'),('original_call_entries','source_visit_index'),('original_API_entries','before_visit'),('callback_entries','before_visit')]:out[k]=[v for v in row[k] if v[field]<end]
 for k in ['original_API_returns','callback_returns']:out[k]=[v for v in row[k] if v['before_visit']<=end]
 # The published stop precedes return-observer bookkeeping at this same PC.
 out['original_API_returns']=[v for v in row['original_API_returns'] if v['before_visit']<end]
 memory=pages(B.B.B.hydrate(row)['initial_image_pages']);intervals=[]
 for k in GROUPS:
  for v in c[k]:a=int(v['address'],16);raw=bytes.fromhex(v['bytes_hex']);put(memory,a,len(raw),raw);intervals.append((a,a+len(raw)))
 merged=[]
 for a,z in sorted(intervals):
  if merged and a<=merged[-1][1]:lo,hi=merged.pop();merged.append((lo,max(hi,z)))
  else:merged.append((a,z))
 returned={v['entry_index'] for v in out['original_API_returns']};out.update(final_private_RAM=c['private_RAM'],final_image_globals=[{'address':hex(a),'bytes_hex':get(memory,a,z-a).hex()} for a,z in merged],final_system=c['system'],final_vectors=c['vectors'],final_page_sha256=c['mapped_page_sha256'],unfinished_API_entry_indices=[j for j in range(len(out['original_API_entries'])) if j not in returned],boundary={'pc':c['PC'],'kind':'before_original_post_lock_timeout_wait_queue_initializer_BL','registers31':c['registers31'],'SP':c['SP'],'NZCV':c['NZCV']},post_phase_three_dispatch_boundary={'call_PC':hex(R.CALL),'target':hex(R.INIT),'kind':'original_main_direct_BL_after_phase_three_return'});return out

def oracle(row,e):
 row=B.B.B.hydrate(row);cut=row['longterm_entry_checkpoint'];prior=B.oracle(prefix(row),json.loads(read(ROOT/(R.B.P+'_checks.json'))));memory=pages(row['initial_image_pages']);checks=[];compared=0
 for k in GROUPS+['timer_image_globals']:
  for v in cut[k]:raw=bytes.fromhex(v['bytes_hex']);put(memory,int(v['address'],16),len(raw),raw)
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def w(a,n,v):put(memory,a,n,v&((1<<(n*8))-1))
 def ok(label,p):assert p,('longterm_contract',label,row['configuration']['label']);checks.append(label)
 text=row['configuration']['boot_text'].encode();ok('bounded_boot_text',len(text)<256);status,raw=parse(text+b'\0',b'longterm',4,0,bytes(4));value=int.from_bytes(raw,'little');threshold=value*1000000 if status and value else MASK;w(0xfffffe000ca92100,8,threshold);f=u(0xfffffe000ca8c000,4);ok('produced_timebase',f==24000000)
 def ticks(v):return ((v//1000000000)*f+((v%1000000000)*f)//1000000000)&MASK
 completed=row['longterm_initializer_returned']
 if completed:
  ok('completed_case_threshold_disabled',threshold==MASK);base=0xfffffe000ca920a8
  w(base,8,base);w(base+8,8,base);w(base+0x10,8,0);w(base+0x28,8,0x44000000);w(base+0x30,8,0x144)
  for off,n in [(0x68,16),(0x88,16),(0x98,16),(0xa8,16),(0xb8,16),(0xc8,16),(0xe8,16),(0xf8,16)]:put(memory,base+off,n,bytes([255])*n if off==0x68 else bytes(n))
  w(base+0x90,8,0);w(base+0x98,8,0x11);w(base+0xd8,8,R.CALLBACK);w(base+0xe0,8,base);w(0xfffffe000cb7d0b8,8,base);w(0xfffffe000cadd708,8,f//100000)
  src=0xfffffe000ca93e08;dst=0xfffffe000cb2a4b4
  for off in [0,4,8]:w(dst+off,4,ticks(u(src+off,4)))
  for soff,doff,n in [(0xc,0xc,16),(0x1c,0x1c,4),(0x48,0x4c,16),(0x58,0x5c,8),(0x90,0x94,16),(0xa0,0xa4,8)]:put(memory,dst+doff,n,get(memory,src+soff,n))
  for soff,doff in [(0x20,0x24),(0x28,0x2c),(0x30,0x34),(0x38,0x3c),(0x40,0x44),(0x60,0x64),(0x68,0x6c),(0x70,0x74),(0x78,0x7c),(0x80,0x84),(0x88,0x8c)]:w(dst+doff,8,ticks(u(src+soff,8)))
  for src,dst in [(0xfffffe000ca92088,0xfffffe000cadd6e8),(0xfffffe000ca92090,0xfffffe000cb7d0c8)]:w(dst,8,ticks((u(src,8)*1000)&MASK))
 else:
  ok('nonzero_threshold_reaches_logging',status!=0 and value!=0 and row['boundary']['kind']=='before_unestablished_logging_system_register');ok('DAIF_unknown_at_source_frontier',row['logging_system_register_frontier']=={'PC':'0xfffffe000c48faf4','operands':'x8, daif','register':'daif'} and 'daif' not in row['initial_system'] and 'daif' not in row['final_system']);ok('printf_vararg_source_labelled_ms',len(row['original_printf_calls'])==1 and row['original_printf_calls'][0]['format_X0']=='0xfffffe0007052b8b' and row['original_printf_calls'][0]['u64_vararg_at_SP']==value)
  counter=0xfffffe000cbe9e58;actual=next(bytes.fromhex(v['bytes_hex'])[counter-int(v['address'],16):counter-int(v['address'],16)+8] for v in row['final_image_globals'] if int(v['address'],16)<=counter<counter+8<=int(v['address'],16)+len(bytes.fromhex(v['bytes_hex'])));ok('original_logging_counter_incremented',int.from_bytes(actual,'little')==(u(counter,8)+1)&MASK)
 timer=[(a,n) for a,n in R.REGIONS if a not in [0xfffffe000cbe9e58,0xfffffe000cad0108,0xfffffe000caab10c]]
 for a,n in timer:
  actual=next((bytes.fromhex(v['bytes_hex'])[a-int(v['address'],16):a-int(v['address'],16)+n] for v in row['final_image_globals'] if int(v['address'],16)<=a<a+n<=int(v['address'],16)+len(bytes.fromhex(v['bytes_hex']))),None);ok('timer_output_'+hex(a),actual==get(memory,a,n));compared+=n
 if completed:
  ok('original_return_to_main',row['boundary']['pc']==hex(R.STOP));effects=[v for v in row['logical_effects'] if v['before_visit']>=cut['before_visit'] and v['kind']=='pacia' and v['PC']=='0xfffffe000bd6502c'];ok('callback_pointer_signature_operands',len(effects)==1 and effects[0]['operands']=='x16, x17')
 ok('no_additional_leaf_models',row['API_models']==prefix(row)['API_models']);ok('system_state_retained',row['final_system']==cut['system']);full_options=option_contracts(row)
 return {'checks':checks,'prior_lock_contracts':prior,'full_option_API_contracts':full_options,'longterm_option_status':status,'longterm_u32':value,'threshold_before_logging_u64':threshold,'initializer_returned':completed,'mutable_bytes_compared':compared,'timebase_word':f,'logging_contract_complete':False}

class Replay(B.Replay):
 def code(self,u,a,n,d):
  self.finish()
  if self.seq==len(self.p['source_visits']):return Core.code(self,u,a,n,d)
  if a==R.PRINTF:
   wanted={'PC':hex(a),'before_visit':self.seq,'format_X0':hex(self.reg(0)),'u64_vararg_at_SP':int.from_bytes(u.mem_read(u.reg_read(ar.UC_ARM64_REG_SP),8),'little'),'return_PC':hex(self.reg(30)),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))};assert self.p['original_printf_calls']==[wanted];self.counts['original_printf_input_calls_checked']+=1
  if a==R.CALL:
   cut=self.p['longterm_entry_checkpoint'];self.composition_checkpoint(cut)
   for k in ['lock_image_globals','timer_image_globals']:
    for v in cut[k]:raw=bytes.fromhex(v['bytes_hex']);assert bytes(u.mem_read(int(v['address'],16),len(raw)))==raw;self.counts['whole_longterm_checkpoint_bytes_checked']+=len(raw)
  return super().code(u,a,n,d)
 def run(self):
  entry=int(self.p['entry_PC'],16);self.ensure(entry);self.u.emu_start(entry,0,count=len(self.p['source_visits'])+len(self.models)+10);self.finish();assert self.seq==len(self.p['source_visits']) and self.mi==len(self.models) and self.counts['final_boundaries_checked']==1
  assert self.entries==self.p['original_API_entries'] and self.returns==self.p['original_API_returns'] and self.active==self.p['unfinished_API_entry_indices'];assert self.callback_index==self.callback_return_index==1029
  assert self.logical==self.p['logical_effects'] and self.system==self.p['final_system'] and bytes(self.u.mem_read(P,SIZE))==uncompress(self.p['final_private_RAM']);self.counts['whole_private_bytes_checked']+=SIZE
  assert {hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}==self.p['final_page_sha256'];self.counts['whole_image_page_bytes_checked']+=len(self.pages)*4096
  for j,v in enumerate(self.p['final_vectors']):assert v==hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))));self.counts['vector_registers_checked']+=1
  return dict(self.counts)
