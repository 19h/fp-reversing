#!/usr/bin/env python3
"""Independent UUID-format, emission, remaining-callback and replay contracts.
Linear journals/mapped bytes, API timeline O(J log J). No executor imports.
"""
import json,struct
from collections import Counter
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_rpc502_vm_handoff import decode as uncompress
from replay_kernel_boot_cpu_identity import pages,get,put
from replay_kernel_boot_option_execution import parse
from replay_kernel_vm_mig import Replay as Core
import replay_kernel_tunable_batch_execution as B
import recover_kernel_uuid_formatter_execution as R
P=B.P;SIZE=B.SIZE;SP=B.SP;MASK=(1<<64)-1

def prior_row(row):
 c=row['formatter_call_boundary'];end=c['before_visit'];out=dict(row);out['source_visits']=row['source_visits'][:end]
 for k in ['source_reads','source_writes']:out[k]=[v for v in row[k] if v['source_visit_index']<end]
 for k,field in [('API_models','before_source_visit_index'),('logical_effects','before_visit'),('original_call_entries','source_visit_index'),('original_API_entries','before_visit'),('callback_entries','before_visit')]:out[k]=[v for v in row[k] if v[field]<end]
 for k in ['original_API_returns','callback_returns']:out[k]=[v for v in row[k] if v['before_visit']<=end]
 returned={v['entry_index'] for v in out['original_API_returns']}
 out.update(final_private_RAM=c['private_RAM'],final_image_globals=c['image_globals']+c['additional_image_globals']+c['registry_image_globals']+c['phase_one_image_globals'],final_system=c['system'],final_vectors=c['vectors'],final_page_sha256=c['mapped_page_sha256'],unfinished_API_entry_indices=[j for j in range(len(out['original_API_entries'])) if j not in returned],boundary={'pc':c['PC'],'kind':'before_original_UUID_formatter_call','registers31':c['registers31'],'SP':c['SP'],'NZCV':c['NZCV']})
 return out

def text(data):return ('-'.join([data[:4].hex(),data[4:6].hex(),data[6:8].hex(),data[8:10].hex(),data[10:].hex()])).upper().encode()

def formatter_contracts(row):
 row=B.hydrate(row);memory=pages(row['initial_image_pages']);initial=uncompress(row['initial_private_RAM'])
 for j in range(0,SIZE,4096):memory[P+j]=bytearray(initial[j:j+4096])
 pending={};events=[];checks=[];formats=[];current=None;calls=Counter()
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def ok(label,p):assert p,('formatter_contract',label,row['configuration']['label']);checks.append(label)
 for j,w in enumerate(row['source_writes']):events.append((w['source_visit_index'],2,j,'write',w))
 for j,e in enumerate(row['original_API_entries']):
  if int(e['PC'],16) in [R.FORMAT,R.ENGINE,R.EMIT]:events.append((e['before_visit'],1,j,'entry',e))
 for j,e in enumerate(row['original_API_returns']):
  if int(row['original_API_entries'][e['entry_index']]['PC'],16) in [R.FORMAT,R.ENGINE,R.EMIT]:events.append((e['before_visit'],0,j,'return',e))
 for _,_,index,kind,e in sorted(events,key=lambda x:x[:3]):
  if kind=='write':raw=bytes.fromhex(e['after_hex']);put(memory,int(e['address'],16),len(raw),raw);continue
  if kind=='return':
   q=pending.pop(e['entry_index']);a=q['target']
   if a==R.EMIT:
    ok('emitter_cursor_'+str(index),u(q['context'],8)==q['cursor_after'] and u(q['context']+8,8)==q['remaining_after'])
    if q['stored']:ok('emitter_byte_'+str(index),get(memory,q['cursor_before'],1)==q['byte'])
   elif a==R.ENGINE:
    ok('engine_attempted_length36_'+str(index),int(e['return_value'],16)==36 and current['emitted']==36);ok('engine_consumed16_varargs_'+str(index),u(q['entry_SP']-0xd0+0x18,8)==current['varargs']+128)
   else:
    ok('formatter_return36_'+str(index),int(e['return_value'],16)==36 and current['emitted']==36)
    n=current['capacity'];take=min(36,max(0,n-1));expected=current['text'][:take]+b'\0' if n else b''
    if n:ok('bounded_output_and_NUL_'+str(index),get(memory,current['destination'],len(expected))==expected)
    formats.append({'entry_index':q['entry_index'],'destination':hex(current['destination']),'capacity_bytes':n,'attempted_bytes':36,'stored_character_bytes':take,'NUL_stored':bool(n),'expected_text':current['text'].decode(),'varargs16':list(current['arguments']),'emission_calls':current['emitted']});current=None
   continue
  target=int(e['PC'],16);v=[int(x,16) for x in e['arguments6']];sp=int(e['entry_SP'],16);calls[hex(target)]+=1;q={'target':target,'entry_SP':sp,'entry_index':index}
  if target==R.FORMAT:
   ok('one_active_formatter_'+str(index),current is None);args=struct.unpack('<16Q',get(memory,sp,128));ok('UUID_format_and_byte_domain_'+str(index),v[2]==0xfffffe00070d7f36 and all(x<=255 for x in args));current={'destination':v[0],'capacity':v[1],'varargs':sp,'arguments':args,'text':text(bytes(args)),'emitted':0,'context':sp-0x20,'cursor':v[0],'remaining':v[1]}
  elif target==R.ENGINE:
   ok('engine_ABI_'+str(index),current is not None and v==[0xfffffe00070d7f36,current['varargs'],R.EMIT,current['context'],10,0]);ok('wrapper_initialized_cursor_and_capacity_'+str(index),u(v[3],8)==current['destination'] and u(v[3]+8,8)==current['capacity'])
  else:
   assert current is not None;j=current['emitted'];ok('emitted_character_'+str(index),j<36 and v[0]&0xffffffff==current['text'][j] and v[1]==current['context']);cursor,remaining=current['cursor'],current['remaining'];ok('emitter_input_state_'+str(index),u(v[1],8)==cursor and u(v[1]+8,8)==remaining);stored=remaining>=2
   current['cursor']=(cursor+int(stored))&MASK;current['remaining']=(remaining-int(stored))&MASK;current['emitted']+=1;q.update(context=v[1],cursor_before=cursor,cursor_after=current['cursor'],remaining_after=current['remaining'],stored=stored,byte=current['text'][j:j+1])
  pending[index]=q
 ok('all_formatter_APIs_returned',not pending and current is None and len(formats)==1)
 return {'checks':checks,'formats':formats,'API_histogram':dict(calls)}

def oracle(row,e):
 row=B.hydrate(row);prior=B.oracle(prior_row(row),json.loads(read(ROOT/(R.B.P+'_checks.json'))));fmt=formatter_contracts(row);cut=row['formatter_call_boundary'];memory=pages(row['initial_image_pages']);ram=uncompress(cut['private_RAM']);checks=[];compared=0
 for j in range(0,SIZE,4096):memory[P+j]=bytearray(ram[j:j+4096])
 for r in cut['image_globals']+cut['additional_image_globals']+cut['registry_image_globals']+cut['phase_one_image_globals']:put(memory,int(r['address'],16),len(bytes.fromhex(r['bytes_hex'])),bytes.fromhex(r['bytes_hex']))
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def w(a,n,v):put(memory,a,n,v)
 def ok(label,p):assert p,('UUID_startup_contract',label,row['configuration']['label']);checks.append(label)
 records=bytes.fromhex(next(r['bytes_hex'] for r in cut['registry_image_globals'] if r['address']==hex(R.B.B.BASE)));options=get(memory,R.B.B.B.K.ARGS+0x6c,256);uuid=bytes.fromhex(prior['UUID_bytes_hex']);w(0xfffffe000cb2a1a0,37,text(uuid)+b'\0');thread=row['final_system']['tpidr_el1'];ordinal=u(thread+0x1b8,2);families=Counter()
 def parsed(key,n,before=None):return parse(options,key.encode(),n,0,before if before is not None else bytes(n))
 for j,c in enumerate(row['callback_entries']):
  if j<368:continue
  phase,rank,target,arg=struct.unpack('<IIQQ',records[24*j:24*j+24]);ok('remaining_entry_'+str(j),c['sorted_index']==j and c['cursor']==hex(R.B.B.BASE+24*j) and (phase,rank,hex(target),hex(arg))==(c['phase_u32'],c['rank_u32'],c['target'],c['argument']) and phase==1);families[hex(target)]+=1;w(0xfffffe0007f8b5f0,4,0)
  if target==R.IMAGE:
   mode=u(0xfffffe0007f8b6f8,4);policy=u(0xfffffe0007f12c60,1)
   if policy&0x19 and mode:
    if mode&1:w(0xfffffe000caceea8,4,1)
    if mode&4:w(0xfffffe0007f8b5ec,4,1)
   key=next(x['text'] for x in e['strings'] if x['address']=='0xfffffe000704ae53');status,_=parsed(key,80);w(0xfffffe0007e5ca28,4,status)
  elif target==R.B.ADJUST:w(arg,8,(u(arg,8)-(ordinal<<14))&MASK)
  elif target==R.PERCPU:
   pointer=(arg+32-(ordinal<<7))&MASK
   if ((arg+32)^pointer)&0xffc0000000000000:pointer=(pointer&0xffffffffffff)|(0xc8a2<<48)
   w(arg+16,8,pointer)
  elif target==R.STACK:
   key=next(x['text'] for x in e['strings'] if x['address']=='0xfffffe000704f9ab');status,raw=parsed(key,4);requested=((int.from_bytes(raw,'little')<<14)&0xffffffff) if status else 16384;ok('selected_stack_size_admitted_'+str(j),requested&0x3fff==0 and requested+16383<=MASK);rounded=requested if requested&(requested-1)==0 else 1<<requested.bit_length();w(0xfffffe0007f30770,8,requested);w(0xfffffe0007e64500,8,(rounded-1)&MASK);w(0xfffffe0007e64508,8,(-rounded)&MASK)
  elif target==R.CAPABILITY:
   record=e['optional_capability_record'];a=int(record['address'],16);ok('selected_optional_capability_callback_is_null',u(a+16,8)==0 and record['callback_pointer'] is None)
   if u(a,1)!=3:w(0xfffffe0007e62bc8,2,u(0xfffffe0007e62bc8,2)|12)
  elif target==R.FLAGS:
   if u(0xfffffe0007f212d8,4):w(0xfffffe0007f18be0,4,u(0xfffffe0007f18be0,4)|0x5dee)
  elif target==R.PLATFORM:
   ok('produced_platform_guard_is1',u(0xfffffe0007f8b648,4)==1)
   if u(0xfffffe0007f8b6f8,1)&10:w(0xfffffe0007f8b640,1,0)
  else:ok('remaining_noop_only',target==R.NOOP)
  ret=row['callback_returns'][j];ok('actual_return_SP_'+str(j),ret['SP']==c['SP'])
  for r in ret['observed_regions']:
   raw=bytes.fromhex(r['bytes_hex']);ok('callback_output_'+str(j)+'_'+r['address'],get(memory,int(r['address'],16),len(raw))==raw);compared+=len(raw)
  w(R.B.B.CURSOR,8,R.B.B.BASE+24*(j+1))
 ok('all392_phase_one_callbacks_returned',len(row['callback_entries'])==len(row['callback_returns'])==392)
 # The next phase transition is original source, including its third trace record.
 w(0xfffffe0007f8b5f0,4,1);w(R.B.B.LAST_PHASE,4,2);state=R.B.B.EVENT_STATE;ok('third_trace_slot_available',u(state,1)==0 and u(state+4,4)==2);event=R.B.B.EVENTS+128;stamp=(row['final_system']['s3_4_c15_c10_6']+u(u(thread+0x1c0,8)+0x58,8))&MASK;w(event,8,stamp);w(event+8,32,b'timeouts\0'.ljust(32,b'\0'));w(event+40,8,0);w(event+48,4,0x07020010);w(state+4,4,3);w(state+8,1,0)
 for r in row['final_image_globals']:
  raw=bytes.fromhex(r['bytes_hex']);ok('final_global_'+r['address'],get(memory,int(r['address'],16),len(raw))==raw);compared+=len(raw)
 b=row['phase_two_dispatch_boundary'];ok('phase_two_target_and_argument_ready_but_not_called',row['boundary']['pc']==hex(R.PHASE2_CALL) and b=={'cursor':hex(R.B.B.BASE+392*24),'phase_u32':2,'rank_u32':0,'target':'0xfffffe000bd12f7c','argument':'0xfffffe000ca94260'})
 ok('logical_system_preserved',row['final_system']==cut['system']);before=uncompress(cut['private_RAM']);after=uncompress(row['final_private_RAM']);ok('nonstack_private_RAM_preserved',before[:SP-P-0x1000]==after[:SP-P-0x1000] and before[SP-P+0x100:]==after[SP-P+0x100:])
 full_options=B.option_contracts(row);full_strings=B.B.string_contracts(row,B.B.B.B.legacy(row))
 return {'checks':checks,'prior_batch_contracts':prior,'formatter_contracts':fmt,'full_option_API_contracts':full_options,'full_string_contracts':full_strings,'remaining_callback_histogram':dict(families),'mutable_bytes_compared':compared,'private_nonstack_bytes_checked':SIZE-0x1100,'phase_two_callback_invoked':False}

def direct_oracle(row):
 row=B.hydrate(row);fmt=formatter_contracts(row);before=uncompress(row['initial_private_RAM']);after=uncompress(row['final_private_RAM']);capacity=row['configuration']['capacity_bytes'];output=P+0x20000;buffer=output+32;expected=bytearray(before);value=text(bytes.fromhex(row['configuration']['UUID_bytes_hex']));take=min(36,max(0,capacity-1))
 if capacity:expected[buffer-P:buffer-P+take+1]=value[:take]+b'\0'
 guard=SP-P-0x1000;assert after[:guard]==expected[:guard] and after[SP-P+0x100:]==expected[SP-P+0x100:],('direct_formatter_guard',row['configuration']['label'])
 assert row['boundary']['registers31'][0]=='0x24' and row['boundary']['SP']==row['entry_SP'] and not row['API_models']
 return {'formatter_contracts':fmt,'whole_nonstack_private_bytes_checked':SIZE-0x1100,'guarded_output_bytes_checked':128,'attempted_bytes':36,'returned_SP_matches':True,'no_return_models':True}

def emission(replay,a,with_system):
 raw=bytes(replay.u.mem_read(a,4));i=next(replay.image.k.cs.disasm(raw,a));assert raw==replay.image.k.read(a,4) and i.mnemonic=='blraa' and i.op_str=='x21, x17' and replay.reg(21)==R.EMIT and replay.reg(17)==0xae56
 event={'PC':hex(a),'kind':'blraa','scope':'original_formatter_byte_output','operands':i.op_str,'before_visit':replay.seq,'system_before':dict(replay.system) if with_system else {},'system_after':dict(replay.system) if with_system else {},'target':hex(replay.reg(21)),'modifier_X17':hex(replay.reg(17)),'character_W0':hex(replay.reg(0)&0xffffffff),'context_X1':hex(replay.reg(1))}
 assert event==replay.p['logical_effects'][len(replay.logical)] and replay.p['source_visits'][replay.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};replay.logical.append(event);replay.current=replay.seq;replay.seq+=1;replay.rc=replay.wc=0;replay.counts['source_visits_checked']+=1;replay.counts['logical_effects_checked']+=1;replay.u.reg_write(ar.UC_ARM64_REG_X30,a+4);replay.u.reg_write(ar.UC_ARM64_REG_PC,R.EMIT)

def API_edges(replay,a):
 while replay.active and replay.entries[replay.active[-1]]['return_PC']==hex(a) and replay.entries[replay.active[-1]]['entry_SP']==hex(replay.u.reg_read(ar.UC_ARM64_REG_SP)):
  replay.returns.append({'entry_index':replay.active.pop(),'before_visit':replay.seq,'return_value':hex(replay.reg(0))})
 if a in [R.FORMAT,R.ENGINE,R.EMIT]:
  replay.active.append(len(replay.entries));replay.entries.append({'PC':hex(a),'entry_SP':hex(replay.u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':[hex(replay.reg(j)) for j in range(6)],'return_PC':hex(replay.reg(30)),'before_visit':replay.seq})

class Replay(B.Replay):
 def code(self,u,a,n,d):
  self.finish()
  if self.seq==len(self.p['source_visits']):return Core.code(self,u,a,n,d)
  API_edges(self,a)
  if a in [R.B.STOP,R.B.STOP+4]:
   key='formatter_call_boundary' if a==R.B.STOP else 'formatter_return_checkpoint';c=self.p[key];self.composition_checkpoint(c)
   if 'mapped_page_sha256' in c:
    actual={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)};wanted=c['mapped_page_sha256'];assert wanted.keys()<=actual.keys() and all(actual[pg]==v for pg,v in wanted.items())
    for pg in actual.keys()-wanted.keys():assert bytes(u.mem_read(int(pg,16),4096))==self.image.logical_page(int(pg,16));self.counts['formatter_checkpoint_eager_original_page_bytes_checked']+=4096
  if R.ENGINE<=a<0xfffffe000bd15408 and next(self.image.k.cs.disasm(bytes(u.mem_read(a,4)),a)).mnemonic=='blraa':return emission(self,a,True)
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(int(self.p['entry_PC'],16));self.u.emu_start(int(self.p['entry_PC'],16),0,count=len(self.p['source_visits'])+len(self.models)+10);self.finish()
  assert self.seq==len(self.p['source_visits']) and self.mi==len(self.models) and self.counts['final_boundaries_checked']==1
  assert self.entries==self.p['original_API_entries'] and self.returns==self.p['original_API_returns'] and self.active==self.p['unfinished_API_entry_indices']
  assert self.additional_checkpoints==11 and self.checkpoints==13 and self.callback_index==self.callback_return_index==392
  assert self.logical==self.p['logical_effects'] and self.system==self.p['final_system'] and bytes(self.u.mem_read(P,SIZE))==uncompress(self.p['final_private_RAM']);self.counts['whole_private_bytes_checked']+=SIZE
  assert {hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}==self.p['final_page_sha256'];self.counts['whole_image_page_bytes_checked']+=len(self.pages)*4096
  for j,v in enumerate(self.p['final_vectors']):assert v==hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))));self.counts['vector_registers_checked']+=1
  self.counts['original_API_entries_and_returns_checked']+=len(self.returns);self.counts['unfinished_original_API_entries_checked']+=len(self.active);return dict(self.counts)

class DirectReplay(Core):
 def __init__(self,image,row):
  row=B.hydrate(row,image);super().__init__(image,row);self.entries=[];self.returns=[];self.active=[];self.logical=[]
 def code(self,u,a,n,d):
  self.finish();API_edges(self,a)
  if self.seq<len(self.p['source_visits']):
   i=next(self.image.k.cs.disasm(bytes(u.mem_read(a,4)),a))
   if i.mnemonic=='blraa':return emission(self,a,False)
   if i.mnemonic=='pacia':
    raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4) and i.op_str=='x16, x17' and self.reg(16)==R.EMIT and self.reg(17)==0xae56;event={'PC':hex(a),'kind':'pacia','operands':i.op_str,'before_visit':self.seq,'X16':hex(self.reg(16)),'X17':hex(self.reg(17))};assert event==self.p['logical_effects'][len(self.logical)] and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};self.logical.append(event);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_effects_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return Core.code(self,u,a,n,d)
 def run(self):
  out=super().run();assert self.entries==self.p['original_API_entries'] and self.returns==self.p['original_API_returns'] and not self.active and self.logical==self.p['logical_effects']
  assert bytes(self.u.mem_read(P,SIZE))==uncompress(self.p['final_private_RAM']);self.counts['whole_private_bytes_checked']+=SIZE
  assert {hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}==self.p['final_page_sha256'];self.counts['whole_image_page_bytes_checked']+=len(self.pages)*4096
  for j,v in enumerate(self.p['final_vectors']):assert v==hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))));self.counts['vector_registers_checked']+=1
  self.counts['original_API_entries_and_returns_checked']+=len(self.returns);return dict(self.counts)
