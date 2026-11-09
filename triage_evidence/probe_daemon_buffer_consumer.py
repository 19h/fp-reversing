#!/usr/bin/env python3
"""Source-pinned A64 continuation through the complete mask loop and its consumer.
The complete sealed prefix is replayed first. Unknown private bytes/registers
stop continuation. Imports, Mach/IOKit and native PAC never execute.
O(prefix bytes+source visits+624*128) time, O(prefix+owner+unique PCs) space.
"""
import hashlib,json,struct,argparse
from pathlib import Path
from collections import Counter
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from daemon_context_transfer_symbolic import P,WRITABLE,loaded_bytes
from replay_daemon_context_transfer import unpack,known
from replay_daemon_prng_output import OutputReplay,twist,temper,INPUTS
from replay_daemon_entropy_return import ARRAY

START=0x100350628;EXIT=0x100315438;ALLOWED_CALLS={0x100427514,0x10041a5e0,0x100444d6c}
def sha(path):
 with path.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def canonical(name):
 if name in ('xzr','wzr'):return 'zero'
 if name in ('fp','lr'):return {'fp':'x29','lr':'x30'}[name]
 if name in ('sp','wsp'):return 'sp'
 if name.startswith('w')and name[1:].isdigit():return 'x'+name[1:]
 if name[:1]in 'bhsdqv'and name[1:].isdigit():return 'q'+name[1:]
 return name
class Consumer(OutputReplay):
 def __init__(self,*args):
  self.dynamic=False;super().__init__(*args)
 def stop(self,kind,**kwargs):
  self.dynamic_boundary={'kind':kind,'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(self.fullreg('sp')),**kwargs};self.u.emu_stop()
 def finish_dynamic(self):
  for row in self.pending_dynamic:
   a,n=row['address'],row['size_bytes'];raw=bytes(self.u.mem_read(a,n));row['after_hex']=raw.hex();self.stream.update(b'W'+struct.pack('<QQI',row['pc'],a,n)+raw)
   if P<=a<a+n<=P+0x10000:self.known[a-P:a-P+n]=bytes([1])*n
   elif self.H<=a<a+n<=self.H+90000:self.heap_known[a-self.H:a-self.H+n]=bytes([1])*n
   else:
    for at in range(a,a+n):self.image_known[at]=True
   if self.consumer_entered:self.consumer_events.append({'kind':'write',**{k:hex(v)if k in ('pc','address')else v for k,v in row.items()}})
  self.pending_dynamic=[]
 def code(self,u,a,n,d):
  if not self.dynamic:return super().code(u,a,n,d)
  self.finish_dynamic()
  if self.pending_call is not None and a==self.pending_call['return_pc']:
   record=self.call_records[self.pending_call['index']];record['returned']=True;record['packet_after']=self.packet_snapshot(int(record['X0'],16));self.pending_call=None
  if a==START and self.lastpc==0x100350624:
   j=self.words_done;assert j<128;self.expected_state=twist(self.expected_state);raw=bytes(u.mem_read(ARRAY,2496));assert raw==b''.join(v.to_bytes(4,'little')for v in self.expected_state),('twist',j)
   word=temper(self.expected_state[j]);old=int.from_bytes(self.expected_buffer[j*4:j*4+4],'little');self.expected_buffer[j*4:j*4+4]=(old^word).to_bytes(4,'little');assert bytes(u.mem_read(self.destination,512))==self.expected_buffer,('mask',j)
   index=int.from_bytes(bytes(u.mem_read(0x1010c67dc,4)),'little');counter=int.from_bytes(bytes(u.mem_read(0x1010c8258,4)),'little');assert index==counter==j+1
   self.word_certificates.append({'word_index':j,'offset_bytes':j*4,'old_u32':hex(old),'state_u32':hex(self.expected_state[j]),'tempered_u32':hex(word),'new_u32':hex(old^word),'global_index':index,'global_counter':counter,'state_sha256':hashlib.sha256(raw).hexdigest(),'buffer_sha256':hashlib.sha256(self.expected_buffer).hexdigest()});self.words_done+=1
   if self.words_done%32==0:print(json.dumps({'words_complete':self.words_done,'dynamic_source_visits':self.dynamic_counts['source_visits']}),flush=True)
  if a==EXIT:
   assert self.words_done==128 and int.from_bytes(bytes(u.mem_read(self.F+0x48c,4)),'little')==512;self.consumer_entered=True;self.exit_snapshot={'pc':hex(a),'source_visits_before_exit':self.dynamic_counts['source_visits'],'buffer_address':hex(self.destination),'buffer_bytes_hex':bytes(u.mem_read(self.destination,512)).hex(),'global_index':int.from_bytes(bytes(u.mem_read(0x1010c67dc,4)),'little'),'global_counter':int.from_bytes(bytes(u.mem_read(0x1010c8258,4)),'little')}
  if a not in self.dynamic_cache:
   raw=IMAGE.read(a,4);ins=next(self.decoder.disasm(raw,a));reads,writes=ins.regs_access();self.dynamic_cache[a]=(ins,[canonical(ins.reg_name(x))for x in reads],[canonical(ins.reg_name(x))for x in writes]);self.dynamic_pool[hex(a)]={'pc':hex(a),'bytes_hex':raw.hex(),'mnemonic':ins.mnemonic,'operands':ins.op_str}
  ins,reads,writes=self.dynamic_cache[a];assert bytes(u.mem_read(a,4))==bytes(ins.bytes),('modified source',hex(a))
  bad=[x for x in reads if not self.register_known.get(x,False)]
  if bad:return self.stop('unknown_register_input',registers=bad,mnemonic=ins.mnemonic,operands=ins.op_str)
  if ins.mnemonic in ('svc','hvc','smc','msr','mrs','pacibsp','paciasp','autibsp','autiasp','brk'):return self.stop('unmodeled_system_or_auth_instruction',mnemonic=ins.mnemonic)
  if ins.mnemonic in ('braa','blraa','braaz','blraaz','br','blr','ret','retab','retaa'):
   reg='x30'if ins.mnemonic in ('ret','retab','retaa')else ins.reg_name(ins.operands[0].reg);target=self.fullreg(canonical(reg));modifier=None
   if ins.mnemonic in ('braa','blraa'):modifier=self.fullreg(canonical(ins.reg_name(ins.operands[1].reg)))
   iscall=ins.mnemonic in ('blraa','blraaz','blr')
   if iscall and target not in ALLOWED_CALLS:
    recent=[e for e in self.consumer_events if e['kind']=='read'and e['size_bytes']==8 and int.from_bytes(bytes.fromhex(e['bytes_hex']),'little')==target]
    address=self.reg(0);packet=self.packet_snapshot(address)
    return self.stop('before_uninspected_call',target=hex(target),modifier=hex(modifier)if modifier is not None else None,matching_target_reads=recent[-4:],packet_snapshot=packet)
   try:self.page(target)
   except (AssertionError,ValueError):return self.stop('outside_image_branch',target=hex(target))
   self.edges[(a,target,modifier,iscall)]+=1
   if iscall and self.consumer_entered:
    record={'pc':hex(a),'target':hex(target),'modifier':hex(modifier)if modifier is not None else None,'X0':hex(self.reg(0)),'argument_registers8':[hex(self.reg(j))for j in range(8)],'packet_before':self.packet_snapshot(self.reg(0)),'returned':False};self.call_records.append(record);assert self.pending_call is None;self.pending_call={'index':len(self.call_records)-1,'return_pc':a+4}
   if iscall:self.set(30,a+4)
   u.reg_write(ar.UC_ARM64_REG_PC,target)
  elif ins.mnemonic=='bl':return self.stop('before_uninspected_direct_call',target=hex(ins.operands[0].imm))
  self.dynamic_counts['source_visits']+=1;self.pc_counts[a]+=1;self.stream.update(b'I'+struct.pack('<Q',a)+bytes(ins.bytes));self.lastpc=a
  for name in writes:self.register_known[name]=True
 def packet_snapshot(self,a,n=64):
  if not(P<=a<a+n<=P+0x10000 or self.H<=a<a+n<=self.H+90000):return None
  mask=self.known[a-P:a-P+n]if P<=a<a+n<=P+0x10000 else self.heap_known[a-self.H:a-self.H+n]
  return {'address':hex(a),'captured_extent_bytes':n,'physical_bytes_hex':bytes(self.u.mem_read(a,n)).hex(),'known_mask_hex':bytes(mask).hex(),'unknown_bits_are_not_definitions':True}
 def known_range(self,a,n):
  if P<=a<a+n<=P+0x10000:return all(self.known[a-P:a-P+n])
  if self.H<=a<a+n<=self.H+90000:return all(self.heap_known[a-self.H:a-self.H+n])
  try:loaded_bytes(a,n)
  except AssertionError:return False
  return all(self.image_known.get(at,True)for at in range(a,a+n))
 def read(self,u,access,a,n,value,d):
  if not self.dynamic:return super().read(u,access,a,n,value,d)
  if not self.known_range(a,n):return self.stop('unknown_or_unowned_memory_read',address=hex(a),size_bytes=n,instruction_effects_not_used=True)
  raw=bytes(u.mem_read(a,n));self.dynamic_counts['read_events']+=1;self.dynamic_counts['read_bytes']+=n;self.stream.update(b'R'+struct.pack('<QQI',self.lastpc,a,n)+raw)
  if n==8 and a in FIXUPS:self.used_fixups.add(a)
  if self.consumer_entered:self.consumer_events.append({'kind':'read','pc':hex(self.lastpc),'address':hex(a),'size_bytes':n,'bytes_hex':raw.hex()})
 def write(self,u,access,a,n,value,d):
  if not self.dynamic:return super().write(u,access,a,n,value,d)
  assert P<=a<a+n<=P+0x10000 or self.H<=a<a+n<=self.H+90000 or any(va<=a<a+n<=va+vs for va,vs in WRITABLE),('unowned write',hex(self.lastpc),hex(a),n)
  if a<P:
   for page in range(a&~4095,((a+n-1)&~4095)+1,4096):self.page(page)
  self.dynamic_counts['write_events']+=1;self.dynamic_counts['write_bytes']+=n;self.pending_dynamic.append({'pc':self.lastpc,'address':a,'size_bytes':n,'before_hex':bytes(u.mem_read(a,n)).hex()})
 def run_consumer(self):
  prefix=super().run_output();self.pending_dynamic=[];self.dynamic_counts=Counter();self.consumer_events=[];self.call_records=[];self.pending_call=None;self.word_certificates=[];self.exit_snapshot=None;self.dynamic_boundary=None;self.stream=hashlib.sha256();self.dynamic_cache={};self.dynamic_pool={};self.used_fixups=set();self.pc_counts=Counter();self.edges=Counter();self.lastpc=None;self.consumer_entered=False;self.image_known={}
  for row in self.trace['steps']:
   for e in row['events']:
    if e['kind']=='write':
     a=int(e['address'],16)
     if a<P:
      for j,k in enumerate(known(e['value'])):self.image_known[a+j]=bool(k)
  self.register_known={'zero':True,'sp':True,'nzcv':True,**{'q'+str(j):True for j in range(32)}}
  self.register_known.update({'x'+str(j):'hex'in shape for j,shape in enumerate(self.trace['boundary']['registers31'])})
  for row in self.trace['steps']:
   for reg,shape in row['registers_after'].items():
    if reg.startswith('q'):self.register_known[reg]='hex'in shape
  self.destination=int.from_bytes(bytes(self.u.mem_read(0x1010c8278,8)),'little');assert self.known_range(self.destination,512)
  self.expected_buffer=bytearray(self.u.mem_read(self.destination,512));initial=bytearray(self.expected_buffer)
  for j,v in enumerate(prefix['initial_buffer_words']):initial[j*4:j*4+4]=int(v,16).to_bytes(4,'little')
  self.initial_unmasked=bytes(initial);self.expected_state=[int.from_bytes(bytes(self.u.mem_read(ARRAY+j*4,4)),'little')for j in range(624)];self.words_done=2;self.dynamic=True
  self.decoder=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);self.decoder.detail=True
  self.u.emu_start(START,0,count=2500000);self.finish_dynamic()
  if self.dynamic_boundary is None:self.stop('visit_limit')
  return {'input':self.c,'values':self.cfg,'pattern':self.pattern,'prefix_verified_counts':prefix['verified_counts'],'prefix_checkpoints':prefix['checkpoints'],'prefix_certificate':prefix['prefix_certificate'],'initial_unmasked_buffer_bytes_hex':self.initial_unmasked.hex(),'dynamic_counts':dict(self.dynamic_counts),'source_stream_sha256':self.stream.hexdigest(),'complete_words_checked':self.words_done,'new_word_certificates':self.word_certificates,'exit_snapshot':self.exit_snapshot,'consumer_events':self.consumer_events,'consumer_calls':self.call_records,'final_buffer_bytes_hex':bytes(self.u.mem_read(self.destination,512)).hex(),'boundary':self.dynamic_boundary,'source_pool':self.dynamic_pool,'source_PC_counts':{hex(a):n for a,n in sorted(self.pc_counts.items())},'abstract_edges':[{'pc':hex(a),'target':hex(t),'modifier':hex(m)if m is not None else None,'call':c,'visits':n}for(a,t,m,c),n in sorted(self.edges.items())],'used_fixups':[hex(a)for a in sorted(self.used_fixups)],'new_API_summaries':0,'native_target_executed':False,'full_goal_complete':False}
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--case',type=int,default=0);parser.add_argument('--values',choices=['zero','reference'],default='reference');parser.add_argument('--all',action='store_true');parser.add_argument('--out',default='daemon_buffer_consumer_profiles.json');args=parser.parse_args()
 names=['daemon_prng_output_profiles.json','daemon_context_transfer_profiles.json','daemon_entropy_return_profiles.json','daemon_seed_material_profiles.json','daemon_arena_storage_profiles.json'];profiles,prior,entropy,material,base=[json.loads((ROOT/n).read_text())for n in names];jobs=[(i,v)for i in [0,1,16,17]for v in ['zero','reference']]if args.all else[(args.case,args.values)];rows=[]
 for index,value_name in jobs:
  pick=lambda q:unpack(next(x for x in q['cases']if x['prior_case_index']==index))
  cfg=next(x for x in INPUTS if x['name']==value_name);pattern=0 if value_name=='zero'else 3
  replay=Consumer(base['cases'][index]['input'],pick(prior),pick(entropy),pick(material),pick(profiles),cfg,pattern);row=replay.run_consumer();row['prior_case_index']=index;rows.append(row);del replay
  print(json.dumps({'case':index,'values':value_name,'words_checked':row['complete_words_checked'],'boundary_kind':row['boundary']['kind'],'boundary_pc':row['boundary']['pc'],'dynamic_counts':row['dynamic_counts'],'completed':len(rows)}),flush=True)
 deps=names+['probe_daemon_buffer_consumer.py','replay_daemon_prng_output.py','replay_daemon_seed_material.py','replay_daemon_context_transfer.py','daemon_receive_tools.py','daemon_receive_fixups.txt']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/args.out).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(r['dynamic_counts']['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
