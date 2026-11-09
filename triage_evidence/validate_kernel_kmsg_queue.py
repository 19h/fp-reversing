#!/usr/bin/env python3
"""Original queue/port/receiver/list ABI, source notification and status oracles.
O(image+source+visits+RAM+effects), O(image+RAM+journals), bounded scalar SMT.
Port/owner/waitq/queue epochs remain conditional; no native IPC or retirement.
"""
import json,struct
from pathlib import Path
from collections import Counter
from z3 import BitVec,BitVecVal,ZeroExt,And,Or,ULE,ULT,Extract,If,UGT,LShR,Solver,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from validate_kernel_kmsg_allocation import fixture_plan
from replay_rpc502_vm_handoff import decode
from replay_kernel_send_right_lifecycle import Replay as ProducerReplay
from replay_kernel_kmsg_queue import Replay
P='kernel_kmsg_queue';R=0x6500000000;PORT=R+0xc0000;MQ=PORT+0x28;KMSG=R+0xd0000;THREAD=R+0x2c000;OWNER=R+0x30000;TASK=R+0x3c000;QSTATS=R+0xb9000;RECV=R+0x60000;OLD=R+0xd8000;QENTRY=0xfffffe000bcc7c34

def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def put(b,o,n,x):b[o:o+n]=x.to_bytes(n,'little')
def qplan(c,meta):
 n=c.get('old_messages',0);out=[(PORT+0x14,struct.pack('<I',0x144)),(MQ+8,struct.pack('<IIHH',7,0x303,c.get('count',n),c.get('limit',16))),(THREAD+0x420,struct.pack('<Q',OWNER)),(OWNER,struct.pack('<Q',THREAD)),(OWNER+0x28,struct.pack('<Q',TASK)),(TASK+0x3d0,struct.pack('<Q',QSTATS)),(QSTATS,bytes(8)),(THREAD+0x211,b'\0')]
 out.extend((meta+((a>>10)&0xffffffff0),struct.pack('<H',kind))for a,kind in[(PORT,22),(OWNER,3)])
 if n:
  out.append((MQ,struct.pack('<Q',OLD)))
  for j in range(n):
   b=bytearray(256);put(b,0,8,OLD+((j+1)%n)*256);put(b,8,8,OLD+((j-1)%n)*256);b[0x3e]=[2,5][j];out.append((OLD+j*256,bytes(b)))
 for j,s in enumerate(c.get('receivers',[])):
  b=bytearray(0x600);put(b,0x388,4,s.get('capacity',44));put(b,0x38c,4,s.get('aux_capacity',0));put(b,0x390,8,s.get('options',0));put(b,0x3a0,4,s.get('state',0x10004001));out.append((RECV+j*4096,bytes(b)))
 return out

def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());producer=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];old=json.loads((ROOT/'kernel_kmsg_allocation_profiles.json').read_text())['cases'][29];counts=Counter();totals=Counter();summaries=[];proofs=[]
 for o,s in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/s)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
  assert all(o[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==22 and sum(len(f['instructions'])for f in src['functions'])==2930 and src['native_queue_delivery_observed']is False
 for f in src['functions']:
  a=int(f['start'],16);raw=im.k.read(a,int(f['end'],16)-a);assert raw.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]==f['instructions'];counts['original_complete_functions_recaptured']+=1
 for e in src['queue_instruction_roles'].values():
  a=int(e['pc'],16);i=next(im.k.cs.disasm(im.k.read(a,4),a));assert i.bytes.hex()==e['bytes_hex']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'];counts['queue_instruction_roles_recaptured']+=1
 for e in src['related_fixed_zone_specs']:assert im.k.read(int(e['specification_address'],16),48).hex()==e['specification_bytes48_hex']and im.pointer(int(e['name_pointer']['slot'],16))==e['name_pointer'];counts['related_IPC_zone_specifications_recaptured']+=1
 assert[(e['identifier_u16'],e['requested_size_u64'])for e in src['related_fixed_zone_specs']]==[(24,256),(22,144)]
 sdk=src['SDK_message_definitions'];assert sha(sdk['path'])==sdk['sha256'];lines=Path(sdk['path']).read_text().splitlines();macros={s.split()[1]:s.split()[2]for s in lines if s.startswith('#define ')and len(s.split())>=3}
 def macro(n):
  token=macros[n]
  try:return int(token,0)
  except ValueError:return macro(token)
 for e in sdk['definitions']:assert lines[e['line']-1]==e['text'];counts['pinned_SDK_macro_lines_checked']+=1
 for name,v in{'MACH_RCV_LARGE':4,'MACH_SEND_TIMED_OUT':0x10000004,'MACH_SEND_NO_BUFFER':0x1000000d,'MACH_RCV_IN_PROGRESS':0x10004001,'MACH_RCV_TOO_LARGE':0x10004004,'MACH_MSG_TYPE_MOVE_SEND_ONCE':18,'MACH_MSG_TYPE_MOVE_SEND':17,'MACH_SEND_TIMEOUT':16}.items():assert macro(name)==v
 count=BitVec('queue_count16',16);limit=BitVec('queue_limit16',16);opts=BitVec('queue_options32',32);disp=BitVec('disposition5',5);n=BitVec('kernel_message_bytes32',32)
 admit=Or(ULT(count,limit),And(ULE(count,65533),Or((opts&0x10000)!=0,disp==18)))
 lock=BitVec('ticket_lock32',32);acquired=lock+0x1000000;released=(acquired&0xff00ffff)|(((LShR(acquired,16)+1)&255)<<16)
 tree=If(ULT(count,limit),True,If(UGT(count,65533),False,If((opts&0x10000)!=0,True,disp==18)))
 queries=[('admitted_reservation_does_not_wrap_u16',admit,ULT(ZeroExt(16,count)+1,65536),True),('queue_branch_tree_equals_compact_admission_rule',None,tree,admit),('ticket_cycle_preserves_low_control_bits',None,released&65535,lock&65535)]
 for name,domain,left,right in queries:
  solver=Solver()
  if domain is not None:solver.add(domain)
  solver.add(left!=right);assert solver.check()==unsat;proofs.append({'name':name,'domain':None if domain is None else str(domain),'query':solver.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1
 freshproducer=ProducerReplay(im,producer).run();base=decode(producer['final_private_RAM']);rows=prof['cases'];assert len(rows)==16
 meta=val(bytes.fromhex(next(e['bytes_hex']for e in producer['final_image_globals']if e['address']=='0xfffffe0007e66f00')),0)
 for j,r in enumerate(rows):
  c=r['configuration'];nold=c.get('old_messages',0);initial=bytearray(base);prefix=[(R+0xdc000,b'\xa5'*4),(THREAD+0xc8,bytes(2)),(PORT+0x48,struct.pack('<Q',R+0xdd000))];environment=fixture_plan({'phase':'notification'});qp=qplan(c,meta);assert all(r[k]is False for k in FLAGS)and decode(r['initial_state_transfer'])==base and r['initial_state_transfer']['path']=='kernel_send_right_lifecycle_profiles.json'and r['initial_state_transfer']['case']==11;counts['exact_source_no_senders_RAM_handoffs_checked']+=1
  assert r['entry_registers31']==producer['boundary']['registers31']and r['entry_SP']==producer['boundary']['SP']and r['entry_NZCV']==producer['boundary']['NZCV']and r['entry_Q_registers32']==producer['final_Q_registers32']and r['register_overlays']==[];counts['exact_source_notification_CPU_call_state_checked']+=1
  assert r['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in prefix+environment+qp]
  for planpart,events in[(prefix,r['memory_overlays']),(environment,r['allocation_environment_overlays']),(qp,r['queue_environment_overlays'])]:
   assert len(planpart)==len(events)
   for (a,b),e in zip(planpart,events,strict=True):assert e['address']==hex(a)and e['before_hex']==initial[a-R:a-R+len(b)].hex()and e['after_hex']==b.hex();initial[a-R:a-R+len(b)]=b;counts['exact_input_epoch_patch_before_images_checked']+=1
  expectedglobals=producer['final_image_globals']+[{'address':'0xfffffe0007e62b68','bytes_hex':struct.pack('<Q',R+0xdc800).hex()},{'address':'0xfffffe0007e5c221','bytes_hex':'00'},{'address':'0xfffffe000caec680','bytes_hex':struct.pack('<QQ',R+0xb0000,R+0xb1000).hex()},{'address':'0xfffffe0007e66ea0','bytes_hex':struct.pack('<QQ',R,R+0x100000).hex()},{'address':'0xfffffe0007e6d038','bytes_hex':struct.pack('<I',0x40000).hex()}];assert[{k:e[k]for k in['address','bytes_hex']}for e in r['initial_image_fixtures']]==expectedglobals and r['final_image_globals']==expectedglobals;counts['exact_inherited_and_declared_type_owner_global_epochs_checked']+=1
  qv=r['queue_entry_variant'];assert qv['before_arguments4']==[hex(MQ),hex(KMSG),'0x50001','0x0'];after=list(qv['before_arguments4']);registers=[];patches=[]
  for k,key in[(2,'queue_options'),(3,'timeout')]:
   if key in c:registers.append({'register':'X'+str(k),'before':after[k],'after':hex(c[key])});after[k]=hex(c[key])
  raw=bytearray(bytes.fromhex(old['final_raw_kmsg256_hex']))
  if'disposition'in c:before=bytes(raw[0x40:0x44]);put(raw,0x40,4,(val(raw,0x40,4)&~31)|c['disposition']);patches.append({'address':hex(KMSG+0x40),'before_hex':before.hex(),'after_hex':raw[0x40:0x44].hex()})
  if'priority'in c:patches.append({'address':hex(KMSG+0x3e),'before_hex':bytes([raw[0x3e]]).hex(),'after_hex':bytes([c['priority']]).hex()});raw[0x3e]=c['priority']
  assert qv['after_arguments4']==after and qv['registers']==registers and qv['patches']==patches;counts['explicit_queue_ABI_and_internal_header_variants_checked']+=1
  f=r['queue_frames'];qentry=next(e for e in f if e['pc']==hex(QENTRY));assert qentry['arguments8'][:4]==after and qentry['thread_nesting']==1 and val(bytes.fromhex(qentry['port144_hex']),0x14,4)==0x01000144;counts['original_held_port_lock_queue_entry_ABI_checked']+=1
  status=None;prefixkind=None;enqueued=False;delivered=None;receivers=c.get('receivers',[]);wake=[];selects=0;wantedreceivers=[];successful=j in[0,1,2,3,4,5,6,7,8,13]
  for k,s in enumerate(receivers):
   ptr=RECV+k*4096;b=bytearray(initial[ptr-R:ptr-R+0x600]);opt=s.get('options',0);trailer={0:8,1:12}[((opt>>24)&15)];fits=s.get('capacity',44)>=36+trailer;selects+=1;wake.append(hex(ptr))
   if fits:put(b,0x3a0,4,0)
   else:put(b,0x3a0,4,0x10004004);put(b,0x3a8,4,36);put(b,0x3ac,4,0)
   if not fits and opt&4:put(b,0x3b0,4,0x303)
   else:put(b,0x3b8,8,KMSG);put(b,0x3a4,4,7);delivered=k
   wantedreceivers.append({'address':hex(ptr),'bytes1536_hex':bytes(b).hex()})
   if delivered is not None:break
  assert len(wantedreceivers)==len(receivers)
  if successful:
   status=0;enqueued=delivered is None
   if enqueued:selects+=1
  elif j in[9,11]:status=0x10000004
  elif j==10:status=0x1000000d
  elif j in[12,15]:prefixkind='before_original_large_queue_policy'
  else:assert j==14;prefixkind='before_original_sender_wait_or_wakeup'
  assert r['waitq_selections']==selects and r['waitq_wakeup_arguments']==wake and r['final_queue_receivers']==wantedreceivers;counts['independent_receiver_fit_status_size_pointer_and_retry_oracles_checked']+=1
  port=bytearray(initial[PORT-R:PORT-R+144]);count0=c.get('count',nold);put(port,0x14,4,0x02020144 if successful else 0x01010144 if j!=14 else 0x01000144)
  if successful:put(port,0x38,2,count0+int(enqueued));put(port,0x30,4,7+int(delivered is not None))
  elif j in[12,15]:put(port,0x38,2,count0+1)
  elif j==14:put(port,0x10,4,val(port,0x10,4)|0x20)
  if enqueued:
   if nold:put(raw,0,8,OLD);put(raw,8,8,OLD+(nold-1)*256)
   else:put(raw,0,8,KMSG);put(raw,8,8,KMSG);put(port,0x28,8,KMSG)
   eq=next(e for e in f if e['pc']=='0xfffffe000bcc7ed4');assert eq['arguments8'][0]==hex(int(not nold or c.get('priority',0)>5));counts['original_enqueue_boolean_distinct_from_send_status_checked']+=1
  assert r['final_destination144_hex']==bytes(port).hex()and r['final_raw_kmsg256_hex']==bytes(raw).hex()and r['raw_kmsg_guard_hex']=='a5'and r['final_queue_task_send_counter']==int(successful)and r['final_queue_thread_nesting']==int(j==14);counts['independent_complete_port_kmsg_task_counter_and_nesting_oracles_checked']+=1
  ram=decode(r['final_private_RAM'])
  for k,e in enumerate(r['final_old_queue_elements']):
   ptr=OLD+k*256;b=bytearray(initial[ptr-R:ptr-R+256]);put(b,0,8,OLD+(k+1)*256 if k+1<nold else KMSG);put(b,8,8,OLD+(k-1)*256 if k else KMSG)
   if c.get('priority',0)>5:b[0x3e]=c['priority']
   assert e=={'address':hex(ptr),'bytes256_hex':bytes(b).hex()};counts['original_circular_list_links_and_monotone_byte_updates_checked']+=1
  if status is not None:
   assert r['boundary']['kind']=='outer_notification_caller_returned';ret=next(e for e in f if e['pc']=='0xfffffe000bcc822c');caller=next(e for e in r['entry_frames']if e['pc']=='0xfffffe000bcd059c');assert ret['arguments8'][0]==caller['arguments5'][0]==hex(status)and ret['thread_nesting']==0;counts['original_queue_status_through_wrapper_and_notification_caller_checked']+=1
  else:assert r['boundary']['kind']==prefixkind;counts['explicit_large_policy_or_sender_wait_frontiers_checked']+=1
  models=r['API_models'];by={}
  for m in models:by.setdefault(m['symbol'],[]).append(m)
  assert not any(name in by for name in['declared_queue_send','declared_destination_lock','declared_destination_unlock','declared_kmsg_allocate'])and not any('zero_check'in name or'zone_allocate'in name for name in by);counts['no_whole_queue_port_lock_or_allocator_model_checked']+=1
  assert len(by.get('declared_waitq_receiver_selection',[]))==selects and len(by.get('declared_waitq_receiver_wakeup',[]))==len(wake)
  destroyed=by.get('declared_message_destroy',[]);assert[m['arguments8'][:2]for m in destroyed]==([[hex(KMSG),'0x0']]if status else[])
  if successful:
   assert sum(v['pc']=='0xfffffe000bccc128'for v in r['source_visits'])==2 and sum(v['pc']=='0xfffffe000bd7e9c4'for v in r['source_visits'])==1;counts['original_type_checked_port_locks_and_owner_task_accessors_checked']+=1
  for k,m in enumerate(models):
   want=[hex(((i+1)*0x123456789abcdef)^((k+1)*0x8b3dc651))for i in range(18)];want[0]=m['return_value'];assert m['after_registers31'][:18]==want and m['native_effects_executed']is False and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0);counts['declared_remaining_primitive_clobber_models_checked']+=1
  for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_dynamic_original_instruction_recaptured']+=1
  totals.update(Replay(im,r).run());summaries.append({'case':j,'configuration':c,'visits':len(r['source_visits']),'status':None if status is None else hex(status),'enqueued':enqueued,'delivered_receiver_index':delivered,'boundary':r['boundary']['kind']});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=16,functions=22,captured_instructions=2930)
 deps=[P+'_source.json',P+'_profiles.json','kernel_send_right_lifecycle_profiles.json','kernel_kmsg_allocation_profiles.json','validate_kernel_kmsg_allocation.py','replay_'+P+'.py','replay_kernel_kmsg_allocation.py','replay_kernel_notification_send.py','replay_kernel_send_right_lifecycle.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','replay_rpc502_vm_handoff.py','recover_kernel_send_right_lifecycle.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_notification_producer_replay':freshproducer,'proofs':proofs,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
