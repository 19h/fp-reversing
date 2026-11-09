#!/usr/bin/env python3
"""Original nested waitq/thread handoff and notification return, independent oracles.
O(image+source+visits+RAM+effects), O(image+RAM+journals), three scalar SMT queries.
Declared queue/thread/CPU/DAIF epochs; no native scheduler or FairPlay delivery.
"""
import json,struct
from collections import Counter
from z3 import BitVec,And,If,ULE,Solver,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from validate_kernel_kmsg_allocation import fixture_plan
from validate_kernel_kmsg_queue import qplan,val,put
from replay_rpc502_vm_handoff import decode
from replay_kernel_send_right_lifecycle import Replay as ProducerReplay
from replay_kernel_waitq_receiver import Replay
P='kernel_waitq_receiver';R=0x6500000000;PORT=R+0xc0000;MQ=PORT+0x28;KMSG=R+0xd0000;THREAD=R+0x2c000;RECV=R+0x60000;INNER=R+0xb5000;SCRATCH=0xfffffe000cac74e0
SELECT=0xfffffe000bd6cf80;CORE=0xfffffe000bd6c660;STAGE=0xfffffe000bd6cbcc;RESUME=0xfffffe000bd6d0d4;SCHED=0xfffffe000bd26ba8

def wplan(c):
 specs=c.get('receivers',[]);ptrs=[RECV+j*4096 for j in range(len(specs))];fifo=c.get('backend')=='fifo';b=bytearray(24);struct.pack_into('<IIQ',b,0,1 if fifo else 2,0x144,ptrs[0]if ptrs else 0)
 out=[(PORT+0x10,struct.pack('<I',3)),(PORT+0x18,struct.pack('<Q',INNER)),(PORT+0x20,bytes(8)),(INNER,bytes(b))]
 for j,(a,s)in enumerate(zip(ptrs,specs,strict=True)):
  links=struct.pack('<QQ',ptrs[(j+1)%len(ptrs)],ptrs[(j-1)%len(ptrs)])if fifo else bytes(16)
  out.extend([(a,links),(a+0x10,bytes(8)),(a+0x18,struct.pack('<Q',s.get('event',0))),(a+0x28,struct.pack('<Q',s.get('waitq',PORT+0x10))),(a+0xa8,bytes(8)),(a+0xb0,struct.pack('<Q',0x11)),(a+0x1f8,struct.pack('<I',s.get('thread_state',5)))])
 return out

def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());producer=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];old=json.loads((ROOT/'kernel_kmsg_allocation_profiles.json').read_text())['cases'][29];counts=Counter();totals=Counter();summaries=[];proofs=[]
 for o,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==34 and sum(len(f['instructions'])for f in src['functions'])==4147 and src['native_receiver_execution_observed']is False
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions'];counts['original_complete_functions_recaptured']+=1
 for e in src['waitq_instruction_roles'].values():
  a=int(e['pc'],16);i=next(im.k.cs.disasm(im.k.read(a,4),a));assert i.bytes.hex()==e['bytes_hex']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'];counts['waitq_instruction_roles_recaptured']+=1
 for e in src['waitq_control_file_bytes']:assert im.k.read(int(e['address'],16),len(bytes.fromhex(e['bytes_hex']))).hex()==e['bytes_hex'];counts['waitq_control_file_ranges_recaptured']+=1
 # The saved-source instructions define the predicates, state mask and hold operations.
 roles=src['waitq_instruction_roles'];assert roles['0xfffffe000bd6ccd8']['operands']=='w8, [x23, #0x1c8]'and roles['0xfffffe000bd6d120']['operands']=='w8, [x21, #0x1c8]'and roles['0xfffffe000bd26c40']['operands']=='w8, [x19, #0x1f8]'
 event=BitVec('event64',64);want=BitVec('wanted_event64',64);identity=BitVec('waitq_identity64',64);outer=BitVec('outer_waitq64',64);state=BitVec('thread_state32',32);nest=BitVec('nesting32',32)
 queries=[('FIFO_two_guard_tree_equals_event_and_identity_match',None,If(identity==outer,If(event==want,True,False),False),And(identity==outer,event==want)),('scheduler_rewrite_clears_selected_bits_and_preserves_others',None,((state|0x100)&~0x14d)|4,(state&~0x14d)|4),('identify_release_balances_one_port_plus_nested_and_spin_holds',ULE(nest,0xfffffffc),((((nest+1)+1)+1)-1)-1+1-1-1,nest)]
 for name,domain,left,right in queries:
  s=Solver()
  if domain is not None:s.add(domain)
  s.add(left!=right);assert s.check()==unsat;proofs.append({'name':name,'domain':None if domain is None else str(domain),'query':s.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1
 fresh=ProducerReplay(im,producer).run();base=decode(producer['final_private_RAM']);meta=val(bytes.fromhex(next(e['bytes_hex']for e in producer['final_image_globals']if e['address']=='0xfffffe0007e66f00')),0);assert len(prof['cases'])==11
 for j,r in enumerate(prof['cases']):
  c=r['configuration'];specs=c.get('receivers',[]);ptrs=[RECV+k*4096 for k in range(len(specs))];fifo=c.get('backend')=='fifo';mask=c.get('interrupt_mask',0x3c0);blocked=j==8;guard=j==9;returned=not(blocked or guard);initial=bytearray(base)
  prefix=[(R+0xdc000,b'\xa5'*4),(THREAD+0xc8,bytes(2)),(PORT+0x48,struct.pack('<Q',R+0xdd000))];environment=fixture_plan({'phase':'notification'});qp=qplan(c,meta);wp=wplan(c)
  assert all(r[k]is False for k in FLAGS)and decode(r['initial_state_transfer'])==base and r['initial_state_transfer']['path']=='kernel_send_right_lifecycle_profiles.json'and r['initial_state_transfer']['case']==11;counts['exact_source_no_senders_RAM_handoffs_checked']+=1
  assert r['entry_registers31']==producer['boundary']['registers31']and r['entry_SP']==producer['boundary']['SP']and r['entry_NZCV']==producer['boundary']['NZCV']and r['entry_Q_registers32']==producer['final_Q_registers32']and r['register_overlays']==[]and r['entry_DAIF_mask']==hex(mask);counts['source_CPU_entry_and_explicit_DAIF_epochs_checked']+=1
  assert r['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in prefix+environment+qp+wp]
  for plan,events in[(prefix,r['memory_overlays']),(environment,r['allocation_environment_overlays']),(qp,r['queue_environment_overlays']),(wp,r['waitq_environment_overlays'])]:
   assert len(plan)==len(events)
   for(a,b),e in zip(plan,events,strict=True):assert e['address']==hex(a)and e['before_hex']==initial[a-R:a-R+len(b)].hex()and e['after_hex']==b.hex();initial[a-R:a-R+len(b)]=b;counts['independent_input_patch_before_images_checked']+=1
  globals=producer['final_image_globals']+[{'address':'0xfffffe0007e62b68','bytes_hex':struct.pack('<Q',R+0xdc800).hex()},{'address':'0xfffffe0007e5c221','bytes_hex':'00'},{'address':'0xfffffe000caec680','bytes_hex':struct.pack('<QQ',R+0xb0000,R+0xb1000).hex()},{'address':'0xfffffe0007e66ea0','bytes_hex':struct.pack('<QQ',R,R+0x100000).hex()},{'address':'0xfffffe0007e6d038','bytes_hex':struct.pack('<I',0x40000).hex()},{'address':hex(SCRATCH),'bytes_hex':bytes(48).hex()}];assert[{k:e[k]for k in['address','bytes_hex']}for e in r['initial_image_fixtures']]==globals and r['final_image_globals']==globals;counts['exact_source_and_declared_global_epochs_checked']+=1
  qv=r['queue_entry_variant'];assert qv['before_arguments4']==qv['after_arguments4']==[hex(MQ),hex(KMSG),'0x50001','0x0']and qv['registers']==qv['patches']==[];counts['unmodified_original_notification_queue_ABI_checked']+=1
  remaining=list(range(len(specs)));selected=[];delivered=None;selects=0
  if guard:selects=1
  else:
   while True:
    selects+=1;candidate=next((k for k in remaining if(not fifo or(specs[k].get('event',0)==0 and specs[k].get('waitq',PORT+0x10)==PORT+0x10))),None)
    if candidate is None:break
    selected.append(candidate);remaining.remove(candidate);s=specs[candidate];fits=s.get('capacity',44)>=44
    if fits or not s.get('options',0)&4:delivered=candidate;break
  expected=[]
  for k,(ptr,s)in enumerate(zip(ptrs,specs,strict=True)):
   b=bytearray(initial[ptr-R:ptr-R+0x600])
   if k in selected:
    b[:16]=bytes(16);put(b,0x18,8,0);put(b,0x28,8,0);b[0xcb]=b[0x58e]=0;put(b,0xd8,4,0);put(b,0x1f8,4,(s.get('thread_state',5)|0x100)if blocked else((s.get('thread_state',5)|0x100)&~0x14d)|4);put(b,0xa8,8,THREAD if blocked else 0)
    fits=s.get('capacity',44)>=44;put(b,0x3a0,4,0 if fits else 0x10004004)
    if not fits:put(b,0x3a8,4,36);put(b,0x3ac,4,0)
    if not fits and s.get('options',0)&4:put(b,0x3b0,4,0x303)
    else:put(b,0x3b8,8,KMSG);put(b,0x3a4,4,7)
   elif fifo and not guard:
    idx=remaining.index(k);put(b,0,8,ptrs[remaining[(idx+1)%len(remaining)]]);put(b,8,8,ptrs[remaining[(idx-1)%len(remaining)]])
   expected.append({'address':hex(ptr),'bytes1536_hex':bytes(b).hex()})
  assert r['final_queue_receivers']==expected and r['waitq_selections']==selects and r['waitq_wakeup_arguments']==[hex(ptrs[k])for k in selected];counts['independent_complete_receiver_matching_state_status_link_oracles_checked']+=1
  inner=bytearray(initial[INNER-R:INNER-R+24]);put(inner,4,4,0x144 if guard else 0x144+selects*0x1010000);put(inner,8,8,ptrs[remaining[0]]if remaining else 0)
  assert r['final_inner24_hex']==bytes(inner).hex()and r['final_scratch48_hex']==bytes(48).hex()and r['final_DAIF_mask']==hex(mask);counts['independent_waitq_head_ticket_scratch_and_mask_oracles_checked']+=1
  port=bytearray(initial[PORT-R:PORT-R+144]);enqueued=returned and delivered is None;put(port,0x14,4,0x02020144 if returned else 0x02010144);put(port,0x38,2,int(enqueued or not returned));put(port,0x30,4,7+int(delivered is not None));raw=bytearray(bytes.fromhex(old['final_raw_kmsg256_hex']))
  if enqueued:put(port,0x28,8,KMSG);put(raw,0,8,KMSG);put(raw,8,8,KMSG)
  assert r['final_destination144_hex']==bytes(port).hex()and r['final_raw_kmsg256_hex']==bytes(raw).hex()and r['raw_kmsg_guard_hex']=='a5'and r['final_queue_task_send_counter']==int(returned)and r['final_queue_thread_nesting']==(2 if blocked else 1 if guard else 0);counts['independent_complete_port_kmsg_accounting_and_nesting_oracles_checked']+=1
  wf=r['waitq_frames'];stageframes=[e for e in wf if int(e['pc'],16)==STAGE];returnframes=[e for e in wf if e['pc']=='0xfffffe000bd6d0b8'];resumeframes=[e for e in wf if int(e['pc'],16)==RESUME];assert len(stageframes)==len(selected)==len(resumeframes)and len(returnframes)==(0 if guard else selects)
  for e in wf:
   pc=int(e['pc'],16);b=bytes.fromhex(e['receiver1536_hex']or'');a=int(e['receiver_address'],16)
   if pc==SELECT:assert e['arguments8'][:5]==[hex(PORT+0x10),'0x0','0x0','0x40','0x0']and e['thread_nesting']==1
   if pc==STAGE:assert e['arguments8'][:2]==[hex(PORT+0x10),hex(a)]and e['thread_nesting']==2 and e['DAIF_mask']=='0x3c0'and val(b,0xa8)==0 and b[:16]==bytes(16);counts['original_waitq_unlink_before_stage_frames_checked']+=1
   if pc==0xfffffe000bd6cfc8 and val(bytes.fromhex(e['scratch48_hex']),0):
    assert val(bytes.fromhex(e['scratch48_hex']),0)==a and bytes.fromhex(e['scratch48_hex'])[8]==1 and b[:16]==struct.pack('<QQ',a,a)and e['thread_nesting']==2 and val(b,0xa8)==0 and val(b,0x1f8,4)==(specs[ptrs.index(a)].get('thread_state',5)|0x100);counts['original_temporary_selected_ring_and_extra_hold_frames_checked']+=1
   if pc==0xfffffe000bd6d0b8:
    got=int(e['arguments8'][0],16);assert e['scratch48_hex']==bytes(48).hex()and e['thread_nesting']==1+int(bool(got))and e['DAIF_mask']==hex(mask)
    if got:assert a==got and b[:16]==bytes(16)and val(b,0xa8)==0 and val(b,0x28)==val(b,0x18)==0;counts['original_selected_return_has_extra_hold_and_free_spin_checked']+=1
   if pc==RESUME:assert e['thread_nesting']==2 and val(b,0xa8)==0 and e['DAIF_mask']==hex(mask)
   if pc in[0xfffffe000bd6d134,SCHED]:assert e['thread_nesting']==2 and val(b,0xa8)==THREAD and val(b,0xb0)==0x11 and e['DAIF_mask']=='0x3c0';counts['original_receiver_spin_owner_assertion_and_hold_consumption_checked']+=1
   if pc==0xfffffe000bd6d168:assert e['thread_nesting']==1 and val(b,0xa8)==0 and val(b,0x1f8,4)==4 and e['DAIF_mask']=='0x3c0';counts['original_fast_scheduler_state_and_spin_release_checked']+=1
   if pc==0xfffffe000bcc8014:assert e['thread_nesting']==1 and e['DAIF_mask']==hex(mask);counts['original_release_return_DAIF_restoration_checked']+=1
  if returned:
   assert r['boundary']['kind']=='outer_notification_caller_returned';f=next(e for e in r['queue_frames']if e['pc']=='0xfffffe000bcc822c');caller=next(e for e in r['entry_frames']if e['pc']=='0xfffffe000bcd059c');assert f['arguments8'][0]==caller['arguments5'][0]=='0x0'and f['thread_nesting']==0;counts['original_notification_caller_success_returns_checked']+=1
  else:
   assert r['boundary']['kind']==('before_original_blocked_thread_scheduler'if blocked else'before_original_waitq_or_scheduler_guard');assert r['boundary']['pc']==hex(SCHED if blocked else 0xfffffe000c62a2b0);counts['explicit_scheduler_or_context_guard_prefixes_checked']+=1
  by=Counter(m['symbol']for m in r['API_models']);assert by=={'declared_byte_copy':1,'opaque_keyed_hash_result':2,'declared_message_tag_helper':1,'declared_send_preflight':1};counts['no_waitq_selection_release_scheduler_or_port_lock_models_checked']+=1
  for ordinal,m in enumerate(r['API_models'],1):
   want=[hex(((k+1)*0x123456789abcdef)^(ordinal*0x8b3dc651))for k in range(18)];want[0]=m['return_value'];assert m['after_registers31'][:18]==want and m['native_effects_executed']is False and int(m['after_NZCV'],16)==(0xf0000000 if ordinal&1 else 0);counts['remaining_primitive_model_clobber_contracts_checked']+=1
  for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_dynamic_original_instruction_recaptured']+=1
  totals.update(Replay(im,r).run());summaries.append({'case':j,'configuration':c,'visits':len(r['source_visits']),'selected_receiver_indices':selected,'remaining_receiver_indices':remaining,'enqueued':enqueued,'delivered_receiver_index':delivered,'send_status':'0x0'if returned else None,'boundary':r['boundary']['kind'],'final_DAIF_mask':r['final_DAIF_mask']});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=11,functions=34,captured_instructions=4147)
 deps=[P+'_source.json',P+'_profiles.json','kernel_send_right_lifecycle_profiles.json','kernel_kmsg_allocation_profiles.json','validate_kernel_kmsg_allocation.py','validate_kernel_kmsg_queue.py','replay_'+P+'.py','replay_kernel_kmsg_queue.py','replay_kernel_kmsg_allocation.py','replay_kernel_notification_send.py','replay_kernel_send_right_lifecycle.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','replay_rpc502_vm_handoff.py','recover_kernel_send_right_lifecycle.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_notification_producer_replay':fresh,'proofs':proofs,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
