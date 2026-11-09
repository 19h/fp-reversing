#!/usr/bin/env python3
"""Independent original init/wait producers, abort/state/priority oracles and joins.
O(image+source+visits+RAM+effects), O(image+RAM+journals), four bounded SMT queries.
No native allocation, thread blocking, race, interrupt or FairPlay transport proof.
"""
import json,struct
from collections import Counter
from z3 import BitVec,BitVecVal,ZeroExt,If,And,Or,ULT,Solver,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from validate_kernel_kmsg_allocation import fixture_plan
from validate_kernel_kmsg_queue import qplan,val,put
from validate_kernel_waitq_receiver import wplan
from replay_rpc502_vm_handoff import decode
from replay_kernel_send_right_lifecycle import Replay as NSReplay
from replay_kernel_waitq_enqueue import Replay,SenderReplay
P='kernel_waitq_enqueue';R=0x6500000000;PORT=R+0xc0000;INNER=R+0xb5000;RECV=R+0x60000;THREAD=R+0x2c000;KMSG=R+0xd0000;ZCELL=0xfffffe000caec980;PSP=R+0xe8000
CONFIGS=[{'interruptibility':0,'thread_limit':2,'priority':0},{'interruptibility':2,'thread_limit':2,'priority':31},{'interruptibility':1,'thread_limit':2,'priority':63,'DAIF_mask':0x200},{'interruptibility':2,'thread_limit':2,'priority':31,'abort_flags':0x10},{'interruptibility':2,'thread_limit':0,'priority':95,'abort_flags':0x10},{'interruptibility':1,'thread_limit':2,'priority':31,'abort_flags':0x30},{'interruptibility':2,'thread_limit':2,'priority':31,'abort_flags':0x30},{'interruptibility':1,'thread_limit':2,'priority':31,'abort_flags':0x10}]

def start_plan(c):
 b=bytearray(1536);put(b,0xb0,8,0x11);put(b,0xc8,2,c['thread_limit']);put(b,0x1c0,8,R+0xb4000);put(b,0x1f8,4,4);put(b,0x210,4,c.get('abort_flags',0));put(b,0x216,2,c['priority']);put(b,0x388,4,44);return[(PORT,bytes(144)),(INNER,bytes(96)),(RECV,bytes(b))]
def port_output():
 b=bytearray(144);put(b,0,4,0x101);put(b,4,4,1);put(b,0x10,4,0xc000b);put(b,0x14,4,0x01000144);put(b,0x34,4,0x303);put(b,0x3a,2,5);put(b,0x48,8,R+0xdd000);return b

def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());seed=json.loads((ROOT/'kernel_waitq_receiver_profiles.json').read_text())['cases'][1];ns=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];old=json.loads((ROOT/'kernel_kmsg_allocation_profiles.json').read_text())['cases'][29];counts=Counter();prodtot=Counter();contot=Counter();summaries=[];proofs=[]
 for o,s in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/s)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==48 and sum(len(f['instructions'])for f in src['functions'])==5827 and src['native_wait_enqueue_observed']is False
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions'];counts['original_complete_functions_recaptured']+=1
 for e in src['enqueue_instruction_roles'].values():
  a=int(e['pc'],16);i=next(im.k.cs.disasm(im.k.read(a,4),a));assert i.bytes.hex()==e['bytes_hex']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'];counts['enqueue_instruction_roles_recaptured']+=1
 for e in src['initialization_constants']:assert im.k.read(int(e['address'],16),len(bytes.fromhex(e['bytes_hex']))).hex()==e['bytes_hex'];counts['initialization_constant_ranges_recaptured']+=1
 z=src['turnstile_zone_spec'];assert z['identifier_u16']==28 and z['requested_size_u64']==96 and im.k.read(int(z['specification_address'],16),48).hex()==z['specification_bytes48_hex']and im.pointer(int(z['name_pointer']['slot'],16))==z['name_pointer'];counts['original_turnstile_zone_specification_recaptured']+=1
 role=src['enqueue_instruction_roles']['0xfffffe000bd6c78c'];assert role['mnemonic']=='cmp'and role['operands']=='x8, #0x10, lsl #12';threshold=0x10<<12;assert threshold==65536 and 31<<8>=4096 and 31<<8<threshold;counts['corrected_priority_word_threshold_with_counterexample_checked']+=1
 i=BitVec('interruptibility2',2);cap=BitVec('thread_limit2',2);f=BitVec('abort_flags32',32);p=BitVec('priority8',8);eff=If(ULT(i,cap),i,cap);state=If(eff==0,BitVecVal(9,32),BitVecVal(1,32))
 tree=If(eff==0,False,If((f&16)==0,False,If(eff==2,True,(f&32)==0)))
 queries=[('effective_interruptibility_is_bounded_by_both_inputs',None,And(Or(eff==i,eff==cap),Or(ULT(eff,i),eff==i),Or(ULT(eff,cap),eff==cap)),True),('abort_guard_tree_equals_compact_predicate',None,tree,And(eff!=0,(f&16)!=0,Or(eff==2,(f&32)==0))),('all_u8_priority_singleton_words_below_actual_threshold',None,ULT(ZeroExt(56,p)<<8,threshold),True),('source_mark_stage_and_fast_scheduler_restore_state4',None,((4|state|0x100)&~0x14d)|4,4)]
 for name,domain,left,right in queries:
  s=Solver()
  if domain is not None:s.add(domain)
  s.add(left!=right);assert s.check()==unsat;proofs.append({'name':name,'domain':None if domain is None else str(domain),'query':s.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1
 freshns=NSReplay(im,ns).run();base=bytearray(decode(ns['final_private_RAM']));meta=val(bytes.fromhex(next(e['bytes_hex']for e in ns['final_image_globals']if e['address']=='0xfffffe0007e66f00')),0);seedplan=[(R+0xdc000,b'\xa5'*4),(THREAD+0xc8,bytes(2)),(PORT+0x48,struct.pack('<Q',R+0xdd000))]+fixture_plan({'phase':'notification'})+qplan({'receivers':[{'capacity':44}]},meta)+wplan({'receivers':[{'capacity':44}]})
 assert seed['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in seedplan]and decode(seed['initial_state_transfer'])==bytes(base)
 for a,b in seedplan:base[a-R:a-R+len(b)]=b
 assert len(prof['cases'])==32 and len(prof['consumers'])==8
 for family,c in enumerate(CONFIGS):
  ram=bytes(base);globals=[{k:e[k]for k in['address','bytes_hex']}for e in seed['initial_image_fixtures']];eff=min(c['interruptibility']&3,c['thread_limit']&3);flags=c.get('abort_flags',0);aborted=bool(eff and flags&16 and(eff==2 or not flags&32));wantport=None;wantinner=bytearray(96);wantrecv=bytearray(1536)
  for offset,kind in enumerate(['port_init','port_unlock','turnstile_allocate','receive_wait']):
   idx=family*4+offset;r=prof['cases'][idx];assert r['family']==family and r['kind']==kind and r['configuration']==c and all(r[k]is False for k in FLAGS)and decode(r['initial_state_transfer'])==ram;counts['exact_producer_full_RAM_handoffs_checked']+=1
   origin=r['initial_state_transfer'];assert(origin['path'],origin['case'])==('kernel_waitq_receiver_profiles.json',1)if offset==0 else(origin['path'],origin['case'])==(P+'_profiles.json',idx-1)
   plan=start_plan(c)if offset==0 else[(RECV+0x30,struct.pack('<Q',INNER))]if offset==3 else[];assert r['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in plan];initial=bytearray(ram);assert len(r['input_overlays'])==len(plan)
   for(a,b),e in zip(plan,r['input_overlays'],strict=True):assert e['address']==hex(a)and e['before_hex']==initial[a-R:a-R+len(b)].hex()and e['after_hex']==b.hex();initial[a-R:a-R+len(b)]=b;counts['declared_raw_context_and_loan_patch_before_images_checked']+=1
   if offset==0:globals=globals+[{'address':hex(ZCELL),'bytes_hex':struct.pack('<QQ',R+0xa0000,R+0xa1000).hex()}]
   assert r['initial_image_fixtures']==globals and r['final_image_globals']==globals and r['entry_DAIF_mask']==r['final_DAIF_mask']==hex(c.get('DAIF_mask',0x3c0));counts['exact_global_and_DAIF_epochs_checked']+=1
   args=[PORT,R+0xdd000,0x101,0,0,0x303]if offset==0 else[PORT+0x14]if offset==1 else[]if offset==2 else[PORT+0x10,0,c['interruptibility'],RECV,0];wantargs=[hex(x)for x in args]+['0x0']*(30-len(args))+[hex(R+0xe0000)];assert r['entry_registers31']==wantargs and r['entry_SP']==hex(PSP);counts['explicit_original_component_call_ABIs_checked']+=1
   wantrecv=bytearray(initial[RECV-R:RECV-R+1536])
   if offset==0:wantport=port_output();put(wantrecv,0x1c8,4,1)
   elif offset==1:put(wantport,0x14,4,0x01010144);put(wantrecv,0x1c8,4,0)
   elif offset==2:put(wantinner,0,4,2);put(wantinner,4,4,0x01010144);put(wantinner,0x50,4,1);put(wantinner,0x54,4,0x100)
   else:
    put(wantport,0x14,4,0x02020144);put(wantport,0x18,8,INNER);put(wantinner,4,4,0x02020144);put(wantinner,0x48,8,PORT);put(wantinner,0x54,4,0x204);put(wantrecv,0x30,8,0);put(wantrecv,0xd8,4,2 if aborted else 0xffffffff);put(wantrecv,0x3a0,4,0x10004005 if aborted else 0x10004001)
    if aborted:
     if flags&32:put(wantrecv,0x210,4,flags&~0x30)
    else:put(wantinner,8,8,RECV);wantinner[0x5d]=c['priority'];put(wantrecv,0x10,8,c['priority']<<8);put(wantrecv,0x28,8,PORT+0x10);put(wantrecv,0x1f8,4,4|(9 if eff==0 else 1));wantrecv[0xcb]=int(eff==2);wantrecv[0x58e]=2
   assert r['final_port144_hex']==bytes(wantport).hex()and r['final_inner96_hex']==bytes(wantinner).hex()and r['final_receiver1536_hex']==bytes(wantrecv).hex();counts['independent_complete_declared_port_turnstile_receiver_oracles_checked']+=1
   if offset==2:
    assert len(r['API_models'])==1;m=r['API_models'][0];assert m['pc']=='0xfffffe000bd75c64'and m['symbol']=='declared_zeroed_raw_turnstile_allocation'and m['arguments8'][:3]==[hex(R+0xa0000),hex(R+0xa1000),'0x8004']and m['return_value']==hex(INNER)and initial[INNER-R:INNER-R+96]==bytes(96);counts['explicit_raw_turnstile_allocation_contracts_checked']+=1
   else:assert r['API_models']==[]
   if offset==3:
    assert r['boundary']['kind']==('original_component_returned'if aborted else'before_original_thread_block')and r['boundary']['pc']==hex(R+0xe0000 if aborted else 0xfffffe000bd28f6c)
    assert len([e for e in r['producer_frames']if e['pc']=='0xfffffe000bd69c78'])==int(not aborted);fr=next(e for e in r['producer_frames']if e['pc']=='0xfffffe000bcc8408');assert fr['arguments8'][0]==('0x2'if aborted else'0xffffffff');counts['original_wait_result_to_block_or_abort_status_branches_checked']+=1
    counts['original_wait_memberships_produced']+=int(not aborted);counts['original_abort_returns_without_membership']+=int(aborted)
   for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_producer_original_instruction_recaptured']+=1
   prodtot.update(Replay(im,r).run());ram=decode(r['final_private_RAM']);print(json.dumps({'case':idx,'kind':kind,'family':family,'independent_replay':'pass'}),flush=True)
  s=prof['consumers'][family];assert s['family']==family and s['enqueue_configuration']==c and decode(s['initial_state_transfer'])==ram and s['initial_state_transfer']['path']==P+'_profiles.json'and s['initial_state_transfer']['case']==family*4+3 and s['initial_private_fixtures']==[];counts['exact_full_RAM_enqueue_to_sender_handoffs_checked']+=1
  assert s['entry_registers31']==ns['boundary']['registers31']and s['entry_SP']==ns['boundary']['SP']and s['entry_NZCV']==ns['boundary']['NZCV']and s['entry_Q_registers32']==ns['final_Q_registers32']and[{k:e[k]for k in['address','bytes_hex']}for e in s['initial_image_fixtures']]==globals and s['final_image_globals']==globals;counts['original_notification_CPU_and_producer_global_join_checked']+=1
  # Complete source-produced records are consumed without field repair.
  put(wantport,0x14,4,0x04040144);put(wantinner,4,4,0x03030144);put(wantinner,8,8,0);raw=bytearray(bytes.fromhex(old['final_raw_kmsg256_hex']))
  if aborted:put(wantport,0x28,8,KMSG);put(wantport,0x38,2,1);put(raw,0,8,KMSG);put(raw,8,8,KMSG)
  else:put(wantport,0x30,4,1);put(wantrecv,0x28,8,0);put(wantrecv,0xd8,4,0);put(wantrecv,0x1f8,4,4);wantrecv[0xcb]=wantrecv[0x58e]=0;put(wantrecv,0x3a0,4,0);put(wantrecv,0x3b8,8,KMSG)
  endram=decode(s['final_private_RAM']);assert s['final_destination144_hex']==bytes(wantport).hex()and endram[INNER-R:INNER-R+96]==bytes(wantinner)and s['final_queue_receivers']==[{'address':hex(RECV),'bytes1536_hex':bytes(wantrecv).hex()}]and s['final_raw_kmsg256_hex']==bytes(raw).hex()and s['waitq_wakeup_arguments']==([]if aborted else[hex(RECV)])and s['final_queue_task_send_counter']==1 and s['final_queue_thread_nesting']==0 and s['final_DAIF_mask']==hex(c.get('DAIF_mask',0x3c0));counts['independent_complete_original_enqueue_sender_composition_oracles_checked']+=1
  assert s['boundary']['kind']=='outer_notification_caller_returned'and next(e for e in s['entry_frames']if e['pc']=='0xfffffe000bcd059c')['arguments5'][0]=='0x0';counts['original_notification_caller_success_returns_checked']+=1
  assert Counter(m['symbol']for m in s['API_models'])=={'declared_byte_copy':1,'opaque_keyed_hash_result':2,'declared_message_tag_helper':1,'declared_send_preflight':1};counts['no_init_wait_enqueue_select_release_or_scheduler_result_models_checked']+=1
  for v in s['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_consumer_original_instruction_recaptured']+=1
  contot.update(SenderReplay(im,s).run());summaries.append({'family':family,'configuration':c,'effective_interruptibility':eff,'wait_aborted':aborted,'produced_thread_state':hex(4 if aborted else 4|(9 if eff==0 else 1)),'priority_word':hex(0 if aborted else c['priority']<<8),'wait_boundary':prof['cases'][family*4+3]['boundary']['kind'],'sender_action':'enqueue'if aborted else'direct_receiver_publication','sender_status':'0x0'});print(json.dumps(summaries[-1]),flush=True)
 counts.update(cases=32,consumers=8,functions=48,captured_instructions=5827)
 deps=[P+'_source.json',P+'_profiles.json','kernel_waitq_receiver_profiles.json','kernel_send_right_lifecycle_profiles.json','kernel_kmsg_allocation_profiles.json','validate_kernel_waitq_receiver.py','validate_kernel_kmsg_queue.py','validate_kernel_kmsg_allocation.py','replay_'+P+'.py','replay_kernel_waitq_receiver.py','replay_kernel_kmsg_queue.py','replay_kernel_kmsg_allocation.py','replay_kernel_notification_send.py','replay_kernel_send_right_lifecycle.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','replay_rpc502_vm_handoff.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(prodtot+contot),'producer_A64_replay':dict(prodtot),'consumer_A64_replay':dict(contot),'fresh_notification_producer_replay':freshns,'proofs':proofs,'family_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(prodtot+contot),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
