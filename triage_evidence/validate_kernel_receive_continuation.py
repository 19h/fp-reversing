#!/usr/bin/env python3
"""Original continuation storage/entry/status, exact RAM joins and stack/context ABI.
O(image+source+visits+RAM+effects), O(image+RAM+journals), four scalar SMT queries.
Scheduler selection/invocation, hardware PAC/key writes and user copyout are not proven.
"""
import json,struct
from collections import Counter
from z3 import BitVec,BitVecVal,If,Or,And,Extract,Solver,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from validate_kernel_kmsg_allocation import fixture_plan
from validate_kernel_kmsg_queue import qplan,val,put
from validate_kernel_waitq_receiver import wplan
from validate_kernel_waitq_enqueue import start_plan,port_output
from replay_rpc502_vm_handoff import decode
from replay_kernel_send_right_lifecycle import Replay as NSReplay
from replay_kernel_receive_continuation import Replay,SenderReplay
P='kernel_receive_continuation';R=0x6500000000;PORT=R+0xc0000;INNER=R+0xb5000;RECV=R+0x60000;THREAD=R+0x2c000;KMSG=R+0xd0000;PSP=R+0xe8000;STACK=R+0xe6000;CALLBACK=0xfffffe000bcc89bc;SELECT=0xfffffe000bd29140;RESULTS=0xfffffe000bcdcc7c
CONFIGS=[{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':0,'capacity':44},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':44},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':43},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':44,'DAIF_mask':0x200},{'interruptibility':2,'thread_limit':0,'priority':31,'has_continuation':1,'capacity':44},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':44,'abort_flags':0x10}]
VARIANTS=[(1,{}),(2,{}),(3,{}),(4,{}),(1,{'thread_state':0x84}),(1,{'wait_result':1}),(1,{'wait_result':2}),(1,{'wait_result':3}),(1,{'wait_result':0xffffffff}),(1,{'receive_status':0x10004001}),(1,{'receive_status':0x1000400e}),(1,{'context_B':1}),(1,{'context_A':2}),(1,{'context_B':0x55,'cached_context_B':0x55,'context_A':0x66,'cached_context_A':0x66})]

def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());seed=json.loads((ROOT/'kernel_waitq_receiver_profiles.json').read_text())['cases'][1];up=json.loads((ROOT/'kernel_waitq_enqueue_profiles.json').read_text());ns=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];old=json.loads((ROOT/'kernel_kmsg_allocation_profiles.json').read_text())['cases'][29];counts=Counter();pt=Counter();st=Counter();dt=Counter();proofs=[];summaries=[]
 for o,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==57 and sum(len(f['instructions'])for f in src['functions'])==7485 and src['native_continuation_execution_observed']is False
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions'];counts['original_complete_functions_recaptured']+=1
 for e in src['continuation_instruction_roles'].values():
  a=int(e['pc'],16);i=next(im.k.cs.disasm(im.k.read(a,4),a));assert i.bytes.hex()==e['bytes_hex']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'];counts['continuation_instruction_roles_recaptured']+=1
 w=BitVec('wait_result32',32);status=BitVec('receive_status32',32);state=BitVec('thread_state32',32);b=BitVec('context_B64',64);bc=BitVec('cached_B64',64);a=BitVec('context_A64',64);ac=BitVec('cached_A64',64);valid=Or(status==0,status==0x10004004,status==0x1000400e);tree=If(w>1,If(w==3,True,w==2),If(w==0,valid,w==1));compact=Or(And(w==0,valid),w==1,w==2,w==3)
 for name,left,right in[('signed_callback_branch_tree_matches_valid_wait_status_partition',tree,compact),('invocation_enable_flag_depends_only_on_state_bit7',(1&~(state>>7)),If(Extract(7,7,state)==0,BitVecVal(1,32),BitVecVal(0,32))),('context_cache_match_avoids_both_reload_frontiers',If(b!=bc,False,If(a!=ac,False,True)),And(b==bc,a==ac)),('wait_success_preserves_existing_receive_status',If(w==0,status,If(w==1,BitVecVal(0x10004003,32),If(w==2,BitVecVal(0x10004005,32),BitVecVal(0x10004006,32))))==status,True)]:
  s=Solver()
  if name=='wait_success_preserves_existing_receive_status':s.add(w==0)
  s.add(left!=right);assert s.check()==unsat;proofs.append({'name':name,'domain':'wait_result32==0'if name=='wait_success_preserves_existing_receive_status'else'all fixed-width inputs','query':s.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1
 fresh=NSReplay(im,ns).run();base=bytearray(decode(ns['final_private_RAM']));meta=val(bytes.fromhex(next(e['bytes_hex']for e in ns['final_image_globals']if e['address']=='0xfffffe0007e66f00')),0);plan=[(R+0xdc000,b'\xa5'*4),(THREAD+0xc8,bytes(2)),(PORT+0x48,struct.pack('<Q',R+0xdd000))]+fixture_plan({'phase':'notification'})+qplan({'receivers':[{'capacity':44}]},meta)+wplan({'receivers':[{'capacity':44}]})
 assert seed['initial_private_fixtures']==[{'address':hex(x),'bytes_hex':y.hex()}for x,y in plan]
 for x,y in plan:base[x-R:x-R+len(y)]=y
 assert decode(up['cases'][0]['initial_state_transfer'])==bytes(base)and len(prof['cases'])==24 and len(prof['consumers'])==6 and len(prof['dispatches'])==14
 for family,c in enumerate(CONFIGS):
  ram=bytes(base);globals=[{k:e[k]for k in['address','bytes_hex']}for e in seed['initial_image_fixtures']];eff=min(c['interruptibility'],c['thread_limit']);aborted=family==5;wantport=None;wantinner=bytearray(96)
  for offset,kind in enumerate(['port_init','port_unlock','turnstile_allocate','receive_wait']):
   idx=family*4+offset;r=prof['cases'][idx];assert r['family']==family and r['kind']==kind and r['configuration']==c and all(r[k]is False for k in FLAGS)and decode(r['initial_state_transfer'])==ram;counts['exact_full_RAM_producer_origins_checked']+=1
   ip=start_plan(c)if offset==0 else[(RECV+0x30,struct.pack('<Q',INNER))]if offset==3 else[]
   if offset==0 and c['capacity']!=44:ip=ip+[(RECV+0x388,struct.pack('<I',c['capacity']))]
   initial=bytearray(ram);assert r['initial_private_fixtures']==[{'address':hex(x),'bytes_hex':y.hex()}for x,y in ip]and len(r['input_overlays'])==len(ip)
   for(x,y),e in zip(ip,r['input_overlays'],strict=True):assert e['address']==hex(x)and e['before_hex']==initial[x-R:x-R+len(y)].hex()and e['after_hex']==y.hex();initial[x-R:x-R+len(y)]=y;counts['independent_producer_input_patch_before_images_checked']+=1
   if offset==0:globals=globals+[{'address':'0xfffffe000caec980','bytes_hex':struct.pack('<QQ',R+0xa0000,R+0xa1000).hex()}]
   entrymask=c.get('DAIF_mask',0x3c0);assert r['initial_image_fixtures']==globals and r['final_image_globals']==globals and r['entry_DAIF_mask']==hex(entrymask)and r['final_DAIF_mask']==hex(0x3c0 if offset==3 and not aborted else entrymask);counts['exact_globals_and_block_prefix_mask_obligations_checked']+=1
   args=[PORT,R+0xdd000,0x101,0,0,0x303]if offset==0 else[PORT+0x14]if offset==1 else[]if offset==2 else[PORT+0x10,0,c['interruptibility'],RECV,c['has_continuation']];regs=[hex(v)for v in args]+['0x0']*(30-len(args))+[hex(R+0xe0000)];assert r['entry_registers31']==regs and r['entry_SP']==hex(PSP);wantrecv=bytearray(initial[RECV-R:RECV-R+1536])
   if offset==0:wantport=port_output();put(wantrecv,0x1c8,4,1)
   elif offset==1:put(wantport,0x14,4,0x01010144);put(wantrecv,0x1c8,4,0)
   elif offset==2:put(wantinner,0,4,2);put(wantinner,4,4,0x01010144);put(wantinner,0x50,4,1);put(wantinner,0x54,4,0x100)
   else:
    put(wantport,0x14,4,0x02020144);put(wantport,0x18,8,INNER);put(wantinner,4,4,0x02020144);put(wantinner,0x48,8,PORT);put(wantinner,0x54,4,0x204);put(wantrecv,0x30,8,0);put(wantrecv,0xd8,4,2 if aborted else 0xffffffff);put(wantrecv,0x3a0,4,0x10004005 if aborted else 0x10004001)
    if not aborted:put(wantinner,8,8,RECV);wantinner[0x5d]=31;put(wantrecv,0x10,8,31<<8);put(wantrecv,0x28,8,PORT+0x10);put(wantrecv,0x1f8,4,4|(9 if eff==0 else 1));wantrecv[0xcb]=int(eff==2);wantrecv[0x58e]=2;put(wantrecv,0xe0,8,CALLBACK if c['has_continuation']else 0)
   assert r['final_port144_hex']==bytes(wantport).hex()and r['final_inner96_hex']==bytes(wantinner).hex()and r['final_receiver1536_hex']==bytes(wantrecv).hex();counts['independent_complete_producer_record_and_continuation_storage_oracles_checked']+=1
   if offset==2:assert len(r['API_models'])==1 and r['API_models'][0]['return_value']==hex(INNER)and r['API_models'][0]['arguments8'][:3]==[hex(R+0xa0000),hex(R+0xa1000),'0x8004']
   else:assert r['API_models']==[]
   expected_sign=[{'pc':'0xfffffe000bcc8428','pointer':hex(CALLBACK),'modifier':'0xd507'}]if offset==3 and not aborted and c['has_continuation']else[];assert r['logical_code_signing']==expected_sign
   if offset==3:
    assert r['boundary']['kind']==('original_component_returned'if aborted else'before_original_scheduler_selection')and len(r['block_frames'])==(0 if aborted else 2)
    if not aborted:
     before,after=r['block_frames'];cont=CALLBACK if c['has_continuation']else 0;assert before['arguments8'][:3]==[hex(cont),'0x0','0x0']and after['arguments8'][0]==hex(RECV)and after['arguments8'][1]=='0xfffffe000cac6e18'and val(bytes.fromhex(after['receiver1536_hex']),0xe0)==cont and val(bytes.fromhex(after['receiver1536_hex']),0xe8)==0;counts['original_block_continuation_argument_and_store_frames_checked']+=1
   for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_producer_original_instruction_recaptured']+=1
   pt.update(Replay(im,r).run());ram=decode(r['final_private_RAM'])
  s=prof['consumers'][family];assert s['initial_private_fixtures']==[]and decode(s['initial_state_transfer'])==ram and s['entry_registers31']==ns['boundary']['registers31']and s['entry_SP']==ns['boundary']['SP']and s['entry_NZCV']==ns['boundary']['NZCV']and s['entry_Q_registers32']==ns['final_Q_registers32'];counts['exact_block_prefix_RAM_to_original_sender_CPU_joins_checked']+=1
  assert[{k:e[k]for k in['address','bytes_hex']}for e in s['initial_image_fixtures']]==globals and s['final_image_globals']==globals
  put(wantport,0x14,4,0x04040144);put(wantinner,4,4,0x03030144);put(wantinner,8,8,0);raw=bytearray(bytes.fromhex(old['final_raw_kmsg256_hex']))
  if aborted:put(wantport,0x28,8,KMSG);put(wantport,0x38,2,1);put(raw,0,8,KMSG);put(raw,8,8,KMSG)
  else:
   put(wantport,0x30,4,1);put(wantrecv,0x28,8,0);put(wantrecv,0xd8,4,0);put(wantrecv,0x1f8,4,4);wantrecv[0xcb]=wantrecv[0x58e]=0;put(wantrecv,0x3a0,4,0 if c['capacity']>=44 else 0x10004004);put(wantrecv,0x3b8,8,KMSG)
   if c['capacity']<44:put(wantrecv,0x3a8,4,36)
  end=decode(s['final_private_RAM']);assert s['final_destination144_hex']==bytes(wantport).hex()and end[INNER-R:INNER-R+96]==bytes(wantinner)and s['final_queue_receivers']==[{'address':hex(RECV),'bytes1536_hex':bytes(wantrecv).hex()}]and s['final_raw_kmsg256_hex']==bytes(raw).hex()and s['final_queue_task_send_counter']==1 and s['final_queue_thread_nesting']==0 and s['final_DAIF_mask']==hex(entrymask)and s['waitq_wakeup_arguments']==([]if aborted else[hex(RECV)]);counts['independent_sender_preserves_continuation_and_publishes_receive_state_checked']+=1
  assert s['boundary']['kind']=='outer_notification_caller_returned'and next(e for e in s['entry_frames']if e['pc']=='0xfffffe000bcd059c')['arguments5'][0]=='0x0';counts['original_sender_caller_success_returns_checked']+=1
  assert Counter(m['symbol']for m in s['API_models'])=={'declared_byte_copy':1,'opaque_keyed_hash_result':2,'declared_message_tag_helper':1,'declared_send_preflight':1}
  for v in s['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_sender_original_instruction_recaptured']+=1
  st.update(SenderReplay(im,s).run());print(json.dumps({'producer_family':family,'sender_replay':'pass'}),flush=True)
 for j,(family,variant)in enumerate(VARIANTS):
  r=prof['dispatches'][j];parent=prof['consumers'][family];ram=decode(parent['final_private_RAM']);initial=bytearray(ram);assert r['family']==family and r['variant']==variant and decode(r['initial_state_transfer'])==ram and r['initial_state_transfer']['path']==P+'_profiles.json'and r['initial_state_transfer']['consumer']==family;counts['exact_sender_RAM_to_continuation_fragment_joins_checked']+=1
  ip=[(RECV+0x158,struct.pack('<Q',STACK))]
  for off,key in[(0xd8,'wait_result'),(0x3a0,'receive_status'),(0x1f8,'thread_state')]:
   if key in variant:ip.append((RECV+off,struct.pack('<I',variant[key])))
  for off,key in[(0x1d0,'context_B'),(0x1d8,'context_A')]:
   if key in variant:ip.append((RECV+off,struct.pack('<Q',variant[key])))
  for off,key in[(0x200,'cached_context_B'),(0x208,'cached_context_A')]:
   if key in variant:ip.append((R+0xb4000+off,struct.pack('<Q',variant[key])))
  assert r['initial_private_fixtures']==[{'address':hex(x),'bytes_hex':y.hex()}for x,y in ip]and len(r['input_overlays'])==len(ip)
  for(x,y),e in zip(ip,r['input_overlays'],strict=True):assert e['address']==hex(x)and e['before_hex']==initial[x-R:x-R+len(y)].hex()and e['after_hex']==y.hex();initial[x-R:x-R+len(y)]=y;counts['explicit_stack_and_controlled_context_patch_before_images_checked']+=1
  regs=['0x0']*31;regs[19]=hex(RECV);regs[21]=hex(CALLBACK);regs[25]=hex(val(ram,RECV-R+0xe8));regs[30]=hex(R+0xe0000);assert r['entry_PC']=='0xfffffe000bd2a1d0'and r['entry_registers31']==regs and val(ram,RECV-R+0xe0)==CALLBACK and r['initial_image_fixtures']==parent['final_image_globals']==r['final_image_globals'];counts['explicit_source_field_derived_fragment_register_and_global_ABIs_checked']+=1
  b=bytearray(initial[RECV-R:RECV-R+1536]);wr=val(b,0xd8,4);rs=val(b,0x3a0,4);enable=1&~(val(b,0x1f8,4)>>7);mismatch=val(b,0x1d0)!=val(initial,0xb4200)or val(b,0x1d8)!=val(initial,0xb4208);valid=wr in[1,2,3]or wr==0 and rs in[0,0x10004004,0x1000400e];put(b,0xe0,8,0);put(b,0xe8,8,0)
  if not mismatch and wr in[1,2,3]:put(b,0x3a0,4,{1:0x10004003,2:0x10004005,3:0x10004006}[wr])
  kind='before_original_context_key_programming'if mismatch else'before_original_user_receive_results'if valid else'before_original_continuation_guard';wantpc=(0xfffffe000bc9c338 if val(b,0x1d0)!=val(initial,0xb4200)else 0xfffffe000bc9c380)if mismatch else RESULTS if valid else 0xfffffe000c62a2b0;entrymask=int(parent['final_DAIF_mask'],16);finalmask=entrymask if mismatch or not enable else entrymask&~0x1c0
  assert r['boundary']['kind']==kind and r['boundary']['pc']==hex(wantpc)and r['final_DAIF_mask']==hex(finalmask)and r['final_receiver1536_hex']==bytes(b).hex()and r['final_port144_hex']==parent['final_destination144_hex']and r['final_inner96_hex']==initial[INNER-R:INNER-R+96].hex();counts['independent_complete_callback_record_status_context_and_mask_oracles_checked']+=1
  assert r['API_models']==[]and len(r['logical_stack_authentication'])==1 and r['logical_stack_authentication'][0]=={'pc':'0xfffffe000bc9c314','pointer':hex(STACK),'modifier':hex((RECV+0x158)|(0x6d42<<48))};counts['original_saved_stack_discriminator_and_logical_auth_contracts_checked']+=1
  entry=next(e for e in r['dispatch_frames']if e['pc']=='0xfffffe000be8b3c4');assert entry['arguments8'][:4]==[hex(CALLBACK),regs[25],hex(wr),hex(enable)]and bytes.fromhex(entry['receiver1536_hex'])[0xe0:0xf0]==bytes(16);counts['original_continuation_clear_and_forwarded_argument_frames_checked']+=1
  assert len(r['logical_continuation_edges'])==int(not mismatch)
  if not mismatch:
   e=r['logical_continuation_edges'][0];assert e=={'pc':'0xfffffe000bc9c3c8','target':hex(CALLBACK),'modifier':'0xd507','arguments2':[regs[25],hex(wr)]};cb=next(e for e in r['dispatch_frames']if e['pc']==hex(CALLBACK));assert cb['SP']==hex(STACK)and cb['FP']=='0x0'and cb['arguments8'][:2]==[regs[25],hex(wr)];counts['original_stack_switch_and_authenticated_callback_ABI_frames_checked']+=1
   if valid:out=next(e for e in r['dispatch_frames']if e['pc']==hex(RESULTS));assert out['arguments8'][0]=='0x0'and val(bytes.fromhex(out['receiver1536_hex']),0x3a0,4)==val(b,0x3a0,4);counts['original_receive_results_entries_checked']+=1
   else:counts['original_wait_or_receive_state_guards_checked']+=1
  else:assert not any(e['pc']==hex(CALLBACK)for e in r['dispatch_frames']);counts['original_context_reload_frontiers_checked']+=1
  for v in r['source_visits']:
   raw=im.k.read(int(v['pc'],16),4);assert raw.hex()==v['bytes_hex'];ins=next(im.k.cs.disasm(raw,int(v['pc'],16)));assert not(ins.mnemonic=='msr'and('key'in ins.op_str or's3_4_'in ins.op_str));counts['every_dispatch_original_instruction_and_no_key_write_checked']+=1
  assert all(r[k]is False for k in FLAGS);dt.update(Replay(im,r).run());summaries.append({'dispatch':j,'source_family':family,'variant':variant,'source_wait_result':hex(wr),'entry_receive_status':hex(rs),'final_receive_status':hex(val(b,0x3a0,4)),'interrupt_enable_flag':enable,'boundary':kind,'final_DAIF_mask':hex(finalmask)});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=24,consumers=6,dispatches=14,functions=57,captured_instructions=7485)
 deps=[P+'_source.json',P+'_profiles.json','kernel_waitq_enqueue_profiles.json','kernel_waitq_receiver_profiles.json','kernel_send_right_lifecycle_profiles.json','kernel_kmsg_allocation_profiles.json','validate_kernel_waitq_enqueue.py','validate_kernel_waitq_receiver.py','validate_kernel_kmsg_queue.py','validate_kernel_kmsg_allocation.py','replay_'+P+'.py','replay_kernel_waitq_enqueue.py','replay_kernel_waitq_receiver.py','replay_kernel_kmsg_queue.py','replay_kernel_kmsg_allocation.py','replay_kernel_notification_send.py','replay_kernel_send_right_lifecycle.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','replay_rpc502_vm_handoff.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(pt+st+dt),'producer_A64_replay':dict(pt),'sender_A64_replay':dict(st),'dispatch_A64_replay':dict(dt),'fresh_notification_producer_replay':fresh,'proofs':proofs,'dispatch_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(pt+st+dt),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
