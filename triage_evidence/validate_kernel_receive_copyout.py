#!/usr/bin/env python3
"""Independent receive ownership/frontend, loan return, header packing and user bytes.
O(image+source+visits+RAM+effects), O(image+RAM+journals), four scalar SMT queries.
Declared namespace/owner/map/cache epochs and copyout/free contracts remain explicit.
"""
import json,struct
from collections import Counter
from z3 import BitVec,ZeroExt,And,Or,ULT,ULE,UGE,Solver,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from validate_kernel_waitq_enqueue import start_plan,port_output
from validate_kernel_kmsg_allocation import fixture_plan
from validate_kernel_kmsg_queue import qplan,val,put
from validate_kernel_waitq_receiver import wplan
from replay_rpc502_vm_handoff import decode
from replay_kernel_send_right_lifecycle import Replay as NSReplay
from replay_kernel_zone_startup import Replay as ZoneReplay
from replay_kernel_receive_copyout import Replay,SenderReplay
P='kernel_receive_copyout';R=0x6500000000;PORT=R+0xc0000;INNER=R+0xb5000;RECV=R+0x60000;THREAD=R+0x2c000;KMSG=R+0xd0000;OWNER=R+0x70000;TASK=R+0x74000;MAP=R+0x78000;USER=R+0x90000;SMR=R+0x9c000;SPACE=R+0xdd000;TABLE=0x400000100000;STACK=R+0xe6000;CALLBACK=0xfffffe000bcc89bc
CONFIGS=[{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':44,'receive_options':2},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':3072,'receive_options':0x7000006},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':44,'receive_options':2,'copyout_result':14},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':44,'receive_options':2,'retain_file_validation':True}]
def extra_plan(meta):
 b=bytearray(56);put(b,0,8,RECV);put(b,0x28,8,TASK);out=[(RECV+0x420,struct.pack('<Q',OWNER)),(OWNER,bytes(b)),(TASK+0x318,struct.pack('<Q',SPACE)),(RECV+0x428,struct.pack('<Q',MAP)),(MAP+0x18,struct.pack('<Q',0xffffffffffffffff)),(MAP+0x2c,struct.pack('<I',14)),(SPACE+0x48,struct.pack('<Q',TABLE|5)),(USER,b'\xa5'*8192)]
 out.extend((meta+((a>>10)&0xffffffff0),struct.pack('<H',kind))for a,kind in[(OWNER,3),(KMSG,24),(INNER,28)]);return out

def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());seed=json.loads((ROOT/'kernel_waitq_receiver_profiles.json').read_text())['cases'][1];up=json.loads((ROOT/'kernel_waitq_enqueue_profiles.json').read_text());ns=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];zone=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'][0];old=json.loads((ROOT/'kernel_kmsg_allocation_profiles.json').read_text())['cases'][29];counts=Counter();pt=Counter();st=Counter();ft=Counter();proofs=[];summaries=[]
 for o,s in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/s)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==80 and sum(len(f['instructions'])for f in src['functions'])==11463 and src['native_receive_copyout_observed']is False
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions'];counts['original_complete_functions_recaptured']+=1
 for e in src['copyout_instruction_roles'].values():
  a=int(e['pc'],16);i=next(im.k.cs.disasm(im.k.read(a,4),a));assert i.bytes.hex()==e['bytes_hex']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'];counts['copyout_instruction_roles_recaptured']+=1
 freshzone=ZoneReplay(im,zone).run();zb=bytes.fromhex(zone['final_zone192_hex'])[0x30:0x38];assert src['zone_validation_source']=={'path':'kernel_zone_startup_profiles.json','case':0,'address':'0xfffffe000caec6b0','bytes8_hex':zb.hex(),'whole_zone_epoch_transferred':False}and zb==bytes.fromhex('0000000100010000');counts['source_zone_validation_arithmetic_fields_replayed_and_transferred']+=1
 refs=BitVec('initial_refs32',32);offset=BitVec('element_offset32',32);n=BitVec('kernel_message_bytes32',32);t=BitVec('trailer_bytes32',32);cap=BitVec('capacity_bytes32',32);wide=ZeroExt(32,n)+ZeroExt(32,t)
 queries=[('separate_right_and_receive_holds_balance_without_wrap',And(UGE(refs,1),ULE(refs,0xffffffd)),((refs+1+1)-1)-1,refs),('zone_256_reciprocal_acceptance_equals_element_alignment',ULE(offset,16383),ULT(offset*0x1000000,0x1000000),(offset&255)==0),('simple_header_contraction_preserves_payload_and_minimum',UGE(n,32),And(UGE(n-8,24),ULE(n-8,n)),True),('representable_message_and_trailer_fit_is_bounded',And(ULE(wide,0xffffffff),ULE(n,cap),ULE(n+t,cap)),And(ULE(n+t,cap),ULE((n+t)-n,t)),True)]
 for name,domain,left,right in queries:
  s=Solver();s.add(domain,left!=right);assert s.check()==unsat;proofs.append({'name':name,'domain':str(domain),'query':s.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1
 freshns=NSReplay(im,ns).run();base=bytearray(decode(ns['final_private_RAM']));meta=val(bytes.fromhex(next(e['bytes_hex']for e in ns['final_image_globals']if e['address']=='0xfffffe0007e66f00')),0);seedplan=[(R+0xdc000,b'\xa5'*4),(THREAD+0xc8,bytes(2)),(PORT+0x48,struct.pack('<Q',SPACE))]+fixture_plan({'phase':'notification'})+qplan({'receivers':[{'capacity':44}]},meta)+wplan({'receivers':[{'capacity':44}]})
 assert seed['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in seedplan]
 for a,b in seedplan:base[a-R:a-R+len(b)]=b
 assert bytes(base)==decode(up['cases'][0]['initial_state_transfer'])and len(prof['cases'])==20 and len(prof['consumers'])==len(prof['finishes'])==4;table=bytearray(4096);struct.pack_into('<QIIQ',table,72,PORT,0x20001,0,0)
 for family,c in enumerate(CONFIGS):
  ram=bytes(base);globals=[{k:e[k]for k in['address','bytes_hex']}for e in seed['initial_image_fixtures']];wantport=None;wantinner=bytearray(96)
  for k,kind in enumerate(['port_init','port_unlock','turnstile_allocate','make_send_once','receive_wait']):
   idx=family*5+k;r=prof['cases'][idx];assert r['family']==family and r['kind']==kind and r['configuration']==c and decode(r['initial_state_transfer'])==ram and all(r[f]is False for f in FLAGS);counts['exact_producer_full_RAM_origins_checked']+=1
   ip=start_plan(c)if k==0 else[(RECV+0x30,struct.pack('<Q',INNER))]if k==4 else[]
   if k==0:
    if c['capacity']!=44:ip=ip+[(RECV+0x388,struct.pack('<I',c['capacity']))]
    ip=ip+extra_plan(meta)
   initial=bytearray(ram);assert r['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in ip]and len(r['input_overlays'])==len(ip)
   for(a,b),e in zip(ip,r['input_overlays'],strict=True):assert e['address']==hex(a)and e['before_hex']==initial[a-R:a-R+len(b)].hex()and e['after_hex']==b.hex();initial[a-R:a-R+len(b)]=b;counts['independent_namespace_owner_map_buffer_patch_before_images_checked']+=1
   if k==0:
    globals=globals+[{'address':'0xfffffe000caec980','bytes_hex':struct.pack('<QQ',R+0xa0000,R+0xa1000).hex()},{'address':hex(TABLE),'bytes_hex':bytes(table).hex()},{'address':'0xfffffe000caac348','bytes_hex':struct.pack('<Q',0x100).hex()},{'address':'0xfffffe000caac350','bytes_hex':struct.pack('<Q',SMR).hex()}]
    if not c.get('retain_file_validation'):globals=globals+[{'address':'0xfffffe000caec6b0','bytes_hex':zb.hex()}]
   assert r['initial_image_fixtures']==globals and r['final_image_globals']==globals;counts['exact_global_namespace_table_and_validation_field_epochs_checked']+=1
   wantrecv=bytearray(initial[RECV-R:RECV-R+1536])
   if k==0:wantport=port_output();put(wantrecv,0x1c8,4,1)
   elif k==1:put(wantport,0x14,4,0x01010144);put(wantrecv,0x1c8,4,0)
   elif k==2:put(wantinner,0,4,2);put(wantinner,4,4,0x01010144);put(wantinner,0x50,4,1);put(wantinner,0x54,4,0x100)
   elif k==3:put(wantport,0x14,4,0x02020144);put(wantport,4,4,2);put(wantport,0x8c,4,1)
   else:
    put(wantport,0x14,4,0x04040144);put(wantport,4,4,3);put(wantport,0x18,8,INNER);put(wantinner,4,4,0x02020144);put(wantinner,8,8,RECV);put(wantinner,0x48,8,PORT);put(wantinner,0x54,4,0x204);wantinner[0x5d]=31;put(wantrecv,0x30,8,0);put(wantrecv,0x10,8,31<<8);put(wantrecv,0x28,8,PORT+0x10);put(wantrecv,0xd8,4,0xffffffff);put(wantrecv,0xe0,8,CALLBACK);put(wantrecv,0x1f8,4,5);wantrecv[0xcb]=1;wantrecv[0x58e]=2;put(wantrecv,0x378,8,USER);put(wantrecv,0x388,4,c['capacity']);put(wantrecv,0x390,8,c['receive_options']);put(wantrecv,0x398,8,PORT);put(wantrecv,0x3a0,4,0x10004001)
   assert r['final_port144_hex']==bytes(wantport).hex()and r['final_inner96_hex']==bytes(wantinner).hex()and r['final_receiver1536_hex']==bytes(wantrecv).hex()and r['final_user8192_hex']==('a5'*8192);counts['independent_complete_reference_frontend_and_wait_record_oracles_checked']+=1
   if k==4:
    assert r['entry_PC']=='0xfffffe000bcdd4e4'and r['entry_registers31'][:8]==[hex(USER),'0x0',hex(c['receive_options']),'0x0','0x0',hex(c['capacity']),'0x0','0x303']and r['boundary']['kind']=='before_original_scheduler_selection';f=next(e for e in r['frontend_frames']if e['pc']=='0xfffffe000bcdd568');assert val(bytes.fromhex(f['port144_hex']),4,4)==3 and f['arguments8'][0]=='0x0';counts['original_namespace_retain_and_frontend_publication_frames_checked']+=1
   if k==2:assert len(r['API_models'])==1 and r['API_models'][0]['return_value']==hex(INNER)
   else:assert r['API_models']==[]
   for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_producer_original_instruction_recaptured']+=1
   pt.update(Replay(im,r).run());ram=decode(r['final_private_RAM'])
  s=prof['consumers'][family];assert s['initial_private_fixtures']==[]and decode(s['initial_state_transfer'])==ram and s['entry_registers31']==ns['boundary']['registers31']and s['entry_SP']==ns['boundary']['SP']and s['entry_NZCV']==ns['boundary']['NZCV']and s['entry_Q_registers32']==ns['final_Q_registers32'];counts['exact_frontend_full_RAM_to_original_sender_joins_checked']+=1
  assert[{k:e[k]for k in['address','bytes_hex']}for e in s['initial_image_fixtures']]==globals and s['final_image_globals']==globals
  put(wantport,0x14,4,0x06060144);put(wantport,0x30,4,1);put(wantinner,4,4,0x03030144);put(wantinner,8,8,0);put(wantrecv,0x28,8,0);put(wantrecv,0xd8,4,0);put(wantrecv,0x1f8,4,4);wantrecv[0xcb]=wantrecv[0x58e]=0;put(wantrecv,0x3a0,4,0);put(wantrecv,0x3b8,8,KMSG);end=decode(s['final_private_RAM'])
  assert s['final_destination144_hex']==bytes(wantport).hex()and end[INNER-R:INNER-R+96]==bytes(wantinner)and s['final_queue_receivers']==[{'address':hex(RECV),'bytes1536_hex':bytes(wantrecv).hex()}]and s['final_queue_task_send_counter']==1 and s['final_queue_thread_nesting']==0 and s['boundary']['kind']=='outer_notification_caller_returned'and next(e for e in s['entry_frames']if e['pc']=='0xfffffe000bcd059c')['arguments5'][0]=='0x0';counts['independent_sender_record_reference_preservation_and_success_oracles_checked']+=1
  assert Counter(m['symbol']for m in s['API_models'])=={'declared_byte_copy':1,'opaque_keyed_hash_result':2,'declared_message_tag_helper':1,'declared_send_preflight':1}
  for v in s['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_sender_original_instruction_recaptured']+=1
  st.update(SenderReplay(im,s).run());r=prof['finishes'][family];initial=bytearray(decode(s['final_private_RAM']));assert decode(r['initial_state_transfer'])==bytes(initial)and r['initial_state_transfer']['path']==P+'_profiles.json'and r['initial_state_transfer']['consumer']==family and r['initial_private_fixtures']==[{'address':hex(RECV+0x158),'bytes_hex':struct.pack('<Q',STACK).hex()}];e=r['input_overlays'][0];assert e['address']==hex(RECV+0x158)and e['before_hex']==initial[RECV-R+0x158:RECV-R+0x160].hex()and e['after_hex']==struct.pack('<Q',STACK).hex();put(initial,RECV-R+0x158,8,STACK);counts['exact_sender_RAM_to_results_with_explicit_stack_epoch_checked']+=1
  regs=['0x0']*31;regs[19]=hex(RECV);regs[21]=hex(CALLBACK);regs[30]=hex(R+0xe0000);assert r['entry_registers31']==regs and r['entry_PC']=='0xfffffe000bd2a1d0'and r['initial_image_fixtures']==globals and r['final_image_globals']==globals
  wantrecv=bytearray(initial[RECV-R:RECV-R+1536]);put(wantrecv,0xe0,8,0);put(wantrecv,0xe8,8,0);put(wantrecv,0x30,8,INNER);put(wantport,0x18,8,0);put(wantinner,0x48,8,0);put(wantinner,0x54,4,0x300);filezero=c.get('retain_file_validation',False);failed=bool(c.get('copyout_result',0));put(wantport,0x14,4,0x07070144 if filezero else 0x08080144);put(wantport,4,4,2 if filezero else 1);put(wantport,0x8c,4,1 if filezero else 0)
  assert r['final_port144_hex']==bytes(wantport).hex()and r['final_inner96_hex']==bytes(wantinner).hex()and r['final_receiver1536_hex']==bytes(wantrecv).hex()and r['final_DAIF_mask']=='0x200';counts['independent_complete_receive_hold_destination_right_and_loan_return_oracles_checked']+=1
  rframes=r['receive_results_frames'];released=next(e for e in rframes if e['pc']=='0xfffffe000bcdce14');assert val(bytes.fromhex(released['port144_hex']),4,4)==2 and val(bytes.fromhex(released['receiver1536_hex']),0x30)==INNER and val(bytes.fromhex(released['port144_hex']),0x18)==0;counts['original_loan_return_before_receive_reference_release_frames_checked']+=1
  expecteduser=bytearray(b'\xa5'*8192);copybytes=0;finalstatus=None
  if filezero:
   assert r['boundary']['kind']=='before_original_copyout_validation_guard'and r['boundary']['pc']=='0xfffffe000c633aa0'and r['API_models']==[]and r['user_copyout_effects']==[]and not r['opaque_copyout_hash_inputs'];counts['original_file_zero_validation_guard_prefixes_checked']+=1
  else:
   packet=bytes.fromhex(ns['notification_packet']['bytes44_hex']);trailer=bytearray(im.k.read(0xfffffe0007010a68,68));assert trailer==struct.pack('<17I',0,8,0,0,1,*([0]*12));tsize=68 if c['receive_options']>>24&15==7 else 8;put(trailer,4,4,tsize);payload=struct.pack('<6I',(val(packet,0,4)&31)<<8,36,0,0x303,0,val(packet,28,4))+packet[32:44]+trailer[:tsize];copybytes=len(payload)
   assert len(r['user_copyout_effects'])==1;ce=r['user_copyout_effects'][0];assert ce['source']==hex(KMSG+0x48)and ce['destination']==hex(USER)and ce['size_bytes']==len(payload)and ce['source_hex']==payload.hex()and ce['before_hex']==('a5'*len(payload))and ce['result']==hex(c.get('copyout_result',0));counts['independent_source_notification_to_packed_user_bytes_oracles_checked']+=1
   if not failed:expecteduser[:len(payload)]=payload
   assert ce['after_hex']==expecteduser[:len(payload)].hex();finalstatus=0x10004008 if failed else 0;assert r['boundary']['kind']=='before_original_return_to_user'and r['boundary']['pc']=='0xfffffe000be80980'and r['boundary']['registers31'][0]==hex(finalstatus);counts['original_results_return_status_through_completion_wrapper_checked']+=1
   pf=next(e for e in rframes if e['pc']=='0xfffffe000bcc62d0');resultptr=int(pf['arguments8'][2],16);rr=bytearray(40)
   if not failed:put(rr,0,4,36);put(rr,4,4,tsize)
   finalram=decode(r['final_private_RAM']);assert finalram[resultptr-R:resultptr-R+40]==bytes(rr);counts['independent_packed_result_record_success_and_failure_oracles_checked']+=1
   assert Counter(m['symbol']for m in r['API_models'])=={'opaque_keyed_hash_result':2,'declared_user_copyout_effect':1,'declared_raw_zone_deallocation':1};free=next(m for m in r['API_models']if m['symbol']=='declared_raw_zone_deallocation');assert free['arguments8'][:4]==[hex(R+0xb0000),hex(R+0xb1000),hex(KMSG),'0x100'];counts['explicit_copyout_hash_and_raw_retirement_contracts_checked']+=1
   zf=next(f for f in src['functions']if f['start']=='0xfffffe000c6480c0');lo=int(zf['start'],16);hi=int(zf['end'],16);allzero=[e for e in r['source_writes']if lo<=int(e['pc'],16)<hi];zero=[e for e in allzero if KMSG<=int(e['address'],16)<KMSG+256];assert all(e in zero or(e['pc']=='0xfffffe000c6480c4'and e['size_bytes']==8)for e in allzero);covered=set()
   for e in zero:
    a=int(e['address'],16);assert KMSG<=a<a+e['size_bytes']<=KMSG+256 and e['after_hex']==bytes(e['size_bytes']).hex()and ce['before_source_visit_index']<e['source_visit_index']<free['before_source_visit_index'];covered.update(range(a,a+e['size_bytes']))
   assert covered==set(range(KMSG,KMSG+256))and finalram[KMSG-R:KMSG-R+256]==bytes(256)and finalram[KMSG-R+256]==0xa5;counts['original_complete_kmsg_zeroing_before_raw_deallocation_checked']+=1
  assert r['final_user8192_hex']==bytes(expecteduser).hex();counts['complete_user_buffer_and_untouched_suffix_oracles_checked']+=1
  for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_results_original_instruction_recaptured']+=1
  assert all(r[f]is False for f in FLAGS);ft.update(Replay(im,r).run());summaries.append({'family':family,'configuration':c,'producer_boundary':prof['cases'][family*5+4]['boundary']['kind'],'results_boundary':r['boundary']['kind'],'final_status':None if finalstatus is None else hex(finalstatus),'copyout_bytes_requested':copybytes,'copyout_bytes_copied':0 if failed or filezero else copybytes,'final_object_refs':1 if not filezero else 2,'final_send_once_rights':0 if not filezero else 1,'turnstile_loan_returned':True});print(json.dumps({**summaries[-1],'independent_replay':'pass'}),flush=True)
 counts.update(cases=20,consumers=4,finishes=4,functions=80,captured_instructions=11463)
 deps=[P+'_source.json',P+'_profiles.json','kernel_receive_continuation_profiles.json','kernel_waitq_enqueue_profiles.json','kernel_waitq_receiver_profiles.json','kernel_send_right_lifecycle_profiles.json','kernel_zone_startup_profiles.json','kernel_zone_startup_source.json','validate_kernel_waitq_enqueue.py','validate_kernel_waitq_receiver.py','validate_kernel_kmsg_queue.py','validate_kernel_kmsg_allocation.py','replay_'+P+'.py','replay_kernel_receive_continuation.py','replay_kernel_waitq_enqueue.py','replay_kernel_waitq_receiver.py','replay_kernel_kmsg_queue.py','replay_kernel_kmsg_allocation.py','replay_kernel_notification_send.py','replay_kernel_send_right_lifecycle.py','replay_kernel_zone_startup.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','replay_rpc502_vm_handoff.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(pt+st+ft),'producer_A64_replay':dict(pt),'sender_A64_replay':dict(st),'results_A64_replay':dict(ft),'fresh_notification_producer_replay':freshns,'fresh_zone_validation_producer_replay':freshzone,'proofs':proofs,'family_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(pt+st+ft),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
