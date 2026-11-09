#!/usr/bin/env python3
"""Independent produced object -> receiver descriptor/user-wire and ownership
oracles, fresh CPU replay and two packing identities. O(image+source+visits+
RAM+effects), O(image+RAM+journals). Native VM/IPC/PAC remain unknown.
"""
import json,struct
from collections import Counter
from z3 import BitVec,BitVecVal,Solver,And,ULE,If,Extract,ZeroExt,LShR,Not,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from replay_rpc502_vm_handoff import decode
from replay_kernel_request_delivery import Replay
from replay_kernel_request_copyin import Replay as ProducerReplay
from validate_kernel_request_receive import context_plan
from validate_kernel_special_reply import gbytes,gput
P='kernel_request_delivery';B=0x6500000000;SIZE=0x100000;SENDER=B+0x60000;RECV=B+0x64000;MAP=B+0x78000;USER=B+0x1000;OOL=B+0x4000;HEADER=B+0x88010;BACK=B+0x8c000;SPACE=B+0xdd000;TABLE=0x400000100000;KMSG=B+0xd0000;REP=B+0x80070;TS=B+0xa8040;LOAN=B+0xac040

def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def put(b,o,n,v):b[o:o+n]=v.to_bytes(n,'little')
def initial_oracle(im,r,parent,counts):
 ram=decode(parent['final_private_RAM']);gl=parent['final_image_globals'];loan=r['kind']=='receiver_turnstile_allocate';plan=context_plan(im,ram,gl,loan);assert r['delivery_environment_overlay_start']==len(plan)
 if loan:plan.append(('private',OOL,b'\xa5'*16385))
 plan.extend([('private',MAP,bytes(1024)),('private',MAP+0x10,struct.pack('<QQ',B,B+SIZE)),('private',MAP+0x2c,struct.pack('<I',14)),('private',MAP+0x88,struct.pack('<I',3))]);meta=val(gbytes(im,gl,0xfffffe0007e66f00,8),0);plan.extend([('private',meta+((MAP>>10)&0xffffffff0),struct.pack('<H',16)),('global',0xfffffe000caec2f4,struct.pack('<H',48))]);initial=bytearray(ram);gg=[dict(e)for e in gl];assert len(plan)==len(r['input_overlays'])
 for(space,a,b),e in zip(plan,r['input_overlays'],strict=True):
  assert e['space']==space and e['address']==hex(a)and e['after_hex']==b.hex();before=initial[a-B:a-B+len(b)]if space=='private'else gbytes(im,gg,a,len(b));assert e['before_hex']==before.hex()
  if space=='private':initial[a-B:a-B+len(b)]=b
  else:gg=gput(gg,a,b)
  counts['independent_ordered_receiver_context_and_view_before_images_checked']+=1
 assert r['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for space,a,b in plan if space=='private']and r['initial_image_fixtures']==gg
 for a,n in[(KMSG,256),(HEADER,48),(BACK,29),(SENDER,1536),(REP,144),(TS,96)]:assert initial[a-B:a-B+n]==ram[a-B:a-B+n]
 assert r['post_setup_original_kmsg256_hex']==ram[KMSG-B:KMSG-B+256].hex()and decode(r['initial_state_transfer'])==ram;counts['exact_source_packet_copy_object_backing_and_sender_preserved_at_entry']+=1;return bytes(initial),gg

def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());prior=json.loads((ROOT/'kernel_request_copyin_profiles.json').read_text());old=json.loads((ROOT/'kernel_request_receive_profiles.json').read_text());counts=Counter();totals=Counter();fresh=Counter();proofs=[];summaries=[]
 for obj,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 assert src['kernel_sha256']==im.k.sha256
 for f in src['functions']:
  a=int(f['start'],16);raw=im.k.read(a,int(f['end'],16)-a);assert raw.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]==f['instructions'];counts['complete_functions_recaptured']+=1
 for e in src['request_delivery_roles'].values():
  a=int(e['pc'],16);i=next(im.k.cs.disasm(im.k.read(a,4),a));assert e=={'pc':hex(a),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str};counts['delivery_instruction_roles_recaptured']+=1
 assert len(prof['loans'])==4 and len(prof['cases'])==8
 for j,r in enumerate(prof['loans']):
  q=prior['cases'][j];fresh.update(ProducerReplay(im,q).run());initial,gl=initial_oracle(im,r,q,counts);assert r['initial_state_transfer']['path']=='kernel_request_copyin_profiles.json'and r['initial_state_transfer']['case_origin']=='request'and r['initial_state_transfer']['producer']==j and r['boundary']['kind']=='original_receiver_turnstile_allocated';expected=bytearray(96)
  for o,n,v in[(0,4,2),(4,4,0x01010144),(0x50,4,1),(0x54,4,0x100)]:put(expected,o,n,v)
  assert decode(r['final_private_RAM'])[LOAN-B:LOAN-B+96]==expected and r['final_image_globals']==gl;counts['source_original_receiver_loan_constructor_checked']+=1;totals.update(Replay(im,r).run())
 for idx,r in enumerate(prof['cases']):
  j=idx//2;c={'producer':j,'capacity':88 if idx%2==0 else 148,'options':2 if idx%2==0 else 0x7000002};assert r['configuration']==c and r['initial_state_transfer']['path']==P+'_profiles.json'and r['initial_state_transfer']['case_origin']=='loan'and r['initial_state_transfer']['producer']==j;initial,gl=initial_oracle(im,r,prof['loans'][j],counts);final=decode(r['final_private_RAM']);mid=502 if j<2 else 700;service=0x303 if j<2 else 0x403;dest=B+0xc0070 if j<2 else B+0xc0100;name=bytes(0x21+k%90 for k in range(28))+b'\0';packet=bytearray.fromhex(prior['cases'][j]['continuous_constructor_handoff']['message88_hex']);message=bytearray(struct.pack('<IIIIII',0x80001112,80,0x207,service,0,mid)+packet[32:]);put(message,28,8,OOL);put(message,36,4,0x01000101);assert len(message)==80 and val(message,40,4)==val(message,52,4)==29
  trailer=bytearray(c['capacity']-80);put(trailer,4,4,len(trailer))
  if len(trailer)>8:put(trailer,16,4,1)
  delivered=bytes(message+trailer);user=bytes.fromhex(r['final_user8192_hex']);assert user==delivered+b'\xa5'*(8192-len(delivered))and r['final_OOL16384_hex']==(name+b'\xa5'*(16384-29)).hex()and r['final_OOL_guard_hex']=='a5';counts['independent_complete_user_message_trailer_OOL_and_guard_oracles_checked']+=1
  assert r['final_copy_header48_hex']=='00'*48 and final[KMSG-B:KMSG-B+256]==bytes(256)and r['final_backing29_hex']==name.hex()and final[HEADER-B+48]==0xa5 and final[BACK-B+29]==0xa5 and final[KMSG-B+256]==0xa5;counts['source_header_kmsg_zeroing_and_stale_backing_bytes_distinguished']+=1
  oldr=old['cases'][idx];oldram=decode(oldr['final_private_RAM']);wantthread=bytearray(oldram[RECV-B:RECV-B+1536]);wantmap=bytearray(1024);put(wantmap,0x10,8,B);put(wantmap,0x18,8,B+SIZE);put(wantmap,0x2c,4,14);put(wantmap,0x88,4,3)
  for a,n in[(dest,144),(REP,144),(TS,96),(LOAN,96),(SPACE,128),(B+0x5a000,32)]:assert final[a-B:a-B+n]==oldram[a-B:a-B+n]
  assert final[RECV-B:RECV-B+1536]==wantthread and final[MAP-B:MAP-B+1024]==wantmap and final[SENDER-B:SENDER-B+1536]==initial[SENDER-B:SENDER-B+1536];counts['complete_port_namespace_thread_loan_map_and_accounting_oracles_checked']+=1
  wanttable=next(bytes.fromhex(e['bytes_hex'])for e in oldr['final_image_globals']if e['address']==hex(TABLE));assert r['final_image_globals']==gput(gl,TABLE,wanttable);counts['complete_namespace_global_publication_oracle_checked']+=1
  alloc=r['VM_allocation_contracts'];assert len(alloc)==1 and alloc[0]['arguments8']==[hex(MAP),hex(B+0xe5ed0),'0x4000','0x0','0x0','0x0','0x0','0x0']and alloc[0]['stack_prefix12_hex']=='030000000700000001000000';counts['exact_VM_allocation_and_stack_option_contracts_checked']+=1
  copies=r['user_byte_copy_contracts'];assert len(copies)==2 and copies[0]['arguments3']==[hex(BACK),hex(OOL),'0x1d']and copies[0]['source_hex']==name.hex()and copies[0]['destination_before_hex']=='a5'*29 and copies[1]['arguments3']==[hex(KMSG+0x48),hex(USER),hex(c['capacity'])]and copies[1]['source_hex']==delivered.hex()and copies[1]['destination_before_hex']=='a5'*c['capacity'];counts['independent_OOL_then_inline_user_copy_effects_checked']+=1
  returns=r['raw_VM_kmsg_retirement_contracts'];assert len(returns)==3;assert returns[0]['arguments4'][:3]==['0xfffffe0007f8bfb0',hex(BACK),'0x1d']and bytes.fromhex(returns[0]['copy48_hex'])[:8]==bytes(8)
  for e,zone,stats,ptr,size in[(returns[1],0xfffffe000caec2c0,B+0x50000,HEADER,48),(returns[2],0xfffffe000caec680,B+0x4c000,KMSG,256)]:
   assert e['arguments4']==[hex(zone),hex(stats),hex(ptr),hex(size)]and e['object_hex']=='00'*size;covered=set()
   for w in r['source_writes']:
    a=int(w['address'],16)
    if ptr<=a<a+w['size_bytes']<=ptr+size and 0xfffffe000c6480c0<=int(w['pc'],16)<0xfffffe000c648170:assert w['source_visit_index']<e['before_source_visit_index']and w['after_hex']=='00'*w['size_bytes'];covered.update(range(a,a+w['size_bytes']))
   assert covered==set(range(ptr,ptr+size));counts['original_complete_zeroing_before_raw_retirement_checked']+=1
  assert returns[0]['before_source_visit_index']<returns[1]['before_source_visit_index']<copies[1]['before_source_visit_index']<returns[2]['before_source_visit_index'];counts['copy_payload_header_user_delivery_kmsg_retirement_order_checked']+=1
  expectedmodels=Counter({'opaque_keyed_hash_result':2,'declared_raw_turnstile_retirement':1,'declared_receiver_VM_allocation':1,'declared_receiver_user_byte_copy':2,'declared_raw_copy_backing_retirement':1,'declared_raw_copy_header_retirement':1,'declared_raw_kmsg_retirement':1});assert Counter(m['symbol']for m in r['API_models'])==expectedmodels and len(r['delivery_full_CPU_RAM_handoffs'])==4
  pcs=Counter(v['pc']for v in r['source_visits']);assert pcs['0xfffffe000bdd148c']==1 and pcs['0xfffffe000bdcb374']==1 and pcs['0xfffffe000bcc62d0']==1 and pcs['0xfffffe000bd28f6c']==0;counts['original_validation_copyout_packing_fast_path_control_flow_checked']+=1
  assert r['boundary']['kind']=='receive_frontend_returned'and r['boundary']['pc']==hex(B+0xe0000)and r['boundary']['registers31'][0]=='0x0'and r['boundary']['SP']==hex(B+0xe6000);counts['source_receive_return_status_and_stack_checked']+=1
  totals.update(Replay(im,r).run());summaries.append({'case':idx,'producer':j,'rpc_id':mid,'capacity_bytes':c['capacity'],'inline_bytes':80,'trailer_bytes':len(trailer),'OOL_bytes':29,'reply_name':'0x207','service_name':hex(service),'status':0,'source_visits':len(r['source_visits'])});print(json.dumps({'case':idx,'independent_replay':'pass','user_bytes':len(delivered)}),flush=True)
 for r in prof['loans']+prof['cases']:
  assert all(r[k]is False for k in FLAGS)
  for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['all_original_instruction_visits_recaptured']+=1
  for ordinal,m in enumerate(r['API_models'],1):
   assert m['native_effects_executed']is False and m['after_registers31'][0]==m['return_value']and m['after_NZCV']==('0xf0000000'if ordinal&1 else'0x0')
   for k in range(1,18):assert int(m['after_registers31'][k],16)==(((k+1)*0x123456789abcdef)^ordinal*0x8b3dc651)&((1<<64)-1)
   counts['declared_primitive_outcomes_and_volatile_clobbers_checked']+=1
 flags=BitVec('internal_descriptor_flags_u32',32);port=BitVec('translated_port_u64',64);mask=flags&0xff00ff00;cond=Extract(15,8,flags)==1
 queries=[('descriptor_deallocate_rebuild_equals_low_byte_boolean',True,mask+If(cond,BitVecVal(1,32),BitVecVal(0,32))==(mask|If(cond,BitVecVal(1,32),BitVecVal(0,32)))),('narrowing_translated_u32_namespace_name_preserves_value',ULE(port,0xffffffff),ZeroExt(32,Extract(31,0,port))==port)]
 for name,domain,claim in queries:
  s=Solver();s.add(domain,Not(claim));assert s.check()==unsat;proofs.append({'name':name,'domain':str(domain),'query':s.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1
 counts.update(functions=len(src['functions']),captured_instructions=sum(len(f['instructions'])for f in src['functions']),loan_producers=4,delivery_cases=8)
 deps=[P+'_source.json',P+'_profiles.json','kernel_request_copyin_profiles.json','kernel_request_receive_profiles.json','replay_'+P+'.py','replay_kernel_request_copyin.py','replay_kernel_request_receive.py','replay_kernel_vm_mig.py','validate_kernel_request_receive.py','validate_kernel_special_reply.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_copyin_request_producer_replays':dict(fresh),'case_summaries':summaries,'proofs':proofs,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_copyin_request_producer_replays':dict(fresh),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
