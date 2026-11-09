#!/usr/bin/env python3
"""Independent queued-state provenance, receiver contexts, full object/name/queue
oracles and fresh CPU replay. O(image+source+visits+RAM+effects), O(image+RAM+
journals). Two bounded scalar proofs; native context/VM/IPC/PAC remain unknown.
"""
import json,struct
from collections import Counter
from z3 import BitVec,Solver,UGE,ULE,And,Not,unsat,Extract
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from replay_rpc502_vm_handoff import decode
from replay_kernel_request_receive import Replay
from replay_kernel_rpc_request import Replay as ProducerReplay
from validate_kernel_special_reply import gbytes,gput
P='kernel_request_receive';B=0x6500000000;SIZE=0x100000;SENDER=B+0x60000;RECV=B+0x64000;OWNER=B+0x68000;TASK=B+0x947c0;MAP=B+0x78000;STATS=B+0x5a000;SMR=B+0x9d000;USER=B+0x1000;PSP=B+0xe6000;SPACE=B+0xdd000;TABLE=0x400000100000;D0=B+0xc0070;D1=B+0xc0100;REP=B+0x80070;TS=B+0xa8040;LOAN=B+0xac040;KMSG=B+0xd0000

def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def put(b,o,n,v):b[o:o+n]=v.to_bytes(n,'little')
def context_plan(im,ram,gl,loan):
 th=bytearray(1536)
 for o,n,v in[(0xb0,8,17),(0x1c0,8,B+0xb4000),(0x1f8,4,4),(0x420,8,OWNER),(0x428,8,MAP),(0x518,4,0x4321)]:put(th,o,n,v)
 own=bytearray(56);put(own,0,8,RECV);put(own,0x28,8,TASK);meta=val(gbytes(im,gl,0xfffffe0007e66f00,8),0)
 plan=[('private',a,b)for a,b in[(RECV,bytes(th)),(OWNER,bytes(own)),(TASK-0x7c0,bytes(0xe90)),(TASK-0x7c0+0x60,struct.pack('<I',4242)),(TASK+0x318,struct.pack('<Q',SPACE)),(TASK+0x3d8,struct.pack('<Q',STATS)),(TASK+0x6c8,struct.pack('<I',1)),(STATS,bytes(32)),(MAP,bytes(128)),(MAP+0x18,struct.pack('<Q',0xffffffffffffffff)),(MAP+0x2c,struct.pack('<I',14)),(USER,b'\xa5'*8192),(SMR,bytes(64)),(SPACE+0x14,struct.pack('<II',0,1)),(SPACE+0x1c,struct.pack('<I',0x35)),(SPACE+0x50,struct.pack('<Q',TASK)),(SPACE+0x70,struct.pack('<II',0xffffffff,0)),(meta+((OWNER>>10)&0xffffffff0),struct.pack('<H',3)),(meta+(((TASK-0x7c0)>>10)&0xffffffff0),struct.pack('<H',26))]]
 if loan:plan.extend(('private',a,b)for a,b in[(LOAN,bytes(96)),(LOAN+96,b'\xa5'),(meta+((LOAN>>10)&0xffffffff0),struct.pack('<H',28))])
 else:plan.append(('private',RECV+0x30,struct.pack('<Q',LOAN)))
 tb=bytearray(gbytes(im,gl,TABLE,4096));put(tb,12,4,2);tb[48:72]=struct.pack('<QIIII',0,0,0,0x11223344,0x55667788);plan.extend(('global',a,b)for a,b in[(TABLE,bytes(tb)),(0xfffffe000caac348,struct.pack('<Q',0x100)),(0xfffffe000caac350,struct.pack('<Q',SMR))]);return plan

def check_initial(im,r,ram,gl,counts):
 initial=bytearray(ram);gg=[dict(e)for e in gl];plan=context_plan(im,ram,gl,r['kind']=='receiver_turnstile_allocate');assert len(plan)==len(r['input_overlays'])
 for(space,a,b),e in zip(plan,r['input_overlays'],strict=True):
  assert e['space']==space and e['address']==hex(a)and e['after_hex']==b.hex();before=initial[a-B:a-B+len(b)]if space=='private'else gbytes(im,gg,a,len(b));assert before.hex()==e['before_hex']
  if space=='private':initial[a-B:a-B+len(b)]=b
  else:gg=gput(gg,a,b)
  counts['independent_context_import_and_overlay_before_images_checked']+=1
 assert r['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for space,a,b in plan if space=='private']and r['initial_image_fixtures']==gg and initial[KMSG-B:KMSG-B+256]==ram[KMSG-B:KMSG-B+256]and r['post_setup_original_kmsg256_hex']==ram[KMSG-B:KMSG-B+256].hex();counts['complete_original_queued_packet_preserved_at_entry']+=1
 for a,n in[(SENDER,1536),(D0,144),(D1,144),(REP,144),(TS,96)]:assert initial[a-B:a-B+n]==ram[a-B:a-B+n]
 counts['sender_ports_queue_and_linkage_preserved_across_receiver_setup']+=1;return bytes(initial),gg

def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());prior=json.loads((ROOT/'kernel_rpc_request_profiles.json').read_text());counts=Counter();totals=Counter();fresh=Counter();proofs=[];summaries=[]
 for obj,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 assert src['kernel_sha256']==im.k.sha256
 for f in src['functions']:
  a=int(f['start'],16);raw=im.k.read(a,int(f['end'],16)-a);assert raw.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]==f['instructions'];counts['complete_functions_recaptured']+=1
 for e in src['request_receive_roles'].values():
  a=int(e['pc'],16);i=next(im.k.cs.disasm(im.k.read(a,4),a));assert e=={'pc':hex(a),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str};counts['receive_instruction_roles_recaptured']+=1
 assert len(prof['loans'])==4 and len(prof['cases'])==10
 expectedloan=bytearray(96)
 for o,n,v in[(0,4,2),(4,4,0x01010144),(0x50,4,1),(0x54,4,0x100)]:put(expectedloan,o,n,v)
 for j,r in enumerate(prof['loans']):
  q=prior['requests'][j];fresh.update(ProducerReplay(im,q).run());assert r['configuration']=={'producer':j,'capacity':88,'options':2,'phase':'loan'}and r['initial_state_transfer']['path']=='kernel_rpc_request_profiles.json'and r['initial_state_transfer']['request']==j and decode(r['initial_state_transfer'])==decode(q['final_private_RAM']);initial,gl=check_initial(im,r,decode(q['final_private_RAM']),q['final_image_globals'],counts)
  assert r['entry_PC']=='0xfffffe000bd682cc'and r['entry_registers31']==['0x0']*30+[hex(B+0xe0000)]and r['boundary']['kind']=='original_receiver_turnstile_allocated'and r['boundary']['registers31'][0]==hex(LOAN)
  assert len(r['API_models'])==1 and r['API_models'][0]['symbol']=='declared_zeroed_raw_receiver_turnstile_storage'and r['API_models'][0]['arguments8'][:3]==['0xfffffe000caec980',hex(B+0x44000),'0x8004']and r['API_models'][0]['return_value']==hex(LOAN);assert len(r['raw_storage_contracts'])==1 and r['raw_storage_contracts'][0]['object_before_hex']=='00'*96
  final=decode(r['final_private_RAM']);assert final[LOAN-B:LOAN-B+96]==expectedloan and final[LOAN-B+96]==0xa5 and final[KMSG-B:KMSG-B+256]==initial[KMSG-B:KMSG-B+256]and r['final_image_globals']==gl;counts['complete_original_receiver_loan_construction_oracles_checked']+=1;totals.update(Replay(im,r).run())
 configs=[{'producer':j,'capacity':cap,'options':opt}for j in range(4)for cap,opt in[(88,2),(148,0x7000002)]]+[{'producer':j,'capacity':87,'options':6,'stop_at_results':True}for j in[0,2]]
 for idx,(r,c)in enumerate(zip(prof['cases'],configs,strict=True)):
  q=prof['loans'][c['producer']];assert r['configuration']==c and r['kind']=='queued_request_receive'and r['initial_state_transfer']['path']==P+'_profiles.json'and r['initial_state_transfer']['loan']==c['producer']and decode(r['initial_state_transfer'])==decode(q['final_private_RAM']);initial,gl=check_initial(im,r,decode(q['final_private_RAM']),q['final_image_globals'],counts);dest=D0 if c['producer']<2 else D1;name=0x303 if dest==D0 else 0x403;large=c.get('stop_at_results',False);regs=[hex(x)for x in[USER,0,c['options'],0,0,c['capacity'],0,name]]+['0x0']*22+[hex(B+0xe0000)]
  assert r['entry_PC']=='0xfffffe000bcdd4e4'and r['entry_SP']==hex(PSP)and r['entry_registers31']==regs and r['entry_DAIF_mask']=='0x200'and r['current_thread']==hex(RECV)and r['destination']==hex(dest)and r['receive_name']==hex(name);counts['receive_frontend_explicit_ABIs_and_complete_origins_checked']+=1
  final=decode(r['final_private_RAM']);port=bytearray(initial[dest-B:dest-B+144]);reply=bytearray(initial[REP-B:REP-B+144]);km=bytearray(initial[KMSG-B:KMSG-B+256]);space=bytearray(initial[SPACE-B:SPACE-B+128]);tb=bytearray(gbytes(im,gl,TABLE,4096));th=bytearray(initial[RECV-B:RECV-B+1536]);stats=bytearray(32)
  for o,n,v in[(0x378,8,USER),(0x388,4,c['capacity']),(0x390,8,c['options']),(0x398,8,dest)]:put(th,o,n,v)
  if large:
   put(port,4,4,6);put(port,0x14,4,0x09090144)
   for o,n,v in[(0x3a0,4,0x10004004),(0x3a8,4,80),(0x3b0,4,name)]:put(th,o,n,v)
   assert r['boundary']['kind']=='before_original_receive_results_with_queue_preserved'and r['boundary']['pc']=='0xfffffe000bcdcc7c'and r['raw_retirement_contracts']==[]and final[TS-B:TS-B+96]==initial[TS-B:TS-B+96];counts['insufficient_capacity_preserves_complete_packet_queue_reply_and_link_checked']+=1
  else:
   for o,n,v in[(4,4,3),(0x14,4,0x0b0b0144),(0x28,8,0),(0x30,4,1),(0x38,2,0),(0x70,8,0),(0x88,4,1)]:put(port,o,n,v)
   for o,n,v in[(0x10,4,0xc400b),(0x14,4,0x04040144),(0x58,8,0),(0x60,4,4242)]:put(reply,o,n,v)
   put(km,0,8,0);put(km,8,8,0);put(km,0x40,4,0x80001112);put(km,0x48,8,0x207);put(km,0x50,8,name)
   for o,n,v in[(8,4,0x01010000),(0x18,4,0),(0x70,4,2),(0x74,4,2)]:put(space,o,n,v)
   put(tb,12,4,0);put(tb,48,8,REP);put(tb,56,4,0x04840001);put(th,0x3b8,8,KMSG);put(stats,0,8,1)
   assert r['boundary']['kind']=='before_original_request_descriptor_copyout'and r['boundary']['pc']=='0xfffffe000bcc5564'and r['boundary']['registers31'][:5]==[hex(KMSG+0x64),'0x1',hex(SPACE),hex(MAP),hex(c['options'])];assert final[TS-B:TS-B+96]==bytes(96)and len(r['raw_retirement_contracts'])==1
   retire=r['raw_retirement_contracts'][0];assert retire['arguments4']==['0xfffffe000caec980',hex(B+0x44000),hex(TS),'0x60']and retire['turnstile96_hex']=='00'*96;covered=set()
   for w in r['source_writes']:
    a=int(w['address'],16)
    if TS<=a<a+w['size_bytes']<=TS+96 and 0xfffffe000c6480c0<=int(w['pc'],16)<0xfffffe000c648170:assert w['source_visit_index']<retire['before_source_visit_index']and w['after_hex']=='00'*w['size_bytes'];covered.update(range(a,a+w['size_bytes']))
   assert covered==set(range(TS,TS+96));counts['original_last_link_hold_zeroing_before_retirement_checked']+=1;counts['source_original_request_reply_right_namespace_publication_checked']+=1
  for a,b in[(dest,port),(REP,reply),(KMSG,km),(SPACE,space),(RECV,th),(STATS,stats),(LOAN,expectedloan)]:assert final[a-B:a-B+len(b)]==b,(idx,hex(a));counts['independent_complete_record_oracles_checked']+=1
  assert r['final_image_globals']==gput(gl,TABLE,bytes(tb))and final[SENDER-B:SENDER-B+1536]==initial[SENDER-B:SENDER-B+1536]and final[USER-B:USER-B+8192]==b'\xa5'*8192 and final[LOAN-B+96]==0xa5;counts['namespace_globals_sender_thread_user_buffer_and_loan_preservation_checked']+=1
  other=D1 if dest==D0 else D0;assert final[other-B:other-B+144]==initial[other-B:other-B+144];pcs=Counter(v['pc']for v in r['source_visits']);assert pcs['0xfffffe000bd28f6c']==0 and pcs['0xfffffe000bcc86e8']==int(not large)and pcs['0xfffffe000bcdce04']==int(not large)and pcs['0xfffffe000bcd5b90']==int(not large);counts['original_fast_dequeue_and_results_control_flow_paths_checked']+=1
  wantmodels=Counter({'opaque_keyed_hash_result':2})
  if not large:wantmodels['declared_raw_turnstile_retirement']=1
  assert Counter(m['symbol']for m in r['API_models'])==wantmodels;assert len(r['continuous_receive_handoffs'])==(1 if large else 3)
  totals.update(Replay(im,r).run());summaries.append({'case':idx,'producer':c['producer'],'rpc_id':502 if dest==D0 else 700,'receive_name':hex(name),'capacity_bytes':c['capacity'],'options':hex(c['options']),'source_visits':len(r['source_visits']),'queue_preserved':large,'reply_name':None if large else'0x207','final_destination_refs':6 if large else 3,'final_destination_send_rights':2 if large else 1,'boundary':r['boundary']['pc']});print(json.dumps({'case':idx,'replay':'pass','queue_preserved':large}),flush=True)
 for r in prof['loans']+prof['cases']:
  assert all(r[k]is False for k in FLAGS)
  for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['all_original_instruction_visits_recaptured']+=1
  for ordinal,m in enumerate(r['API_models'],1):
   assert m['native_effects_executed']is False and m['after_registers31'][0]==m['return_value']and m['after_NZCV']==('0xf0000000'if ordinal&1 else'0x0')
   for j in range(1,18):assert int(m['after_registers31'][j],16)==(((j+1)*0x123456789abcdef)^ordinal*0x8b3dc651)&((1<<64)-1)
   if m['symbol']=='opaque_keyed_hash_result':assert m['return_value']=='0x123456789abcdef0'
   elif m['symbol']=='declared_raw_turnstile_retirement':assert m['return_value']=='0x0'
   else:assert m['symbol']=='declared_zeroed_raw_receiver_turnstile_storage'and m['return_value']==hex(LOAN)
   counts['bounded_primitive_outcomes_and_volatile_clobbers_checked']+=1
 from z3 import Or,LShR
 size=BitVec('internal_size_u32',32);trailer=BitVec('trailer_size_u32',32);index=BitVec('free_entry_index_u32',32);user=(size-8-16)+16
 queries=[('type1_user_size_and_trailer_addition_do_not_wrap',And(UGE(size,52),ULE(size,0xffffffc3),Or(trailer==8,trailer==68)),And(user==size-8,UGE(user,44),UGE(user+trailer,user))),('generated_reply_name_retains_index_and_generation_bits',ULE(index,0xffffff),And(Extract(7,0,(index<<8)|7)==7,LShR((index<<8)|7,8)==index))]
 for name,domain,claim in queries:
  s=Solver();s.add(domain,Not(claim));assert s.check()==unsat;proofs.append({'name':name,'domain':str(domain),'query':s.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1
 counts.update(functions=len(src['functions']),captured_instructions=sum(len(f['instructions'])for f in src['functions']),loan_producers=4,receiver_cases=10,accepted_cases=8,capacity_guard_cases=2)
 deps=[P+'_source.json',P+'_profiles.json','kernel_rpc_request_profiles.json','replay_'+P+'.py','replay_kernel_rpc_request.py','replay_kernel_vm_mig.py','validate_kernel_special_reply.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_request_producer_replays':dict(fresh),'case_summaries':summaries,'proofs':proofs,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_request_producer_replays':dict(fresh),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
