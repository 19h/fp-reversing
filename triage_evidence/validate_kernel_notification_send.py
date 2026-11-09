#!/usr/bin/env python3
"""Produced ID70 packet, storage/normalization, stage-dependent send/cleanup ABI.
O(image+visits+RAM+effects), O(image+RAM+journals); fixed-width solver queries.
Models of keyed hashes/queues/destruction do not establish native delivery/rights.
"""
import json,struct,hashlib
from collections import Counter
from z3 import BitVec,BitVecVal,Extract,ZeroExt,LShR,If,And,Or,ULE,Solver,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from replay_rpc502_vm_handoff import decode
from replay_kernel_send_right_lifecycle import Replay as ProducerReplay
from replay_kernel_notification_send import Replay
P='kernel_notification_send';R=0x6500000000;KMSG=R+0xd0000;HEADER=R+0xd4000;DATA=R+0xd8000;ACCEPT=R+0xdc000;KSPACE=R+0xdc800;USPACE=R+0xdd000;THREAD=R+0x2c000;DEST=R+0xc0000;M=(1<<64)-1;SPECIAL={0x10000003,0x10000004,0x10000007,0x1000000d}
def val(b,o,n=4):return int.from_bytes(b[o:o+n],'little')
def frame(r,a):return next((f for f in r['entry_frames']if f['pc']==hex(a)),None)
def wrap_options(o,f):
 x=o&~(1<<37)
 return (x|((~(o>>1))&0x40000))if not f&0x800 else x&~0x40000
def queue_options(o,f):return((o&~0x10000)|0x10)if f&0x400 else o
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());producer=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];counts=Counter();totals=Counter();summaries=[];proofs=[]
 for o,s in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/s)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
  assert all(o[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==10 and sum(len(f['instructions'])for f in src['functions'])==1503
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 for e in src['exact_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 oh=src['opaque_keyed_hash'];raw=im.k.read(int(oh['start'],16),int(oh['end'],16)-int(oh['start'],16));assert len(raw)==180 and raw.hex()==oh['bytes_hex']and hashlib.sha256(raw).hexdigest()==oh['sha256']and len(oh['PACGA_sites'])==5
 tr=src['disposition_translation'];assert tr['words6_u32']==[val(im.k.read(int(tr['address'],16),24),4*j)for j in range(6)]and tr['words6_u32'][2]==18
 template=bytes.fromhex(src['kernel_trailer_template']['bytes68_hex']);assert im.k.read(int(src['kernel_trailer_template']['address'],16),68)==template
 rpc=json.loads((ROOT/'kernel_rpc_transport_contracts.json').read_text());rr=next(r for r in rpc['native_ranges']if r['start']=='0xfffffe000bcf59e0');assert im.k.read(int(rr['start'],16),int(rr['end'],16)-int(rr['start'],16)).hex()==rr['bytes']
 shared=[]
 for e in rpc['direct_edges']:
  if e['target']not in['0xfffffe000bcc68c4','0xfffffe000bcc6b10','0xfffffe000bcc7040']:continue
  a=int(e['site'],16);i=next(im.k.cs.disasm(im.k.read(a,4),a));assert i.mnemonic=='bl'and i.op_str=='#'+e['target'];shared.append(e);counts['original_RPC_shared_preparation_copyin_send_edges_checked']+=1
 assert len(shared)==3
 fresh_producer=ProducerReplay(im,producer).run();counts['fresh_original_notification_producer_replay_checked']=1
 o=BitVec('options64',64);f=BitVec('thread_flags16',16);q=BitVec('queue_status32',32);x=o&BitVecVal(M^(1<<37),64);literal=BitVecVal(0xffffffdffffbffff,64)
 sourcewrap=If(f&0x800==0,x|ZeroExt(32,(~LShR(Extract(31,0,o),1))&0x40000),o&literal)
 compactwrap=If(f&0x800==0,x|If(o&(1<<19)==0,BitVecVal(1<<18,64),BitVecVal(0,64)),x&BitVecVal(M^(1<<18),64))
 sourcequeue=If(f&0x400!=0,(o&BitVecVal(0xfffffffffffeffff,64))|0x10,o);compactqueue=If(f&0x400!=0,(o&BitVecVal(M^(1<<16),64))|(1<<4),o)
 n=q-0x10000003;bitmap=And(ULE(n,10),((BitVecVal(1,32)<<n)&0x413)!=0)
 for label,left,right in[('send_wrapper_options_all_u64_flags16',sourcewrap,compactwrap),('common_send_option_mutation_all_u64_flags16',sourcequeue,compactqueue),('send_failure_bitmap_all_u32',bitmap,Or(*[q==s for s in sorted(SPECIAL)]))]:
  s=Solver();s.add(left!=right);assert s.check()==unsat;proofs.append({'name':label,'query':s.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1
 rows=prof['cases'];assert len(rows)==52;packet=int(producer['notification_packet']['address'],16);base=decode(producer['final_private_RAM']);origbytes=bytes.fromhex(producer['notification_packet']['bytes44_hex']);assert len(origbytes)==44
 for j,r in enumerate(rows):
  c=r['configuration'];cls=c['storage_class'];flags=c.get('thread_flags',0);options=c.get('options',0x50001);prep=wrap_options(options,flags);effective=queue_options(prep,flags);sendbytes=c.get('send_bytes',44);short=sendbytes<32;allocfail=c.get('allocation_null',False);bad=c.get('destination_null',False);inactive=c.get('destination_inactive',False);sent=not(short or allocfail or bad);queued=sent and not inactive;status=c.get('queue_status',0);cleanup=sent and(inactive or status==0x10000003);header=KMSG+0x40 if cls<2 else HEADER;body=DATA if cls&1 else header+32
  assert all(r[k]is False for k in FLAGS)and decode(r['initial_state_transfer'])==base and r['initial_state_transfer']['path']=='kernel_send_right_lifecycle_profiles.json'and r['initial_state_transfer']['case']==11;counts['exact_producer_RAM_bases_checked']+=1
  plan=[(KMSG,bytes(0x400)),(KMSG+0x3f,bytes([cls<<6]))]
  if cls>=2:plan.append((KMSG+0xe8,struct.pack('<Q',HEADER)))
  if cls&1:plan.append((KMSG+0xf0,struct.pack('<Q',DATA)))
  if cls>=2:plan.append((HEADER,b'\xa5'*256))
  if cls&1:plan.append((DATA,b'\xa5'*256))
  plan.extend([(ACCEPT,b'\xa5'*4),(THREAD+0xc8,struct.pack('<H',flags)),(DEST+0x48,struct.pack('<Q',USPACE))])
  if bad:plan.append((packet+8,bytes(8)))
  if inactive:plan.append((DEST+1,bytes(1)))
  init=bytearray(base);assert len(plan)==len(r['memory_overlays'])==len(r['initial_private_fixtures'])
  for (a,b),e,p in zip(plan,r['memory_overlays'],r['initial_private_fixtures'],strict=True):
   assert e['address']==hex(a)and e['before_hex']==init[a-R:a-R+len(b)].hex()and e['after_hex']==b.hex()and p=={'address':hex(a),'bytes_hex':b.hex()};init[a-R:a-R+len(b)]=b;counts['explicit_memory_overlay_patches_checked']+=1
  want=list(producer['boundary']['registers31']);allowed={1:sendbytes,2:options,4:ACCEPT if c.get('accepted_output')else 0};overlays=[]
  for k,v in allowed.items():
   if want[k]!=hex(v):overlays.append(('X'+str(k),want[k],hex(v)));want[k]=hex(v)
  assert[(e['register'],e['before'],e['after'])for e in r['register_overlays']]==overlays and r['entry_registers31']==want and r['entry_SP']==producer['boundary']['SP']and r['entry_NZCV']==producer['boundary']['NZCV']and r['entry_Q_registers32']==producer['final_Q_registers32'];counts['exact_CPU_entry_with_declared_ABI_variants_checked']+=1
  inherited=producer['final_image_globals'];assert[{k:e[k]for k in['address','bytes_hex']}for e in r['initial_image_fixtures'][:len(inherited)]]==inherited
  assert[(e['address'],e['bytes_hex'])for e in r['initial_image_fixtures'][len(inherited):]]==[('0xfffffe0007e62b68',struct.pack('<Q',KSPACE).hex()),('0xfffffe0007e5c221','00')];counts['exact_inherited_and_explicit_environmental_globals_checked']+=1
  assert r['header_address']==hex(header)and r['body_address']==hex(body)and r['boundary']['kind']=='outer_notification_caller_returned'and r['boundary']['pc']=='0x65000e0000'and r['boundary']['registers31'][18:]==producer['entry_registers31'][18:]and r['boundary']['SP']==producer['entry_SP'];counts['original_notification_caller_epilogue_and_saved_state_checked']+=1
  assert frame(r,0xfffffe000bcc68c4)['arguments5'][:4]==[hex(packet),hex(sendbytes),hex(options&~(1<<37)),hex(int(r['entry_SP'],16)-0x48)];counts['wrapper_preparation_ABI_and_local_stack_output_checked']+=1
  assert all((int(r['final_Q_registers32'][k],16)&((1<<64)-1))==(int(r['entry_Q_registers32'][k],16)&((1<<64)-1))for k in range(8,16))
  final=decode(r['final_private_RAM']);wantpacket=bytearray(origbytes)
  if bad:wantpacket[8:16]=bytes(8)
  assert final[packet-R:packet-R+44]==wantpacket and r['final_source_port144_hex']==producer['final_ports144_hex'][hex(R+0x83000)];counts['original_input_packet_and_cleared_request_source_preserved_checked']+=1
  expectedreturn=0x1000000e if short else 0x1000000d if allocfail else 0x10000003 if bad else 0 if cleanup else status
  returned=frame(r,0xfffffe000bcd059c);assert int(returned['arguments5'][0],16)==expectedreturn;counts['stage_dependent_helper_status_and_ignored_caller_return_checked']+=1
  accepted=int(sent)if c.get('accepted_output')else 0xa5a5a5a5;assert r['final_accepted_u32']==accepted;counts['optional_copyin_completion_output_checked']+=int(c.get('accepted_output',False))
  assert r['final_thread_flags_u16']==(flags&~0x400 if sent else flags);counts['thread_flag_epoch_and_bit10_clear_checked']+=1
  copied=not(short or allocfail);models=r['API_models'];by={}
  for m in models:by.setdefault(m['symbol'],[]).append(m)
  def args(name):return[[int(x,16)for x in m['arguments8']]for m in by.get(name,[])]
  assert[a[:4]for a in args('declared_kmsg_allocate')]==([]if short else[[sendbytes,0,0,1]])
  if not short:assert by['declared_kmsg_allocate'][0]['return_value']==('0x0'if allocfail else hex(KMSG));counts['original_allocator_ABI_and_declared_result_checked']+=1
  expectedcopies=[]if not copied else[(header,packet,32),(DATA,packet+32,12)]if cls&1 else[(header,packet,44)]
  assert[a[:3]for a in args('declared_byte_copy')]==[list(t)for t in expectedcopies];counts['exact_storage_class_copy_plans_checked']+=1
  if copied:
   expectedheader=bytearray(wantpacket[:32]);struct.pack_into('<I',expectedheader,4,44);assert r['final_header32_hex']==expectedheader.hex()and r['final_body12_hex']==bytes(wantpacket[32:44]).hex();counts['original_header_size_and_packet_body_normalization_checked']+=1
   copyframe=frame(r,0xfffffe000bcc6b10);assert copyframe['header32_hex']==expectedheader.hex()
  if sent:
   hf=r['opaque_hash_inputs'];assert len(hf)==2 and hf[0]['arguments4'][1:]==['0x24',hex(KMSG|0x3409000000000000),'0x0']and hf[0]['bytes_hex']==struct.pack('<IIQQIII',18,44,DEST,0,0,70,0).hex()
   assert hf[1]['arguments4']==[hex(body+12),'0x44','0x123456789abcdef0','0x1']and hf[1]['bytes_hex']==r['final_trailer68_hex']==template.hex()and r['final_kmsg1024_hex'][0x38*2:0x3c*2]=='78563412';counts['original_canonical_hash_inputs_trailer_and_modeled_signature_checked']+=1
   rights=frame(r,0xfffffe000bcc9718);assert rights['arguments5'][:2]==[hex(DEST),'0x12']and frame(r,0xfffffe000bcc7040)['arguments5'][:3]==[hex(KMSG),hex(prep),'0x0'];counts['original_MOVE_SEND_ONCE_copyin_and_common_send_entry_checked']+=1
   hi=rights['source_visit_index'];lo=frame(r,0xfffffe000bcc7040)['source_visit_index'];assert not any(hi<=w['source_visit_index']<lo and int(w['address'],16)in[DEST+4,DEST+0x88,DEST+0x8c]for w in r['source_writes']);counts['MOVE_SEND_ONCE_copyin_no_extra_counter_store_checked']+=1
  else:assert not r['opaque_hash_inputs']and frame(r,0xfffffe000bcc7040)is None
  assert[a[:4]for a in args('declared_queue_send')]==([[DEST+0x28,KMSG,effective,0]]if queued else[])and[a[:2]for a in args('declared_send_preflight')]==([[KMSG,effective]]if queued else[]);counts['original_option_and_queue_argument_frames_checked']+=int(queued)
  assert[a[0]for a in args('declared_send_failure_helper')]==([KMSG]if queued and status in SPECIAL else[])
  destroyflag=1 if cleanup else 0 if queued and status else None
  assert[a[:2]for a in args('declared_message_destroy')]==([]if destroyflag is None else[[KMSG,destroyflag]])and[a[0]for a in args('declared_kmsg_buffer_free')]==([KMSG]if copied and bad else[]);counts['stage_specific_free_destroy_and_failure_request_plans_checked']+=1
  dest=bytes.fromhex(r['final_destination144_hex']);assert val(dest,4)==2-int(cleanup)and val(dest,0x8c)==1;counts['original_destination_ref_drops_distinguished_from_modeled_retirement_checked']+=1
  for k,m in enumerate(models):
   sym=m['symbol'];a=[int(v,16)for v in m['arguments8']]
   expected=0 if sym not in['declared_kmsg_allocate','declared_byte_copy','opaque_keyed_hash_result','declared_send_preflight','declared_queue_send']else(0 if allocfail else KMSG)if sym=='declared_kmsg_allocate'else a[0]if sym=='declared_byte_copy'else 0x123456789abcdef0 if sym=='opaque_keyed_hash_result'else c.get('preflight_status',0)if sym=='declared_send_preflight'else status
   assert int(m['return_value'],16)==expected and m['native_effects_executed']is False
   assert sym in['declared_kmsg_allocate','declared_byte_copy','opaque_keyed_hash_result','declared_send_preflight','declared_queue_send','declared_message_tag_helper','declared_destination_lock','declared_destination_unlock','declared_send_failure_helper','declared_message_destroy','declared_kmsg_buffer_free']
   if sym in['declared_message_tag_helper','declared_send_failure_helper','declared_kmsg_buffer_free']:assert a[0]==KMSG
   if sym=='declared_destination_lock':assert a[0]==DEST
   if sym=='declared_destination_unlock':assert a[0]==DEST+0x14
   want=[hex(((i+1)*0x123456789abcdef)^((k+1)*0x8b3dc651))for i in range(18)];want[0]=m['return_value'];assert m['after_registers31'][:18]==want and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0);counts['declared_API_result_and_clobber_oracles_checked']+=1
  for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_dynamic_original_instruction_recaptured']+=1
  totals.update(Replay(im,r).run());summaries.append({'case':j,'storage_class':cls,'visits':len(r['source_visits']),'helper_status_u32':expectedreturn,'copyin_output':accepted,'destroy_flag':destroyflag});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=52,functions=10,captured_instructions=1503)
 deps=[P+'_source.json',P+'_profiles.json','kernel_send_right_lifecycle_profiles.json','kernel_rpc_transport_contracts.json','replay_'+P+'.py','replay_kernel_send_right_lifecycle.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','replay_rpc502_vm_handoff.py','recover_kernel_send_right_lifecycle.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'shared_RPC_edges':shared,'fresh_notification_producer_replay':fresh_producer,'proofs':proofs,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
