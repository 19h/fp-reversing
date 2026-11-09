#!/usr/bin/env python3
"""Original host acquisition/release counters, notification packet and kext import.
O(image+source+visits+RAM), O(image+RAM+journals); three bounded bit-vector queries.
No native delivery, allocator retirement, lifetime balance or PAC proof is implied.
"""
import json,struct
from pathlib import Path
from collections import Counter
from z3 import BitVec,BitVecVal,ZeroExt,ULT,ULE,UGE,And,Not,Solver,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from replay_kernel_send_right_lifecycle import Replay
from replay_rpc502_vm_handoff import decode
P='kernel_send_right_lifecycle';R=0x6500000000;PORT=R+0x83000;PORT2=R+0x83800;NOTIFY=R+0xc0000;HOST=0xfffffe000cad0238;META=R+0x9c000;METABASE=META-(((R+0x68000)>>10)&0xffffffff0)
def val(b,o,n=4):return int.from_bytes(b[o:o+n],'little')
def obj(r,a=PORT):return bytes.fromhex(r['final_ports144_hex'][hex(a)])
def globals_of(r,key):return{e['address']:e['bytes_hex']for e in r[key]}
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());rows=prof['cases'];counts=Counter();totals=Counter();summaries=[];proofs=[]
 for o,s in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/s)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
  assert all(o[k]is False for k in FLAGS)
 assert len(rows)==22 and src['kernel_sha256']==im.k.sha256 and len(src['functions'])==8 and sum(len(f['instructions'])for f in src['functions'])==455
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 for e in src['exact_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for e in src['port_type_descriptors']:
  a=int(e['address'],16);assert im.k.read(a,40).hex()==e['bytes40_hex']and im.pointer(a)==e['name_pointer']and im.k.read(int(e['name_pointer']['target'],16),len(e['name'])+1)==e['name'].encode()+b'\0';counts['original_port_kind_records_checked']+=1
 assert src['port_type_descriptors'][1]['name']=='port'and src['port_type_descriptors'][1]['flags_u16']&0x20
 for e in src['SDK_definitions']:
  q=Path(e['path']);assert sha(q)==e['sha256']
  for line in e['selected_definitions']:assert q.read_text().splitlines()[line['line']-1]==line['text'];counts['SDK_definition_lines_recaptured']+=1
 sdk='\n'.join(e['text']for f in src['SDK_definitions']for e in f['selected_definitions']);assert 'MACH_MSG_TYPE_MOVE_SEND_ONCE    18'in sdk and 'MACH_NOTIFY_FIRST               0100'in sdk and 'MACH_NOTIFY_NO_SENDERS          (MACH_NOTIFY_FIRST + 006)'in sdk
 x=BitVec('word32',32);wide=ZeroExt(32,x)+1
 queries=[('host_slot_acceptance_u32',Not(ULT(x-37,BitVecVal((1<<32)-36,32))),And(UGE(x,1),ULE(x,36))),('copy_send_count_unsigned_limit_u32',wide==((wide<<31)>>31),ULE(x,0xfffffffe)),('object_ref_copy_biased_guard_u32',Not(ULE(x+0xf0000001,0xf0000001)),And(UGE(x,1),ULE(x,0x0ffffffe)))]
 for label,left,right in queries:
  s=Solver();s.add(left!=right);assert s.check()==unsat;proofs.append({'name':label,'query':s.sexpr(),'result':'unsat'});counts['bounded_u32_guard_proofs_unsat']+=1
 assert rows[0]['boundary']['registers31'][0]==hex(HOST)and not rows[0]['API_models'];counts['original_host_priv_global_identity_checked']=1
 for a,b,port,refs,send in[(1,2,PORT,3,2),(3,4,PORT2,5,1),(17,18,PORT,3,0xfffffffe)]:
  acq,rel=rows[a],rows[b];assert val(obj(acq,port),4)==refs+1 and val(obj(acq,port),0x88)==send+1 and acq['output_name_or_pointer_u64']==port and acq['boundary']['registers31'][0]=='0x0'
  assert val(obj(rel,port),4)==refs and val(obj(rel,port),0x88)==send and rel['notification_packet']is None
  assert decode(rel['initial_state_transfer'])==decode(acq['final_private_RAM'])and rel['initial_state_transfer']['case']==a and globals_of(rel,'initial_image_fixtures')==globals_of(acq,'final_image_globals');counts['original_acquire_release_counter_and_memory_pairs_checked']+=1
  assert acq['final_host_lock8_hex']==rel['final_host_lock8_hex']=='00'*8 and any(w['pc']=='0xfffffe000bcf25dc'for w in acq['source_writes'])and any(w['pc']=='0xfffffe000bcf2698'for w in acq['source_writes']);counts['original_host_atomic_lock_acquire_release_pairs_checked']+=1
 assert rows[5]['output_name_or_pointer_u64']==0 and rows[5]['boundary']['registers31'][0]=='0x0'and not rows[5]['API_models'];counts['empty_host_slot_success_with_NULL_checked']=1
 for j in[6,7]:assert rows[j]['boundary']['registers31'][0]=='0x4'and rows[j]['output_name_or_pointer_u64']==0xa5a5a5a5a5a5a5a5 and not rows[j]['API_models'];counts['host_invalid_slot_unchanged_output_checked']+=1
 for j in[8,9]:assert not rows[j]['API_models']and not any(int(w['address'],16)==PORT+0x88 for w in rows[j]['source_writes']);counts['NULL_dead_release_sentinel_checked']+=1
 assert val(obj(rows[10]),4)==2 and val(obj(rows[10]),0x88)==0 and rows[10]['notification_packet']is None;counts['last_send_without_request_checked']=1
 notify=rows[11];packet=notify['notification_packet'];want=struct.pack('<IIQQII8sI',18,0,NOTIFY,0,0,70,im.k.read(0xfffffe000ca92798,8),7)
 assert len(want)==44 and packet['bytes44_hex']==want.hex()and packet['arguments5']==[packet['address'],'0x2c','0x50001','0x0','0x0']and packet['call_site']=='0xfffffe000bcd0598'and notify['boundary']['pc']=='0xfffffe000bcf55dc';counts['original_no_senders_44byte_kernel_packet_checked']=1
 assert val(obj(notify),4)==2 and val(obj(notify),0x88)==0 and val(obj(notify),0x50,8)==0 and val(obj(notify,NOTIFY),4)==2 and val(obj(notify,NOTIFY),0x8c)==1;counts['request_extraction_clear_and_pending_send_once_scope_checked']=1
 dead=rows[12];assert val(obj(dead),0x50,8)==0 and val(obj(dead),4)==2 and val(obj(dead),0x88)==0 and val(obj(dead,NOTIFY),4)==1 and val(obj(dead,NOTIFY),0x8c)==0 and dead['notification_packet']is None and any(v['pc']=='0xfffffe000bcce494'for v in dead['source_visits']);counts['inactive_notification_original_send_once_release_checked']=1
 for j,pc,refs,send in[(13,'0xfffffe000bcc922c',0,0),(15,'0xfffffe000c629ddc',3,0xffffffff),(16,'0xfffffe000c641fa8',0xffffffff,0),(20,'0xfffffe000c629ddc',3,0)]:
  r=rows[j];assert r['boundary']['pc']==pc and val(obj(r),4)==refs and val(obj(r),0x88)==send and r['boundary']['kind']=='before_validation_or_final_retirement';counts['original_counter_guard_or_final_reference_frontiers_checked']+=1
 assert rows[20]['final_host_lock8_hex']==struct.pack('<Q',0x1234).hex();counts['nonreturning_overflow_keeps_unfinished_host_lock_epoch_checked']=1
 assert rows[19]['boundary']['kind']=='returned'and val(obj(rows[19]),0x88)==0x80000000 and val(obj(rows[19]),4)==4;counts['unsigned_send_count_crosses_signed32_boundary_checked']=1
 assert val(obj(rows[14]),4)==1 and val(obj(rows[14]),0x88)==0 and rows[14]['boundary']['kind']=='returned';counts['inactive_nonfinal_reference_release_checked']=1
 kext=json.loads((ROOT/'kext_vm_copyout_bridge_profiles.json').read_text())['cases'][7];r=rows[21];assert decode(r['initial_state_transfer'])==decode(kext['final_private_RAM'])and r['initial_state_transfer']['path']=='kext_vm_copyout_bridge_profiles.json'and r['initial_state_transfer']['case']==7
 assert r['entry_registers31']==kext['boundary']['registers31']and r['entry_SP']==kext['boundary']['SP']and r['entry_NZCV']==kext['boundary']['NZCV']and r['entry_Q_registers32']==kext['final_Q_registers32']
 inherited=kext['final_image_globals'];assert[{k:e[k]for k in['address','bytes_hex']}for e in r['initial_image_fixtures'][:len(inherited)]]==inherited
 assert[(e['address'],e['bytes_hex'])for e in r['initial_image_fixtures'][len(inherited):]]==[('0xfffffe0007e66e50',struct.pack('<QQ',R,R+0x100000).hex()),('0xfffffe0007e66f00',struct.pack('<Q',METABASE).hex())]and r['final_Q_registers32']==r['entry_Q_registers32']
 imports=r['port_object_imports'];assert len(imports)==1 and imports[0]['producer_case']==1 and imports[0]['bytes_hex']==rows[1]['final_ports144_hex'][hex(PORT)]and imports[0]['address']==hex(PORT)
 assert[(int(e['address'],16),len(e['bytes_hex'])//2)for e in r['initial_private_fixtures']]==[(PORT,144)]+[(METABASE+((a>>10)&0xffffffff0),2)for a in[PORT,PORT2,NOTIFY]];counts['kext_exact_CPU_RAM_base_and_explicit_acquired_object_import_checked']=1
 assert r['boundary']['kind']=='returned_to_actual_caller'and r['boundary']['pc']=='0xfffffe000a615f30'and r['boundary']['registers31'][18:]==r['entry_registers31'][18:]and r['boundary']['SP']==r['entry_SP']and val(obj(r),4)==3 and val(obj(r),0x88)==2;counts['original_kext_release_body_and_actual_caller_return_checked']=1
 for j,row in enumerate(rows):
  assert all(row[k]is False for k in FLAGS)
  for v in row['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_dynamic_original_instruction_recaptured']+=1
  for k,m in enumerate(row['API_models']):
   args=[int(x,16)for x in m['arguments8']];assert m['symbol']in['port_lock_model','port_unlock_model']and args[0]in[PORT+0x14,PORT2+0x14,NOTIFY+0x14]and m['return_value']=='0x0'
   if m['symbol']=='port_lock_model':assert args[1]==0xfffffe0007e66e08
   want=[hex(((i+1)*0x123456789abcdef)^((k+1)*0x8b3dc651))for i in range(18)];want[0]='0x0';assert m['after_registers31'][:18]==want and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0)and m['native_effects_executed']is False;counts['declared_lock_ABI_and_volatile_clobber_models_checked']+=1
  totals.update(Replay(im,row).run());summaries.append({'case':j,'phase':row['configuration']['phase'],'visits':len(row['source_visits']),'boundary':row['boundary']['kind']});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=22,functions=8,captured_instructions=455)
 deps=[P+'_source.json',P+'_profiles.json','kext_vm_copyout_bridge_profiles.json','replay_'+P+'.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','replay_rpc502_vm_handoff.py','recover_kernel_send_right_lifecycle.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'proofs':proofs,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
