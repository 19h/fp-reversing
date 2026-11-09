#!/usr/bin/env python3
"""Independent original adapter/factory, complete type3 object/backing/caller and
RPC queue validation. O(image+source+visits+RAM+effects), O(image+RAM+journals).
Two scalar proofs; raw allocation/map byte effects and PAC remain conditional.
"""
import json,struct
from collections import Counter
from z3 import BitVec,Solver,And,UGE,ULE,Or,Not,LShR,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from replay_rpc502_vm_handoff import decode
from replay_kernel_request_copyin import Replay
from replay_kernel_rpc_request import Replay as EnvironmentReplay
from validate_kernel_rpc_request import check_overlays
from validate_kernel_special_reply import gbytes,gput
P='kernel_request_copyin';B=0x6500000000;SIZE=0x100000;THREAD=B+0x60000;HEADER=B+0x88010;BACK=B+0x8c000;KMAP=B+0x84000;IMAP=B+0x85000;STAGING=B+0x70000;KMSG=B+0xd0000;D0=B+0xc0070;D1=B+0xc0100;REP=B+0x80070;TS=B+0xa8040;ZSTATS=B+0x50000

def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def put(b,o,n,v):b[o:o+n]=v.to_bytes(n,'little')
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());prior=json.loads((ROOT/'kernel_rpc_request_profiles.json').read_text());counts=Counter();totals=Counter();fresh=Counter();proofs=[];summaries=[]
 for obj,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 assert src['kernel_sha256']==im.k.sha256
 for f in src['functions']:
  a=int(f['start'],16);raw=im.k.read(a,int(f['end'],16)-a);assert raw.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]==f['instructions'];counts['complete_functions_recaptured']+=1
 for e in src['request_copyin_roles'].values():
  a=int(e['pc'],16);i=next(im.k.cs.disasm(im.k.read(a,4),a));assert e=={'pc':hex(a),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str};counts['copyin_instruction_roles_recaptured']+=1
 ad=src['vm_copyin_adapter'];assert im.k.read(int(ad['adapter'],16),8).hex()==ad['adapter_bytes8_hex']and im.k.read(int(ad['stub'],16),16).hex()==ad['stub_bytes16_hex']and im.pointer(0xfffffe000847c560)==ad['pointer']and ad['pointer']['target']=='0xfffffe000bdd1594'and im.k.symbols([0xfffffe000bdd1594])['0xfffffe000bdd1594']==ad['target_symbols'];counts['original_adapter_stub_chained_slot_and_export_binding_checked']=1
 assert src['copy_policy_file']['bytes4_hex']==im.k.read(0xfffffe0007e6a01c,4).hex()=='02000000'and src['copy_zone_file']['bytes192_hex']==im.k.read(0xfffffe000caec2c0,192).hex()=='00'*192 and src['copy_zone_file']['creation_caller_established']is False;counts['original_policy2_and_file_zero_class19_view_checked']=1
 assert len(prof['cases'])==4
 for j,(r,index)in enumerate(zip(prof['cases'],[4,10,15,21],strict=True)):
  env=prior['environment'][index];old=prior['requests'][j];fresh.update(EnvironmentReplay(im,env).run());c=old['configuration'];ram=decode(env['final_private_RAM']);gl=env['final_image_globals'];assert r['configuration']==c and r['family']==j and r['kind']=='constructor_VM_copyin_RPC_request'and r['initial_state_transfer']['path']=='kernel_rpc_request_profiles.json'and r['initial_state_transfer']['environment']==index and decode(r['initial_state_transfer'])==ram
  name=bytes(0x21+k%90 for k in range(28))+b'\0';plan=[('private',B+0x90000,name),('private',B+0x81000,b'\xa5'*8),('private',STAGING,b'\xa5'*0x10001)]+[('global',a,b)for a,b in[(0xfffffe000ccca078,b'\1'),(0xfffffe000cccca58,bytes(8)),(0xfffffe0007efa630,struct.pack('<Q',IMAP)),(0xfffffe0007f860a8,struct.pack('<Q',KMAP)),(0xfffffe0007e6d9c0,struct.pack('<I',14))]];assert r['VM_environment_overlay_start']==len(plan)==8
  for at in[KMAP,IMAP]:
   mb=bytearray(1024);put(mb,0x10,8,B);put(mb,0x18,8,B+SIZE);put(mb,0x2c,4,14);put(mb,0x88,4,3);plan.append(('private',at,bytes(mb)))
  meta=val(gbytes(im,gl,0xfffffe0007e66f00,8),0)
  plan.extend(('private',a,b)for a,b in[(HEADER,bytes(48)),(HEADER+48,b'\xa5'),(BACK,b'\xa5'*29),(BACK+29,b'\xa5'),(THREAD+0x428,struct.pack('<Q',KMAP)),(meta+((IMAP>>10)&0xffffffff0),struct.pack('<H',16)),(meta+((HEADER>>10)&0xffffffff0),struct.pack('<H',19))]);plan.append(('global',0xfffffe000caec2c0,struct.pack('<QQ',0xfffffe000caec2c0,ZSTATS)));initial,initialgl=check_overlays(im,r,ram,gl,plan,counts);assert r['VM_policy_initial_u32_bytes']=='02000000'and all(int(e['address'],16)!=0xfffffe0007e6a01c for e in r['input_overlays']);counts['unmodified_file_policy_and_independent_context_oracles_checked']+=1
  assert (HEADER>>14)!=(IMAP>>14)and(IMAP>>14)==(KMAP>>14)and BACK+29<B+0x90000 and HEADER+49<BACK;counts['disjoint_copy_map_type_cells_and_live_observation_regions_checked']+=1
  expected=bytearray(48);put(expected,0,8,BACK);put(expected,0x20,8,29);put(expected,0x2d,1,3);assert r['VM_final_copy48_hex']==expected.hex()and r['VM_final_backing_hex']==name.hex()and r['VM_copy_guard_hex']=='a5'and r['VM_backing_guard_hex']=='a5';counts['independent_complete_original_type3_header_and_backing_oracles_checked']+=1
  frames={e['pc']:e for e in r['VM_copyin_frames']};assert r['VM_actual_caller_return_PC']=='0xfffffe000a60b784'and frames['0xfffffe000a508e2c']['arguments8'][:4]==[hex(IMAP),hex(STAGING),'0x1d','0x0']and frames['0xfffffe000bdd1594']['arguments8'][:4]==[hex(IMAP),hex(STAGING),'0x1d','0x0'];outptr=int(r['VM_copy_output_address'],16)
  ret=frames['0xfffffe000a60b784'];assert ret['arguments8'][0]=='0x0'and ret['copy48_hex']==expected.hex()and ret['backing_hex']==name.hex()and ret['published_pointer_hex']==struct.pack('<Q',HEADER).hex();hs=r['VM_full_CPU_RAM_handoffs'];assert len(hs)==4 and[hd['pc']for hd in hs]==['0xfffffe000a508e2c','0xfffffe000bdd1f38','0xfffffe000a60b784','0xfffffe000bcf5e28'];api,publication,returning,rpc=hs;assert api['SP']==returning['SP']and all(api['registers31'][k]==returning['registers31'][k]for k in range(18,30))and api['registers31'][30]=='0xfffffe000a60b784'and returning['registers31'][30]=='0xfffffe000a60b784'and val(decode(returning['private_RAM']),outptr-B)==HEADER;counts['original_export_factory_publication_actual_caller_return_and_ABI_checked']+=1
  oldhandoff=bytearray.fromhex(old['continuous_constructor_handoff']['message88_hex']);put(oldhandoff,36,8,HEADER);assert r['continuous_constructor_handoff']['message88_hex']==oldhandoff.hex();packetframe=next(e for e in r['VM_full_CPU_RAM_handoffs']if e['pc']=='0xfffffe000bcf5e28');assert decode(packetframe['private_RAM'])[HEADER-B:HEADER-B+48]==expected and decode(packetframe['private_RAM'])[BACK-B:BACK-B+29]==name;counts['source_produced_copy_object_forwarded_into_original_RPC_packet_checked']+=1
  final=decode(r['final_private_RAM']);oldfinal=decode(old['final_private_RAM']);wantkmsg=bytearray(oldfinal[KMSG-B:KMSG-B+256]);put(wantkmsg,0x64,8,HEADER);wantthread=bytearray(oldfinal[THREAD-B:THREAD-B+1536]);put(wantthread,0x428,8,KMAP)
  for a,b in[(KMSG,wantkmsg),(THREAD,wantthread),(HEADER,expected),(BACK,name)]:assert final[a-B:a-B+len(b)]==b;counts['independent_complete_factory_thread_and_queued_packet_oracles_checked']+=1
  for a,n in[(D0,144),(D1,144),(REP,144),(TS,96),(B+0x58000,32)]:assert final[a-B:a-B+n]==oldfinal[a-B:a-B+n]
  assert r['final_image_globals']==gput(old['final_image_globals'],0xfffffe000caec2c0,struct.pack('<QQ',0xfffffe000caec2c0,ZSTATS))and r['boundary']['kind']=='before_original_common_RPC_receive'and r['boundary']['pc']=='0xfffffe000bcc83b4';counts['original_port_right_queue_accounting_and_receive_frontier_preserved']+=1
  assert len(r['VM_raw_storage_contracts'])==2 and[rw['returned_pointer']for rw in r['VM_raw_storage_contracts']]==[hex(BACK),hex(HEADER)]and r['VM_raw_storage_contracts'][0]['object_before_hex']=='a5'*29 and r['VM_raw_storage_contracts'][1]['object_before_hex']=='00'*48
  raw=r['VM_raw_storage_contracts'];assert raw[0]['arguments4']==['0xfffffe0007f8bfb0','0x1d','0x0','0x0']and raw[1]['arguments4'][:3]==['0xfffffe000caec2c0',hex(ZSTATS),'0x4'];assert len(r['VM_lower_copy_contracts'])==1 and r['VM_lower_copy_contracts'][0]['arguments5']==[hex(IMAP),hex(STAGING),hex(BACK),'0x1d','0x1']and r['VM_lower_copy_contracts'][0]['source_hex']==name.hex();counts['raw_backing_header_and_lower_map_copy_ABI_contracts_checked']+=1
  syms=Counter(m['symbol']for m in r['API_models']);assert syms['vm_map_copyin_model']==0 and syms['declared_raw_copy_backing_storage']==1 and syms['declared_raw_copy_header_storage']==1 and syms['declared_copyin_map_byte_effect']==1 and len(r['API_models'])==17-int(c['prebound_reply'])
  pcs=Counter(v['pc']for v in r['source_visits']);assert all(pcs[a]==1 for a in['0xfffffe000a508e2c','0xfffffe000a69f464','0xfffffe000bdd1594','0xfffffe000bdd15a4','0xfffffe000bdd1f38','0xfffffe000a60b784'])and pcs['0xfffffe000bdd16dc']==0 and pcs['0xfffffe000be318e8']==0;counts['whole_copyin_model_removed_original_adapter_factory_and_return_executed']=counts.get('whole_copyin_model_removed_original_adapter_factory_and_return_executed',0)+1
  allowed=set(m['symbol']for m in old['API_models'])-{'vm_map_copyin_model'}|{'declared_raw_copy_backing_storage','declared_raw_copy_header_storage','declared_copyin_map_byte_effect'}
  for ordinal,m in enumerate(r['API_models'],1):
   assert m['symbol']in allowed and m['native_effects_executed']is False and m['after_registers31'][0]==m['return_value']and m['after_NZCV']==('0xf0000000'if ordinal&1 else'0x0')
   for k in range(1,18):assert int(m['after_registers31'][k],16)==(((k+1)*0x123456789abcdef)^ordinal*0x8b3dc651)&((1<<64)-1)
   counts['bounded_primitive_models_and_volatile_clobbers_checked']+=1
  for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['all_original_instruction_visits_recaptured']+=1
  totals.update(Replay(im,r).run());summaries.append({'case':j,'rpc_id':502 if c['mode']==1 else 700,'prebound_reply':c['prebound_reply'],'source_visits':len(r['source_visits']),'copy_type':3,'copy_extent_bytes':29,'copy_pointer':hex(HEADER),'backing_pointer':hex(BACK),'actual_VM_caller_return':r['VM_actual_caller_return_PC'],'boundary':r['boundary']['pc']});print(json.dumps({'case':j,'independent_replay':'pass','visits':len(r['source_visits'])}),flush=True)
 length=BitVec('string_length_u32',32);base=BitVec('source_base_u64',64);size=BitVec('source_extent_u64',64);end=base+size
 queries=[('string_plus_NUL_extent_no_u32_wrap_in_small_copy_domain',ULE(length,32767),And(UGE(length+1,1),ULE(length+1,32768))),('page_rounded_small_copy_interval_contains_original_bytes',And(UGE(base,B),ULE(base,B+SIZE-32768),UGE(size,1),ULE(size,32768)),And(ULE(base&~0x3fff,base),UGE((end+0x3fff)&~0x3fff,end),UGE((end+0x3fff)&~0x3fff,base&~0x3fff)))]
 for name,domain,claim in queries:
  s=Solver();s.add(domain,Not(claim));assert s.check()==unsat;proofs.append({'name':name,'domain':str(domain),'query':s.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1
 counts.update(cases=4,functions=len(src['functions']),captured_instructions=sum(len(f['instructions'])for f in src['functions']))
 deps=[P+'_source.json',P+'_profiles.json','kernel_rpc_request_profiles.json','replay_'+P+'.py','replay_kernel_rpc_request.py','replay_kext_constructor_request.py','replay_kernel_vm_mig.py','validate_kernel_rpc_request.py','validate_kernel_special_reply.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_environment_replays':dict(fresh),'case_summaries':summaries,'proofs':proofs,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_environment_replays':dict(fresh),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
