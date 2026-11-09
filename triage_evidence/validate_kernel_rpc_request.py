#!/usr/bin/env python3
"""Original source recapture, independent fixture/ABI/reference/packet oracles,
fresh complete-state CPU replay and two scalar identities. O(image+source+
visits+RAM+effects), O(image+RAM+journals); fixed-width SMT domains recorded.
No native IPC, VM, scheduler, allocator backing or PAC effects are inferred.
"""
import json,struct
from collections import Counter
from z3 import BitVec,Solver,unsat,If,Extract,ZeroExt
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from replay_rpc502_vm_handoff import decode
from replay_kernel_rpc_request import Replay
from replay_kernel_zone_startup import Replay as ZoneReplay
from validate_kernel_special_reply import gbytes,gput
P='kernel_rpc_request';B=0x6500000000;SIZE=0x100000;THREAD=B+0x60000;OWNER=B+0x5c000;TASK=B+0x987c0;STATS=B+0x58000;CPU_DATA=B+0xb4000;D0=B+0xc0070;D1=B+0xc0100;REP=B+0x80070;TS=B+0xa8040;KMSG=B+0xd0000;KS=B+0x54000;RS=B+0x54100;SERVER=B+0xdd000;TABLE=0x400000100000;HOST=0xfffffe000cad0238;META=(B+0x9c000-((KMSG>>10)&0xffffffff0))&((1<<64)-1);ARRAY=0xfffffe000caeb480

def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def put(b,o,n,v):b[o:o+n]=v.to_bytes(n,'little')
def rec(r,a,n):return decode(r['final_private_RAM'])[a-B:a-B+n]
def bootstrap_plan(zones):
 th=bytearray(1536)
 for o,n,v in[(0xb0,8,17),(0x1c0,8,CPU_DATA),(0x1f8,4,4),(0x420,8,OWNER),(0x518,4,0x1234),(0x43b,1,17)]:put(th,o,n,v)
 own=bytearray(56);put(own,0,8,THREAD);put(own,0x28,8,TASK);tb=bytearray(4096)
 for idx,port in[(3,D0),(4,D1)]:put(tb,idx*24,8,port);put(tb,idx*24+8,4,0x20001)
 plan=[('private',a,b)for a,b in[(THREAD,bytes(th)),(OWNER,bytes(own)),(TASK-0x7c0,bytes(0xe90)),(TASK+0x318,struct.pack('<Q',KS)),(TASK+0x3d0,struct.pack('<Q',STATS)),(STATS,bytes(32)),(CPU_DATA,bytes(0x300)),(D0,bytes(144)),(D1,bytes(144)),(REP,bytes(144)),(TS,bytes(96)),(KS,bytes(128)),(RS,bytes(128)),(SERVER,bytes(128)),(SERVER+0x48,struct.pack('<Q',TABLE|5)),(KMSG,bytes(256)),(KMSG+256,b'\xa5')]]
 for a,typ in[(D0,22),(D1,22),(REP,22),(TS,28),(KMSG,24),(OWNER,3),(TASK-0x7c0,26),(KS,40),(SERVER,40)]:plan.append(('private',META+((a>>10)&0xffffffff0),struct.pack('<H',typ)))
 for z in zones:
  plan.extend(('private',int(e['address'],16),bytes.fromhex(e['bytes_hex']))for e in z['source_private_regions']);plan.append(('global',int(z['zone_address'],16),bytes.fromhex(z['final_zone192_hex'])))
 plan.extend([('private',B+0x4d004,struct.pack('<H',1)),('private',B+0x4e010,struct.pack('<Q',KMSG))])
 plan.extend(('global',a,b)for a,b in[(0xfffffe0007e66e50,struct.pack('<QQ',B,B+SIZE)),(0xfffffe0007e66f00,struct.pack('<Q',META)),(0xfffffe0007e66ea0,struct.pack('<QQ',B,B+SIZE)),(0xfffffe0007e6d038,struct.pack('<I',0x40000)),(0xfffffe0007e5c470,struct.pack('<Q',ARRAY+192*40)),(0xfffffe0007e62b68,bytes(8)),(0xfffffe0007e63348,bytes(8)),(0xfffffe0007e5c221,bytes(1)),(HOST+8,bytes(8)),(HOST+0x10+17*8,struct.pack('<Q',D0)),(HOST+0x10+34*8,struct.pack('<Q',D1)),(TABLE,bytes(tb))]);return plan

def check_overlays(im,r,ram,gl,plan,counts):
 initial=bytearray(ram);gl=[dict(e)for e in gl];assert len(r['input_overlays'])==len(plan)
 for (space,a,b),e in zip(plan,r['input_overlays'],strict=True):
  assert e['space']==space and e['address']==hex(a)and e['after_hex']==b.hex();before=initial[a-B:a-B+len(b)]if space=='private'else gbytes(im,gl,a,len(b));assert e['before_hex']==before.hex()
  if space=='private':initial[a-B:a-B+len(b)]=b
  else:gl=gput(gl,a,b)
  counts['ordered_fixture_and_source_import_before_images_checked']+=1
 assert r['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for space,a,b in plan if space=='private']and r['initial_image_fixtures']==gl;return bytes(initial),gl

def check_models(r,counts):
 allowed={'declared_raw_special_space_storage','declared_raw_reply_port_storage','declared_raw_turnstile_storage','opaque_keyed_hash_result','declared_send_preflight','declared_message_tag_helper','aligned_allocation_model','allocation_model','strlen_model','kmem_alloc_model','memcpy_model','declared_byte_copy','vm_map_copyin_model'}
 for ordinal,m in enumerate(r['API_models'],1):
  assert m['symbol']in allowed and m['native_effects_executed']is False
  for j in range(1,18):assert int(m['after_registers31'][j],16)==(((j+1)*0x123456789abcdef)^ordinal*0x8b3dc651)&((1<<64)-1)
  assert m['after_NZCV']==('0xf0000000'if ordinal&1 else'0x0')and m['after_registers31'][0]==m['return_value']
  if m['symbol']=='opaque_keyed_hash_result':assert m['return_value']=='0x123456789abcdef0'
  if m['symbol']in['declared_send_preflight','declared_message_tag_helper']:assert m['return_value']=='0x0'
  if m['symbol']=='declared_byte_copy':
   assert m['pc']=='0xfffffe000c647f10'and len(m['memory_effects'])==1;e=m['memory_effects'][0];assert e['address']==m['arguments8'][0]and len(e['after_hex'])//2==int(m['arguments8'][2],16)and m['return_value']==m['arguments8'][0]
  counts['explicit_primitive_model_contracts_and_clobbers_checked']+=1

def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());ctors=json.loads((ROOT/'kext_constructor_request_profiles.json').read_text());counts=Counter();totals=Counter();summaries=[];proofs=[]
 for obj,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 assert src['kernel_sha256']==im.k.sha256 and im.k.read(0xfffffe0007e62b68,8)==bytes(8)and im.k.read(0xfffffe0007e63348,8)==bytes(8)
 for f in src['functions']:
  a=int(f['start'],16);raw=im.k.read(a,int(f['end'],16)-a);assert raw.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]==f['instructions'];counts['complete_functions_independently_recaptured']+=1
 for e in src['rpc_request_instruction_roles'].values():
  a=int(e['pc'],16);i=next(im.k.cs.disasm(im.k.read(a,4),a));assert e=={'pc':hex(a),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str};counts['request_instruction_roles_recaptured']+=1
 zones=prof['zone_producers'];assert len(zones)==4
 for z,name,ident,base in zip(zones,['ipc ports','turnstiles','ipc spaces','ipc kmsgs'],[22,28,40,24],[B+0x40000,B+0x44000,B+0x48000,B+0x4c000],strict=True):
  spec=next(e for e in src['rpc_zone_entries']if e['name']==name);assert im.k.read(int(spec['entry_address'],16),24).hex()==spec['entry_bytes24_hex']and im.k.read(int(spec['specification_address'],16),48).hex()==spec['specification_bytes48_hex']and im.pointer(int(spec['name_pointer']['slot'],16))==spec['name_pointer'];size=spec['requested_size_u64'];zone=ARRAY+ident*192;want=bytearray(192);rp=((1<<32)+size-1)//size;cache=ident in[22,24]
  for o,n,v in[(0,8,zone),(8,8,base),(16,8,int(spec['name_pointer']['target'],16)),(0x28,4,rp),(0x30,4,rp),(0x34,2,size),(0x36,2,16384%size),(0x38,2,1),(0x3a,2,16384//size)]:put(want,o,n,v)
  if cache:put(want,0x40,8,base+0x1000);put(want,0x7e,2,0x100000//(16*size))
  if ident==40:
   for o,n,v in[(0x3c,4,0x400),(0x58,8,zone+0x50),(0x60,4,0x144),(0x80,4,0x144),(0x84,4,0xffffffff)]:put(want,o,n,v)
  assert z['final_zone192_hex']==want.hex()and z['zone_address']==hex(zone)and z['identifier']==ident and z['boundary']['kind']=='startup_callback_returned'
  expected=[(base,bytes(32))]
  if cache:
   cb=bytearray(64)
   for o,n,v in[(0,4,0x144),(8,8,base+0x2010),(16,8,base+0x2110),(0x28,8,base+0x1020)]:put(cb,o,n,v)
   expected.extend([(base+0x1000,bytes(cb)),(base+0x2000,bytes(144)),(base+0x2100,bytes(144))])
  assert [(int(e['address'],16),bytes.fromhex(e['bytes_hex']))for e in z['source_private_regions']]==expected;counts['complete_startup_zone_and_regional_record_oracles_checked']+=1;totals.update(ZoneReplay(im,z).run())
 assert len(prof['environment'])==22 and len(prof['requests'])==4;ei=0
 for family,(mode,prebound)in enumerate([(1,False),(1,True),(0,False),(0,True)]):
  c={'page_shift':14,'length':28,'cpu_type':0x100000c,'cpu_subtype':0,'origin':1,'mode':mode,'prebound_reply':prebound};ram=bytes(SIZE);gl=[];origin={'path':'explicit_zero_RAM','case':None}
  for kind in ['bootstrap','dest_init0','dest_unlock0','dest_init1','dest_unlock1']+(['reply_create']if prebound else[]):
   r=prof['environment'][ei];assert r['family']==family and r['kind']==kind and r['configuration']==c and decode(r['initial_state_transfer'])==ram and all(r['initial_state_transfer'][k]==v for k,v in origin.items());initial,initialgl=check_overlays(im,r,ram,gl,bootstrap_plan(zones)if kind=='bootstrap'else[],counts)
   args=[];entry=0xfffffe000c629780
   if kind.startswith('dest_init'):entry=0xfffffe000bccd170;args=[D0 if kind.endswith('0')else D1,SERVER,0x101,0,0,0x303 if kind.endswith('0')else 0x403]
   elif kind.startswith('dest_unlock'):entry=0xfffffe000bd0ab18;args=[(D0 if kind.endswith('0')else D1)+0x14]
   elif kind=='reply_create':entry=0xfffffe000bcf8e14
   regs=['0x0']*31
   for j,v in enumerate(args):regs[j]=hex(v)
   regs[30]=hex(B+0xe0000);assert r['entry_PC']==hex(entry)and r['entry_SP']==hex(B+0xe8000)and r['entry_registers31']==regs and r['entry_DAIF_mask']=='0x3c0'and r['current_thread']==hex(THREAD);counts['explicit_environment_call_ABIs_and_full_RAM_origins_checked']+=1
   assert all(r[k]is False for k in FLAGS);check_models(r,counts);totals.update(Replay(im,r).run());ram=decode(r['final_private_RAM']);gl=r['final_image_globals'];origin={'path':P+'_profiles.json','environment':ei};ei+=1
  # Independent destination object oracle after source init and unlock.
  for a,name in[(D0,0x303),(D1,0x403)]:
   want=bytearray(144)
   for o,n,v in[(0,4,0x101),(4,4,1),(0x10,4,0xc000b),(0x14,4,0x01010144),(0x34,4,name),(0x3a,2,5),(0x48,8,SERVER)]:put(want,o,n,v)
   assert ram[a-B:a-B+144]==want;counts['complete_original_service_port_initialization_oracles_checked']+=1
  space=bytearray(128);space[:8]=im.k.read(0xfffffe000700dc58,8);put(space,8,4,0x144);space[12:20]=im.k.read(0xfffffe000700dc60,8);put(space,0x58,8,16);put(space,0x68,4,3)
  assert ram[KS-B:KS-B+128]==space and ram[RS-B:RS-B+128]==space and val(gbytes(im,gl,0xfffffe0007e62b68,8),0)==KS and val(gbytes(im,gl,0xfffffe0007e63348,8),0)==RS;counts['complete_special_space_bootstrap_and_publication_oracles_checked']+=1
  r=prof['requests'][family];assert r['configuration']==c and r['family']==family and r['kind']=='constructor_RPC_request'and decode(r['initial_state_transfer'])==ram and all(r['initial_state_transfer'][k]==v for k,v in origin.items())and all(r[k]is False for k in FLAGS)
  plan=[('private',B+0x90000,bytes(0x21+j%90 for j in range(28))+b'\0'),('private',B+0x81000,b'\xa5'*8),('private',B+0x70000,b'\xa5'*0x10001)]+[('global',a,b)for a,b in[(0xfffffe000ccca078,b'\1'),(0xfffffe000cccca58,bytes(8)),(0xfffffe0007efa630,struct.pack('<Q',B+0x85000)),(0xfffffe0007f860a8,struct.pack('<Q',B+0x84000)),(0xfffffe0007e6d9c0,struct.pack('<I',14))]]
  check_overlays(im,r,ram,gl,plan,counts);check_models(r,counts);dest=D0 if mode else D1;mid=502 if mode else 700;name=0x303 if mode else 0x403;frames={e['pc']:e for e in r['request_frames']};h=r['continuous_constructor_handoff'];packet=bytes.fromhex(h['message88_hex']);prior=next(x for x in ctors['cases']if x['configuration']=={k:v for k,v in c.items()if k!='prebound_reply'});wantpacket=bytearray.fromhex(prior['message88_hex']);put(wantpacket,8,8,dest);assert packet==wantpacket and val(packet,0,4)==0x80001513 and val(packet,4,4)==0 and val(packet,16)==0 and val(packet,28,4)==mid and h['handoff_overlays']==[];counts['independent_original_constructor_packet_equivalence_checked']+=1
  assert frames['0xfffffe000bcf258c']['arguments8'][:3]==[hex(HOST),'0xffffffff','0x11'if mode else'0x22']and frames['0xfffffe000bcc68c4']['arguments8'][:3]==[h['message_address'],'0x58','0x2000000000']and frames['0xfffffe000bcc7040']['arguments8'][:3]==[hex(KMSG),'0x10001','0x0']and frames['0xfffffe000bcc7c34']['arguments8'][:4]==[hex(dest+0x28),hex(KMSG),'0x10001','0x0'];counts['original_host_slot_allocator_prep_send_queue_ABIs_checked']+=1
  # Host helper acquires one send reference; COPY_SEND and two object holds follow.
  at_rpc=frames['0xfffffe000bcf59e0'];pd=bytes.fromhex(at_rpc['destination0_144_hex'if mode else'destination1_144_hex']);assert val(pd,4,4)==2 and val(pd,0x88,4)==1
  mainpcs=Counter(v['pc']for v in r['source_visits']);assert mainpcs['0xfffffe000bcf8e14']==int(not prebound)and mainpcs['0xfffffe000bcc24a4']==1 and mainpcs['0xfffffe000bd75c64']==1 and mainpcs['0xfffffe000bcd00bc']==1 and mainpcs['0xfffffe000bcd0628']==1 and mainpcs['0xfffffe000bd57150']==1 and mainpcs['0xfffffe000bcd9e98']==1 and mainpcs['0xfffffe000bcd8264']==1;counts['original_host_reference_voucher_and_reply_creation_or_reuse_paths_checked']+=1
  final=decode(r['final_private_RAM']);want=bytearray(144)
  for o,n,v in[(0,4,0x101),(4,4,5),(0x10,4,0xc000b),(0x14,4,0x07070144),(0x28,8,KMSG),(0x34,4,name),(0x38,2,1),(0x3a,2,5),(0x48,8,SERVER),(0x70,8,TS),(0x88,4,2)]:put(want,o,n,v)
  assert final[dest-B:dest-B+144]==want;other=D1 if mode else D0;assert final[other-B:other-B+144]==ram[other-B:other-B+144]
  reply=bytearray(144)
  for o,n,v in[(0,4,0x20b),(4,4,2),(0x10,4,0xc100b),(0x14,4,0x03030144),(0x34,4,1),(0x3a,2,5),(0x40,8,THREAD),(0x48,8,RS),(0x58,8,dest),(0x8c,4,1)]:put(reply,o,n,v)
  ts=bytearray(96)
  for o,n,v in[(0,4,2),(4,4,0x02020144),(0x48,8,dest),(0x50,4,1),(0x54,4,0x204),(0x58,4,1)]:put(ts,o,n,v)
  assert final[REP-B:REP-B+144]==reply and final[TS-B:TS-B+96]==ts;counts['independent_complete_destination_reply_and_turnstile_oracles_checked']+=1
  kh=bytearray(packet);put(kh,0,4,0x80111211);put(kh,4,4,88);put(kh,16,8,REP);km=bytearray(256);km[0x40:0x98]=kh
  for o,n,v in[(0,8,KMSG),(8,8,KMSG),(0x38,4,0x12345678),(0x3f,1,0x11),(0x9c,4,8),(0xa8,4,1)]:put(km,o,n,v)
  assert final[KMSG-B:KMSG-B+256]==km and final[KMSG-B+256]==0xa5 and final[STATS-B:STATS-B+32]==b'\1'+bytes(31)and final[B+0x4c000-B:B+0x4c000-B+32]==struct.pack('<Q',256)+bytes(24);counts['independent_complete_queued_kmsg_and_accounting_oracles_checked']+=1
  th=final[THREAD-B:THREAD-B+1536];assert val(th,0x3f0)==REP and val(th,0x1c8,4)==0 and val(th,0x388,4)==0xffffffff and val(th,0x448)==0 and val(th,0x4b0)==0 and val(th,0x5a0)==0
  b=r['boundary'];assert b['kind']=='before_original_common_RPC_receive'and b['pc']=='0xfffffe000bcc83b4'and b['registers31'][:5]==[hex(REP+0x10),'0x0','0x1',hex(THREAD),'0x0']and b['registers31'][30]=='0xfffffe000bcf5c48';counts['original_receive_frontier_and_thread_state_ABIs_checked']+=1
  raw=r['raw_storage_contracts'];assert len(raw)==1+int(not prebound)
  for e in raw:
   a=int(e['returned_pointer'],16);ident=22 if a==REP else 28;stats=B+0x40000 if a==REP else B+0x44000;extent=144 if a==REP else 96;assert e['arguments4'][:3]==[hex(ARRAY+192*ident),hex(stats),'0x8004']and e['object_before_hex']=='00'*extent
  syms=Counter(m['symbol']for m in r['API_models']);assert syms['allocation_model']==3 and syms['opaque_keyed_hash_result']==2 and syms['declared_send_preflight']==1 and syms['declared_message_tag_helper']==1 and syms['declared_raw_reply_port_storage']==int(not prebound)and syms['declared_raw_turnstile_storage']==1 and len(r['API_models'])==14+int(not prebound);counts['bounded_remaining_primitive_models_checked']+=1
  totals.update(Replay(im,r).run());summaries.append({'family':family,'rpc_id':mid,'host_slot':17 if mode else 34,'prebound_reply':prebound,'source_visits':len(r['source_visits']),'destination_refs':5,'destination_send_rights':2,'reply_refs':2,'reply_send_once_rights':1,'queued_count':1,'boundary':b['pc']});print(json.dumps({'family':family,'independent_replay':'pass','visits':len(r['source_visits'])}),flush=True)
 assert ei==22
 # Scalar domains are separate from the finite CPU executions.
 word=BitVec('caller_mode_u64',64);bits=BitVec('header_bits_u32',32);queries=[('mode_partition_uses_low32',If(Extract(31,0,word)==1,502,700),If((word&0xffffffff)==1,502,700)),('local_disposition_insertion_preserves_remote_byte',Extract(7,0,bits|0x00111500),Extract(7,0,bits))]
 for name,left,right in queries:
  s=Solver();s.add(left!=right);assert s.check()==unsat;proofs.append({'name':name,'domain':'all u64 modes'if name.startswith('mode')else'all u32 headers','query':s.sexpr(),'result':'unsat'});counts['scalar_proofs_unsat']+=1
 for r in prof['environment']+prof['requests']:
  for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['main_original_instruction_visits_recaptured']+=1
 counts.update(zone_producers=4,environment_components=22,request_cases=4,functions=len(src['functions']),captured_instructions=sum(len(f['instructions'])for f in src['functions']))
 deps=[P+'_source.json',P+'_profiles.json','kext_constructor_request_profiles.json','replay_'+P+'.py','replay_kext_constructor_request.py','replay_kernel_vm_mig.py','replay_kernel_zone_startup.py','validate_kernel_special_reply.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'family_summaries':summaries,'proofs':proofs,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
