#!/usr/bin/env python3
"""Independent reply-right namespace provenance, record, generation and ABI checks.
O(image+source+visits+RAM+effects), O(image+RAM+journals), four scalar SMT queries.
Private namespace/port/type epochs, packet representation and logical PAC remain
premises; no native IPC, namespace, VM, protected copyout or retirement executes.
"""
import json,struct
from collections import Counter
from z3 import BitVec,Int,ZeroExt,LShR,ULE,UGE,Solver,And,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from replay_rpc502_vm_handoff import decode
from replay_kernel_reply_namespace import Replay
from replay_kernel_zone_startup import Replay as ZoneReplay
from replay_kernel_receive_copyout import Replay as ReceiveReplay
from replay_kext_constructor_request import Replay as ConstructorReplay
P='kernel_reply_namespace';B=0x6500000000;SIZE=0x100000;RECV=B+0x60000;PORT=B+0xc0000;SPACE=B+0xdd000;TABLE=0x400000100000;REPLY=B+0x80070;TASK=B+0x74000;FOREIGN=B+0x88000;OWNER=B+0x8c000;KMSG=B+0xd0000;MAP=B+0x78000;OUT=B+0x94000;HALT=B+0xe0000;PSP=B+0xe8000
CONFIGS=[{'index':2,'old_bits':0,'constructor_case':1},{'index':5,'old_bits':0x02000000,'constructor_case':17},{'index':2,'old_bits':0xfc000000,'constructor_case':1},{'index':41,'old_bits':0xf8000000,'constructor_case':1},{'index':2,'old_bits':0,'constructor_case':1,'free_head_zero':True},{'index':2,'old_bits':0,'constructor_case':1,'threshold_counter':36},{'index':42,'old_bits':0,'constructor_case':1},{'index':2,'old_bits':0,'constructor_case':1,'threshold_counter':35}]
KINDS=['destination_make_send_1','destination_make_send_2','reply_init','reply_unlock','reply_make_send_once','header']
def put(b,o,n,v):b[o:o+n]=v.to_bytes(n,'little')
def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def globset(rows,a,b):
 rows=[dict(e)for e in rows]
 for e in rows:
  if e['address']==hex(a)and len(e['bytes_hex'])==len(b)*2:e['bytes_hex']=b.hex();return rows
 return rows+[{'address':hex(a),'bytes_hex':b.hex()}]
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());old=json.loads((ROOT/'kernel_receive_copyout_profiles.json').read_text());ctors=json.loads((ROOT/'kext_constructor_request_profiles.json').read_text());zone=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'][1];counts=Counter();totals=Counter();summaries=[];proofs=[]
 for obj,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==91 and sum(len(f['instructions'])for f in src['functions'])==12562
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions'];counts['original_complete_functions_recaptured']+=1
 for e in src['reply_namespace_instruction_roles'].values():
  a=int(e['pc'],16);i=next(im.k.cs.disasm(im.k.read(a,4),a));assert e=={'pc':hex(a),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str};counts['reply_namespace_instruction_roles_recaptured']+=1
 z=bytes.fromhex(zone['final_zone192_hex'])[0x30:0x38];assert src['port_zone_validation_source']=={'path':'kernel_zone_startup_profiles.json','case':1,'address':'0xfffffe000caec530','bytes8_hex':z.hex(),'whole_zone_epoch_transferred':False}and z.hex()=='721cc70190007000';freshzone=ZoneReplay(im,zone).run();counts['source_port_zone_validation_fields_fresh_replayed']=1
 assert src['reply_type_policy']=={'address':'0xfffffe0007e62ba0','bytes2_hex':im.k.read(0xfffffe0007e62ba0,2).hex()}and val(im.k.read(0xfffffe0007e62ba0,2),0,2)&0x200;counts['original_selected_type_policy_recaptured']=1
 freshparent=ReceiveReplay(im,old['finishes'][0]).run();freshctors={str(j):ConstructorReplay(im,ctors['cases'][j]).run()for j in[1,17]};counts['fresh_receive_results_parent_replayed']=1;counts['fresh_original_kext_packet_producers_replayed']=2
 x=BitVec('entry_bits32',32);idx=BitVec('index32',32);cap=BitVec('table_bytes32',32);delta=((x<<2)&0x0c000000)+0x04000000;seed=LShR(x,24)&3;name=(idx<<8)|LShR(x,24)|3;wide=ZeroExt(32,x)+ZeroExt(32,delta);quot=Int('capacity_quotient');rem=Int('capacity_remainder');extent=24*quot+rem
 queries=[('generation_stride_is_one_plus_retained_two_bit_seed',True,delta,(seed+1)<<26),('generation_overflow_matches_six_bit_generation_plus_stride',True,UGE(wide,0x100000000),UGE(LShR(x,26)+seed+1,64)),('constructed_name_revalidates_index_and_generation',ULE(idx,0xffffff),And(LShR(name,8)==idx,(name<<24)==((x&0xfc000000)|0x03000000)),True),('decoded_capacity_reciprocal_equals_division_by_24',And(quot>=0,rem>=0,rem<24,extent<=268419072),And(extent*0x0aaaaaab>=quot*0x100000000,extent*0x0aaaaaab<(quot+1)*0x100000000),True)]
 for label,domain,left,right in queries:
  s=Solver();s.add(domain,left!=right);assert s.check()==unsat;proofs.append({'name':label,'domain':str(domain),'query':s.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1;print(json.dumps({'proof':label,'result':'unsat'}),flush=True)
 assert len(prof['cases'])==48 and len(prof['lookups'])==20;seedram=decode(old['finishes'][0]['final_private_RAM']);seedglobals=old['finishes'][0]['final_image_globals'];raw=decode(old['consumers'][0]['final_private_RAM'])[0xd0000:0xd0100];lookupidx=0
 for family,c in enumerate(CONFIGS):
  ram=seedram;gl=[dict(e)for e in seedglobals];origin={'path':'kernel_receive_copyout_profiles.json','finish':0};packet0=bytes.fromhex(ctors['cases'][c['constructor_case']]['message88_hex']);packet=bytearray(packet0);struct.pack_into('<IIQQ',packet,0,0x80001211,88,PORT,REPLY);good=not c.get('free_head_zero')and c.get('threshold_counter',0)<=35 and c['index']<=41
  seed=c['old_bits']>>24&3;total=c['old_bits']+((seed+1)<<26);carry=total>=1<<32;newbits=(((0x35&1)<<1)|((0x35>>1)&1))<<24 if carry else total;newname=(c['index']<<8)|(newbits>>24)|3
  for step,kind in enumerate(KINDS):
   r=prof['cases'][family*6+step];assert r['kind']==kind and r['configuration']==c and r['family']==family and decode(r['initial_state_transfer'])==ram and all(r[k]is False for k in FLAGS)
   for k,v in origin.items():assert r['initial_state_transfer'][k]==v
   counts['exact_full_RAM_component_origins_checked']+=1;initial=bytearray(ram);plan=[];gplan=[]
   if step==0:
    meta=val(bytes.fromhex(next(e['bytes_hex']for e in gl if e['address']=='0xfffffe0007e66f00')),0);plan=[(REPLY,bytes(144)),(SPACE+0x14,struct.pack('<II',c.get('threshold_counter',0),1)),(SPACE+0x1c,struct.pack('<I',0x35)),(SPACE+0x50,struct.pack('<Q',TASK)),(SPACE+0x70,struct.pack('<II',0xffffffff,0)),(OWNER,bytes(0x340)),(OWNER+0x318,struct.pack('<Q',FOREIGN)),(OUT,b'\xa5'*16),(meta+((REPLY>>10)&0xffffffff0),struct.pack('<H',22))];tb=bytearray(bytes.fromhex(next(e['bytes_hex']for e in gl if e['address']==hex(TABLE))));struct.pack_into('<I',tb,12,0 if c.get('free_head_zero')else c['index']);struct.pack_into('<QIIII',tb,24*c['index'],0,c['old_bits'],0,0x11223344,0x55667788);gplan=[(TABLE,bytes(tb)),(0xfffffe000caec530,z)]
   if kind=='header':
    b=bytearray(raw);b[0x40:0x98]=packet;plan=[(KMSG,bytes(b))];assert r['packet_import']=={'constructor_case':c['constructor_case'],'constructor_message88_hex':packet0.hex(),'internal_message88_hex':packet.hex(),'source_kmsg_container256_hex':raw.hex(),'native_transport_continuity_established':False};counts['original_packet_tail_and_explicit_internal_header_imports_checked']+=1
   else:assert r['packet_import']is None
   assert r['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in plan]and len(r['input_overlays'])==len(plan)+len(gplan)
   for(a,b),e in zip(plan,r['input_overlays'][:len(plan)],strict=True):assert e['address']==hex(a)and e['before_hex']==initial[a-B:a-B+len(b)].hex()and e['after_hex']==b.hex()and e['space']=='private';initial[a-B:a-B+len(b)]=b;counts['private_overlay_before_images_checked']+=1
   for(a,b),e in zip(gplan,r['input_overlays'][len(plan):],strict=True):
    before=next((bytes.fromhex(x['bytes_hex'])for x in gl if x['address']==hex(a)),im.k.read(a,len(b))if a!=TABLE else bytes());assert e['address']==hex(a)and e['before_hex']==before.hex()and e['after_hex']==b.hex()and e['space']=='image_global';gl=globset(gl,a,b);counts['global_overlay_before_images_checked']+=1
   assert r['initial_image_fixtures']==gl;wp=bytearray(initial[PORT-B:PORT-B+144]);wr=bytearray(initial[REPLY-B:REPLY-B+144]);ws=bytearray(initial[SPACE-B:SPACE-B+128]);we=bytearray(bytes.fromhex(next(e['bytes_hex']for e in gl if e['address']==hex(TABLE)))[24*c['index']:24*c['index']+24]);wh=bytearray(initial[KMSG-B+0x40:KMSG-B+0x98]);nest=0
   entries={KINDS[0]:(0xfffffe000bccffa4,[PORT]),KINDS[1]:(0xfffffe000bccffa4,[PORT]),'reply_init':(0xfffffe000bccd170,[REPLY,FOREIGN,0x101,OWNER,0,0x707]),'reply_unlock':(0xfffffe000bd0ab18,[REPLY+0x14]),'reply_make_send_once':(0xfffffe000bcd0694,[REPLY]),'header':(0xfffffe000bcc4e98,[KMSG,SPACE,MAP,0x07000002])};entry,args=entries[kind];regs=['0x0']*31
   for j,v in enumerate(args):regs[j]=hex(v)
   regs[30]=hex(HALT);assert r['entry_PC']==hex(entry)and r['entry_registers31']==regs and r['entry_SP']==hex(PSP)and r['entry_DAIF_mask']=='0x200'
   if step in[0,1]:put(wp,4,4,step+2);put(wp,0x88,4,step+1);put(wp,0x14,4,(0x09090144 if step==0 else 0x0a0a0144))
   elif step==2:
    wr=bytearray(144)
    for o,n,v in[(0,4,0x101),(4,4,1),(8,8,OWNER),(0x10,4,0x000c000b),(0x14,4,0x01000144),(0x34,4,0x707),(0x3a,2,5),(0x48,8,FOREIGN)]:put(wr,o,n,v)
    nest=1
   elif step==3:put(wr,0x14,4,0x01010144)
   elif step==4:put(wr,4,4,2);put(wr,0x8c,4,1);put(wr,0x14,4,0x02020144)
   else:
    assert len(r['API_models'])==2 and all(m['symbol']=='opaque_keyed_hash_result'and m['return_value']=='0x123456789abcdef0'for m in r['API_models']);counts['only_declared_keyed_hash_models_checked']+=1;put(ws,8,4,0x01010000 if good else 0x01000000)
    if good:
     put(wp,4,4,2);put(wp,0x88,4,1);put(wp,0x14,4,0x0b0b0144);put(wr,0x14,4,0x03030144);put(ws,0x18,4,0);put(ws,0x1c,4,0xd if carry else 0x35);put(ws,0x70,4,c['index']);put(ws,0x74,4,c['index']);put(we,0,8,REPLY);put(we,8,4,newbits|0x40001);put(we,12,4,0);wh=bytearray(struct.pack('<IIQQII',0x80001112,88,newname,0x303,0,val(packet,28,4))+packet[32:]);tb=bytearray(bytes.fromhex(next(e['bytes_hex']for e in gl if e['address']==hex(TABLE))));put(tb,12,4,0);tb[24*c['index']:24*c['index']+24]=we;gl=globset(gl,TABLE,bytes(tb));assert r['boundary']['kind']=='before_original_descriptor_copyout'and r['boundary']['pc']=='0xfffffe000bcc5564';counts['original_header_namespace_publications_checked']+=1
     af=next(e for e in r['namespace_frames']if e['pc']=='0xfffffe000bcbc228');pf=next(e for e in r['namespace_frames']if e['pc']=='0xfffffe000bcd5d50');done=next(e for e in r['namespace_frames']if e['pc']=='0xfffffe000bcc5294');assert af['arguments8'][1]==hex(newname)and bytes.fromhex(af['entry24_hex'])[:16]==struct.pack('<QII',REPLY,newbits,0)and val(bytes.fromhex(pf['reply144_hex']),4,4)==3 and val(bytes.fromhex(done['reply144_hex']),4,4)==3;counts['allocation_before_publication_and_temporary_reference_frames_checked']+=1
     assert any(e['pc']=='0xfffffe000be57f8c'for e in r['namespace_frames'])==carry;counts['source_generation_stride_cached_rollover_and_name_oracles_checked']+=1
    else:
     nest=1;assert r['boundary']['kind']==('before_original_namespace_trap'if c['index']==42 else'before_original_namespace_growth');counts['held_growth_or_invalid_free_entry_prefixes_checked']+=1
   if kind!='header':assert r['API_models']==[]and r['boundary']['kind']=='original_component_returned'
   assert r['final_port144_hex']==wp.hex()and r['final_reply144_hex']==wr.hex()and r['final_space128_hex']==ws.hex()and r['final_entry24_hex']==we.hex()and r['final_header88_hex']==wh.hex()and r['final_output16_hex']=='a5'*16 and r['final_nesting']==nest and r['final_image_globals']==gl;counts['complete_port_reply_space_entry_header_and_global_oracles_checked']+=1
   for e in r['source_visits']:assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex'];counts['every_original_instruction_recaptured']+=1
   totals.update(Replay(im,r).run());ram=decode(r['final_private_RAM']);origin={'path':P+'_profiles.json','case':family*6+step}
  if good:
   base=ram;basegl=[dict(e)for e in gl];baseorigin=dict(origin)
   for kind in ['translate_valid','lookup_unlock','translate_wrong_right','translate_stale']:
    if kind in ['translate_wrong_right','translate_stale']:ram=base;gl=basegl;origin=baseorigin
    r=prof['lookups'][lookupidx];assert r['family']==family and r['kind']==kind and r['configuration']==c and decode(r['initial_state_transfer'])==ram and r['initial_image_fixtures']==gl and r['final_image_globals']==gl and all(r[k]is False for k in FLAGS)
    for k,v in origin.items():assert r['initial_state_transfer'][k]==v
    initial=bytearray(ram);wp=bytes(initial[PORT-B:PORT-B+144]);wr=bytearray(initial[REPLY-B:REPLY-B+144]);output=bytearray(initial[OUT-B:OUT-B+16]);args=[REPLY+0x14]if kind=='lookup_unlock'else[SPACE,newname^(4 if kind=='translate_stale'else 0),0 if kind=='translate_wrong_right'else 2,OUT];entry=0xfffffe000bd0ab18 if kind=='lookup_unlock'else 0xfffffe000bcc92e4;regs=['0x0']*31
    for j,v in enumerate(args):regs[j]=hex(v)
    regs[30]=hex(HALT);assert r['entry_registers31']==regs and r['entry_PC']==hex(entry)
    if kind=='lookup_unlock':assert r['initial_private_fixtures']==[]and r['input_overlays']==[];put(wr,0x14,4,0x04040144);expectedstatus=None
    else:
     assert r['initial_private_fixtures']==[{'address':hex(OUT),'bytes_hex':'a5'*16}]and len(r['input_overlays'])==1 and r['input_overlays'][0]['before_hex']==output.hex();output=bytearray(b'\xa5'*16);put(wr,0x14,4,0x04030144 if kind=='translate_valid'else 0x04040144);expectedstatus=0 if kind=='translate_valid'else 17 if kind=='translate_wrong_right'else 15
     if kind=='translate_valid':put(output,0,8,REPLY)
    assert r['API_models']==[]and r['boundary']['kind']=='original_component_returned'and r['final_reply144_hex']==wr.hex()and r['final_port144_hex']==wp.hex()and r['final_output16_hex']==output.hex()and r['final_nesting']==(1 if kind=='translate_valid'else 0)
    if expectedstatus is not None:assert r['boundary']['registers31'][0]==hex(expectedstatus)
    assert r['final_space128_hex']==bytes(initial[SPACE-B:SPACE-B+128]).hex()and r['final_entry24_hex']==prof['cases'][family*6+5]['final_entry24_hex']and r['final_header88_hex']==prof['cases'][family*6+5]['final_header88_hex'];counts['produced_name_right_generation_reference_lock_and_output_oracles_checked']+=1
    for e in r['source_visits']:assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex'];counts['every_original_instruction_recaptured']+=1
    totals.update(Replay(im,r).run());ram=decode(r['final_private_RAM']);origin={'path':P+'_profiles.json','lookup':lookupidx};lookupidx+=1
  summaries.append({'family':family,'configuration':c,'header_boundary':prof['cases'][family*6+5]['boundary']['kind'],'message_id':val(packet,28,4),'produced_reply_name':hex(newname)if good else None,'entry_bits':hex(newbits|0x40001)if good else None,'reply_refs':2,'reply_send_once_rights':1,'destination_refs':2 if good else 3,'destination_send_rights':1 if good else 2,'final_nesting':0 if good else 1});print(json.dumps(summaries[-1]),flush=True)
 assert lookupidx==20;counts.update(cases=48,lookups=20,functions=91,captured_instructions=12562)
 deps=[P+'_source.json',P+'_profiles.json','kernel_receive_copyout_profiles.json','kernel_zone_startup_profiles.json','kext_constructor_request_profiles.json','replay_'+P+'.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','replay_kernel_zone_startup.py','replay_kernel_receive_copyout.py','replay_kext_constructor_request.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_parent_receive_results_replay':freshparent,'fresh_port_zone_producer_replay':freshzone,'fresh_kext_packet_producer_replays':freshctors,'proofs':proofs,'family_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
