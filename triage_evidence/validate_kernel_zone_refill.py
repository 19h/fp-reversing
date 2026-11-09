#!/usr/bin/env python3
"""Original refill/bitmap recapture, held-state transfer, inventory/page oracles.
O(image+source+visits+RAM+effects), O(image+RAM+journals), bounded scalar SMT.
No native target allocation, storage, locking, IPC or authentication effects.
"""
import json,struct
from collections import Counter
from z3 import BitVec,BitVecVal,ZeroExt,ULT,ULE,And,If,Solver,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from replay_rpc502_vm_handoff import decode
from replay_kernel_zone_startup import Replay as ProducerReplay
from replay_kernel_zone_refill import Replay
P='kernel_zone_refill';R=0x6500000000;SIZE=0x100000;ZONE=0xfffffe000caec680;CACHE=R+0xb2000;STATS=R+0xb1000;THREAD=R+0x2c000;PAGE=R+0xd0000;META=R+0xc0000;BITMAP=R+0xc1000;MAG=R+0xbc000;EMPTY=R+0xbd000;CURRENT=R+0xb2ff0;SLOTS=CURRENT+16;INDEX=PAGE>>14;HEADBASE=0xfffffe000ca8c000

def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def put(b,o,n,x):b[o:o+n]=x.to_bytes(n,'little')
def selections(bits,cursor,n):
 out=[]
 for _ in range(n):
  chosen=next((cursor+d)%64 for d in range(1,65)if bits&(1<<((cursor+d)%64)));out.append(chosen);bits^=1<<chosen;cursor=chosen
 return out,bits

def input_plan(c):
 mode=c['mode'];quota=c.get('quota',0);out=[(0xfffffe000cb0bc50,bytes(4)),(0xfffffe000cb115b0,bytes(4)),(0xfffffe000ca92380,bytes([c.get('phase',0)])),(PAGE,bytes(16384)),(PAGE+16384,b'\xa5')]
 if quota:out.append((ZONE+0x7c,struct.pack('<H',quota)))
 if mode in['shared','local']:
  n=c.get('magazines',1);empty=c.get('empty_magazines',0)
  for k in range(n):out.append((MAG+k*256,struct.pack('<QQ',MAG+(k+1)*256 if k+1<n else EMPTY if mode=='local'and empty else 0,0)+struct.pack('<16Q',*[PAGE+k*4096+h*256 for h in range(16)])))
  for k in range(empty):out.append((EMPTY+k*256,struct.pack('<QQ',EMPTY+(k+1)*256 if k+1<empty else 0,0)))
  if mode=='shared':
   out.append((ZONE+0x48,struct.pack('<IIQQ',n,0,MAG,MAG+(n-1)*256)))
   if empty:out.append((CACHE+0x18,struct.pack('<IIQQ',0,empty,EMPTY,CACHE+0x20)))
  else:out.extend([(CACHE+0x18,struct.pack('<IIQQ',n,empty,MAG,MAG+(n-1)*256)),(ZONE+0x58,struct.pack('<Q',ZONE+0x50))])
  if c.get('security_bit12'):out.append((0xfffffe0007e6a7a0+4*24,struct.pack('<I',1<<12)))
 if mode=='page':
  used=c.get('used',16);free=c.get('bitmap',((1<<64)-1)^((1<<used)-1));out.extend([(ZONE+0x9c,struct.pack('<I',INDEX)),(ZONE+0xa8,struct.pack('<I',64-used)),(ZONE+0xb0,bytes(4)),(0xfffffe0007e66f00,struct.pack('<Q',META-INDEX*16)),(0xfffffe0007e66e70,struct.pack('<Q',BITMAP)),(META,struct.pack('<HHIII',0x1018,used,0,0,(ZONE+0x9c-(HEADBASE-4))>>2)),(BITMAP,struct.pack('<Q',free)),(STATS+0x18,struct.pack('<I',c.get('cursor',0)))])
 return out

def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());parent=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'][7];counts=Counter();totals=Counter();summaries=[];proofs=[]
 for o,s in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/s)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
  assert all(o[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==19 and sum(len(f['instructions'])for f in src['functions'])==3511 and src['native_cache_refill_observed']is False
 for f in src['functions']:
  a=int(f['start'],16);raw=im.k.read(a,int(f['end'],16)-a);assert raw.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]==f['instructions'];counts['original_complete_functions_recaptured']+=1
 for e in src['refill_instruction_roles'].values():
  a=int(e['pc'],16);i=next(im.k.cs.disasm(im.k.read(a,4),a));assert im.k.read(a,4).hex()==e['bytes_hex']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'];counts['refill_instruction_roles_recaptured']+=1
 for e in src['original_control_globals']:assert im.k.read(int(e['address'],16),len(e['bytes_hex'])//2).hex()==e['bytes_hex'];counts['original_control_global_file_bytes_recaptured']+=1
 available=BitVec('available32',32);capacity=BitVec('capacity16',16);bits=BitVec('nonzero_bitmap64',64);ident=BitVec('zone_index32',32);delta=ZeroExt(32,ident)*192;cleared=bits&(bits-1);chosen=bits^cleared
 queries=[('partial_fill_bound',None,ULE(If(ULT(available,ZeroExt(16,capacity)),available,ZeroExt(16,capacity)),ZeroExt(16,capacity)),True),('nonzero_bitmap_removes_exactly_one_bit',bits!=0,And(chosen!=0,(chosen&(chosen-1))==0,(bits&chosen)==chosen),True),('guarded_zone_security_index',ULT(ident,690),((delta*0x1555556)>>30)&0x3fffffffc,ZeroExt(32,ident)*4)]
 for name,domain,left,right in queries:
  sol=Solver()
  if domain is not None:sol.add(domain)
  sol.add(left!=right);assert sol.check()==unsat;proofs.append({'name':name,'domain':None if domain is None else str(domain),'query':sol.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1
 freshproducer=ProducerReplay(im,parent).run();base=decode(parent['final_private_RAM']);assert val(base,THREAD-R+0x1c8,4)==1;originalglobals={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in parent['final_image_globals']};rows=prof['cases'];assert len(rows)==12
 for j,r in enumerate(rows):
  c=r['configuration'];mode=c['mode'];quota=c.get('quota',0);page=mode=='page';empty=mode=='empty';gated=page and c.get('phase',0)!=0;ram=decode(r['final_private_RAM']);z=bytes.fromhex(r['final_zone192_hex']);cache=bytes.fromhex(r['final_cache64_hex']);stats=bytes.fromhex(r['final_statistics32_hex']);ff=r['refill_frames'];models=r['API_models'];n=c.get('magazines',1);oldempty=c.get('empty_magazines',0)
  assert all(r[k]is False for k in FLAGS)and r['private_RAM']=={'address':hex(R),'size_bytes':SIZE,'initial_byte':0}and r['entry_PC']==parent['boundary']['pc']and r['entry_SP']==parent['boundary']['SP']and r['entry_registers31']==parent['boundary']['registers31']and r['entry_NZCV']==parent['boundary']['NZCV']and r['entry_Q_registers32']==parent['final_Q_registers32']and r['initial_state_transfer']['path']=='kernel_zone_startup_profiles.json'and r['initial_state_transfer']['case']==7 and decode(r['initial_state_transfer'])==base;counts['exact_held_GP_SP_NZCV_SIMD_RAM_entry_checked']+=1
  assert r['private_system_register_fixtures']==[{'register':'TPIDR_EL1','value':hex(THREAD)}]and r['zone_address']==hex(ZONE)and r['selected_cache_address']==hex(CACHE)and r['selected_statistics_address']==hex(STATS)
  inherited=r['initial_image_fixtures'][:len(parent['final_image_globals'])];assert[{k:e[k]for k in['address','bytes_hex']}for e in inherited]==parent['final_image_globals'];counts['exact_held_image_global_transfer_checked']+=1
  initial=bytearray(base);gbytes={a+k:b for a,raw in originalglobals.items()for k,b in enumerate(raw)};privatepatches=[];imagepatches=[]
  assert[(int(e['address'],16),bytes.fromhex(e['after_hex']))for e in r['memory_overlays']]==input_plan(c);counts['exact_declared_input_patch_plan_checked']+=1
  for e in r['memory_overlays']:
   a=int(e['address'],16);b=bytes.fromhex(e['after_hex']);assert e['reason']
   if R<=a<a+len(b)<=R+SIZE:before=bytes(initial[a-R:a-R+len(b)]);initial[a-R:a-R+len(b)]=b;privatepatches.append({'address':hex(a),'bytes_hex':b.hex()})
   else:
    before=bytes(gbytes[a+k]if a+k in gbytes else im.logical_page((a+k)&~4095)[(a+k)&4095]for k in range(len(b)));gbytes.update({a+k:x for k,x in enumerate(b)});imagepatches.append({'address':hex(a),'bytes_hex':b.hex()})
   assert before.hex()==e['before_hex'];counts['explicit_inventory_arena_and_environment_patch_before_images_checked']+=1
  assert r['initial_private_fixtures']==privatepatches and[{k:e[k]for k in['address','bytes_hex']}for e in r['initial_image_fixtures'][len(inherited):]]==imagepatches
  assert set(m['symbol']for m in models)<= {'declared_lock_acquisition'}and len(models)==int(empty or page or quota!=0)
  for k,m in enumerate(models):
   assert m['arguments8'][0]==hex(CACHE if quota else ZONE+0x80)and m['return_value']=='0x0'and m['native_effects_executed']is False;want=[hex(((i+1)*0x123456789abcdef)^((k+1)*0x8b3dc651))for i in range(18)];want[0]='0x0';assert m['after_registers31'][:18]==want and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0);counts['declared_lock_ABI_and_clobber_model_checked']+=1
  counts['no_whole_refill_fill_selection_or_allocation_model_checked']+=1
  first=ff[0];assert first['pc']=='0xfffffe000bd75e20'and first['arguments5'][:4]==[hex(ZONE),'0x0','0x8004',hex(CACHE)]and first['thread_nesting']==1
  returned=not empty and not gated;assert r['raw_arena_guard_hex']=='a5'and r['final_raw_arena16384_hex']=='00'*16384
  wantz=bytearray(gbytes[ZONE+k]for k in range(192));wantcache=bytearray(initial[CACHE-R:CACHE-R+64]);wantstats=bytearray(initial[STATS-R:STATS-R+32]);full=[];empties=[];localfull=[];localempty=[];indices=[];count=0
  if page or empty:wantz[0x82]=(wantz[0x82]+1)&255
  else:
   if quota:wantcache[2]=(wantcache[2]+1)&255
   count=16;localempty=[EMPTY+k*0x100 for k in range(oldempty)]
   if mode=='local':
    localfull=[MAG+k*0x100 for k in range(n)];current=localfull.pop(0);localempty.insert(0,CURRENT);counts['nonempty_local_full_inventory_bypasses_shared_and_spill_checked']+=1
   else:
    put(wantz,0x60,4,0x01010000);full=[MAG+k*0x100 for k in range(n)]
    if quota:
     flushed=max(oldempty-quota//2,0)if oldempty>=quota else 0;empties=localempty[:flushed];localempty=localempty[flushed:];transfer=min(quota-len(localempty),len(full));localfull=full[:transfer];full=full[transfer:];current=localfull.pop(0);localempty.insert(0,CURRENT)
     if flushed:counts['original_empty_magazine_spill_and_quota_limited_shared_refill_checked']+=1
    else:current=full.pop(0);empties=[CURRENT]
   for b,o,fs,es,head in[(wantz,0x48,full,empties,ZONE+0x50),(wantcache,0x18,localfull,localempty,CACHE+0x20)]:
    put(b,o,4,len(fs));put(b,o+4,4,len(es));put(b,o+8,8,(fs+es)[0]if fs+es else 0);put(b,o+16,8,fs[-1]if fs else head)
   put(wantcache,8,8,current+16)
   for nodes in[full+empties,localfull+localempty]:
    for k,node in enumerate(nodes):assert val(ram,node-R)==(nodes[k+1]if k+1<len(nodes)else 0);counts['independent_magazine_list_next_links_checked']+=1
   assert ram[current-R:current-R+16]==bytes(16);counts['original_shared_local_full_empty_partition_and_current_exchange_checked']+=1
  if page and not gated:
   used=c.get('used',16);bitmap=c.get('bitmap',((1<<64)-1)^((1<<used)-1));cursor=c.get('cursor',0);count=min(64-used,16);assert bitmap.bit_count()==64-used;indices,remaining=selections(bitmap,cursor,count);put(wantz,0xa8,4,64-used-count);put(wantstats,0x18,4,indices[-1]);meta=bytearray(initial[META-R:META-R+16]);put(meta,2,2,used+count)
   if used+count==64:put(wantz,0x9c,4,0);put(wantz,0xa0,4,INDEX);put(meta,12,4,(ZONE+0xa0-(HEADBASE-4))>>2);counts['original_partial_to_full_page_list_transition_checked']+=1
   assert bytes(meta).hex()==r['final_metadata16_hex']and r['final_bitmap8_hex']==struct.pack('<Q',remaining).hex();counts['original_page_type_counts_and_independent_free_bit_selection_checked']+=1
   selector=[e for e in ff if e['pc']=='0xfffffe000bd76ad0'];selret=[e for e in ff if e['pc']=='0xfffffe000bd76f70'];assert len(selector)==len(selret)==count
   for e,ret,index in zip(selector,selret,indices,strict=True):assert e['arguments5'][:4]==[hex(ZONE),hex(STATS),hex(META),'0x8004']and ret['arguments5'][0]==hex(index);counts['original_bitmap_selector_request_and_return_ABI_checked']+=1
   fill=next(e for e in ff if e['pc']=='0xfffffe000bd76db4');assert fill['arguments5'][:3]==[hex(ZONE),'0x8004',hex(CACHE)]and fill['thread_nesting']==1;counts['original_partial_page_fill_request_ABI_checked']+=1
   for k,index in enumerate(indices):assert val(ram,SLOTS-R+8*k)==(PAGE+index*256 if k<count-1 else 0)
   assert ram[SLOTS-R+8*count:SLOTS-R+128]==bytes(128-8*count);counts['original_bitmap_to_magazine_pointer_and_consumed_slot_join_checked']+=1
  elif gated:
   assert r['final_metadata16_hex']==initial[META-R:META-R+16].hex()and r['final_bitmap8_hex']==initial[BITMAP-R:BITMAP-R+8].hex()and not any(e['pc']=='0xfffffe000bd76ad0'for e in ff);counts['original_file_phase_gate_preserves_page_and_reaches_fallback_checked']+=1
  else:assert r['final_metadata16_hex']=='00'*16 and r['final_bitmap8_hex']=='00'*8
  if returned:
   put(wantcache,4,2,count-1);put(wantstats,0,8,256);obj=PAGE+(indices[-1]if page else 15)*256;assert r['boundary']['kind']=='original_constructor_returned_after_refill'and r['boundary']['registers31'][0]==hex(obj)and r['boundary']['registers31'][18:]==parent['entry_registers31'][18:]and r['boundary']['SP']==parent['entry_SP']and r['final_thread_nesting']==0 and r['final_returned_element256_hex']=='00'*256
   ret=next(e for e in ff if e['pc']=='0xfffffe000bd75de4');assert ret['arguments5'][0]==hex(CACHE)and val(bytes.fromhex(ret['cache64_hex']),4,2)==count and ret['thread_nesting']==1;counts['original_refill_return_and_outer_constructor_ABI_checked']+=1
   zero=next(e for e in r['allocation_frames']if e['pc']=='0xfffffe000bc9d9c0');assert zero['arguments4'][:2]==[hex(obj),'0x100'];covered=set()
   for e in r['source_reads']:
    a=int(e['address'],16)
    if 0xfffffe000bc9d9c0<=int(e['pc'],16)<0xfffffe000bc9daa0 and obj<=a<obj+256:assert a+e['size_bytes']<=obj+256;covered.update(range(a,a+e['size_bytes']))
   assert covered==set(range(obj,obj+256));counts['original_complete_256byte_zero_check_after_refill_checked']+=1
  else:assert r['boundary']['kind']=='before_original_zone_fallback'and r['boundary']['pc']=='0xfffffe000bd76394'and r['final_thread_nesting']==1 and r['final_returned_element256_hex']is None;counts['empty_or_gated_refill_to_held_fallback_frontier_checked']+=1
  assert z==bytes(wantz)and cache==bytes(wantcache)and stats==bytes(wantstats);counts['independent_full_zone_cache_statistics_field_oracles_checked']+=1
  for e in r['final_image_globals']:
   a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex'])
   if a==ZONE:assert b==z
   else:assert b==bytes(gbytes[a+k]for k in range(len(b)))
  for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_dynamic_original_instruction_recaptured']+=1
  totals.update(Replay(im,r).run());summaries.append({'case':j,'configuration':c,'source_visits':len(r['source_visits']),'selected_indices':indices,'boundary':r['boundary']['kind']});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=12,functions=19,captured_instructions=3511)
 deps=[P+'_source.json',P+'_profiles.json','kernel_zone_startup_profiles.json','replay_'+P+'.py','replay_kernel_zone_startup.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','replay_rpc502_vm_handoff.py','recover_kernel_send_right_lifecycle.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_held_prefix_producer_replay':freshproducer,'proofs':proofs,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
