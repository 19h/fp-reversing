#!/usr/bin/env python3
"""Recapture original startup metadata and independently replay zone/consumer ABI.
O(image+fixups+source+visits+RAM+effects), O(image+RAM+journals).
Fixed-width scalar proofs have bounded domains; no native target effects.
"""
import json,struct
from collections import Counter
from z3 import BitVec,BitVecVal,ZeroExt,If,ULE,ULT,UGE,And,Solver,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from replay_rpc502_vm_handoff import decode
from replay_kernel_zone_startup import Replay
P='kernel_zone_startup';R=0x6500000000;SIZE=0x100000;ARRAY=0xfffffe000caeb480;STARTUP=0xfffffe000c63222c;CREATE=0xfffffe000bd772b4;CACHEINIT=0xfffffe000bd77bb0;STATS=R+0xb1000;CACHE=R+0xb2000;MAGVIEW=R+0x88000;PUB=R+0x8000;THREAD=R+0x2c000;KMSG=R+0xd0000

def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());counts=Counter();totals=Counter();summaries=[];proofs=[]
 for o,s in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/s)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
  assert all(o[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==16 and sum(len(f['instructions'])for f in src['functions'])==2732
 for f in src['functions']:
  a=int(f['start'],16);raw=im.k.read(a,int(f['end'],16)-a);assert raw.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]==f['instructions'];counts['original_complete_functions_recaptured']+=1
 for e in src['startup_instruction_roles'].values():
  a=int(e['pc'],16);assert im.k.read(a,4).hex()==e['bytes_hex'];i=next(im.k.cs.disasm(im.k.read(a,4),a));assert e['instruction']=={'ea':hex(a),'mnemonic':i.mnemonic,'operands':i.op_str};counts['startup_instruction_roles_recaptured']+=1
 catalog=src['zone_startup_entries'];assert len(catalog)==70 and len({e['entry_address']for e in catalog})==70
 actual={}
 for off,row in im.meta.items():
  if row['target']!=hex(STARTUP):continue
  sg=next(s for s in im.k.root['segments']if s['file_offset']<=off<s['file_offset']+s['file_size']);actual[hex(sg['address']+off-sg['file_offset']-8)]=row
 assert set(actual)=={e['entry_address']for e in catalog}
 for e in catalog:
  entry=int(e['entry_address'],16);a=int(e['specification_address'],16);raw=im.k.read(a,48);assert im.k.read(entry,24).hex()==e['entry_bytes24_hex']and raw.hex()==e['specification_bytes48_hex']
  for key,slot in[('callback_pointer',entry+8),('argument_pointer',entry+16),('name_pointer',a+8)]:assert im.pointer(slot)==e[key]
  assert e['callback_pointer']['target']==hex(STARTUP)and e['argument_pointer']['target']==hex(a)and int.from_bytes(im.k.read(entry,4),'little')==e['subsystem_word0']and int.from_bytes(im.k.read(entry+4,4),'little')==e['rank_word4']
  assert im.k.read(int(e['name_pointer']['target'],16),128).split(b'\0')[0].decode()==e['name']and val(raw,16)==e['requested_size_u64']and val(raw,24)==e['flags_u64']and val(raw,32,2)==e['identifier_u16']
  for key,o in[('optional_publication_pointer',0),('optional_setup_object',40)]:assert e[key]==(im.pointer(a+o)if raw[o:o+8]!=bytes(8)else None)
  assert e['specification_section']==next(s for s in im.k.kernel['sections']if s['address']<=a<s['address']+s['size'])and e['fixed_zone_address']==(hex(ARRAY+192*e['identifier_u16'])if e['identifier_u16']<40 else None);counts['startup_entries_specs_fixups_and_names_recaptured']+=1
 expected={24:('ipc kmsgs',256,0x2000010,0xfffffe000cbc8310,0xfffffe000cbea3c8),22:('ipc ports',144,0x2000011,0xfffffe000cbc8340,0xfffffe000cbea3e0),23:('ipc port sets',56,0x2000001,0xfffffe000cbc8370,0xfffffe000cbea3f8)}
 selected={}
 for ident,(name,size,flags,a,entry)in expected.items():
  e=next(e for e in catalog if e['entry_address']==hex(entry));selected[ident]=e;assert(e['name'],e['requested_size_u64'],e['flags_u64'],e['specification_address'],e['identifier_u16'])==(name,size,flags,hex(a),ident)and e['optional_publication_pointer']is None and e['optional_setup_object']is None and(e['subsystem_word0'],e['rank_word4'])==(7,3);counts['original_IPC_fixed_specs_checked']+=1
 resolved=src['resolved_kmsg_startup_specification'];assert{key:resolved[key]for key in selected[24]}==selected[24]and resolved['static_fixed_slot_relationship_established']is True and resolved['native_runtime_identity_observed']is False and'candidate_kmsg_initialization_record'not in src
 assert src['startup_execution_order_established']is False and src['native_zone_population_established']is False
 for e in src['selected_slot_file_images']:assert int(e['address'],16)==ARRAY+192*e['identifier']and im.k.read(int(e['address'],16),192).hex()==e['bytes192_hex'];counts['selected_fixed_slot_file_images_recaptured']+=1
 s=BitVec('requested_size64',64);ident=BitVec('fixed_identifier32',32);q=BitVec('cache_quotient32',32);maximum=If(UGE(s,1),s,BitVecVal(1,64))
 queries=[('admitted_size_rounds_up_to_8',ULE(s,32768),(maximum+7)&0x1fff8,((maximum+7)/8)*8),('fixed_slot_address_no_u64_wrap',ULT(ident,40),BitVecVal(ARRAY,64)+ZeroExt(32,ident)*192,BitVecVal(ARRAY,64)+(ZeroExt(32,ident)<<7)+(ZeroExt(32,ident)<<6)),('cache_capacity_fits_signed15',None,ULE(If(ULT(q,32767),q,BitVecVal(32767,32)),32767),True)]
 for name,domain,left,right in queries:
  solver=Solver()
  if domain is not None:solver.add(domain)
  solver.add(left!=right);assert solver.check()==unsat;proofs.append({'name':name,'domain':None if domain is None else str(domain),'query':solver.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1
 assert ARRAY+192*39+191<(1<<64)and 32768*65535==2147450880<1<<32;counts['admitted_fixed_slot_and_cache_product_numeric_bounds_checked']=1
 rows=prof['cases'];assert len(rows)==10
 for j,r in enumerate(rows):
  c=r['configuration'];consumer=c.get('phase')=='consumer';ident=r['identifier'];zone=ARRAY+192*ident;z=bytes.fromhex(r['final_zone192_hex']);ram=decode(r['final_private_RAM']);globals={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in r['final_image_globals']};models=r['API_models'];frames=r['startup_frames'];assert len(ram)==SIZE and all(r[k]is False for k in FLAGS)and r['zone_address']==hex(zone)and len(z)==192 and val(z,0)==zone and val(z,8)==STATS and val(z,16)==int(selected[ident]['name_pointer']['target'],16)
  regs=['0x0']*31;regs[30]=hex(R+0xe0000);assert r['entry_SP']==hex(R+0xf0000)and r['entry_NZCV']=='0x40000000'and r['entry_Q_registers32']==['0x0']*32
  assert r['private_RAM']=={'address':hex(R),'size_bytes':SIZE,'initial_byte':0}
  if not consumer:
   spec=selected[ident];a=int(spec['specification_address'],16);req=c.get('size_variant',spec['requested_size_u64']);size=((max(req,1)+7)//8)*8;instances=c.get('instances',1);cache_enabled=ident!=23;budget=c.get('cache_budget',0x100000);capacity=c.get('magazine_capacity',16);regs[0]=hex(a)
   assert r['entry_registers31']==regs and r['entry_PC']==hex(STARTUP)and r['catalog_entry_address']==spec['entry_address']and r['specification_address']==hex(a)and r['boundary']['kind']=='startup_callback_returned'and r['boundary']['registers31'][18:]==regs[18:]and r['boundary']['SP']==r['entry_SP']
   want=[(zone,bytes(192)),(0xfffffe000caeb45a,struct.pack('<H',40)),(0xfffffe000cb7f2c8,bytes(2)),(0xfffffe0007f8b5f0,bytes(4)),(0xfffffe000caeb600,struct.pack('<Q',0xfffffe000caeb600)),(0xfffffe0007e66f38,struct.pack('<I',instances)),(0xfffffe0007e6a248,struct.pack('<H',capacity)),(0xfffffe0007e66e38,struct.pack('<I',budget)),(0xfffffe0007e66f58,struct.pack('<Q',MAGVIEW)),(0xfffffe0007e6a7a0+4*ident,bytes(4))]
   if c.get('publication_variant'):want.append((a,struct.pack('<Q',PUB)))
   if 'size_variant'in c:want.append((a+16,struct.pack('<Q',req)))
   assert[(int(e['address'],16),bytes.fromhex(e['bytes_hex']))for e in r['initial_image_fixtures']]==want and r['initial_private_fixtures']==[{'address':hex(MAGVIEW),'bytes_hex':struct.pack('<QQ',R+0x8a000,R+0x8b000).hex()},{'address':hex(PUB),'bytes_hex':('a5'*8)}];counts['explicit_bootstrap_epochs_and_raw_zero_storage_checked']+=1
   create=next(e for e in frames if e['pc']==hex(CREATE));assert create['arguments5']==[spec['name_pointer']['target'],hex(req),hex(spec['flags_u64']),hex(ident),'0x0']and create['zone192_hex']=='00'*192
   ret=next(e for e in frames if e['pc']=='0xfffffe000c632254');assert ret['arguments5'][0]==hex(zone)and ret['zone192_hex']==z.hex();counts['original_spec_decode_creator_and_return_ABI_checked']+=1
   assert val(z,0x34,2)==size and val(z,0x36,2)==16384%size and val(z,0x38,2)==1 and val(z,0x3a,2)==16384//size and val(z,0x40)==(CACHE if cache_enabled else 0)and val(z,0x7e,2)==(min(budget//(capacity*size),32767)if cache_enabled else 0)
   assert r['final_statistics32_hex']=='00'*32 and globals[0xfffffe000cb7f2c8]==b'\x01\0'and globals[0xfffffe000caeb45a]==b'\x28\0';counts['original_self_view_size_page_arithmetic_and_cache_capacity_checked']+=1
   assert r['publication_u64']==(zone if c.get('publication_variant')else 0xa5a5a5a5a5a5a5a5);pubwrites=[e for e in r['source_writes']if e['address']==hex(PUB)];assert len(pubwrites)==int(bool(c.get('publication_variant')))
   if pubwrites:assert pubwrites[0]['pc']=='0xfffffe000c63225c'and pubwrites[0]['after_hex']==struct.pack('<Q',zone).hex()
   counts['original_optional_publication_store_checked']+=1
   by={}
   for m in models:by.setdefault(m['symbol'],[]).append(m)
   assert len(by['declared_registry_lock'])==len(by['declared_registry_unlock'])==1 and by['declared_registry_lock'][0]['arguments8'][0]=='0xfffffe000cb7f158'and by['declared_registry_unlock'][0]['arguments8'][0]=='0xfffffe000cb7f158'
   for k in['declared_zone_lock','declared_zone_unlock']:assert len(by[k])==(2 if cache_enabled else 1)and all(m['arguments8'][0]==hex(zone+0x80)for m in by[k])
   stats=by['declared_raw_percpu_statistics_storage'];assert len(stats)==1 and stats[0]['arguments8'][:3]==['0xfffffe000caeb600','0x20','0x7']and stats[0]['return_value']==hex(STATS)
   cache=by.get('declared_raw_percpu_cache_storage',[]);assert len(cache)==int(cache_enabled)
   if cache:assert cache[0]['arguments8'][:3]==['0xfffffe000caeb600','0x40','0x3f']and cache[0]['return_value']==hex(CACHE)
   mags=by.get('declared_raw_magazine_storage',[]);assert len(mags)==2*instances*int(cache_enabled)and len(r['raw_magazine_returns'])==len(mags)
   for k,m in enumerate(mags):assert m['arguments8'][:3]==[hex(R+0x8a000),hex(R+0x8b000),'0x8004']and m['return_value']==hex(R+0xb2ff0+k*0x100)and r['raw_magazine_returns'][k]=={'index':k,'pointer':m['return_value']}
   assert len(r['final_cache_instances64_hex'])==instances
   for k,raw in enumerate(r['final_cache_instances64_hex']):
    cb=bytearray(64)
    if cache_enabled:struct.pack_into('<I',cb,0,0x144);struct.pack_into('<QQ',cb,8,R+0xb3000+k*0x200,R+0xb3100+k*0x200);struct.pack_into('<Q',cb,0x28,CACHE+(k<<14)+0x20)
    assert bytes(cb).hex()==raw;counts['original_empty_current_spare_cache_records_checked']+=int(cache_enabled)
   assert len(r['logical_data_signing'])==int(cache_enabled)
   if cache_enabled:assert r['logical_data_signing']==[{'pc':'0xfffffe000bd77ca8','pointer':hex(CACHE),'modifier':hex(((zone+0x40)&((1<<48)-1))|(0x8b6b<<48))}]
   counts['declared_raw_storage_magazine_and_lock_ABIs_checked']+=1
  else:
   parent=rows[r['initial_state_transfer']['case']];base=decode(parent['final_private_RAM']);cpu=c.get('cpu_index',0);cache=CACHE+(cpu<<14);stats=STATS+(cpu<<14);slot=val(base,cache-R+8);regs[:4]=['0x2c','0x0','0x0','0x1'];assert r['entry_registers31']==regs and r['entry_PC']=='0xfffffe000bcc24a4'and r['initial_state_transfer']['path']==P+'_profiles.json'and decode(r['initial_state_transfer'])==base
   assert[{k:e[k]for k in['address','bytes_hex']}for e in r['initial_image_fixtures']]==parent['final_image_globals']and r['final_zone192_hex']==parent['final_zone192_hex']and r['private_system_register_fixtures']==[{'register':'TPIDR_EL1','value':hex(THREAD)}];counts['exact_source_built_zone_full_RAM_and_global_handoffs_checked']+=1
   patches=[(KMSG,bytes(256)),(KMSG+256,b'\xa5'),(THREAD+0x1b8,struct.pack('<H',cpu)),(THREAD+0x1c0,struct.pack('<Q',R+0xb4000)),(THREAD+0x1c8,bytes(4)),(R+0xb4000,bytes(80))]
   if c['fill_cache']:patches.extend([(cache+4,struct.pack('<H',1)),(slot,struct.pack('<Q',KMSG))])
   assert r['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in patches]and r['selected_cache_address']==hex(cache)and r['selected_statistics_address']==hex(stats)and r['current_slot_address']==hex(slot)and models==[];counts['explicit_post_startup_thread_and_filled_cache_epochs_checked']+=1
   af=r['allocation_frames'];zf=next(e for e in af if e['pc']=='0xfffffe000bd75c64');assert zf['arguments4'][:3]==[hex(zone),hex(STATS),'0x8004']and zf['thread_nesting']==0 and any(e['address']==hex(zone)and e['size_bytes']==8 for e in r['source_reads'])and any(e['address']==hex(zone+8)and e['size_bytes']==8 for e in r['source_reads']);counts['actual_embedded_zone_view_consumer_ABI_checked']+=1
   assert r['final_kmsg256_hex']=='00'*256 and r['raw_kmsg_guard_hex']=='a5'and r['final_slot16_hex']=='00'*16 and r['final_cache_instances64_hex']==parent['final_cache_instances64_hex']
   zero=[e for e in af if e['pc']=='0xfffffe000bc9d9c0']
   if c['fill_cache']:
    assert r['boundary']['kind']=='consumer_allocator_returned'and r['boundary']['registers31'][0]==hex(KMSG)and r['boundary']['registers31'][18:]==regs[18:]and r['boundary']['SP']==r['entry_SP']and r['final_thread_nesting']==0 and r['final_statistics32_hex']==struct.pack('<Q',256).hex()+'00'*24 and len(zero)==1 and zero[0]['arguments4'][:2]==[hex(KMSG),'0x100']
    covered=set()
    for e in r['source_reads']:
     a=int(e['address'],16)
     if 0xfffffe000bc9d9c0<=int(e['pc'],16)<0xfffffe000bc9daa0 and KMSG<=a<KMSG+256:assert a+e['size_bytes']<=KMSG+256;covered.update(range(a,a+e['size_bytes']))
    assert covered==set(range(KMSG,KMSG+256));counts['original_filled_cache_pop_and_complete_zero_check_checked']+=1
   else:assert r['boundary']['kind']=='before_original_cache_refill'and r['final_thread_nesting']==1 and r['final_statistics32_hex']=='00'*32 and not zero;counts['source_built_empty_cache_refill_frontier_checked']+=1
   for other in range(parent['configuration'].get('instances',1)):
    if other!=cpu:assert ram[STATS-R+(other<<14):STATS-R+(other<<14)+32]==base[STATS-R+(other<<14):STATS-R+(other<<14)+32];counts['other_CPU_statistics_unchanged_checked']+=1
   assert r['final_image_globals']==parent['final_image_globals'];counts['source_built_zone_and_image_globals_unchanged_by_consumer_checked']+=1
  for k,m in enumerate(models):
   want=[hex(((i+1)*0x123456789abcdef)^((k+1)*0x8b3dc651))for i in range(18)];want[0]=m['return_value'];assert m['native_effects_executed']is False and m['after_registers31'][:18]==want and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0);counts['declared_primitive_clobber_models_checked']+=1
  for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_dynamic_original_instruction_recaptured']+=1
  totals.update(Replay(im,r).run());summaries.append({'case':j,'configuration':c,'visits':len(r['source_visits']),'boundary':r['boundary']['kind']});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=10,functions=16,captured_instructions=2732)
 deps=[P+'_source.json',P+'_profiles.json','replay_'+P+'.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','replay_rpc502_vm_handoff.py','recover_kernel_send_right_lifecycle.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'proofs':proofs,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
