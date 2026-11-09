#!/usr/bin/env python3
"""Source,free bindings,overwrite and chain contracts for mode471C cleanup.
O(source events+fixups+256*bank rules+literal census) time/space. Native allocation,
caller reachability,object type and library/kernel behavior remain unknown.
"""
import json,hashlib,struct
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,TABLE,FIXUPS,selected,qword
from replay_daemon_descriptor_producers import unpack
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_context_lock import ida_output
from recover_daemon_iokit_census import text_section
from daemon_import_bindings import binding

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def span(n,a,z):
 b=IMAGE.read(a,z-a);return{'label':n,'start':hex(a),'end':hex(z),'bytes_hex':b.hex(),'sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]}
def main():
 spans=[span(n,a,z)for n,a,z in [('guard310',0x100b31ce4,0x100b31d14),('guardD8',0x100c70c9c,0x100c70ce4),('chain_advance',0x100a2ae1c,0x100a2ae6c),('chain_header',0x100aca350,0x100aca3ac),('unlink_head',0x100a264d0,0x100a264f8),('unlink_interior',0x100926c00,0x100926c24),('free310',0x100bdf2d4,0x100bdf348),('freeD8',0x100be0e20,0x100be0eac),('seed',0x100bb1574,0x100bb15d0),('fill_constants',0x100bb1650,0x100bb16b8),('fill_length',0x100a048d4,0x100a04904),('fill_body',0x100a1bf1c,0x100a1bfa4),('fill_exit',0x100abd000,0x100abd080),('free_object',0x100bd9d20,0x100bd9da0),('key_clear',0x100b11d40,0x100b11dac),('result_store',0x10095f074,0x10095f078),('caller_free',0x10039c94c,0x10039c9ac),('candidate_allocation872',0x100c11650,0x100c116e4)]]
 paths=[];fix=set();pool={};retired=set();datasets=['daemon_object_consumers_profiles.json','daemon_object_consumers_continuations.json','daemon_object_consumers_counters.json']
 for name in datasets:
  for j,row in enumerate(json.loads((ROOT/name).read_text())['cases']):
   t=unpack(row);F=int(t['initial_SP'],16);cfg=row['configuration'];fix.update(int(a,16)for a in t['used_fixups']);pool.update({pc:x['bytes_hex']for pc,x in t['source_pool'].items()});retired.update(x['pc']for x in t['steps']);regs={};seed=None;events=[];overwrite=[]
   for e in row['prefix']['source_reads']:
    a=int(e['address'],16)
    if a in FIXUPS and e['size_bytes']==8:fix.add(a)
   for st in t['steps']:
    if st['pc']=='0x100a1bf1c'and seed is None:seed=regs['x11']
    for e in st['events']:
     a=int(e['address'],16)
     if st['pc']=='0x100a1bf7c':overwrite.append(e)
     elif st['pc']in ['0x100a264e0','0x100926c0c','0x100b11d50','0x100b11d70','0x100b11d7c','0x100b11d94','0x10095f074']or(st['pc']in['0x100b31cec','0x100c70ca8','0x100a2ae2c']):events.append({'pc':st['pc'],**e})
    regs.update(st['registers_after'])
   paths.append({'dataset':name,'case_index':j,'configuration':cfg,'SP':hex(F),'source_visits':len(t['steps']),'overwrite_seed64':seed,'overwrite_bytes':len(overwrite),'overwrite_first':overwrite[:1],'overwrite_last':overwrite[-1:],'events':events,'free_calls':[{'pc':m['pc'],'arguments2':m['arguments8'][:2],'owner_effects':m.get('owner_effects',[])}for m in t['api_models']if m['name']=='free'],'boundary':{k:v for k,v in t['boundary'].items()if k not in['registers31','SIMD32']},'retired_owners':t['retired_owners']})
 rules=[('free310',0x100fc4230,0x101031fa0,0x6c,0xcb81),('freeD8',0x100e99a00,0x100f4e390,0xd7,0xcb7c),('free_object',0x101031da0,0x100e99900,0x86,0xcbb0),('candidate_malloc872',0x100e99a00,0x100f4e390,0x9c,0xcbdf)];banks=[]
 for n,l,r,k,add in rules:
  x=selected(l,r,k,add,TABLE);banks.append({'label':n,'root_premise':'Captured source roots for executed frees; candidate malloc additionally assumes incoming X14=0x100F4E390. Native allocation phase unknown.',**x});fix.add(int(x['slot'],16))
 dispatch=[{'index':hex(i),'slot':hex(TABLE+i*8),'target':hex(qword(TABLE+i*8))}for i in[0x2ddf,0x2dfc,0x9b74,0x9b7b,0x7e8c,0x9e9d]];fix.update(int(x['slot'],16)for x in dispatch)
 live=[]
 for name in ['daemon_object_consumers_live_ida.json','daemon_object_consumers_more_ida.json','daemon_object_consumers_alloc_ida.json']:
  r=json.loads((ROOT/name).read_text());assert not r.get('isError')
  for x in ida_output(r)['results']:
   a=int(x['address'],16);b=bytes.fromhex(x['bytes']);assert IMAGE.read(a,len(b))==b
   for i in x['instructions']:
    raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw
    if'size'in i:assert len(raw)<=i['size']
    else:assert i.get('decoded')is False and len(raw)==1
   live.append({'address':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'display_rows':len(x['instructions']),'partial_macro_rows':sum(len(bytes.fromhex(i['bytes']))<i['size']for i in x['instructions']if'size'in i),'undecoded_byte_rows':sum('size'not in i for i in x['instructions'])})
 A,N=text_section();raw=IMAGE.read(A,N);literal=[A+j*4 for j,(w,)in enumerate(struct.iter_unpack('<I',raw))if w in[0x52800000|(872<<5),0xd2800000|(872<<5)]];assert literal==[0x100c116a8]
 deps=datasets+['daemon_object_consumers_symbolic.py','daemon_object_consumers_live_ida.json','daemon_object_consumers_more_ida.json','daemon_object_consumers_alloc_ida.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'paths':paths,'banks_exhaustive256':banks,'original_fixups':verify_used_fixups(fix),'dispatch_slots':dispatch,'live_IDB_matches':live,'distinct_continuation_retired_opcodes':len(retired),'distinct_continuation_inspected_opcodes':len(pool),'original_bindings':{'free':binding(0x10109ff30),'candidate_malloc':binding(0x10109ff58)},'overwrite_contract':{'size_bytes':872,'seed64':'(SP+0x2BA0)+0x2F40B33D2E85D192 modulo2^64 under SP&15==0 and mode471C','byte':'u8((((S+i+0x6E) XOR0xBA)*(S+i+0x7F)))','address':'object+871-i, i in0..871','old_byte_consumed':False,'native_entropy_or_erasure_guarantee':'unknown'},'literal_allocation_census':{'scope':'Aligned literal MOV W0/X0,#872 in original text only; obfuscated/computed sizes excluded.','text_address':hex(A),'text_size_bytes':N,'text_sha256':hashlib.sha256(raw).hexdigest(),'matches':[hex(x)for x in literal],'candidate_continuous_allocation_to_registry':'unknown'},'counter_contract':{'global':'0x1010c5754','width_bits':32,'removal':'C-1 modulo2^32','main_cases_initial_counter':'file-image zero fixture','supplement_initial_counter':3,'native_counter_producer':'unknown'},'native_object_type':'unknown','native_object_allocation_size':'unknown','native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_consumers_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'paths':len(paths),'spans':len(spans),'fixups':len(out['original_fixups']['records']),'banks256':len(banks),'IDB_bytes':sum(x['size_bytes']for x in live),'retired_opcodes':len(retired),'inspected_opcodes':len(pool)}),flush=True)
if __name__=='__main__':main()
