#!/usr/bin/env python3
"""Freeze the two cleanup lookup records and complete table probe helper.
O(B+I+256R) extraction time/space. Read-only image access; no target executes.
"""
import json
from kext_port_tools import ROOT, SOURCE, IMAGE, POOL, TABLE, qword, selected, CS
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from verify_daemon_reader_record_payloads_publication import read, sha

P='userclient_hash_table_lookup'
SCOPE='Original-source two cleanup lookup records, their common table-probe helper, raw entry-state/key/probe policy, optional found flag, index/status outputs and conditional caller gates. Table producers, update/removal, native lifetimes, synchronization and daemon-kext pairing remain unknown.'
SPANS={
 'caller_first':(0xfffffe000a626dcc,0xfffffe000a626f10),
 'caller_first_gate':(0xfffffe000a626f14,0xfffffe000a626f40),
 'caller_entry_address':(0xfffffe000a626f48,0xfffffe000a626f78),
 'caller_entry_retag':(0xfffffe000a626f7c,0xfffffe000a626f80),
 'caller_found_gate':(0xfffffe000a626f80,0xfffffe000a626fa4),
 'caller_second':(0xfffffe000a626fac,0xfffffe000a6270a0),
 'caller_second_gate':(0xfffffe000a6270a4,0xfffffe000a6270d8),
 'frame_enter':(0xfffffe000a5ae358,0xfffffe000a5ae374),
 'lookup_key':(0xfffffe000a5ae374,0xfffffe000a5ae418),
 'lookup_gate':(0xfffffe000a5ae418,0xfffffe000a5ae49c),
 'lookup_decode':(0xfffffe000a5ae4a4,0xfffffe000a5ae514),
 'flag_clear':(0xfffffe000a5ae51c,0xfffffe000a5ae530),
 'probe_setup':(0xfffffe000a5ae538,0xfffffe000a5ae654),
 'probe_resume':(0xfffffe000a5ae65c,0xfffffe000a5ae668),
 'probe_wrap':(0xfffffe000a5ae670,0xfffffe000a5ae6b0),
 'probe_limit':(0xfffffe000a5ae6b8,0xfffffe000a5ae6fc),
 'probe_state':(0xfffffe000a5ae704,0xfffffe000a5ae720),
 'state_empty_test':(0xfffffe000a5ae724,0xfffffe000a5ae728),
 'probe_other':(0xfffffe000a5ae72c,0xfffffe000a5ae754),
 'key_address':(0xfffffe000a5ae758,0xfffffe000a5ae770),
 'key_retag':(0xfffffe000a5ae774,0xfffffe000a5ae778),
 'key_compare':(0xfffffe000a5ae778,0xfffffe000a5ae79c),
 'key_mismatch':(0xfffffe000a5ae7a4,0xfffffe000a5ae7c8),
 'choose_empty':(0xfffffe000a5ae7cc,0xfffffe000a5ae7ec),
 'found_gate':(0xfffffe000a5ae7f4,0xfffffe000a5ae82c),
 'flag_set':(0xfffffe000a5ae834,0xfffffe000a5ae840),
 'index_output':(0xfffffe000a5ae848,0xfffffe000a5ae860),
 'status_output':(0xfffffe000a5ae868,0xfffffe000a5ae86c),
 'epilogue':(0xfffffe000a5ae86c,0xfffffe000a5ae888),
}
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py',
 'recover_kext_aes_handoff.py','lskd_values_symbolic.py','audit_userclient_hash_table_initializer.py',
 'userclient_context_lifecycle_source.json','userclient_hash_table_bootstrap_audit.json',
 'userclient_hash_table_initializer_checks.json','userclient_hash_table_initializer_audit.json']
FALSE=['native_API_executed','native_PAC_authenticated','native_daemon_kext_pairing_established',
 'whole_machine_context_lifetime_established','UID_business_semantics_established',
 'table_producers_established','table_update_contract_established','native_locking_established',
 'full_populated_cleanup_established','IDB_modified','full_goal_complete']

def build():
 assert sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 k=Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 helper=function(k,entry,0xfffffe000a5ae354)
 parent=json.loads(read(ROOT/'userclient_context_lifecycle_source.json'))['functions']['destroy']
 fs={'lookup':helper,'caller':parent}
 spans=[]
 for label,(a,z) in SPANS.items():
  raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw
  rows=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]
  f=parent if label.startswith('caller_') else helper
  assert rows==[i for i in f['instructions'] if a<=int(i['ea'],16)<z] and len(rows)*4==len(raw)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'instructions':rows})
 selected_pc={int(i['ea'],16) for s in spans for i in s['instructions']}
 transfers=[]
 for f in fs.values():
  for i in f['instructions']:
   a=int(i['ea'],16)
   if (f==helper or 0xfffffe000a626dc8<=a<0xfffffe000a6270dc) and i['mnemonic'] in ['braa','blraa','b.eq','retab']:
    assert a not in selected_pc
    transfers.append({**i,'bytes_hex':k.read(a,4).hex()})
 pairs={'F':(qword(POOL+0x458)-8,qword(POOL+0x638)-12),
        'V':(qword(POOL+0xc08)-8,qword(POOL+0x158)-4),
        'B':(0xfffffe000792fdc0,0xfffffe00079392f0)}
 banks={n+side:{'address':hex(a),'bytes_hex':IMAGE.read(a,256).hex()} for n,pair in pairs.items() for side,a in zip(['L','R'],pair)}
 rules=[]
 for name,p,key,add,base,bias,div in [
  ('first_lookup','F',0x47,0xe9e,TABLE,0,0x6a0f),
  ('second_lookup','V',0x98,0xe84,TABLE,0,0x6a0f),
  ('helper_table','B',0x93,-0xb9,POOL,-12,None)]:
  r=selected(*pairs[p],key,add,base,bias);r.update(name=name,pair=p,original_pointer=pointer(k,int(r['slot'],16)))
  assert (int(r['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(r['target'],16)
  if div is not None:assert int(r['original_pointer']['diversity'],16)==div and r['original_pointer']['authenticated']
  rules.append(r)
 assert int(rules[0]['target'],16)==int(rules[1]['target'],16)==int(helper['start'],16)
 assert int(rules[2]['target'],16)==TABLE
 # Freeze every branch pointer whose target lies in this helper, and the
 # caller's immediate processing-region branch slots. Membership is checked
 # against the original chained-fixup reader rather than invented slots.
 branches=[]
 for ix in range(0xf00):
  slot=TABLE+8*ix
  try:target=qword(slot)
  except ValueError:continue
  if int(helper['start'],16)<=target<int(helper['end'],16) or 0xfffffe000a626dc8<=target<0xfffffe000a627400 or ix==0x2d4:
   p=pointer(k,slot);assert int(p['target'],16)==target;p['index']=ix
   branches.append(p)
 pools=[pointer(k,POOL+off) for off in [0x458,0x638,0xc08,0x158]]
 assert all(int(p['target'],16)==qword(int(p['slot'],16)) for p in pools)
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),
  'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n) for n in DEPS},
  'lookup_function':helper,'parent_caller_sha256':parent['sha256'],
  'caller_region':{'start':'0xfffffe000a626dc8','end_exclusive':'0xfffffe000a6270dc','bytes_hex':k.read(0xfffffe000a626dc8,0x314).hex()},
  'spans':spans,'transfers':transfers,
  'banks':banks,'bank_rules':rules,'pool_pointers':pools,'branch_pointers':branches,
  'exact_symbols':k.symbols([int(helper['start'],16)]),
  'verified_counts':{'lookup_captured_instructions':len(helper['instructions']),'caller_region_instructions':197,
   'lookup_selected_instructions':303,'caller_selected_instructions':188,'source_spans':len(spans),
   'selected_instructions':len(selected_pc),'terminal_transfers':len(transfers),'literal_bank_arrays':len(banks),
   'bank_rules':len(rules),'bank_input_cases':256*len(rules),'pool_pointers':len(pools),
   'branch_pointers':len(branches),'lookup_record_bytes':48,'entry_stride_bytes':24,'cleanup_lookup_calls':2},
  'conditional_hash_table_lookup_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
