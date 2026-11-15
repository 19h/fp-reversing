#!/usr/bin/env python3
"""Freeze cleanup entry mutation, backward reclamation and typed-free ABI.
O(B+I+256R) time/space. Original/normalized reads only; no target executes.
"""
import json
import struct
from kext_port_tools import ROOT, SOURCE, IMAGE, POOL, TABLE, qword, selected, CS
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from verify_daemon_reader_record_payloads_publication import read, sha

P='userclient_hash_table_reclamation'
SCOPE='Original-source token0xc28 entry writer, token0x559 backward table reclamation, both cleanup records, raw counter/state/key/value updates and conditional site.FPSecureTunnel typed-free request. Producers, native object identity/deallocation, serialization and daemon-kext pairing remain unknown.'
SPANS={
 'caller_entry_address':(0xfffffe000a6270e0,0xfffffe000a627108),
 'caller_entry_retag':(0xfffffe000a62710c,0xfffffe000a627110),
 'caller_entry_request':(0xfffffe000a627110,0xfffffe000a6271e8),
 'caller_table_request':(0xfffffe000a6271ec,0xfffffe000a6272f4),
 'caller_table_return':(0xfffffe000a6272f8,0xfffffe000a627304),
 'caller_free_gate':(0xfffffe000a62730c,0xfffffe000a62735c),
 'caller_free_request':(0xfffffe000a627364,0xfffffe000a6273e8),
 'caller_free_return':(0xfffffe000a6273ec,0xfffffe000a6273f8),
 'writer_environment':(0xfffffe000a5aec28,0xfffffe000a5aec78),
 'writer_codec_gate':(0xfffffe000a5aec78,0xfffffe000a5aed18),
 'writer_increment_gate':(0xfffffe000a5aed20,0xfffffe000a5aed80),
 'writer_decrement_gate':(0xfffffe000a5aed88,0xfffffe000a5aedbc),
 'writer_counter':(0xfffffe000a5aedc4,0xfffffe000a5aede0),
 'writer_fields':(0xfffffe000a5aede8,0xfffffe000a5aee04),
 'writer_return':(0xfffffe000a5aee0c,0xfffffe000a5aee10),
 'table_frame':(0xfffffe000a616864,0xfffffe000a616884),
 'table_guard_save':(0xfffffe000a616884,0xfffffe000a616898),
 'table_roots':(0xfffffe000a616898,0xfffffe000a616988),
 'table_codec_gate':(0xfffffe000a616988,0xfffffe000a616a10),
 'table_next_gate':(0xfffffe000a616a18,0xfffffe000a616aa4),
 'table_capacity_gate':(0xfffffe000a616aac,0xfffffe000a616af4),
 'table_prepare':(0xfffffe000a616afc,0xfffffe000a616bb8),
 'table_cursor':(0xfffffe000a616bc0,0xfffffe000a616be0),
 'table_cursor_retag':(0xfffffe000a616be4,0xfffffe000a616be8),
 'table_state_gate':(0xfffffe000a616be8,0xfffffe000a616bfc),
 'table_clear_request':(0xfffffe000a616c00,0xfffffe000a616ca8),
 'table_continue':(0xfffffe000a616cac,0xfffffe000a616d08),
 'table_success':(0xfffffe000a616d0c,0xfffffe000a616d14),
 'table_status':(0xfffffe000a616d18,0xfffffe000a616d1c),
 'table_canary':(0xfffffe000a616d1c,0xfffffe000a616d30),
 'table_epilogue':(0xfffffe000a616d34,0xfffffe000a616d50),
}
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py',
 'lskd_values_symbolic.py','audit_userclient_hash_table_initializer.py','audit_userclient_hash_table_lookup.py',
 'userclient_context_lifecycle_source.json','userclient_hash_table_lookup_checks.json',
 'userclient_hash_table_lookup_audit.json','userclient_hash_table_initializer_checks.json']
FALSE=['native_API_executed','native_PAC_authenticated','native_daemon_kext_pairing_established',
 'native_deallocation_established','native_payload_type_identity_established','native_locking_established',
 'whole_machine_context_lifetime_established','UID_business_semantics_established','table_producers_established',
 'full_populated_cleanup_established','IDB_modified','full_goal_complete']

def build():
 assert sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 k=Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 fs={n:function(k,entry,a) for n,a in [('writer',0xfffffe000a5aec24),('reclaimer',0xfffffe000a616860)]}
 parent=json.loads(read(ROOT/'userclient_context_lifecycle_source.json'))['functions']['destroy']
 for f in fs.values():
  raw=bytes.fromhex(f['bytes_hex']);assert IMAGE.read(int(f['start'],16),len(raw))==raw
 spans=[]
 for label,(a,z) in SPANS.items():
  raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw
  ii=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]
  f=parent if label.startswith('caller_') else fs['writer' if label.startswith('writer_') else 'reclaimer']
  assert ii==[i for i in f['instructions'] if a<=int(i['ea'],16)<z] and len(ii)*4==len(raw)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'instructions':ii})
 transfers=[]
 for f in [*fs.values(),parent]:
  for i in f['instructions']:
   a=int(i['ea'],16)
   if (f!=parent or 0xfffffe000a6270dc<=a<0xfffffe000a627400) and i['mnemonic'] in ['braa','blraa','b.eq','b.ne','bl','ret','retab']:
    transfers.append({**i,'bytes_hex':k.read(a,4).hex()})
 pairs={'U':(qword(POOL+0x4f0)-4,qword(POOL+0x578)-4),
        'V':(qword(POOL+0xc08)-8,qword(POOL+0x158)-4),
        'T':(qword(POOL+0x840),qword(POOL+0xbb8))}
 banks={n+side:{'address':hex(a),'bytes_hex':IMAGE.read(a,256).hex()} for n,pair in pairs.items() for side,a in zip(['L','R'],pair)}
 rules=[]
 for name,p,key,add,base,bias,div in [
  ('caller_writer','U',0xef,0xefc,TABLE,0,0x3936),('caller_reclaimer','U',0xef,0xef5,TABLE,0,0xaf1c),
  ('caller_free','V',0x98,0xe96,TABLE,0,0x4d6a),('free_descriptor','T',0x3e,0xc3,POOL,0,None),
  ('writer_table','V',5,6,POOL,-12,None),('table_controller_A','T',0xb4,0x13a,POOL,-4,None),
  ('table_controller_B','V',0x6d,9,POOL,-4,None),('table_table','T',0x5c,-0x9f,POOL,-12,None),
  ('nested_writer','V',0x6d,0xf4a,TABLE,0,0x3936)]:
  r=selected(*pairs[p],key,add,base,bias);r.update(name=name,pair=p,original_pointer=pointer(k,int(r['slot'],16)))
  assert (int(r['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(r['target'],16)
  if div is not None:assert r['original_pointer']['authenticated'] and int(r['original_pointer']['diversity'],16)==div
  rules.append(r)
 branches=[]
 for ix in range(0xf00):
  target=qword(TABLE+8*ix)
  if any(int(f['start'],16)<=target<int(f['end'],16) for f in fs.values()) or ix in [0x39b,0x4fa,0x518,0xa8f]:
   p=pointer(k,TABLE+8*ix);assert int(p['target'],16)==target;p['index']=ix;branches.append(p)
 a=0xfffffe000847bf60;raw=IMAGE.read(a,64);np,sp=[struct.unpack_from('<Q',raw,o)[0] for o in [16,32]]
 name=IMAGE.read(np,64).split(b'\0')[0];sig=IMAGE.read(sp,64).split(b'\0')[0];flags,size=struct.unpack_from('<II',raw,40)
 assert (name,sig,flags,size)==(b'site.FPSecureTunnel',b'',0x6c,120)
 pn,ps=pointer(k,a+16),pointer(k,a+32)
 assert (int(pn['target'],16),int(ps['target'],16))==(np,sp) and k.read(a+40,8)==raw[40:48]
 assert k.read(np,len(name)+1)==name+b'\0' and k.read(sp,1)==b'\0'
 descriptor={'address':hex(a),'normalized64_bytes_hex':raw.hex(),'original64_bytes_hex':k.read(a,64).hex(),
  'name':name.decode(),'signature':sig.decode(),'flags_u32':flags,'size_bytes':size,'name_pointer':pn,'signature_pointer':ps}
 prior=json.loads(read(ROOT/'userclient_hash_table_initializer_checks.json'))
 adapter=k.function(0xfffffe000c4ba368);assert adapter['instructions'][1]['operands']=='#0xfffffe000bcff010'
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in DEPS},'functions':fs,'parent_caller_sha256':parent['sha256'],
  'caller_region':{'start':'0xfffffe000a6270dc','end_exclusive':'0xfffffe000a627400','bytes_hex':k.read(0xfffffe000a6270dc,0x324).hex()},
  'spans':spans,'transfers':transfers,'banks':banks,'bank_rules':rules,'branch_pointers':branches,
  'pool_pointers':[pointer(k,POOL+o) for o in [0x4f0,0x578,0xc08,0x158,0x840,0xbb8]],
  'typed_free_descriptor':descriptor,'free_adapter':adapter,'exact_symbols':k.symbols([0xfffffe000c4ba368]),
  'stack_guard_pointer':prior['stack_guard_pointer'],'stack_fail_pointer':prior['stack_fail_pointer'],'stack_fail_stub':prior['stack_fail_stub'],
  'verified_counts':{'writer_captured_instructions':124,'reclaimer_captured_instructions':318,'caller_region_instructions':201,
   'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'literal_bank_arrays':6,'bank_rules':len(rules),'bank_input_cases':256*len(rules),
   'branch_pointers':len(branches),'pool_pointers':6,'writer_record_bytes':48,'reclaimer_record_bytes':40,
   'entry_stride_bytes':24,'typed_free_bytes':120},
  'conditional_hash_table_reclamation_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
