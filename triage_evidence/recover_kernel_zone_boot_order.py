#!/usr/bin/env python3
"""Caller/registration custody for capacity policy and phase-7 zone startup.
O(collection bytes + fixups + records + source) time/space; read-only.
Static ordering is conditional on sorted metadata and returning callbacks.
"""
import json,struct
from collections import Counter
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_magazine_bootstrap as M

P='kernel_zone_boot_order';CALLER=0xfffffe000c634e88;DISPATCH=0xfffffe000c6302c4;OBSERVER=0xfffffe000bd3ad04
CURSOR=0xfffffe000cbc9a48;PHASE=0xfffffe0007f8b5f0;ANNOUNCED=0xfffffe000cb62ec8
DESCRIPTORS=0xfffffe000cb7f2d0;SECURITY=0xfffffe0007e6a7a0
OBJECTS=[(0xfffffe000cb7f5d0,0xfffffe000bd79158,0x02200001),(0xfffffe000cb7f1f0,0xfffffe000bd77d00,0x02200003)]
FUNCTIONS=[CALLER,M.POLICY,DISPATCH,OBSERVER,M.PARSER,M.NUMBER,M.PREDICATE,M.BOOT]
SPANS={'metadata_iteration':(0xfffffe000c632014,0xfffffe000c632040),
 'descriptor_address':(0xfffffe000c632118,0xfffffe000c632120),
 'descriptor_fields':(0xfffffe000c63215c,0xfffffe000c632168),
 'direct_descriptor_request':(0xfffffe000c63217c,0xfffffe000c632188),
 'request_phase6':(0xfffffe000c634fcc,0xfffffe000c634fd4),
 'request_phase7':(0xfffffe000c635050,0xfffffe000c635058),
 'feature_high_word':(0xfffffe000c63218c,0xfffffe000c632198),
 'caller_memory_read':(0xfffffe000c635008,0xfffffe000c635010)}
HELPERS={0xfffffe000c637698:'vm_page_bootstrap',0xfffffe000c636dac:'vm_object_bootstrap',
 0xfffffe000be2eb88:'unlabeled_intervening_helper',0xfffffe000c6365b0:'vm_map_init',0xfffffe000c6353e4:'kmem_init',
 0xfffffe000be3e790:'trace_string_helper',0xfffffe000c26ad94:'trace_emit_helper',0xfffffe000c5e73a4:'print_helper'}
SCOPE='Original complete caller, capacity-policy body, startup dispatcher and phase observer in a continuous private call stack. All registered callback bodies and other boot/storage/trace/descriptor helpers are explicit no-RAM ordinary-return models. Static phase/rank ordering is established for pinned metadata; native callback effects, successful boot, zone-view publication, allocation ownership and daemon transaction identity are not established.'
FALSE=M.FALSE+['native_callback_effects_established','continuous_zone_creation_executed','private_registered_callback_bodies_executed']

def build():
 im=Image();k=im.k;k.cs.detail=True;functions=[k.function(a) for a in FUNCTIONS]
 old=json.loads(read(ROOT/'startup_dispatch_checks.json'));prior=json.loads(read(ROOT/'kernel_magazine_bootstrap_checks.json'))
 matched=0
 for f in functions[1:]:
  candidates=prior['functions']+[{**s,'bytes':s['bytes_hex']} for s in old['spans']]
  assert any(all(c.get(key)==value for key,value in f.items()) for c in candidates);matched+=1
 table=old['startup_section'];start=table['address'];raw=k.read(start,table['size']);logical=bytearray(raw)
 assert raw.hex()==''.join(r['bytes_hex'] for r in old['records']) and len(raw)==24*3519
 for row in old['records']:
  at=int(row['address'],16);assert at==start+24*((at-start)//24)
  for off in [8,16]:
   if raw[at-start+off:at-start+off+8]!=bytes(8):
    ptr=im.pointer(at+off);p=next(p for p in row['fixups'] if p['slot']==hex(at+off))
    assert p['chain_membership_verified'] and p['word']==ptr['raw'] and p['target']==ptr['target']
    assert p['pointer_format']==ptr['format']==8 and p['authenticated']==bool(ptr['auth']) and p['diversity']==ptr['diversity']
    logical[at-start+off:at-start+off+8]=int(ptr['target'],16).to_bytes(8,'little')
 assert logical.hex()==old['logical_table_bytes_hex']
 rows=[r for r in old['records'] if r['phase32'] in [6,7]]
 magazines=[r for r in rows if int.from_bytes(bytes.fromhex(r['logical_bytes_hex'])[8:16],'little')==M.BOOT]
 assert len(magazines)==1 and (magazines[0]['phase32'],magazines[0]['rank32'])==(7,0)
 assert sum(r['phase32']==7 and r['rank32']==0 for r in rows)==1
 specs=[r for r in json.loads(read(ROOT/'kernel_zone_startup_source.json'))['zone_startup_entries'] if r['name'] in ['ipc kmsgs','ipc ports','ipc port sets']]
 # The original spelling is retained, including the port-set separator.
 if len(specs)!=3:
  specs=[r for r in json.loads(read(ROOT/'kernel_zone_startup_source.json'))['zone_startup_entries'] if r['identifier_u16'] in [22,23,24]]
 assert len(specs)==3
 for s in specs:
  r=next(r for r in rows if r['address']==s['entry_address']);assert (r['phase32'],r['rank32'])==(7,3)
  assert r['logical_bytes_hex'][16:32]==int(s['callback_pointer']['target'],16).to_bytes(8,'little').hex()
  assert r['logical_bytes_hex'][32:48]==int(s['specification_address'],16).to_bytes(8,'little').hex()
 spans=[]
 for label,(a,b) in SPANS.items():
  raw=k.read(a,b-a);ii=list(k.cs.disasm(raw,a));assert len(ii)*4==len(raw)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(b),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 literals=[]
 for a in [0xfffffe0007056bf9,0xfffffe0007056c0b,0xfffffe0007056c1a,0xfffffe0007056c2e,0xfffffe0007056c3a,0xfffffe0007056c44,0xfffffe0007056c52,0xfffffe0007056c73]:
  b=k.read(a,128).split(bytes(1))[0];literals.append({'address':hex(a),'bytes_hex':(b+bytes(1)).hex(),'text':b.decode('ascii')})
 calls=[]
 for i in k.cs.disasm(bytes.fromhex(functions[0]['bytes']),CALLER):
  if i.mnemonic=='bl':calls.append({'pc':hex(i.address),'target':hex(i.operands[0].imm&((1<<64)-1))})
 counts={'captured_functions':len(functions),'captured_instructions':sum(len(f['instructions']) for f in functions),
  'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'matched_prior_functions':matched,
  'source_blocks':len(spans),'block_instructions':sum(len(s['instructions']) for s in spans),
  'startup_records_rechecked':len(old['records']),'startup_pointer_fixups_rechecked':sum(len(r['fixups']) for r in old['records']),
  'phase6_records':sum(r['phase32']==6 for r in rows),'phase7_records':sum(r['phase32']==7 for r in rows),
  'unique_phase7_rank0_magazine':len(magazines),'selected_IPC_records':len(specs),'caller_direct_call_sites':len(calls)}
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'dependencies':{n:sha(ROOT/n) for n in ['kernel_native_reader.py','kernel_vm_mig_tools.py','startup_dispatch_checks.json',
   'audit_startup_dispatch.py','kernel_magazine_bootstrap_checks.json','kernel_zone_startup_source.json','probe_kernel_magazine_bootstrap.py',
   'replay_kernel_magazine_bootstrap.py','audit_kernel_magazine_bootstrap.py']},
  'functions':functions,'spans':spans,'caller_direct_calls':calls,'literals':literals,'startup_section':table,
  'phase6_phase7_records':rows,'phase7_rank_histogram':{str(r):n for r,n in sorted(Counter(r['rank32'] for r in rows if r['phase32']==7).items())},
  'magazine_startup_record':magazines[0],'selected_IPC_specifications':specs,
  'exact_symbols':k.symbols([*FUNCTIONS,*HELPERS,0xfffffe000be577f0,0xfffffe000be57bec,DESCRIPTORS,SECURITY,
   0xfffffe000cb29cb0,0xfffffe000cb29cb4,0xfffffe000cae4dc0,*[a for r in OBJECTS for a in r[:2]]]),
  'shared_sane_size_word':{'address':'0xfffffe000cb29cb0','size_bytes':8,'file_bytes_hex':k.read(0xfffffe000cb29cb0,8).hex(),
   'policy_high_word_address':'0xfffffe000cb29cb4','policy_load_PC':'0xfffffe000c632190','caller_load_PC':'0xfffffe000c63500c'},
  'verified_counts':counts,'conditional_kernel_zone_boot_order_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
