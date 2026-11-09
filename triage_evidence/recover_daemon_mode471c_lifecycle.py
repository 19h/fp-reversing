#!/usr/bin/env python3
"""Capture original source, import/fixup and byte-owner contracts for mode471C.
O(source+events+bank bytes) time/space. Original bytes are primary; native incoming
phase, concurrency, publisher reachability and PAC behavior remain unknown.
"""
import json,hashlib,struct,subprocess
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,FIXUPS,qword,selected
from replay_daemon_descriptor_producers import unpack
from recover_daemon_descriptor_producers import verify_used_fixups
from daemon_import_bindings import binding
from replay_daemon_mode471c_lifecycle import SPECS

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 p=json.loads((ROOT/'daemon_mode471c_lifecycle_profiles.json').read_text());spans=[]
 for n,a,z in [('lazy_gate',0x10064ffbc,0x100650004),('slot_epoch',0x10097290c,0x10097291c),('creator_after',0x1009729d4,0x100972a24),('acquire_record_call',0x100933c2c,0x100933ce8),('cleanup_record_call',0x100a20470,0x100a20520),('field_gate',0x100b353a4,0x100b353fc),('zero_field_handler',0x1009df7a0,0x1009df80c),('nonzero_field_entry',0x1008bf64c,0x1008bf6f0),('nonzero_first_search',0x100bb01e8,0x100bb0248),('outer_free_boundary',0x10039c94c,0x10039c9ac),('outer_bank_roots',0x100387e40,0x100387e6c),('word_preservation',0x100975750,0x1009757a8),('publish_cell',0x1002097cc,0x1002097ec),('result_store',0x10095f074,0x10095f078)]:
  b=IMAGE.read(a,z-a);spans.append({'label':n,'start':hex(a),'end':hex(z),'bytes_hex':b.hex(),'sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]})
 paths=[];fix=set();pool={};retired=set()
 for r in p['cases']:
  t=unpack(r);F=int(t['initial_SP'],16);ops=t['api_models'];cfg=r['configuration'];fix.update(int(a,16)for a in t['used_fixups'])
  for e in r['prefix']['source_reads']:
   a=int(e['address'],16)
   if a in FIXUPS and e['size_bytes']==8:fix.add(a)
  pool.update({pc:s['bytes_hex']for pc,s in t['source_pool'].items()});retired.update(s['pc']for s in t['steps']);events=[]
  for s in t['steps']:
   for e in s['events']:
    a=int(e['address'],16)
    if (a in [0x1010c67c0,0x1010c67d0,0x1010c9288,0x1010c67a8]or a in[F+0x2a70,F+0xde90,F+0xde98,F+0xdea0]or s['pc']=='0x10095f074'):events.append({'pc':s['pc'],**e})
  paths.append({'configuration':cfg,'source_visits':r['source_visits'],'calls':[{'pc':x['pc'],'name':x['name'],'arguments2':x['arguments8'][:2],'configuration':x.get('configuration'),'returned_status32':x.get('returned_status32'),'callback_invoked':x.get('callback_invoked',False)}for x in ops],'events':events,'boundary':t['boundary']['pc'],'borrowed_owners':t['borrowed_owners'],'allocated_owners':t['allocated_owners'],'retired_owners':t['retired_owners'],'callback_pending':t['callback_pending']})
 selectors=[{'index':hex(i),'slot':hex(TABLE+i*8),'target':hex(qword(TABLE+i*8))}for i in[0x443f,0x447c,0x51d7,0x40c7,0x8210,0x821b,0x41e9]];fix.update(int(x['slot'],16)for x in selectors)
 rules=[('acquire_call',0x100fc4130,0x101031ea0,0xbb,0xcb38,TABLE,0),('cleanup_call',0x100e99700,0x100f4e190,0x81,0xcb5b,TABLE,0),('free_call',0x100fc4230,0x101031fa0,0xe4,0xcbab,TABLE,0)]
 roots=[{'offset_from_SP':hex(off),'pool_slot':hex(POOL+d),'bias':hex(bias),'value':hex((qword(POOL+d)+bias)&((1<<64)-1))}for off,d,bias in[(0xa28,0x60f0,0xffffffffa75b1642),(0xa30,0x2240,0xfffffffffa184636)]];assert [x['value']for x in roots]==['0x100fc4230','0x101031fa0'];fix.update(int(x['pool_slot'],16)for x in roots if int(x['pool_slot'],16)in FIXUPS)
 banks=[]
 for n,l,r,k,add,b,bias in rules:
  try:x=selected(l,r,k,add,b,bias)
  except AssertionError as e:raise AssertionError((n,str(e)))
  banks.append({'label':n,**x});fix.add(int(x['slot'],16))
 sdk=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk');cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-fsyntax-only',str(ROOT/'daemon_mode471c_lifecycle_sdk.c')];cp=subprocess.run(cmd,capture_output=True,text=True);assert cp.returncode==0;(ROOT/'daemon_mode471c_lifecycle_sdk_compile.txt').write_text(cp.stdout+cp.stderr)
 sdkheaders=[sdk/'usr/include/pthread.h',sdk/'usr/include/sys/_pthread/_pthread_types.h'];trace=Path('/Users/___/Downloads/zut/annotated-strace-rax-user.txt')
 deps=['daemon_mode471c_lifecycle_profiles.json','daemon_mode471c_lifecycle_symbolic.py','daemon_rwlock_lifecycle_contracts.json','daemon_rwlock_lifecycle_proofs.json','daemon_iokit_sync_contracts.json','daemon_mode471c_lifecycle_live_ida.json','daemon_mode471c_lifecycle_sdk.c','daemon_mode471c_lifecycle_sdk_compile.txt'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'banks_exhaustive256':banks,'original_fixups':verify_used_fixups(fix),'selectors':selectors,'source_derived_initial_roots':roots,'paths':paths,'distinct_continuation_retired_opcodes':len(retired),'distinct_continuation_inspected_opcodes':len(pool),'imported_APIs':{hex(pc):{'name':name,'modifier16':hex(div),'binding':binding(slot)}for pc,(name,slot,div)in SPECS.items()},'sdk_compile':{'command':cmd,'exit_code':cp.returncode,'headers':[{'path':str(h),'sha256':sha(h)}for h in sdkheaders],'sizeof_pthread_once_t_bytes':16,'sizeof_pthread_rwlock_t_bytes':200,'sizeof_pointer_bytes':8,'sizeof_int_bytes':4,'native_program_executed':False},'annotated_trace':{'path':str(trace),'size_bytes':trace.stat().st_size,'sha256':sha(trace),'prior_audit':'zut_trap_argument_audit.json','new_native_emission_evidence':False},'field_cells':{'lock':'0x1010c67c0','u32_tested_field':'0x1010c67d0','key_array_pointer':'0x1010c67a8','payload_base_pointer':'0x1010c9288','record_stride_bytes':32,'key_stride_bytes':16,'native_shared_structure_membership':'unknown','native_publishers':'unknown'},'boundary':'0x10039c998','native_target_executed':False,'idb_mutated':False,'fresh_IDB_bytes_verified':0,'full_goal_complete':False};(ROOT/'daemon_mode471c_lifecycle_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'banks256':len(banks),'fixups':len(out['original_fixups']['records']),'retired_opcodes':len(retired),'inspected_opcodes':len(pool),'sdk_compile_exit':cp.returncode}))
if __name__=='__main__':main()
