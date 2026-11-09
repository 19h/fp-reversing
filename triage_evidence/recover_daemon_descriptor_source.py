#!/usr/bin/env python3
"""Pin daemon descriptor setup/callback source, original binds and SDK layouts.
Original bytes and finite component boundaries; no native host/IPC/PAC effects.
O(binary bytes + retained code + import/IDA metadata) time and space.
"""
import json,struct,hashlib,re
from pathlib import Path
from daemon_receive_tools import ROOT,IMAGE,SOURCE,FIXUPS,CS,selected,TABLE,POOL
from daemon_import_bindings import binding
from recover_cf_wake_send_wrapper import FLAGS,sha
from bootpolicy_cache_reader import Cache,Dylib
from recover_cf_receive import CF_PATH
P='daemon_descriptor_source';INIT=0x100437c18;SETUP=0x10009689c;CALLBACK=0x10044f23c;WRAPPER=0x100001f2c;HEADER=0x1010c4cd8
STACK=0x70000000;STACK_SIZE=0x80000;HEAP=0x5000000000;IMPORTS=0x6000000000;HALT=0x6001000000;CFREF=HEAP+0x20000;CFSRC=HEAP+0x21000;MACHREF=HEAP+0x22000;RL=HEAP+0x23000;MODE=HEAP+0x3e000;ARG=STACK+0x1000;CBSP=STACK+0x60000;OUT=CBSP-0x149c
REGIONS=[(0x101038000,0x7c000),(0x1010b4000,0x18000),(STACK,STACK_SIZE),(HEAP,0x40000),(IMPORTS,0x100000)]
RANGES=[(WRAPPER,0x100001f50),(0x100e2a8c0,0x100e2a8d0),(CALLBACK,0x10044f60c),(SETUP,0x100096958),(0x1000979fc,0x100097b88),(0x10002f070,0x10002f14c),(0x1000933c0,0x100093518),(0x100387d8c,0x100387e7c),(0x1003977a8,0x1003977e4),(0x10035e268,0x10035e2b4),(0x1003c122c,0x1003c1334),(0x1000a352c,0x1000a35e8),(INIT,0x100437f90)]
SDK=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk')
def build():
 fs=[]
 for a,z in RANGES:
  raw=IMAGE.read(a,z-a);ins=list(CS.disasm(raw,a));assert len(ins)*4==len(raw);fs.append({'start':hex(a),'end':hex(z),'bytes':raw.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 cases=[('kqueue',0x100fc4230,0x101031fa0,0x6c,0xce93),('signal',0x100fc4130,0x101031ea0,0xbb,0xcd9a),('kevent registration',0x100e99a00,0x100f4e390,0xd7,0xcd7a),('CF descriptor wrapper',0x100fc4130,0x101031ea0,0xbb,0xce02),('descriptor enable',0x100fc4230,0x101031fa0,0x6c,0xcc8e),('descriptor source',0x100e99a00,0x100f4e390,0x9c,0xce7d),('get main loop',0x100fc4130,0x101031ea0,0xa3,0xcccf),('add source',0x100fc4230,0x101031fa0,0xf3,0xcd60),('release source',0x101031da0,0x100e99900,0xa,0xcb94)]
 banks=[]
 for label,*args in cases:banks.append({'label':label,**selected(*args)})
 slots={int(e['slot'],16)for e in banks}|{0x1010b1c30,0x10109fea0,0x1010a0a88};binds=[binding(a)for a in sorted(slots)if isinstance(FIXUPS[a]['target'],str)]
 # This data bind's nonzero addend is canceled by original ADD, not omitted.
 mode=selected(0x101031da0,0x100e99900,0x9a,0xbdb,POOL);mb=binding(int(mode['slot'],16));bias=-0x7ed8f1f2;assert mb['total_addend']+bias==0 and mb['symbol']=='_kCFRunLoopDefaultMode'
 ida=json.loads((ROOT/(P+'_ida.json')).read_text());txt=next(e['text']for e in ida['byte_readback']['content']if e['type']=='text');body=txt.split('[assist:tool-output]\n',1)[1].split('\n[/assist:tool-output]',1)[0];rows=json.loads(body)['results'];matches=[]
 for e in rows:b=bytes.fromhex(e['bytes']);assert IMAGE.read(int(e['address'],16),len(b))==b;matches.append({'address':e['address'],'bytes_checked':len(b),'match':True})
 headers=[SDK/'usr/include/sys/event.h',SDK/'usr/include/sys/signal.h',SDK/'System/Library/Frameworks/CoreFoundation.framework/Versions/A/Headers/CFFileDescriptor.h']
 prior=json.loads((ROOT/'cf_source_wake_callers_source.json').read_text());cs=prior['CF_source'];cache=Cache();cf=Dylib(cache,CF_PATH);stop=cf.function(0x184784250);assert cf.exports['_CFRunLoopStop']['address']==0x184784250 and next(f for f in cs['CF_functions']if f['start']=='0x184784250')['bytes']==stop['bytes']
 for e in cs['cache_files']:assert sha(e['path'])==e['sha256']
 return{'CF_source':cs,'root_caller_options':prior['root_caller_options'],'CF_stop_export':{'address':'0x184784250','nlist':cf.symbols_at(0x184784250),'original_function':stop,'daemon_binding':binding(0x1010a0690)},'scope':__doc__,'generator_sha256':sha(__file__),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in[P+'_ida.json','daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','daemon_registration_contracts.json','cf_source_wake_callers_source.json','cf_source_wake_callers_checks.json']},'original_ranges':fs,'exhaustive_banks_256':banks,'selected_bindings':binds,'default_mode_binding':{'bank':mode,'binding':mb,'original_signed_addition':hex(bias&((1<<64)-1)),'combined_addend':0},'IDA_original_byte_matches':matches,'SDK_headers':[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in headers],'scope_boundaries':{'setup_entry_register_state':hex(0x3a74),'whole_startup_reachability':'unknown','CF_source_construction':'declared lower API result','native_event_generation':'unknown','hardware_PAC':'unknown'},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'source_ranges':len(s['original_ranges']),'original_instructions':sum(len(f['instructions'])for f in s['original_ranges']),'banks_256':len(s['exhaustive_banks_256']),'bindings':len(s['selected_bindings']),'IDA_bytes_checked':sum(e['bytes_checked']for e in s['IDA_original_byte_matches'])}),flush=True)
