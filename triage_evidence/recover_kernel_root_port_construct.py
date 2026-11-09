#!/usr/bin/env python3
"""Original dispatch-root mach_port_construct handler/core/object/guard path.
Pinned original bytes and complete 24-byte caller options; lower task/raw/copy
contracts and logical PAC remain explicit. No native kernel or IPC executes.
"""
import json
from pathlib import Path
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_root_port_construct';CONSTRUCT=0xfffffe000bcdbda4;CORE=0xfffffe000bce00b8;ALLOC=0xfffffe000bccd000;INIT=0xfffffe000bccd170;PUBLISH=0xfffffe000bccb548;GUARD=0xfffffe000bce0624;COPYIN=0xfffffe000be76e18
SDK=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX27.0.sdk/usr/include/mach/port.h')
def caller_options():
 p=json.loads((ROOT/'cf_mode_construction_profiles.json').read_text());r=p['cases'][0];e=next(e for e in r['mode_models']if e['name']=='root_port_construct_contract');at=int(e['before']['registers31'][1],16);out=bytearray(24);seen=set();used=[]
 for w in r['source_writes']:
  a=int(w['address'],16);b=bytes.fromhex(w['after_hex'])
  if w['source_visit_index']>=e['before_source_visit_index']:break
  if max(at,a)<min(at+24,a+len(b)):
   for pos in range(max(at,a),min(at+24,a+len(b))):out[pos-at]=b[pos-a];seen.add(pos-at)
   used.append(w)
 assert seen==set(range(24))and bytes(out)==b'\x31'+bytes(23)
 return{'case':0,'options_pointer':hex(at),'bytes24_hex':out.hex(),'original_producer_writes':used,'kernel_call_contract_PC':e['pc'],'context':e['before']['registers31'][2]}
def build():
 im=Image();old=json.loads((ROOT/'kernel_portset_delivery_source.json').read_text());starts=sorted({int(f['start'],16)for f in old['functions']}|{CONSTRUCT,CORE,ALLOC,INIT,PUBLISH,GUARD});syms=im.k.symbols(starts);fs=[]
 for a in starts:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];fs.append(f)
 row=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text())['mach_entries'][24];ptr=im.pointer(0xfffffe0007efb010+24*24+8);assert ptr['target']==hex(CONSTRUCT)==row['handler_pointer']['target']and ptr['raw']==row['handler_pointer']['raw'];opts=caller_options();text=SDK.read_text();assert '#define MPO_CONTEXT_AS_GUARD                 0x01'in text and '#define MPO_INSERT_SEND_RIGHT                0x10'in text and '#define MPO_STRICT                           0x20'in text and 'uint64_t                   reserved[2]'in text
 return{**old,'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['kernel_portset_delivery_source.json','kernel_portset_delivery_profiles.json','kernel_zone_startup_profiles.json','cf_mode_construction_source.json','cf_mode_construction_profiles.json','cf_control_port_dispatch_source.json','kernel_dispatch_contracts.json','probe_kernel_portset_delivery.py','replay_kernel_portset_delivery.py','kernel_vm_mig_tools.py']},'functions':fs,'root_construct_trap_binding':{'index':24,'signed_selector':-24,'argument_count':row['argument_count'],'name':row['name'],'pointer':ptr},'root_caller_options':opts,'SDK_context':{'path':str(SDK),'sha256':sha(SDK),'runtime_version_equivalence':'unknown'},'root_lower_boundaries':[{'address':hex(a),'role':role,'bytes16_hex':im.k.read(a,16).hex()}for a,role in[(COPYIN,'declared_options_user_copyin'),(0xfffffe000bd75c64,'declared_zeroed_raw_port_storage'),(0xfffffe000bcfb4f0,'declared_task_name_conversion')]],'CF_source':json.loads((ROOT/'cf_control_port_dispatch_source.json').read_text())}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'kernel_functions':len(s['functions']),'kernel_instructions':sum(len(f['instructions'])for f in s['functions']),'options24':s['root_caller_options']['bytes24_hex']}),flush=True)
