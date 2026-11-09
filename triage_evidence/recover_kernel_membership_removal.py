#!/usr/bin/env python3
"""Read-only static extraction, trap/MIG binding and ownership-path capture.
No target instruction execution/emulation, IPC, scheduler or namespace mutation.
O(image+fixups+symbols+capture+hash bytes), O(image+fixups+capture).
"""
import hashlib,json,struct
from pathlib import Path
from kernel_vm_mig_tools import Image
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
ROOT=Path(__file__).resolve().parent;P='kernel_membership_removal'
FLAGS=['native_target_executed','target_instructions_emulated','native_IPC_executed','native_namespace_effects_observed','native_right_retirement_observed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']
EXTRACT_HANDLER=0xfffffe000bcdbd34;CORE=0xfffffe000bcdffd8;PAIR=0xfffffe000bcc936c;UNLINK=0xfffffe000bd6d9c0;RPC_STUB=0xfffffe000bd87b68
KERNEL=[EXTRACT_HANDLER,CORE,PAIR,UNLINK,RPC_STUB,0xfffffe000bcdb844,0xfffffe000bcdb8b0,0xfffffe000bcdbcc4,0xfffffe000bcde540,0xfffffe000bcde6d8,0xfffffe000bcdfec8,0xfffffe000bf08714,0xfffffe000bcfb4f0,0xfffffe000bcfadc0]
LIBRARY=[0x18054b360,0x180547b04,0x18056dcb0,0x18054906c,0x180547ac8,0x18056c8a4,0x180548320,0x180547ad4,0x18056c9c0]
FRONTIERS={0xfffffe000bcd2fbc:'two_name_namespace_lookup',0xfffffe000bd0b348:'space_unlock',0xfffffe000bccc128:'member_object_lock',0xfffffe000bcd2378:'set_object_lock',0xfffffe000bd0ab18:'object_unlock',0xfffffe000bd7a4b8:'returned_link_storage_free',0xfffffe000c629ba0:'namespace_diagnostic_or_guard_call',0xfffffe000bcd3cfc:'right_deallocation_dispatch',0xfffffe000bcd4250:'right_mod_refs_dispatch'}
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def build():
 im=Image();symbols=im.k.symbols(KERNEL+list(FRONTIERS));fs=[]
 for a in KERNEL:f=im.k.function(a);f['exact_symbols']=symbols[hex(a)];fs.append(f)
 tables=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text());traps=[]
 for index in(18,19,22,23):
  row=tables['mach_entries'][index];ptr=im.pointer(0xfffffe0007efb010+24*index+8);munger=im.pointer(0xfffffe0007efb010+24*index+16);assert ptr['raw']==row['handler_pointer']['raw']and ptr['target']==row['handler_pointer']['target']and munger['target']==row['munger_pointer']['target'];traps.append({'index':index,'signed_selector':-index,'table_name':row['name'],'argument_count':row['argument_count'],'u32_words':row['u32_words'],'handler_pointer':ptr,'munger_pointer':munger})
 sub=next(s for s in im.subsystems()if s['start']<=3227<s['end']);routine=next(r for r in sub['routines']if r['id']==3227);assert routine['stub']['target']==hex(RPC_STUB);sub={k:sub[k]for k in('registry_index','registry_pointer','address','selector','start','end','maximum','header_bytes_hex')}
 c=Cache();lk=Dylib(c,'/usr/lib/system/libsystem_kernel.dylib');cf=Dylib(c,'/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation');lf=[]
 for lib,a in[(lk,a)for a in LIBRARY]+[(cf,0x18477921c)]:f=lib.function(a);f['exact_nlist']=lib.symbols_at(a);lf.append(f)
 constants=[{'address':hex(a),'bytes8_hex':c.read(a,8).hex()}for a in(0x18057d380,0x18057d6c0,0x1eb065de0)];a=0x188085b70;raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(cell);assert ptr['target']=='0x18054b360'
 task_binding=c.pointer(0x1e01c8b30);assert task_binding['target']=='0x1ed83e960';task_binding['exact_nlist']=lk.symbols_at(0x1ed83e960);assert any(e['name']=='_mach_task_self_'for e in task_binding['exact_nlist'])
 frontiers=[{'address':hex(a),'role_inference':role,'prefix16_hex':im.k.read(a,16).hex(),'exact_symbols':symbols[hex(a)]}for a,role in FRONTIERS.items()];files=sorted(c.used|{str(CACHE)})
 return{'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kernel_vm_mig_tools.py','bootpolicy_cache_reader.py','kernel_dispatch_contracts.json','daemon_service_cf_lifecycle_source.json','daemon_service_cf_lifecycle_checks.json','cf_mach_port_retirement_source.json','kernel_portset_delivery_source.json']},'kernel_sha256':im.k.sha256,'kernel_UUID':im.k.kernel.get('uuid'),'kernel_functions':fs,'kernel_NDR8_hex':im.k.read(0xfffffe000ca92798,8).hex(),'original_trap_bindings':traps,'MIG_subsystem':sub,'MIG_routine_3227':routine,'kernel_frontiers':frontiers,'cache_uuid':c.uuid,'library_uuid':lk.uuid,'CF_uuid':cf.uuid,'cache_functions':lf,'cache_constants':constants,'task_self_static_binding':task_binding,'original_CF_stub':{'address':hex(a),'bytes16_hex':raw.hex(),'pointer':ptr,'exact_export':'_mach_port_extract_member','export':lk.exports['_mach_port_extract_member']},'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files],**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'kernel_functions':len(s['kernel_functions']),'kernel_instructions':sum(len(f['instructions'])for f in s['kernel_functions']),'cache_functions':len(s['cache_functions']),'cache_instructions':sum(len(f['instructions'])for f in s['cache_functions']),'cache_files':len(s['cache_files'])}),flush=True)
