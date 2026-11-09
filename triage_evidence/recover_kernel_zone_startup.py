#!/usr/bin/env python3
"""Original startup zone specifications, creator and embedded zone-view identity.
O(image+fixups+source), O(image+catalog+source). No native startup/IPC/IDB effects.
"""
import json,struct
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_zone_startup';STARTUP=0xfffffe000c63222c;CREATE=0xfffffe000bd772b4;CACHEINIT=0xfffffe000bd77bb0;ARRAY=0xfffffe000caeb480
def main():
 im=Image();old=json.loads((ROOT/'kernel_kmsg_allocation_source.json').read_text());out=dict(old);starts=[*[int(f['start'],16)for f in old['functions']],STARTUP,CREATE,CACHEINIT];syms=im.k.symbols(starts);funcs=[]
 for a in starts:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];funcs.append(f)
 entries=[]
 for off,row in im.meta.items():
  if row['target']!=hex(STARTUP):continue
  sg=next(s for s in im.k.root['segments']if s['file_offset']<=off<s['file_offset']+s['file_size']);slot=sg['address']+off-sg['file_offset'];arg=im.pointer(slot+8);a=int(arg['target'],16);raw=im.k.read(a,48);nameptr=im.pointer(a+8);name=im.k.read(int(nameptr['target'],16),128).split(b'\0')[0];ident=struct.unpack_from('<H',raw,32)[0];publication=im.pointer(a)if raw[:8]!=bytes(8)else None;setup=im.pointer(a+40)if raw[40:48]!=bytes(8)else None;section=next(s for s in im.k.kernel['sections']if s['address']<=a<s['address']+s['size'])
  entries.append({'entry_address':hex(slot-8),'entry_bytes24_hex':im.k.read(slot-8,24).hex(),'subsystem_word0':int.from_bytes(im.k.read(slot-8,4),'little'),'rank_word4':int.from_bytes(im.k.read(slot-4,4),'little'),'callback_pointer':im.pointer(slot),'argument_pointer':arg,'specification_address':hex(a),'specification_bytes48_hex':raw.hex(),'specification_section':section,'name_pointer':nameptr,'name':name.decode(),'requested_size_u64':int.from_bytes(raw[16:24],'little'),'flags_u64':int.from_bytes(raw[24:32],'little'),'identifier_u16':ident,'optional_publication_pointer':publication,'optional_setup_object':setup,'fixed_zone_address':hex(ARRAY+192*ident)if ident<40 else None})
 entries.sort(key=lambda e:int(e['entry_address'],16));out.pop('candidate_kmsg_initialization_record',None);out['resolved_kmsg_startup_specification']={**next(e for e in entries if e['name']=='ipc kmsgs'),'static_fixed_slot_relationship_established':True,'native_runtime_identity_observed':False};assert any(e['name']=='ipc kmsgs'and e['identifier_u16']==24 and e['requested_size_u64']==256 for e in entries)
 sites=[0xfffffe000c632240,0xfffffe000c632248,0xfffffe000c632250,0xfffffe000c63225c,0xfffffe000bd7733c,0xfffffe000bd7734c,0xfffffe000bd7747c,0xfffffe000bd77590,0xfffffe000bd77708,0xfffffe000bd77c54,0xfffffe000bd77c6c,0xfffffe000bd77cb4]
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_kmsg_allocation_source.json','kernel_kmsg_allocation_profiles.json','kernel_send_right_lifecycle_profiles.json','kernel_vm_mig_tools.py','kext_port_tools.py']},functions=funcs,zone_startup_entries=entries,zone_array_base=hex(ARRAY),zone_array_stride_bytes=192,startup_instruction_roles={hex(a):{'pc':hex(a),'bytes_hex':im.k.read(a,4).hex(),'instruction':next(i for i in im.k.function(a,exact=False)['instructions']if i['ea']==hex(a))}for a in sites},selected_slot_file_images=[{'identifier':i,'address':hex(ARRAY+192*i),'bytes192_hex':im.k.read(ARRAY+192*i,192).hex()}for i in[16,19,22,23,24]],startup_execution_order_established=False,native_zone_population_established=False,**{k:False for k in FLAGS});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'startup_entries':len(entries),'fixed_entries':[(e['name'],e['identifier_u16'],e['requested_size_u64'])for e in entries if e['identifier_u16']in[16,19,22,23,24]]}),flush=True)
if __name__=='__main__':main()
