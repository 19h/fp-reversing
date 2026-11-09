#!/usr/bin/env python3
"""Original kmsg constructor, populated zone-cache allocator and zero check.
O(image+captured bytes+fixups), O(image+source). Startup-record interpretation
and runtime zone population are distinct; no native target/IPC/IDB effects.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_kmsg_allocation'
def main():
 im=Image();old=json.loads((ROOT/'kernel_notification_send_source.json').read_text());out=dict(old);starts=[*[int(f['start'],16)for f in old['functions']],0xfffffe000bd75c64,0xfffffe000bc9d9c0,0xfffffe000bd76394];syms=im.k.symbols(starts);funcs=[]
 for a in starts:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];funcs.append(f)
 sites=[0xfffffe000bcc2530,0xfffffe000bcc2688,0xfffffe000bcc2690,0xfffffe000bcc2698,0xfffffe000bcc26a4,0xfffffe000bcc26c0,0xfffffe000bcc26f4,0xfffffe000bd75c88,0xfffffe000bd75ccc,0xfffffe000bd75cd4,0xfffffe000bd75ce4,0xfffffe000bd75cf8,0xfffffe000bd75d1c,0xfffffe000bd75d94,0xfffffe000bd769bc]
 record={'address':'0xfffffe000cbc8310','bytes48_hex':im.k.read(0xfffffe000cbc8310,48).hex(),'name_pointer':im.pointer(0xfffffe000cbc8318),'name_address':'0xfffffe000704984a','name_bytes_hex':im.k.read(0xfffffe000704984a,10).hex(),'adjacent_size_word_address':'0xfffffe000cbc8320','adjacent_size_word_u64':int.from_bytes(im.k.read(0xfffffe000cbc8320,8),'little'),'startup_consumer_and_runtime_zone_identity_established':False};assert record['adjacent_size_word_u64']==256
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_notification_send_source.json','kernel_notification_send_profiles.json','kernel_send_right_lifecycle_profiles.json','kernel_vm_mig_tools.py','kext_port_tools.py']},functions=funcs,allocation_instruction_roles={hex(a):{'pc':hex(a),'bytes_hex':im.k.read(a,4).hex(),'instruction':next(i for i in im.k.function(a,exact=False)['instructions']if i['ea']==hex(a))}for a in sites},original_kmsg_zone_cells={'address':'0xfffffe000caec680','bytes16_hex':im.k.read(0xfffffe000caec680,16).hex(),'native_runtime_value_established':False},candidate_kmsg_initialization_record=record,**{k:False for k in FLAGS});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'candidate_size_word':record['adjacent_size_word_u64']}),flush=True)
if __name__=='__main__':main()
