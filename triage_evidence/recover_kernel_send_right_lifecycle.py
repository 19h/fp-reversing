#!/usr/bin/env python3
"""Original host-slot acquisition, send-reference release and notification source.
O(image+captured bytes), O(image+source). No native IPC, target or IDB operations.
"""
import json,hashlib
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
P='kernel_send_right_lifecycle';STARTS=[0xfffffe000bcf27ac,0xfffffe000bcf258c,0xfffffe000bcd00bc,0xfffffe000bcd0448,0xfffffe000bcc8f4c,0xfffffe000bcce494,0xfffffe000bcc922c,0xfffffe000bcc90a0]
FLAGS=['native_target_executed','native_VM_effects_executed','native_retirement_executed','native_namespace_conversion_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']
def main():
 im=Image();funcs=[]
 for a in STARTS:
  f=im.k.function(a);f['exact_symbols']=im.k.symbols([a])[hex(a)];funcs.append(f)
 types=[]
 for j in range(13):
  a=0xfffffe0007e62b70+40*j;p=im.pointer(a);b=im.k.read(int(p['target'],16),100).split(b'\0')[0];types.append({'index':j,'address':hex(a),'bytes40_hex':im.k.read(a,40).hex(),'name_pointer':p,'name':b.decode(),'flags_u16':int.from_bytes(im.k.read(a+8,2),'little')})
 sdk=[]
 for name in['message.h','notify.h']:
  q=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach')/name;lines=q.read_text().splitlines();sdk.append({'path':str(q),'sha256':sha(q),'selected_definitions':[{'line':j+1,'text':s}for j,s in enumerate(lines)if s.startswith('#define MACH_MSG_TYPE_MOVE_SEND_ONCE')or s.startswith('#define MACH_NOTIFY_FIRST')or s.startswith('#define MACH_NOTIFY_NO_SENDERS')]})
 sites=[0xfffffe000bcd04dc,0xfffffe000bcd04e4,0xfffffe000bcd052c,0xfffffe000bcd0598,0xfffffe000bcd060c,0xfffffe000bcd0170,0xfffffe000bcd015c,0xfffffe000bcc8fe4,0xfffffe000bcf2678,0xfffffe000bcf2684]
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kext_vm_copyout_bridge_profiles.json','kernel_vm_mig_tools.py','kext_port_tools.py']},'kernel_sha256':im.k.sha256,'functions':funcs,'port_type_descriptors':types,'exact_instruction_roles':{hex(a):{'pc':hex(a),'bytes_hex':im.k.read(a,4).hex(),'instruction':next(i for i in im.k.function(a,exact=False)['instructions']if i['ea']==hex(a))}for a in sites},'boundary_symbols':im.k.symbols([0xfffffe000bcf55dc,0xfffffe000bd0aecc,0xfffffe000bd0ab18,0xfffffe000c629ddc,0xfffffe000c641fa8,0xfffffe000bcc922c]),'notification_constants':[{'address':hex(a),'bytes8_hex':im.k.read(a,8).hex()}for a in[0xfffffe000700dc78,0xfffffe000700dc00,0xfffffe000ca92798]],'SDK_definitions':sdk,**{k:False for k in FLAGS}};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'type_descriptors':len(types)}),flush=True)
if __name__=='__main__':main()
