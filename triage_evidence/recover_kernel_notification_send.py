#!/usr/bin/env python3
"""Original send-only wrapper, preparation/copyin, common send and caller return.
O(image+captured bytes), O(image+source). No native target, IPC or IDB effects.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_notification_send';STARTS=[0xfffffe000bcf55dc,0xfffffe000bcc68c4,0xfffffe000bcc6b10,0xfffffe000bcc9718,0xfffffe000bcc4194,0xfffffe000bcc2104,0xfffffe000bcc7040,0xfffffe000bcd0448,0xfffffe000bcc24a4,0xfffffe000bcc2974]
def main():
 im=Image();syms=im.k.symbols(STARTS);funcs=[]
 for a in STARTS:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];funcs.append(f)
 sites=[0xfffffe000bcc69f0,0xfffffe000bcc6ae8,0xfffffe000bcc6cc8,0xfffffe000bcc6bc0,0xfffffe000bcf5610,0xfffffe000bcf564c,0xfffffe000bcf5678,0xfffffe000bcc7080,0xfffffe000bcf5698,0xfffffe000bcd059c]
 deps=[P+'_prior_manifest.json','kernel_send_right_lifecycle_profiles.json','kernel_reply_send_source.json','kernel_rpc_transport_contracts.json','kernel_vm_mig_tools.py','kext_port_tools.py']
 opaque=json.loads((ROOT/'kernel_reply_send_source.json').read_text())['opaque_hash'];assert im.k.read(int(opaque['start'],16),int(opaque['end'],16)-int(opaque['start'],16)).hex()==opaque['bytes_hex']
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'kernel_sha256':im.k.sha256,'functions':funcs,'opaque_keyed_hash':opaque,'exact_instruction_roles':{hex(a):{'pc':hex(a),'bytes_hex':im.k.read(a,4).hex(),'instruction':next(i for i in im.k.function(a,exact=False)['instructions']if i['ea']==hex(a))}for a in sites},'disposition_translation':{'address':'0xfffffe0007010ab0','words6_u32':[int.from_bytes(im.k.read(0xfffffe0007010ab0+4*j,4),'little')for j in range(6)]},'kernel_trailer_template':{'address':'0xfffffe0007010a68','bytes68_hex':im.k.read(0xfffffe0007010a68,68).hex()},**{k:False for k in FLAGS}};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs)}),flush=True)
if __name__=='__main__':main()
