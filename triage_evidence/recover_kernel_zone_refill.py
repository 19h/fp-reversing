#!/usr/bin/env python3
"""Original magazine refill, partial-page fill and bitmap selection contracts.
O(image+source), O(image+source). No native allocation, IPC or IDB effects.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_zone_refill';STARTS=[0xfffffe000bd75e20,0xfffffe000bd76db4,0xfffffe000bd76ad0]
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_zone_startup_source.json').read_text()));starts=[*[int(f['start'],16)for f in out['functions']],*STARTS];syms=im.k.symbols(starts);funcs=[]
 for a in starts:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];funcs.append(f)
 sites=[0xfffffe000bd75e4c,0xfffffe000bd75ea4,0xfffffe000bd760f4,0xfffffe000bd76140,0xfffffe000bd7614c,0xfffffe000bd761fc,0xfffffe000bd76208,0xfffffe000bd76290,0xfffffe000bd76e24,0xfffffe000bd76f14,0xfffffe000bd76f6c,0xfffffe000bd76f90,0xfffffe000bd76fd0,0xfffffe000bd771a4,0xfffffe000bd771d8,0xfffffe000bd76b34,0xfffffe000bd76be0,0xfffffe000bd76c7c]
 roles={}
 for a in sites:i=next(im.k.cs.disasm(im.k.read(a,4),a));roles[hex(a)]={'pc':hex(a),'bytes_hex':im.k.read(a,4).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_zone_startup_source.json','kernel_zone_startup_profiles.json','kernel_vm_mig_tools.py','kext_port_tools.py']},functions=funcs,refill_instruction_roles=roles,new_function_entries=[hex(a)for a in STARTS],original_control_globals=[{'address':hex(a),'bytes_hex':im.k.read(a,n).hex()}for a,n in[(0xfffffe000cb0bc50,4),(0xfffffe000cb115b0,4),(0xfffffe000ca92380,1),(0xfffffe0007e66f00,8),(0xfffffe0007e66e70,8)]],native_cache_refill_observed=False,**{k:False for k in FLAGS});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'new_functions':len(STARTS)}),flush=True)
if __name__=='__main__':main()
