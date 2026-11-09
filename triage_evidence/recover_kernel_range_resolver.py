#!/usr/bin/env python3
"""Original range bitmap allocator, record producer and free-interval helpers.
O(image+source bytes), O(image+source). No native VM/IPC or IDB effects.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
P='kernel_range_resolver'
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_map_store_init_source.json').read_text()));starts=list(dict.fromkeys([*[int(f['start'],16)for f in out['functions']],0xfffffe000bddee0c,0xfffffe000bdde280,0xfffffe000bdddbd8]));funcs=[]
 for a in starts:
  f=im.k.function(a,exact=True);f['exact_symbols']=im.k.symbols([a])[hex(a)];funcs.append(f)
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in ['kernel_map_store_init_source.json','kernel_map_store_init_profiles.json','kernel_vm_entry_copy_profiles.json','kernel_vm_mig_tools.py',P+'_prior_manifest.json']},functions=funcs,range_file_cells=[{'address':hex(a),'bytes_hex':im.k.read(a,n).hex(),'native_runtime_value_established':False}for a,n in[(0xfffffe0007e69fe0,16),(0xfffffe000cb80d60,0x1c0),(0xfffffe000cb810e0,8),(0xfffffe000caec380,16)]]);(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs)}),flush=True)
if __name__=='__main__':main()
