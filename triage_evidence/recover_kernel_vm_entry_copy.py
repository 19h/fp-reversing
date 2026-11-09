#!/usr/bin/env python3
"""Original type2 entry-copy, cursor release and copy-list interfaces.
O(image+captured bytes), O(image+source). No native VM, IPC or IDB change.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
P='kernel_vm_entry_copy'
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_vm_range_cursor_source.json').read_text()));starts=list(dict.fromkeys([*[int(f['start'],16)for f in out['functions']],0xfffffe000bdc6728,0xfffffe000bdee258,0xfffffe000bde11e0,0xfffffe000be3431c,0xfffffe000be344c8,0xfffffe000be304e8,0xfffffe000bdd014c,0xfffffe000bde1248,0xfffffe000bde7448]));funcs=[]
 for a in starts:
  f=im.k.function(a,exact=True);f['exact_symbols']=im.k.symbols([a])[hex(a)];funcs.append(f)
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in ['kernel_vm_range_cursor_source.json','kernel_vm_range_cursor_profiles.json','rpc502_reply_copyin_profiles.json','kernel_vm_mig_tools.py',P+'_prior_manifest.json']},functions=funcs,entry_initializer_constant={'address':'0xfffffe000700dc38','bytes_hex':im.k.read(0xfffffe000700dc38,8).hex()},entry_zone_file={'address':'0xfffffe000caec140','bytes_hex':im.k.read(0xfffffe000caec140,16).hex(),'runtime_identity_established':False});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'entry_initializer_constant':out['entry_initializer_constant']}),flush=True)
 for a in [0xfffffe000bdc6728,0xfffffe000bdee258,0xfffffe000bde11e0,0xfffffe000be3431c]:
  f=next(f for f in funcs if f['start']==hex(a));print(f['start'],len(f['instructions']));print('\n'.join(i['ea']+' '+i['mnemonic']+' '+i['operands']for i in f['instructions'][:55]))
if __name__=='__main__':main()
