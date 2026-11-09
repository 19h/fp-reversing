#!/usr/bin/env python3
"""Original type2 copyout range reservation, entry conversion and map insertion.
O(image+captured bytes), O(image+source). No native VM, IPC or IDB effects.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
P='kernel_type2_copyout'
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_vm_entry_copy_source.json').read_text()));starts=list(dict.fromkeys([*[int(f['start'],16)for f in out['functions']],0xfffffe000bdcbfcc,0xfffffe000bdcc14c,0xfffffe000bdc7434,0xfffffe000bde01b0,0xfffffe000bdca43c,0xfffffe000bdc8760,0xfffffe000bdc8ba4,0xfffffe000bde1300,0xfffffe000be2fac0,0xfffffe000bdde9ac,0xfffffe000bdcd914,0xfffffe000bddf0b0,0xfffffe000bddf2c8,0xfffffe000be2f754]));funcs=[]
 for a in starts:
  f=im.k.function(a,exact=True);f['exact_symbols']=im.k.symbols([a])[hex(a)];funcs.append(f)
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in ['kernel_vm_entry_copy_source.json','kernel_vm_entry_copy_profiles.json','rpc502_reply_copyin_profiles.json','kernel_vm_mig_tools.py',P+'_prior_manifest.json']},functions=funcs,type2_copyout_globals=[{'address':hex(a),'bytes_hex':im.k.read(a,n).hex(),'native_runtime_value_established':False}for a,n in[(0xfffffe000cb50620,4),(0xfffffe000cb0bc50,4),(0xfffffe0007e69f90,96)]],copyout_entry_initializer_constant={"address":"0xfffffe000700dc68","bytes_hex":im.k.read(0xfffffe000700dc68,8).hex()});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs)}),flush=True)
 for a in [0xfffffe000bdcbfcc,0xfffffe000bdcc14c,0xfffffe000bdc7434]:
  f=next(f for f in funcs if f['start']==hex(a));print(f['start'],len(f['instructions']));print('\n'.join(i['ea']+' '+i['mnemonic']+' '+i['operands']for i in f['instructions']if i['mnemonic'].startswith('b')or i['mnemonic']in ['retab','ret']))
if __name__=='__main__':main()
