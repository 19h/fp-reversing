#!/usr/bin/env python3
"""Original VM range cursor, packed entry lookup and type2 factory interfaces.
O(image+captured bytes), O(image+source); no native VM operation or IDB mutation.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
P='kernel_vm_range_cursor'
def main():
 im=Image();out=dict(json.loads((ROOT/'rpc502_vm_handoff_source.json').read_text()));starts=list(dict.fromkeys([*[int(f['start'],16)for f in out['functions']],0xfffffe000be31808,0xfffffe000be318e8,0xfffffe000be3218c,0xfffffe000bdc7274,0xfffffe000bddd5dc,0xfffffe000be33a44,0xfffffe000bdd20d8,0xfffffe000bdd21fc,0xfffffe000bdc6608,0xfffffe000be32a0c,0xfffffe000be32b84,0xfffffe000be32954,0xfffffe000be3397c,0xfffffe000be313a4,0xfffffe000be2fdb8,0xfffffe000be2ff8c,0xfffffe000be2fea8,0xfffffe000bdd2750]));funcs=[]
 for a in starts:
  f=im.k.function(a,exact=True);f['exact_symbols']=im.k.symbols([a])[hex(a)];funcs.append(f)
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in ['rpc502_vm_handoff_source.json','rpc502_reply_copyin_profiles.json','kernel_vm_mig_tools.py',P+'_prior_manifest.json']},functions=funcs,callback_global={'address':'0xfffffe000cae4e58','bytes_hex':im.k.read(0xfffffe000cae4e58,4).hex(),'exact_symbols':im.k.symbols([0xfffffe000cae4e58])['0xfffffe000cae4e58']},range_callback={'object_address':'0xfffffe0007e6a140','pointer':im.pointer(0xfffffe0007e6a150),'exact_symbols':im.k.symbols([0xfffffe000bdd2750])['0xfffffe000bdd2750']},cursor_marker={'address':'0xfffffe000cb0bf18','exact_symbols':im.k.symbols([0xfffffe000cb0bf18])['0xfffffe000cb0bf18']},native_target_executed=False,native_VM_effects_executed=False,native_retirement_executed=False,native_namespace_conversion_executed=False,native_IPC_executed=False,hardware_PAC_executed=False,idb_mutated=False,complete_FairPlay_round_trip_established=False,full_goal_complete=False);(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'cursor_marker':out['cursor_marker']}),flush=True)
if __name__=='__main__':main()
