#!/usr/bin/env python3
"""Original upstream filename-copyin/factory provenance, static only.
Conditional factory path does not attest actual runtime copy representation.
O(original collection/source bytes) time/space. No target execution.
"""
import json
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
def recover():
 image=Image();k=image.k;functions=[k.function(a)for a in [0xfffffe000bdd1594,0xfffffe000bdd15a4]];spans=[]
 for role,a,z in [('kext_copyin_arguments',0xfffffe000a60b75c,0xfffffe000a60b788),('small_copy_gate',0xfffffe000bdd16b4,0xfffffe000bdd16dc),('map_interval_gate',0xfffffe000bdd183c,0xfffffe000bdd186c),('kernel_buffer_factory',0xfffffe000bdd1ee8,0xfffffe000bdd1f3c)]:
  raw=k.read(a,z-a);spans.append({'role':role,'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(raw,a)]})
 allcode={int(e['ea'],16):(e['mnemonic'],e['operands'])for f in functions for e in f['instructions']}
 for a,pair in {0xfffffe000bdd159c:('cset','w3, ne'),0xfffffe000bdd15a0:('b','#0xfffffe000bdd15a4'),0xfffffe000bdd16c8:('cmp','x2, #8, lsl #12'),0xfffffe000bdd1f0c:('stp','x23, xzr, [x0, #0x20]'),0xfffffe000bdd1f14:('mov','w8, #3'),0xfffffe000bdd1f18:('strb','w8, [x0, #0x2d]'),0xfffffe000bdd1f24:('pacda','x17, x16'),0xfffffe000bdd1f28:('str','x17, [x0]')}.items():assert allcode[a]==pair
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kext_port_vm_contracts.json','kernel_rpc_transport_contracts.json','rpc502_receive_bridge_checks.json']},'kernel_sha256':k.sha256,'functions':functions,'source_spans':spans,'verified_counts':{'original_functions':2,'function_instructions':sum(len(f['instructions'])for f in functions),'review_spans':4,'exact_instruction_role_checks':8},'conditional_factory_fields':{'size':'copy+0x20=input extent X23','type':'copy+0x2d=3','payload_pointer':'copy+0 stores logical X24, DA discriminator 0xb7af','small_copy_gate_bytes':32768},'actual_copy_type_established':False,'entry_list_expansion_reachable_from_ordinary_kext_request_established':False,'native_factory_or_mapping_executed':False,'all_checks_pass':True,'full_goal_complete':False}
if __name__=='__main__':
 c=recover();(ROOT/'rpc502_receive_bridge_copyin.json').write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
