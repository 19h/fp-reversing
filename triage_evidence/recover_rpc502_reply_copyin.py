#!/usr/bin/env python3
"""Original outgoing reply OOL normalization, conversion, factory and cleanup.
O(captured bytes) time/space. Static collection reads; no target or IDB mutation.
"""
import json
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha
FUNCTIONS=[0xfffffe000bcc30b0,0xfffffe000bcc3fe8,0xfffffe000bcc42f0,0xfffffe000bdd15a4,0xfffffe000bcc2a1c,0xfffffe000bdc6308,0xfffffe000bdc2fc0]
def recover():
 k=Image().k;functions=[k.function(a,exact=True)for a in FUNCTIONS]
 roles={
 'body_call':(0xfffffe000bcc3fa0,'bl','#0xfffffe000bcc42f0'),
 'normalize_flags':(0xfffffe000bcc40ec,'and','w9, w9, #0xff0001ff'),
 'body_copyin':(0xfffffe000bcc44e4,'bl','#0xfffffe000bdd15a4'),
 'descriptor_copy_signature':(0xfffffe000bcc4a3c,'movk','x16, #0x5d4f, lsl #48'),
 'small_extent_gate':(0xfffffe000bdd16c8,'cmp','x2, #8, lsl #12'),
 'backing_copy':(0xfffffe000bdd1eb4,'bl','#0xfffffe000bdc2fc0'),
 'factory_extent':(0xfffffe000bdd1f0c,'stp','x23, xzr, [x0, #0x20]'),
 'factory_type3':(0xfffffe000bdd1f18,'strb','w8, [x0, #0x2d]'),
 'destroy_source_gate':(0xfffffe000bdd1f30,'tbnz','w19, #0, #0xfffffe000bdd1f60'),
 'source_remove_request':(0xfffffe000bdd1ffc,'bl','#0xfffffe000bdc3c2c'),
 'publish_copy':(0xfffffe000bdd1f38,'str','x22, [x25]'),
 'prefix_cleanup':(0xfffffe000bcc4af0,'bl','#0xfffffe000bcc2a1c'),
 'cleanup_discard':(0xfffffe000bcc2adc,'bl','#0xfffffe000bdc6308'),
 'cleanup_clear_descriptor':(0xfffffe000bcc2a60,'str','xzr, [x19]'),
 }
 checked={}
 for name,(a,m,o)in roles.items():
  i=next(k.cs.disasm(k.read(a,4),a));assert(i.mnemonic,i.op_str)==(m,o);checked[name]={'pc':hex(a),'bytes_hex':i.bytes.hex(),'mnemonic':m,'operands':o}
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kernel_native_reader.py','rpc502_reply_bridge_profiles.json','kernel_reply_copyout_source.json']},'kernel_sha256':k.sha256,'functions':functions,'exact_instruction_roles':checked,'exact_symbols':k.symbols([0xfffffe000bdd15a4,0xfffffe000bdc6308,0xfffffe000bdc2fc0]),'native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'rpc502_reply_copyin_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'functions':len(r['functions']),'instructions':sum(len(f['instructions'])for f in r['functions']),'roles':len(r['exact_instruction_roles'])}))
