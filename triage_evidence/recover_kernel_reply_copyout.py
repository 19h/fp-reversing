#!/usr/bin/env python3
"""Capture matching-kernel type3 copyout/discard and release-call provenance.
O(original captured bytes) time/space. No target invocation or IDB mutation.
"""
import json
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha
FUNCTIONS=[0xfffffe000bdd1574,0xfffffe000bdcb374,0xfffffe000bdcbbb0,0xfffffe000bdc6308,0xfffffe000bcfec48,0xfffffe000bd74fcc,0xfffffe000bdcc234,0xfffffe000bdcc374]
def recover():
 k=Image().k;functions=[k.function(a,exact=True)for a in FUNCTIONS]
 roles={
 'wrapper_reads_object_extent':(0xfffffe000bdd157c,'ldr','x3, [x2, #0x20]'),
 'wrapper_consume':(0xfffffe000bdd1580,'mov','w4, #1'),
 'type3_dispatch':(0xfffffe000bdcb414,'bl','#0xfffffe000bdcbbb0'),
 'type3_allocate':(0xfffffe000bdcbe3c,'bl','#0xfffffe000bdc76b4'),
 'type3_current_map_copy':(0xfffffe000bdcbe54,'bl','#0xfffffe000be7798c'),
 'type3_other_map_copy':(0xfffffe000bdcbd44,'bl','#0xfffffe000be7798c'),
 'consume_gate':(0xfffffe000bdcbe5c,'cbz','w23, #0xfffffe000bdcbf50'),
 'clear_payload_before_release':(0xfffffe000bdcbf0c,'str','xzr, [x22]'),
 'payload_release':(0xfffffe000bdcbf1c,'bl','#0xfffffe000bcfec48'),
 'header_zero':(0xfffffe000bdcbf38,'bl','#0xfffffe000c6480c0'),
 'header_release':(0xfffffe000bdcbf4c,'bl','#0xfffffe000bd74fcc'),
 'discard_clear_payload':(0xfffffe000bdc64e8,'str','xzr, [x19]'),
 'discard_payload_release':(0xfffffe000bdc64f4,'bl','#0xfffffe000bcfec48'),
 'discard_header_release':(0xfffffe000bdc6544,'b','#0xfffffe000bd74fcc'),
 'context_result_pointer':(0xfffffe000bdcc254,'mov','x19, x8'),
 'context_saved_pointers':(0xfffffe000bdcc340,'stp','x22, x23, [x19]'),
 'context_saved_mode':(0xfffffe000bdcc344,'stp','w20, wzr, [x19, #0x10]'),
 'context_restore_pointers':(0xfffffe000bdcc38c,'ldp','x20, x21, [x0]'),
 }
 checks={}
 for name,(a,m,o)in roles.items():
  i=next(k.cs.disasm(k.read(a,4),a));assert(i.mnemonic,i.op_str)==(m,o);checks[name]={'pc':hex(a),'bytes_hex':i.bytes.hex(),'mnemonic':m,'operands':o}
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kernel_native_reader.py','kext_port_vm_contracts.json']},'kernel_sha256':k.sha256,'functions':functions,'exact_instruction_roles':checks,'exact_symbols':k.symbols([0xfffffe000bdd1574,0xfffffe000bdc6308,0xfffffe000be7798c,0xfffffe000c6480c0,0xfffffe000bcfec48,0xfffffe000bd74fcc]),'native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'kernel_reply_copyout_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'functions':len(r['functions']),'instructions':sum(len(f['instructions'])for f in r['functions']),'roles':len(r['exact_instruction_roles'])}))
