#!/usr/bin/env python3
"""Capture original common receive/dequeue and recipient field readers.
O(collection/fixup/source bytes) time/space. No native target or IPC.
"""
import json
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
RECEIVE=0xfffffe000bcc83b4;ON_THREAD=0xfffffe000bcc8514;CONTINUE=0xfffffe000bcc89bc;COPY_SIZE=0xfffffe000bcc4bb4;TRAILER_SIZE=0xfffffe000bcc2068;VERIFY=0xfffffe000bcc222c;TRAILER_PTR=0xfffffe000bcc2104
FUNCTIONS=[RECEIVE,ON_THREAD,CONTINUE,COPY_SIZE,TRAILER_SIZE,VERIFY,TRAILER_PTR]
def recover():
 image=Image();k=image.k;functions=[k.function(a)for a in FUNCTIONS];unique={e['ea']:k.read(int(e['ea'],16),4).hex()for f in functions for e in f['instructions']};readers=[]
 for role,a,z in [('user_fields',0xfffffe000bcdccf8,0xfffffe000bcdcd1c),('rpc_fields',0xfffffe000bcf5c48,0xfffffe000bcf5c64)]:
  raw=k.read(a,z-a);readers.append({'role':role,'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(raw,a)]})
 callers=[]
 for role,a,z in [('user_receive_call',0xfffffe000bcdd6c0,0xfffffe000bcdd70c),('kernel_RPC_call',0xfffffe000bcf5c3c,0xfffffe000bcf5c64)]:
  raw=k.read(a,z-a);callers.append({'role':role,'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(raw,a)]})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kernel_queue_send_source.json','kernel_queue_send_profiles.json','kernel_queue_send_checks.json','kernel_queue_send_consumers.json','xnu_namespace_reference_osfmk_ipc_ipc_mqueue.c.txt']},'kernel_sha256':k.sha256,'functions':functions,'unique_source':unique,'reader_fragments':readers,'caller_excerpts':callers,'peek_state_pair':{'address':'0xfffffe000700dc70','bytes_hex':k.read(0xfffffe000700dc70,8).hex()},'exact_symbols':k.symbols(FUNCTIONS),'native_target_executed':False,'native_IPC_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 c=recover();(ROOT/'kernel_queue_receive_source.json').write_text(json.dumps(c,indent=2)+'\n');print(json.dumps({'functions':len(c['functions']),'unique_source':len(c['unique_source']),'peek_pair':c['peek_state_pair']}),flush=True)
