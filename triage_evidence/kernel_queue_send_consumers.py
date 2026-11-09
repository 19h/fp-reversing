#!/usr/bin/env python3
"""Original-byte producer/consumer field and authentication-context joins.
Prior records locate source only; fresh original machine bytes are compared.
Representation agreement does not establish identical live thread or delivery.
O(collection/fixup/source bytes) time/space. No native target execution.
"""
import json,hashlib
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
def recover():
 image=Image();k=image.k;spans=[]
 for name,a,z in [('producer_handoff',0xfffffe000bcc7fe4,0xfffffe000bcc800c),('producer_error',0xfffffe000bcc7e98,0xfffffe000bcc7ea8),('user_reader',0xfffffe000bcdccf8,0xfffffe000bcdcd20),('user_sequence',0xfffffe000bcdcd40,0xfffffe000bcdcd48),('RPC_reader',0xfffffe000bcf5c48,0xfffffe000bcf5c64)]:
  raw=k.read(a,z-a);f=k.function(a,exact=False);spans.append({'label':name,'start':hex(a),'end':hex(z),'function_start':f['start'],'function_end':f['end'],'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(raw,a)]})
 code={int(e['pc'],16):(e['mnemonic'],e['operands'])for s in spans for e in s['instructions']}
 expected={0xfffffe000bcc7fe4:('str','wzr, [x23, #0x3a0]'),0xfffffe000bcc7ea4:('str','w8, [x23, #0x3a0]'),0xfffffe000bcc7fe8:('add','x16, x23, #0x3b8'),0xfffffe000bcc7fec:('movk','x16, #0x33ff, lsl #48'),0xfffffe000bcc7ff4:('pacda','x17, x16'),0xfffffe000bcc7ff8:('str','x17, [x23, #0x3b8]'),0xfffffe000bcc8008:('str','w8, [x23, #0x3a4]'),0xfffffe000bcdccfc:('ldr','w0, [x24, #0x3a0]'),0xfffffe000bcdcd04:('ldr','x16, [x24, #0x3b8]'),0xfffffe000bcdcd0c:('add','x17, x24, #0x3b8'),0xfffffe000bcdcd10:('movk','x17, #0x33ff, lsl #48'),0xfffffe000bcdcd14:('autda','x16, x17'),0xfffffe000bcdcd40:('ldr','w8, [x24, #0x3a4]'),0xfffffe000bcf5c48:('ldr','w27, [x19, #0x3a0]'),0xfffffe000bcf5c4c:('ldr','x16, [x19, #0x3b8]'),0xfffffe000bcf5c54:('add','x17, x19, #0x3b8'),0xfffffe000bcf5c58:('movk','x17, #0x33ff, lsl #48'),0xfffffe000bcf5c5c:('autda','x16, x17')}
 for a,want in expected.items():assert code[a]==want,(hex(a),code[a],want)
 for n in ['kernel_user_copyout_contracts.json','kernel_rpc_transport_contracts.json']:
  prior=json.loads((ROOT/n).read_text())
  for f in prior['native_ranges']:
   a=int(f['start'],16);raw=bytes.fromhex(f['bytes']);assert k.read(a,len(raw))==raw
 joins=[{'field_offset':'0x3a0','width_bits':32,'producer_sites':['0xfffffe000bcc7fe4','0xfffffe000bcc7ea4'],'user_reader':'0xfffffe000bcdccfc','RPC_reader':'0xfffffe000bcf5c48'},{'field_offset':'0x3a4','width_bits':32,'producer_sites':['0xfffffe000bcc8008'],'user_reader':'0xfffffe000bcdcd40','RPC_reader':None},{'field_offset':'0x3b8','width_bits':64,'producer_sites':['0xfffffe000bcc7ff8'],'user_reader':'0xfffffe000bcdcd04','RPC_reader':'0xfffffe000bcf5c4c','authentication_key_family':'DA','discriminator':'0x33ff','modifier_low48':'address of receiver+0x3b8 storage'}]
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kernel_user_copyout_contracts.json','kernel_rpc_transport_contracts.json','kernel_queue_send_source.json','kernel_queue_send_checks.json']},'kernel_sha256':k.sha256,'source_spans':spans,'field_joins':joins,'verified_counts':{'source_spans':len(spans),'captured_instructions':len(code),'exact_instruction_role_checks':len(expected),'field_joins':len(joins),'prior_contracts_rechecked':2},'same_live_receiver_thread_established':False,'native_authentication_executed':False,'continuous_receiver_execution_established':False,'native_user_delivery_established':False,'all_checks_pass':True,'full_goal_complete':False}
if __name__=='__main__':
 out=recover();(ROOT/'kernel_queue_send_consumers.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)
