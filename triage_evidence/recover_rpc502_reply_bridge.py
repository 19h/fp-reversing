#!/usr/bin/env python3
"""Recover original RPC502 response producer and kext consumer bytes.
O(captured bytes) time/space; read-only original images, no IDB or target calls.
"""
import json
from daemon_receive_tools import ROOT,IMAGE,CS,FIXUPS,SOURCE
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha

def capture(read,cs,start,end):
 raw=read(start,end-start);ins=list(cs.disasm(raw,start));assert len(ins)*4==len(raw)
 return {'start':hex(start),'end':hex(end),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'bytes_hex':i.bytes.hex()}for i in ins]}

def recover():
 k=Image().k
 spans={'daemon_stub':capture(IMAGE.read,CS,0x1000050c8,0x100005274),'daemon_demux':capture(IMAGE.read,CS,0x100005274,0x100005304),'kext_client':capture(k.read,k.cs,0xfffffe000a5a2064,0xfffffe000a5a22d4),'kernel_destroy':capture(k.read,k.cs,0xfffffe000bcf5ea4,0xfffffe000bcf5f18),'kernel_MIG_noops':capture(k.read,k.cs,0xfffffe000bcf5f24,0xfffffe000bcf5f34)}
 roles={
  'first_record_output_argument':(0xfffffe000a5a2084,'mov','x21, x6'),
  'second_record_output_argument':(0xfffffe000a5a2080,'mov','x20, x7'),
  'reply_id_guard':(0xfffffe000a5a2140,'cmp','w8, #0x25a'),
  'complex_count_guard':(0xfffffe000a5a2198,'cmp','w9, #2'),
  'complex_size_guard':(0xfffffe000a5a21a0,'cmp','w8, #0x188'),
  'first_type_guard':(0xfffffe000a5a21b4,'cmp','w8, #1'),
  'second_type_guard':(0xfffffe000a5a21c0,'cmp','w8, #1'),
  'first_length_guard':(0xfffffe000a5a21d0,'cmp','w8, w9'),
  'second_length_guard':(0xfffffe000a5a21e0,'cmp','w9, w10'),
  'first_OOL_output':(0xfffffe000a5a2278,'str','x14, [x13]'),
  'second_OOL_output':(0xfffffe000a5a2284,'str','x8, [x11]'),
  'destroy_rejected_reply':(0xfffffe000a5a2298,'bl','#0xfffffe000a69f314'),
  'daemon_success_size':(0x100005250,'mov','w9, #0x180'),
  'daemon_success_count':(0x100005258,'mov','w8, #2'),
 }
 checked={}
 for name,(a,m,o)in roles.items():
  read,cs=(IMAGE.read,CS)if a<0x200000000 else(k.read,k.cs);i=next(cs.disasm(read(a,4),a));assert(i.mnemonic,i.op_str)==(m,o),(name,i.mnemonic,i.op_str);checked[name]={'pc':hex(a),'mnemonic':m,'operands':o,'bytes_hex':i.bytes.hex()}
 thunks=[]
 for a,slot,role in [(0xfffffe000a69f314,0xfffffe000847c4b8,'destroy_message'),(0xfffffe000a69f364,0xfffffe000847c4e0,'deallocate_reply_port'),(0xfffffe000a69f384,0xfffffe000847c4f0,'put_reply_port')]:
  raw=k.logical_page(slot&~4095)if hasattr(k,'logical_page')else Image().logical_page(slot&~4095)
  target=int.from_bytes(raw[slot&4095:(slot&4095)+8],'little')
  thunks.append({'role':role,'slot':hex(slot),'target':hex(target),'capture':capture(k.read,k.cs,a,a+16)})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_receive_tools.py','kernel_vm_mig_tools.py']},'daemon_sha256':sha(SOURCE),'kernel_sha256':k.sha256,'spans':spans,'exact_instruction_roles':checked,'thunks':thunks,'NDR_import':{'slot':'0x1010b1e10','original_word_hex':IMAGE.read(0x1010b1e10,8).hex(),'fixup':FIXUPS[0x1010b1e10],'runtime_binding_established':False},'native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'rpc502_reply_bridge_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'captured_instructions':sum(len(x['instructions'])for x in r['spans'].values()),'instruction_roles':len(r['exact_instruction_roles']),'thunks':r['thunks']}))
