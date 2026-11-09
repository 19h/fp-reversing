#!/usr/bin/env python3
"""Original RPC502 body/VM-copy validation and daemon MIG guard capture.
O(original bytes/fixups/source) time/space. No native target execution.
"""
import json
from daemon_receive_tools import ROOT,IMAGE,CS,SOURCE
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
FUNCTIONS=[0xfffffe000bcc5564,0xfffffe000bdd148c,0xfffffe000bdcb374,0xfffffe000bdd048c,0xfffffe000bdc1cd4,0xfffffe000bcd5b90]
def recover():
 image=Image();k=image.k;functions=[k.function(a)for a in FUNCTIONS];raw=IMAGE.read(0x1000050c8,0x134);return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_receive_delivery_source.json','kernel_receive_delivery_profiles.json','kernel_user_copyout_contracts.json','daemon_receive_contracts.json','kernel_vm_mig_tools.py']},'kernel_sha256':k.sha256,'daemon_sha256':sha(SOURCE),'functions':functions,'unique_source':{e['ea']:k.read(int(e['ea'],16),4).hex()for f in functions for e in f['instructions']},'daemon_guard':{'start':'0x1000050c8','end':'0x1000051fc','bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,0x1000050c8)]},'native_target_executed':False,'native_IPC_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 c=recover();(ROOT/'rpc502_receive_bridge_source.json').write_text(json.dumps(c,indent=2)+'\n');print(json.dumps({'kernel_functions':len(c['functions']),'kernel_instructions':len(c['unique_source']),'daemon_guard_instructions':len(c['daemon_guard']['instructions'])}),flush=True)
