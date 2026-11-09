#!/usr/bin/env python3
"""Original receive-results/header/name-conversion/packing source capture.
O(collection/fixup/source bytes) time/space; no native target execution.
"""
import json
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
RESULTS=0xfffffe000bcdcc7c;HEADER=0xfffffe000bcc4e98;DESTINATION=0xfffffe000bcca164;PACK=0xfffffe000bcc62d0;PORT_CHECK=0xfffffe000bccd418;PORT_UNLOCK=0xfffffe000bccf39c
FUNCTIONS=[RESULTS,HEADER,DESTINATION,PACK,PORT_CHECK,PORT_UNLOCK,0xfffffe000bcc2868]
def recover():
 image=Image();k=image.k;functions=[k.function(a)for a in FUNCTIONS];unique={e['ea']:k.read(int(e['ea'],16),4).hex()for f in functions for e in f['instructions']};return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kernel_queue_receive_source.json','kernel_queue_send_profiles.json','kernel_user_copyout_contracts.json']},'kernel_sha256':k.sha256,'functions':functions,'unique_source':unique,'exact_symbols':k.symbols(FUNCTIONS),'native_target_executed':False,'native_IPC_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 c=recover();(ROOT/'kernel_receive_delivery_source.json').write_text(json.dumps(c,indent=2)+'\n');print(json.dumps({'functions':len(c['functions']),'unique_source':len(c['unique_source'])}),flush=True)
