#!/usr/bin/env python3
"""Capture original queue admission/post, insertion and receiver metadata helpers.
O(collection/fixup/source bytes) time/space. No native target or IPC.
"""
import json
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
QUEUE=0xfffffe000bcc7c34;ENQUEUE=0xfffffe000bcc2bc4;COPY_SIZE=0xfffffe000bcc4bb4;TRAILER_SIZE=0xfffffe000bcc2068
IDENTIFY=0xfffffe000bd6cf80;RESUME=0xfffffe000bd6d0d4;CLEAR=0xfffffe000bd6c4b0;TASK=0xfffffe000bd7e9c4
PREPARE=0xfffffe000bd68474;ASSERT_WAIT=0xfffffe000bd6e0fc;DESTROY=0xfffffe000bcc2c40
FUNCTIONS=[QUEUE,ENQUEUE,COPY_SIZE,TRAILER_SIZE,IDENTIFY,RESUME,CLEAR,TASK,PREPARE,ASSERT_WAIT,DESTROY]
def recover():
 image=Image();functions=[image.k.function(a)for a in FUNCTIONS];unique={e['ea']:image.k.read(int(e['ea'],16),4).hex()for f in functions for e in f['instructions']};return{'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kernel_reply_send_source.json','xnu_namespace_reference_osfmk_ipc_ipc_mqueue.c.txt','kernel_namespace_contracts.json']},'kernel_sha256':image.k.sha256,'functions':functions,'unique_source':unique,'exact_symbols':image.k.symbols(FUNCTIONS),'reference':{'file':'xnu_namespace_reference_osfmk_ipc_ipc_mqueue.c.txt','url':'https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_mqueue.c','exact_native_build_match_established':False},'native_target_executed':False,'native_IPC_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 c=recover();(ROOT/'kernel_queue_send_source.json').write_text(json.dumps(c,indent=2)+'\n');print(json.dumps({'functions':len(c['functions']),'unique_source':len(c['unique_source'])}))
