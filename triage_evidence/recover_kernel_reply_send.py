#!/usr/bin/env python3
"""Original kernel reply caller/trailer/queue/cleanup interface capture.
Static file reads only; compiler-bounded opaque hash bytes retain decode gaps.
O(KC/fixup/source bytes) time/space; no native target/IPC/PAC.
"""
import bisect,json,hashlib
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
SEND=0xfffffe000bcc7040;TRAILER_INIT=0xfffffe000bcc4194;TRAILER_PTR=0xfffffe000bcc2104;HASH_FN=0xfffffe000bc9d90c
DISPATCH=0xfffffe000bcf4154;LOCK=0xfffffe000bccc128;UNLOCK=0xfffffe000bd0ab18;PREFLIGHT=0xfffffe000bcc0f9c;QUEUE=0xfffffe000bcc7c34;FAILURE=0xfffffe000bcc1cec;DESTROY=0xfffffe000bcc2c40;FINAL_REF=0xfffffe000bcc922c
FUNCTIONS=[SEND,TRAILER_INIT,TRAILER_PTR,DISPATCH,LOCK,PREFLIGHT,QUEUE,FAILURE,DESTROY,FINAL_REF,0xfffffe000bcc222c]
def recover():
 image=Image();k=image.k;functions=[k.function(a)for a in FUNCTIONS];source={}
 for f in functions:
  for e in f['instructions']:source[e['ea']]=k.read(int(e['ea'],16),4).hex()
 ix=bisect.bisect_left(k.starts,HASH_FN);assert k.starts[ix]==HASH_FN;end=k.starts[ix+1];raw=k.read(HASH_FN,end-HASH_FN);words=[]
 for at in range(HASH_FN,end,4):
  b=k.read(at,4);ins=list(k.cs.disasm(b,at));words.append({'pc':hex(at),'bytes_hex':b.hex(),'assembly':ins[0].mnemonic+' '+ins[0].op_str if ins else None})
 template=k.read(0xfffffe0007010a68,68);assert template[20:52]==bytes(32)
 pacga=[x['pc']for x in words if x['assembly']and x['assembly'].startswith('pacga ')];assert len(pacga)==5;ret=next(x['pc']for x in words if x['assembly']=='retab ');assert all(int(x['pc'],16)>int(ret,16)for x in words if x['assembly']is None)
 return{'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kernel_vm_mig_source.json','kernel_user_copyout_contracts.json']},'kernel_sha256':k.sha256,'functions':functions,'unique_source':source,'exact_symbols':k.symbols(FUNCTIONS+[HASH_FN]),'opaque_hash':{'start':hex(HASH_FN),'end':hex(end),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'words':words,'decode_gap_count':sum(x['assembly']is None for x in words),'return_pc':ret,'decode_gaps_are_after_return':True,'source_algorithm_family':'PACGA-based buffer folding','PACGA_sites':pacga,'native_hardware_key_established':False,'native_tag_values_established':False},'kernel_template':{'address':'0xfffffe0007010a68','bytes_hex':template.hex()},'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'kernel_reply_send_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'functions':len(r['functions']),'unique_source':len(r['unique_source']),'hash_bytes':len(bytes.fromhex(r['opaque_hash']['bytes_hex'])),'hash_decode_gaps':r['opaque_hash']['decode_gap_count']}),flush=True)
