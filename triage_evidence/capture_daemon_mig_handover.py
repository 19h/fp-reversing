#!/usr/bin/env python3
"""Capture the original copy helper, post-copy caller spans and cursor decode.
O(original span bytes + 256 bank inputs) time, O(spans) space. No target runs.
"""
import bisect,json
from daemon_receive_tools import ROOT,SOURCE,IMAGE,POOL,selected
from capture_daemon_operation_heads import function_starts
from capture_daemon_record720 import sha
def capture():
 starts,_=function_starts();j=bisect.bisect_left(starts,0x10046f89c);assert starts[j]==0x10046f89c;helper={'start':hex(starts[j]),'end':hex(starts[j+1]),'bytes_hex':IMAGE.read(starts[j],starts[j+1]-starts[j]).hex()};spans=[]
 for name,a,z in [('AD952088_after_copy',0x100466838,0x100466a0c),('A70E6EB4_after_copy',0x100592f68,0x100593030),('A70E6EB4_nonnull_copy_and_handover',0x1004c42cc,0x1004c464c),('AD952088_caller_consumer',0x100466a0c,0x100466a20),('A70E6EB4_caller_gate',0x1004c464c,0x1004c4680)]:spans.append({'name':name,'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex()})
 cursor=selected(0x100e99700,0x100f4e190,0x81,0x409,POOL,-0xea9dcf);assert cursor['slot']=='0x1010a3be8'and cursor['target']=='0x1010b8d10'
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_operation_heads_symbolic.json','daemon_operation_heads_proofs.json','daemon_core_dispatch_source.json','capture_daemon_operation_heads.py']},'copy_helper':helper,'post_copy_source_spans':spans,'cursor_decode':cursor,'cached_cursor_native_value':'unknown','native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=capture();(ROOT/'daemon_mig_handover_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'helper_bytes':len(bytes.fromhex(r['copy_helper']['bytes_hex'])),'cursor_cell':r['cursor_decode']['target'],'caller_spans':len(r['post_copy_source_spans'])}),flush=True)
