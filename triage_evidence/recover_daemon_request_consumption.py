#!/usr/bin/env python3
"""Pin reviewed original daemon callback/demux/stub bytes and transport sources.
O(image+instructions+fixups), O(image+instructions). No target operations.
"""
import hashlib,json
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS
P='daemon_request_consumption'
FLAGS={k:False for k in ['native_target_executed','native_IPC_executed','native_VM_effects_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']}
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def build():
 old=json.loads((ROOT/'daemon_receive_contracts.json').read_text());ranges=[]
 for lo,hi in [(int(r['start'],16),int(r['end'],16))for r in old['ranges']]+[(0x1000050c8,0x100005274)]:
  raw=IMAGE.read(lo,hi-lo);ranges.append({'start':hex(lo),'end':hex(hi),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,lo)]})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_path':str(SOURCE),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_receive_contracts.json','daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_rpc502_probe.py','kernel_request_delivery_profiles.json','kernel_request_delivery_checks.json']},'ranges':ranges,'roles':{'callback':'0x100425f78','demux502':'0x100005274','stub502':'0x1000050c8','audit_size_guard':'0x100005128','audit_copy16a':'0x1000051cc','audit_copy16b':'0x1000051d0','application_call':'0x1000051f8','application_entry':'0x100422d48','request_remote_clear':'0x10006ce34','request_destroy_call':'0x10006ce90','reply_send_call':'0x100035184'},**FLAGS}
if __name__=='__main__':
 out=build();(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(out['ranges']),'instructions':sum(len(r['instructions'])for r in out['ranges'])}))
