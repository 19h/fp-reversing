#!/usr/bin/env python3
"""Record explicit ABI samples at source cleanup/cache/consumer cutpoints.
O(two component executions+samples) time, O(component journals+samples) space.
Undefined frame/register bytes remain marked, never promoted to facts.
"""
import json
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE
from recover_daemon_object_creation import sha
from probe_daemon_cache_publication import Run,outcomes
LANDMARKS={0x100be097c:'consumer_byte_unmask',0x100aee670:'next_context_initialization',0x100d59b88:'next_context_prefix_copy',0x100b687f4:'formatted_object_load',0x100b9caf0:'serial_cleanup_gate',
 0x100b03b68:'UTF8_free',0x100bac388:'caller_FP_record',
 0x100b8e774:'sample_source_byte',0x100b8e7e0:'sample_candidate_store',
 0x1009b56d4:'cache_writer_setup',0x100a3ce28:'cache_writer_block',
 0x100a4132c:'cache_writer_block_exit',0x100ac1c7c:'cache_consumer_entry',
 0x100ac3cf4:'cache_consumer_first_byte',0x100ac7c1c:'cache_consumer_last_store',
 0x100be25b8:'next_fixed20_caller',0x10095eb00:'next_input_frontier'}
FIELDS=[0x3178,0x3504,0x26e0,0x2708,0x2710,0x2890,0x2910,0x2a48,0x2f08,0x30b8,
 0x31a8,0x32d0,0x32e8,0x3458,0x3598,0x3610,0x3620,0x3650,0x36f8,0x3700]
class Sample(Run):
 def __init__(self,c,cfg):super().__init__(c,cfg);self.samples=[]
 def code(self,u,a,n,d):
  self.flush()
  if a in LANDMARKS:
   fields={}
   for off in FIELDS:
    at=self.F+off;size=4 if off==0x3504 else 8;known=all(at+j in self.defined for j in range(size));fields[hex(off)]={'defined':known,'size_bytes':size,'value_u64':hex(int.from_bytes(bytes(u.mem_read(at,size)),'little'))if known else None}
   self.samples.append({'pc':hex(a),'role':LANDMARKS[a],'registers31':[hex(self.reg('x'+str(j)))for j in range(31)],'defined_GPRs':sorted(self.known),'frame_fields':fields})
  return super().code(u,a,n,d)
def build():
 cs=json.loads((ROOT/'daemon_cache_publication_context.json').read_text())['contexts'];rows=[];seen=set();cfg=next(outcomes())
 for c in cs:
  if c['message_hex']in seen:continue
  seen.add(c['message_hex']);r=Sample(c,cfg);t=r.run();rows.append({'identity_case_index':c['identity_case_index'],'parent_context_sha256':t['parent_context_sha256'],'message_hex':c['message_hex'],'configuration':cfg,'SP':t['entry_SP'],'samples':r.samples,'source_visits':len(t['steps']),'cache_defined_mask36':t['cache_defined_mask36'],'boundary':t['boundary']})
  if len(rows)==2:break
 assert len(rows)==2;return rows
def main():
 rows=build();deps=['daemon_cache_publication_context.json','probe_daemon_cache_publication.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache_publication_interfaces.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'sampled_cases':len(rows),'cutpoint_samples':sum(len(r['samples'])for r in rows)}),flush=True)
if __name__=='__main__':main()
