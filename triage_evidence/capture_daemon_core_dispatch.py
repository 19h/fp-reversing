#!/usr/bin/env python3
"""Capture exact private state before the operation's first use. The original
entry prefix has no earlier overlapping read/write of the four operation bytes;
parameterization changes that explicit entry argument, not an unavailable byte.
O(parent visits + effects) time, O(defined cells + journal) space. No native APIs.
"""
import json
from collections import Counter
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from replay_daemon_descriptor_producers import Replay
from recover_daemon_object_clock import sections
CP=0x1004c244c
class CaptureReplay(Replay):
 snapshot=None
 def code(self,u,a,n,d):
  if a==CP:self.snapshot={'known_GPRs':{'x'+str(j):hex(self.reg('x'+str(j)))for j in range(31)},'SP':hex(self.reg('sp')),'NZCV':hex(self.reg('NZCV'))}
  return super().code(u,a,n,d)
def capture():
 parent=json.loads((ROOT/'daemon_shared_roots_profiles.json').read_text());p=parent['cases'][0];limit=next(j for j,r in enumerate(p['source_visits'])if r['pc']==hex(CP));R=int(p['record_address'],16);overlap=lambda e:int(e['address'],16)<R+16 and R+12<int(e['address'],16)+e['size_bytes']
 assert not any(overlap(e)for e in p['source_reads']if e['source_visit_index']<limit)and not any(overlap(e)for e in p['source_writes']if e['source_visit_index']<limit)
 rep=CaptureReplay(p);checked=rep.run();assert checked['all_checks_pass']and rep.snapshot is not None;ram={}
 for g in p['initial_private_fixtures']+p['initial_image_fixtures']:
  for j,b in enumerate(bytes.fromhex(g['bytes_hex'])):ram[int(g['address'],16)+j]=b
 for e in p['source_writes']:
  if e['source_visit_index']>=limit:break
  for j,b in enumerate(bytes.fromhex(e['after_hex'])):ram[int(e['address'],16)+j]=b
 # Retain the parent private environment's observed writable-image cells;
 # this is not an assignment of their native initial values.
 writable=[s for s in sections()if s['segment']=='__DATA'];observed=[]
 for e in p['source_reads']:
  if e['source_visit_index']>=limit:break
  a=int(e['address'],16)
  if a in FIXUPS or not any(s['start']<=a<a+e['size_bytes']<=s['start']+s['size_bytes']for s in writable):continue
  # Only seed bytes that were never written: source writes above already
  # reconstruct their final checkpoint epoch.
  for j,b in enumerate(bytes.fromhex(e['bytes_hex'])):
   if a+j not in ram:ram[a+j]=b;observed.append(hex(a+j))
 snap=rep.snapshot;snap['known_GPRs']['sp']=snap['SP'];F=int(snap['SP'],16)
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_shared_roots_profiles.json','replay_daemon_descriptor_producers.py','daemon_descriptor_producers_source.json']},'entry_PC':hex(CP),'context':snap,'known_bytes':[{'address':hex(a),'value':b}for a,b in sorted(ram.items())],'operation_field':hex(R+12),'protected_record':hex(R),'borrowed_argument_record':'0x6800001000','frame_owner':{'address':hex(F),'size_bytes':0x10dd0},'operation_unread_prefix_source_visits':limit,'earlier_operation_reads':0,'earlier_operation_writes':0,'observed_parent_image_byte_addresses':observed,'parent_replay_counts':checked['verified_counts'],'native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=capture();(ROOT/'daemon_core_dispatch_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'prefix_visits':r['operation_unread_prefix_source_visits'],'known_bytes':len(r['known_bytes']),'first_use':r['entry_PC'],'operation_field':r['operation_field']}),flush=True)
