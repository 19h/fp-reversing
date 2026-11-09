#!/usr/bin/env python3
"""Capture verified pre-creator RAM/registers and retain unknown-byte aliases.
O(snapshot+sealed source visits+effects) time/space. No native target/API/PAC.
"""
import json,hashlib,base64,zlib
from pathlib import Path
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE
from replay_daemon_callback_revisit import Replay

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def pack(b):return base64.b64encode(zlib.compress(bytes(b))).decode()
def raw(s):return zlib.decompress(base64.b64decode(s))
def main():
 old=json.loads((ROOT/'daemon_callback_revisit_snapshot.json').read_text());p=json.loads((ROOT/'daemon_callback_revisit_profiles.json').read_text());b=raw(p['payload_zlib_base64']);assert hashlib.sha256(b).hexdigest()==p['payload_sha256'];t=json.loads(b);v=Replay(old,t,3);r=v.run();assert r['all_checks_pass']and r['boundary']['pc']=='0x100492644';F=int(old['frame_SP'],16);H=int(old['arena_owner'],16);masks={n:bytearray(raw(old[n]['known_mask_zlib_base64']))for n in ['private_owner','heap_owner']};aliases={int(a,16):off for a,off in old['unknown_stack_aliases'].items()};regs=t['initial_registers'].copy();flags=int(old['NZCV'],16)
 for step in t['steps']:
  regs.update(step['registers_after'])
  if 'NZCV_after'in step:flags=step['NZCV_after']
  for e in step['events']:
   if e['kind']!='write':continue
   a=int(e['address'],16);terms=list(bytes.fromhex(e['value']['hex']))if'hex'in e['value']else e['value']['terms'];assert len(terms)==e['size_bytes']
   for j,term in enumerate(terms):
    at=a+j
    for name,base in [('private_owner',0x6400000000),('heap_owner',H)]:
     if base<=at<base+len(masks[name]):masks[name][at-base]=isinstance(term,int)
    if isinstance(term,dict):aliases[at]=term['origin']
    else:aliases.pop(at,None)
 assert flags==v.register('NZCV')
 for j,shape in enumerate(t['boundary']['registers31']):assert regs['x'+str(j)]==shape
 regions=[]
 for lo,hi,permissions in v.u.mem_regions():
  b=bytes(v.u.mem_read(lo,hi-lo+1));regions.append({'address':hex(lo),'size_bytes':len(b),'permissions':permissions,'sha256':hashlib.sha256(b).hexdigest(),'bytes_zlib_base64':pack(b)})
 origins={x['offset']for x in t['origins']}|{int(k)for k in old['inherited_unknown_backing']};inherited={str(off):v.backing[off]for off in sorted(origins)};aliases={hex(a):off for a,off in aliases.items()if off!=a-F};owners={n:{**old[n],'known_mask_zlib_base64':pack(masks[n])}for n in masks};deps=['daemon_callback_revisit_snapshot.json','daemon_callback_revisit_profiles.json','daemon_callback_revisit_replays.json','daemon_callback_revisit_checks.json','replay_daemon_callback_revisit.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'prior_case_index':old['prior_case_index'],'values':old['values'],'frame_SP':old['frame_SP'],'arena_owner':old['arena_owner'],'boundary':t['boundary'],'logical_registers':regs,'NZCV':hex(flags),**owners,'image_known_overrides':old['image_known_overrides'],'unknown_stack_aliases':aliases,'inherited_unknown_backing':inherited,'regions':regions,'sealed_source_visits_replayed':len(t['steps']),'snapshot_before_creator_call':True,'unknown_backing_is_not_source_definition':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_context_lock_snapshot.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_visits':len(t['steps']),'regions':len(regions),'alias_bytes':len(aliases),'retained_origin_backing':len(inherited),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
