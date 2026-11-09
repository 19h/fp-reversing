#!/usr/bin/env python3
"""Recover digest serializers, selector decisions and bounded frame-root ABI.
O(source+all visits/effects) time; O(compressed artifacts+largest decoded
journal) space. Native frame continuity/cache publication remain unknown.
"""
import json,struct,hashlib,capstone
from pathlib import Path
from collections import Counter
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS
from recover_daemon_object_creation import sha,span
from recover_daemon_cache36 import ida_matches
from recover_daemon_iokit_census import text_section
from recover_daemon_descriptor_producers import verify_used_fixups
from replay_daemon_descriptor_producers import unpack
from daemon_digest_output_access import register_access,key,audit
from daemon_digest_output_inputs import retained_short
SPECS=[('route_entry',0x1009de090,0x1009de0c8),('selector_gate',0x100b30120,0x100b30158),('be_route',0x100a4739c,0x100a473f8),('be_size_gate',0x100ae05dc,0x100ae0648),('be_first',0x100be71bc,0x100be7294),('be_loop',0x1008b6060,0x1008b6170),('le_route',0x10095b7dc,0x10095b834),('le_size_gate',0x100c0a3c4,0x100c0a418),('le_first',0x100b57120,0x100b571ec),('le_loop',0x100b30004,0x100b3010c),('join_prefix',0x100bb1574,0x100bb15d0),('join_resume',0x100bb15d0,0x100bb1620),('stack_root',0x1007cfa64,0x1007cfab4),('conditional_root',0x100ace964,0x100ace9a8),('direct_root',0x100bdb258,0x100bdb278)]
COUNTERS={'be_loop':16,'le_loop':15}
def liveins(a,z):
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;defined=set();need={}
 for i in cs.disasm(IMAGE.read(a,z-a),a):
  reads,writes=register_access(i)
  for r in reads:
   n=cs.reg_name(r)
   if n not in ['wzr','xzr']and key(n)not in defined:need[key(n)]=n
  defined.update(key(cs.reg_name(r))for r in writes)
 return need
def helper_abis(t):
 cfg=t['configuration'];selector=cfg['selector'];F=int(t['SP'],16);C=int(t['context'],16);O=int(t['output'],16);out={}
 if cfg['output_size']==0 or cfg.get('decision_only'):return out
 for name,a,z in SPECS:
  if not name.startswith('be_'if selector==2 else'le_')or name not in ['be_first','be_loop','le_first','le_loop']:continue
  shots=[x['registers31']for x in t['serializer_entries']if x['pc']==hex(a)];need=liveins(a,z-4);seeds={};loop=name.endswith('loop');last=4 if selector==2 else 3;indices=list(range(1,last+1))if loop else[0];assert len(shots)==len(indices)
  for k,n in need.items():
   if k=='sp':seeds[k]={'kind':'frame_pointer'};continue
   reg=int(k[1:]);vals=[r[reg]for r in shots]
   if loop and reg==COUNTERS[name]:assert vals==[4*j for j in indices];seeds[k]={'kind':'byte_counter'};continue
   assert len(set(vals))==1,(name,k,vals);v=vals[0];seeds[k]={'kind':'context_pointer'}if v==C else{'kind':'output_pointer'}if v==O else{'kind':'table_pointer'}if v==TABLE else{'kind':'constant','value':v}
  edges=[e for e in t['edges']if e[0]==z-4];assert len(edges)==len(shots);out[name]={'start':hex(a),'end':hex(z),'seeds':seeds,'counter_domain':([1,last]if loop else[0,0]),'output_size':cfg['output_size'],'selector':selector,'loop_slot':hex(edges[0][2]),'exit_slot':hex(edges[-1][2]),'byte_store_order':[1,2,3,0]if name=='be_loop'else[0,1,2,3]}
 return out
def root_census():
 a,n=text_section();raw=IMAGE.read(a,n);patterns={};rows=[]
 for op,scale,label in [(0xf9400000,8,'read64'),(0xf9000000,8,'write64'),(0xb9400000,4,'read32'),(0xb9000000,4,'write32')]:patterns[op|((0x3050//scale)<<10)|(31<<5)]=label
 for j in range(0,n-3,4):
  w=struct.unpack_from('<I',raw,j)[0]
  if(w&0xffffffe0)in patterns:
   i=next(Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(raw[j:j+4],a+j));rows.append({'address':hex(a+j),'kind':patterns[w&0xffffffe0],'bytes_hex':raw[j:j+4].hex(),'instruction':i.mnemonic+' '+i.op_str})
 return {'text_start':hex(a),'text_size_bytes':n,'text_sha256':hashlib.sha256(raw).hexdigest(),'scope':'Exact SP+0x3050 scalar32/64 unsigned-immediate encodings only; overlapping/paired/computed/alias/frame-base accesses excluded.','records':rows}
def main():
 p=json.loads((ROOT/'daemon_digest_output_profiles.json').read_text());pool={};slots=set();route_slots={};abis={};totals=Counter();decisions=[]
 for group in ['cases','decision_cases']:
  for row in p[group]:
   t=unpack(row)
   for a,b in t['source_pool'].items():assert a not in pool or pool[a]==b;pool[a]=b
   for pc,target,slot,modifier in t['edges']:
    slots.add(slot);d=route_slots.setdefault(hex(pc),{});assert hex(target)not in d or d[hex(target)]==hex(slot);d[hex(target)]=hex(slot)
   for name,abi in helper_abis(t).items():
    if name in abis:assert abis[name]==abi
    else:abis[name]=abi
   totals[group+'_count']+=1;totals[group+'_source_visits']+=len(t['steps']);totals[group+'_BRAA']+=len(t['edges']);totals[group+'_reads']+=sum(e['kind']=='read'for e in t['events']);totals[group+'_writes']+=sum(e['kind']=='write'for e in t['events'])
   if group=='decision_cases':decisions.append({'selector_word32':t['configuration']['selector'],'frontier':t['boundary']['pc'],'kind':t['boundary']['kind']})
 for row in p['conditional_pipelines']:
  t=unpack(row);totals['conditional_pipeline_count']+=1
  for key0 in ['core_trace','serializer_trace']:
   tt=t[key0];totals[key0+'_source_visits']+=len(tt['steps']);totals[key0+'_BRAA']+=len(tt['edges']);totals[key0+'_reads']+=sum(e['kind']=='read'for e in tt['events']);totals[key0+'_writes']+=sum(e['kind']=='write'for e in tt['events'])
 rows,rc=retained_short();live=ida_matches('daemon_digest_output_ida_bytes.json');deps=['daemon_digest_output_profiles.json','daemon_digest_output_inputs.py','daemon_digest_output_access.py','daemon_digest_output_ida_bytes.json','daemon_sha1_core_checks.json','daemon_identity_cache_profiles.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':[span(n,a,z)for n,a,z in SPECS],'source_pool':pool,'helper_ABIs':abis,'route_slots':route_slots,'original_fixups':verify_used_fixups(slots),'live_IDB_matches':live,'SP3050_census':root_census(),'shift_access_audit':audit(),'capstone_version':capstone.__version__,'selector_decisions':decisions,'retained_short_inputs':rows,'retained_counts':rc,'trace_totals':dict(totals),'new_port_emission_established':False,'native_identity_or_cache_publication_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_digest_output_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(SPECS),'helper_ABIs':len(abis),'fixups':len(out['original_fixups']['records']),'IDB_bytes':sum(x['size_bytes']for x in live),'root_accesses':len(out['SP3050_census']['records']),'retained':rc,'totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
