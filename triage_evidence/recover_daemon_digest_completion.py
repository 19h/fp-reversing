#!/usr/bin/env python3
"""Recover source-local overwrite, decoded copy, restore and producer ABIs.
O(original text+new visits/effects+retained audit) time; O(compressed profiles
+largest decoded journal+source text) space. Native joins remain unknown.
"""
import json,struct,hashlib
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS
from recover_daemon_object_creation import sha,span
from recover_daemon_cache36 import ida_matches
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_iokit_census import text_section
from replay_daemon_descriptor_producers import unpack
from daemon_digest_completion_model import SPECS,overwrite_byte
from daemon_digest_completion_inputs import retained
def census():
 a,n=text_section();b=IMAGE.read(a,n);offsets=[0x2f00,0x3278,0x3610,0x26e0,0x33c8,0x3108,0x2da8,0x34b8,0x2c28]
 patterns={0xf9000000|((off//8)<<10)|(31<<5):off for off in offsets};rows=[]
 for j in range(0,n-3,4):
  w=struct.unpack_from('<I',b,j)[0];off=patterns.get(w&0xffffffe0)
  if off is not None:
   i=next(CS.disasm(b[j:j+4],a+j));rows.append({'address':hex(a+j),'offset':hex(off),'bytes_hex':b[j:j+4].hex(),'instruction':i.mnemonic+' '+i.op_str})
 return {'text_start':hex(a),'text_size_bytes':n,'text_sha256':hashlib.sha256(b).hexdigest(),'scope':'Exact STR Xn,[SP,#offset] unsigned-immediate encodings; computed, paired, aliased, overlapping and other-width stores excluded.','records':rows}
def main():
 p=json.loads((ROOT/'daemon_digest_completion_profiles.json').read_text());pool={};slots=set();routes={};totals=Counter();boundaries=Counter()
 for r in p['cases']:
  t=unpack(r);kind=r['configuration']['kind'];totals[kind+'_cases']+=1;totals[kind+'_source_visits']+=len(t['steps']);totals[kind+'_BRAA']+=len(t['edges']);totals[kind+'_reads']+=sum(e['kind']=='read'for e in t['events']);totals[kind+'_writes']+=sum(e['kind']=='write'for e in t['events']);boundaries[t['boundary']['pc']]+=1
  for a,b in t['source_pool'].items():assert a not in pool or pool[a]==b;pool[a]=b
  for pc,target,slot,mod in t['edges']:
   slots.add(slot);rs=routes.setdefault(hex(pc),{});assert hex(target)not in rs or rs[hex(target)]==hex(slot);rs[hex(target)]=hex(slot)
 rows,rc=retained();deps=['daemon_digest_completion_profiles.json','daemon_digest_completion_model.py','daemon_digest_completion_inputs.py','daemon_digest_completion_ida_bytes.json','daemon_digest_output_checks.json','daemon_identity_cache_checks.json','daemon_identity_cache_context.json','daemon_identity_cache_profiles.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':[span(n,a,z)for n,a,z in SPECS],'source_pool':pool,'route_slots':routes,'original_fixups':verify_used_fixups(slots),'live_IDB_matches':ida_matches('daemon_digest_completion_ida_bytes.json'),'saved_field_writer_census':census(),'overwrite_byte_table256_hex':bytes(overwrite_byte(s)for s in range(256)).hex(),'retained_saved_fields':rows,'retained_counts':rc,'trace_totals':dict(totals),'boundaries':dict(boundaries),'new_port_emission_established':False,'native_cache_or_driver_link_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/'daemon_digest_completion_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(SPECS),'fixups':len(out['original_fixups']['records']),'totals':dict(totals),'retained':rc,'boundaries':dict(boundaries)}),flush=True)
if __name__=='__main__':main()
