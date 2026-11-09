#!/usr/bin/env python3
"""Recover update/finalization convention pairs and source continuation sinks.
O(retained visits+effects+source spans+256 bank inputs) time. Space includes
loaded artifact bytes and the largest decoded journal. Native frame continuity,
full digest/cache and transport remain unknown.
"""
import json
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS,selected
from recover_daemon_object_creation import sha,span
from recover_daemon_cache36 import ida_matches
from recover_daemon_descriptor_producers import verify_used_fixups
from replay_daemon_descriptor_producers import unpack
SPECS=[('new_finalize_caller',0x10094dec4,0x10094df00),('fixed20_caller',0x100be25b8,0x100be2600),('saved_finalize_caller',0x100baaf1c,0x100baaf58),('wrapped_finalize_entry',0x100c03b20,0x100c03b78),('wrapped_pad',0x100ac0fe8,0x100ac1044),('encoded_update',0x100a0aad0,0x100a0ab40),('inline_pad',0x100bb2284,0x100bb22e8),('inline_return',0x100bd9ba0,0x100bd9bac),('identity_output_reserve',0x100baff6c,0x100baffe0),('post_finalize',0x100a0e340,0x100a0e3ec),('post_allocate',0x100bb02a8,0x100bb0318),('wrapped_return_load',0x1009f2fb4,0x1009f2ff0),('wrapped_null_return',0x100b2050c,0x100b20514)]
INDICES=[0xac2e,0x49c6,0x9b,0x9c,0xb5d,0xb75,0x9930,0x995b,0xc567,0xc554,0x3b,0xbfc2,0x18,0xbe37,0x3c2d,0x3bff]
def retained_audit():
 p=json.loads((ROOT/'daemon_identity_cache_profiles.json').read_text());counts=Counter();rows=[]
 for j,row in enumerate(p['cases']):
  cfg=row['configuration']
  if not(cfg['identity_present']and cfg['buffer_nonnull']and cfg['conversion_success']):continue
  t=unpack(row);F=int(t['entry_SP'],16);puts={};reads=[]
  for e in t['events']:
   if e['kind']=='write':
    a=int(e['address'],16)
    for k,b in enumerate(bytes.fromhex(e['after_hex'])):puts[a+k]=b
   elif e['pc']=='0x100a0aaec':reads.append(e)
  def field(o,n):return int.from_bytes(bytes(puts[F+o+k]for k in range(n)),'little')
  entry=next(e for e in t['edges']if e['pc']=='0x1009154f8');assert entry['slot']=='0x10105ed20'and entry['target']=='0x100a0aad0';is_short=cfg['UTF16_length']<64;assert bool(reads)and not any(pc==0x100c03b20 for pc,h in t['steps']);counts['encoded_update_entry_edges']+=1
  if is_short:
   e=next(e for e in t['edges']if e['pc']=='0x100bd9ba8');assert e['slot']=='0x10103fa98'and e['target']=='0x100baff6c';e=next(e for e in t['edges']if e['pc']=='0x100baffdc');assert e['target']=='0x100bb2284'and e['slot']=='0x101076a00';counts['identity_inline_finalize_paths']+=1;C=field(0x3610,8);O=field(0x31a8,8);assert C==F+0x3c70 and O==F+0x3ce0 and field(0x3620,8)==0x310 and field(0x2f40,8)==C and field(0x2fe0,8)==O and O>=C+100;counts['distinct_context_output_views']+=1
  else:C=field(0x2bf8,8);O=None;counts['long_update_frontiers']+=1
  assert not any(t['cache_owner_defined_mask36']);rows.append({'case_index':j,'configuration':cfg,'parent_payload_sha256':row['payload_sha256'],'SP':hex(F),'encoded_entry_edge':entry,'context':hex(C),'reserved_output':None if O is None else hex(O),'global_cache_owner':t['cache_owner_address'],'cache_owner_defined_bytes':0,'inline_finalize_seen':is_short,'wrapped_finalize_seen':False,'boundary':row['boundary']});counts['retained_cases_checked']+=1;counts['retained_visits_inspected']+=len(t['steps']);counts['retained_effects_inspected']+=len(t['events'])
 assert len(rows)==480 and counts['identity_inline_finalize_paths']==288 and counts['long_update_frontiers']==192;return rows,dict(counts)
def main():
 rows,counts=retained_audit();slots=[{'index':hex(i),'slot':hex(TABLE+i*8),'fixup':FIXUPS[TABLE+i*8]}for i in INDICES];bank=selected(0x101031da0,0x100e99900,0x86,0xcbb5,TABLE,0);assert bank['target']=='libSystem/_malloc';fix=[int(x['slot'],16)for x in slots]+[int(bank['slot'],16)];live=ida_matches('daemon_digest_conventions_ida_bytes.json');deps=['daemon_digest_conventions_ida_bytes.json','daemon_identity_cache_profiles.json','daemon_identity_cache_context.json','daemon_identity_cache_checks.json','daemon_digest_routes_contracts.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':[span(n,a,z)for n,a,z in SPECS],'slots':slots,'original_fixups':verify_used_fixups(fix),'post_finalize_malloc_bank256':bank,'retained_identity_cases':rows,'retained_counts':counts,'live_IDB_matches':live,'encoded_length_bias32':'0x1ad72f12','new_port_emission_established':False,'completed_digest_or_cache_content_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_digest_conventions_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(SPECS),'fixups':len(out['original_fixups']['records']),'retained':counts,'IDB_ranges':len(live),'IDB_bytes':sum(x['size_bytes']for x in live)}),flush=True)
if __name__=='__main__':main()
