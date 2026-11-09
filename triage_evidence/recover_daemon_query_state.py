#!/usr/bin/env python3
"""Pin original query-state source, exhaustive bank roots and local ABI frontiers.

O(B+I+256R+F) time,O(B+I+F) space. No native execution or IDB mutation.
"""
import hashlib,json
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE,POOL,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
SPANS=[('caller_pack_and_return',0x1003c39b0,0x1003c3b04),('state_helper',0x100013ac0,0x100013d3c),('state_helper_normal_return',0x1000898d8,0x100089908),('zero_capability_fallback',0x1000115a0,0x100011678),('iterator_release',0x100483c6c,0x100483cd4),('open_connection_cell',0x100478b98,0x100478bb4),('outer_frame',0x1004601d0,0x100460208)]
RULES=[('record_helper',0x100fc4130,0x101031ea0,0xbb,0xcba1,TABLE,0),('controller_A',0x100e99700,0x100f4e190,0x56,0x1d8,POOL,0xffffffff80a161aa),('controller_B',0x100fc4130,0x101031ea0,0xa3,0x22,POOL,0xffffffffec9e1772),('state_cache',0x100e99a00,0x100f4e390,0x78,0x1e2,POOL,0xfffffffffeff1acd),('helper_dispatch_table',0x101031da0,0x100e99900,0x9a,0x835,POOL,0xffffffffd0c4d1ee),('fallback_call',0x100e99700,0x100f4e190,0x81,0xcde9,TABLE,0),('iterator_release_call',0x100e99a00,0x100f4e390,0x9c,0xcc3c,TABLE,0)]
DIRECT=[('nonzero_capabilities',TABLE+0x2757*8),('zero_capabilities',TABLE+0x58fc*8),('caller_return_dispatch',TABLE+0x4ef4*8)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 spans=[native(*r)for r in SPANS];banks=[]
 for label,l,r,key,add,base,bias in RULES:
  row=selected(l,r,key,add,base,bias);row.update(label=label,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex());banks.append(row)
 direct=[{'label':label,'slot':hex(a),'original_word_hex':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for label,a in DIRECT]
 prof=json.loads((ROOT/'daemon_query_state_profiles.json').read_text());used={int(x['address'],16)for row in prof['cases']for x in row['source_fixup_reads']};used|={int(b['slot'],16)for b in banks};used|={a for l,a in DIRECT};used.discard(0x1010b1e18)
 fix=verify_original_fixups(used);live=json.loads((ROOT/'daemon_query_state_live_ida.json').read_text());matched=[]
 for r in live['disassembly']['results']:
  for i in r['instructions']:
   raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw;matched.append({'pc':i['address'],'size_bytes':len(raw)})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','recover_daemon_iokit_census.py','daemon_query_state_live_ida.json']},'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':banks,'dispatch_slots':direct,'original_fixup_records':fix,'stack_guard_binding':binding(0x1010b1e18),'release_binding':binding(0x1010a0240),'live_IDB_source_rows_matched':matched,'premises':{'source_entry':'0x100364398','W21':'0x9376','X19':'0x101031ea0','X24':hex(TABLE),'FP':'F+0x120','F20_left_bank':'0x100fc4130','F8_saved_connection_pointer':'0x1010b6384','F58_saved_state_pointer':'0x1010b6380','private_state_flag_fixture':'09','private_connection_fixture':'0x5804','opaque_guard_fixture':'0x5d0ff00dcafed00d','native_full_entry_reachability_proved':False},'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/'daemon_query_state_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_spans':len(spans),'bank_rules':len(banks),'original_fixups':len(fix['records']),'live_IDB_instruction_rows':len(matched)}),flush=True)
if __name__=='__main__':main()
