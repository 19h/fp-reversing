#!/usr/bin/env python3
"""Original allocation-return stores, reciprocal links, flags and cache roots.
O(source bytes+profiles+fixups+IDA rows) time/space; no target execution.
"""
import hashlib,json
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,verify_original_fixups,TABLE,FIXUPS
from recover_daemon_iokit_census import native
from probe_daemon_arena_storage import RANGES,D,N
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 spans=[native(n,a,z)for n,(a,z)in zip(['allocation_return','flag_gate','pointer_cache'],RANGES)]
 spans += [native('ready_publication',0x10046c73c,0x10046c780),native('other_flag_branch',0x100332700,0x100332734),native('unknown_read_frontier',0x1003ecb8c,0x1003ecb94)]
 p=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text());assert len(p['cases'])==64
 used={int(x['address'],16)for r in p['cases']for x in r['source_fixup_reads']};used|={TABLE+0x457c*8};used-={0x1010b1e18}
 live=json.loads((ROOT/'daemon_arena_storage_live_ida.json').read_text())
 for x in live['instructions']:assert IMAGE.read(int(x['address'],16),len(bytes.fromhex(x['bytes'])))==bytes.fromhex(x['bytes'])
 first=p['cases'][0];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_arena_storage.py','daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_iokit_census.py','daemon_arena_storage_profiles.json','daemon_arena_storage_live_ida.json','daemon_arena_entry_contracts.json','daemon_frame_entry_contracts.json']},'source_sha256':sha(SOURCE),'spans':spans,'descriptor_address':hex(D),'allocation_extent_bytes':N,'source_fixup_records':verify_original_fixups(used),'live_IDB_source_rows_matched':len(live['instructions']),'phase_registers_at_malloc':{},'source_cache_store_sites':{'SP+0x5f8':'0x100322440','SP+0x540':'0x100322444'},'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};out['phase_registers_at_malloc']={f'x{j}':json.loads((ROOT/'daemon_arena_entry_profiles.json').read_text())['cases'][0]['boundary']['registers31'][j]for j in [19,20,21,22,25,26,27,28]};out['dependencies']['daemon_arena_entry_profiles.json']=sha(ROOT/'daemon_arena_entry_profiles.json');(ROOT/'daemon_arena_storage_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'original_fixups':len(used),'IDB_rows':len(live['instructions'])}),flush=True)
if __name__=='__main__':main()
