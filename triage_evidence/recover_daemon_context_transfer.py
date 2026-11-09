#!/usr/bin/env python3
"""Original context/copy/comparison/entropy ABI and loader-zero provenance.
O(source bytes+traces+256R+fixups+SDK bytes) time,O(largest trace) space.
No target/native execution or IDB mutation.
"""
import hashlib,json,subprocess
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,selected,verify_original_fixups
from recover_daemon_iokit_census import native
from resolve_kernel_collection_interfaces import macho
from daemon_import_bindings import binding
from replay_daemon_context_transfer import unpack
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=json.loads((ROOT/'daemon_context_transfer_profiles.json').read_text());spans=[native(n,a,z)for n,a,z in [('context_entry',0x1003ecb8c,0x1003ed07c),('caller_key_producer',0x10032c960,0x10032c9a4),('comparison_helper',0x10041a5e0,0x10041a670),('comparison_caller',0x1002dc094,0x1002dc1a8),('nonzero_continuation',0x10031cc98,0x10031ccd8),('entropy_import',0x10040953c,0x100409578)]]
 banks=[selected(0x100e99800,0x100f4e290,0x61,0xcbad,TABLE,0),selected(0x100fc4230,0x101031fa0,0x6c,0xcba5,TABLE,0)];fix={int(a,16)for r in p['cases']for a in r['fixup_addresses']};fix|={TABLE+0x174e*8,TABLE+0x178c*8};fix-={0x1010b1e18}
 live=json.loads((ROOT/'daemon_context_transfer_live_ida.json').read_text());entropy=json.loads((ROOT/'daemon_context_entropy_live_ida.json').read_text());rows=live['instructions']+entropy['instructions']
 for row in rows:assert IMAGE.read(int(row['address'],16),len(bytes.fromhex(row['bytes'])))==bytes.fromhex(row['bytes'])
 sec=next(s for s in macho(IMAGE.data,0,'daemon')['sections']if s['address']<=0x1010c8258<s['address']+s['size']);assert sec['flags']&255==1
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());header=sdk/'usr/include/_stdlib.h';lines=header.read_text().splitlines();declarations=[{'line':j+1,'text':s.strip()}for j,s in enumerate(lines)if'arc4random(void)'in s];assert declarations==[{'line':287,'text':'uint32_t arc4random(void);'}]
 summaries=[]
 for row in p['cases']:
  t=unpack(row);unknown_writes=[{'pc':s['pc'],**e}for s in t['steps']for e in s['events']if e['kind']=='write'and'terms'in e['value']];summaries.append({'case':row['prior_case_index'],'boundary':t['boundary'],'origins':t['origins'],'final_source_fields':t['final_source_fields'],'unknown_copy_stores':unknown_writes,'source_visits':len(t['steps']),'loader_zero_reads':row['loader_zero_reads']})
 deps=['daemon_context_transfer_profiles.json','daemon_context_transfer_symbolic.py','daemon_context_transfer_live_ida.json','daemon_context_entropy_live_ida.json','daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py','resolve_kernel_collection_interfaces.py','recover_daemon_iokit_census.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':banks,'source_fixup_records':verify_original_fixups(fix),'comparison_slots':[{'slot':hex(TABLE+i*8),'index':hex(i)}for i in [0x174e,0x178c]],'entropy_binding':binding(int(banks[1]['slot'],16)),'zero_fill_control_section':sec,'zero_fill_control_address':'0x1010c8258','SDK_header':{'path':str(header),'sha256':sha(header),'declarations':declarations,'scope':'Installed SDK declaration only; native target execution and build equivalence unknown.'},'live_IDB_source_rows_matched':len(rows),'context_summaries':summaries,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_context_transfer_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'banks':len(banks),'fixups':len(fix),'IDB_rows':len(rows),'contexts':len(summaries)}),flush=True)
if __name__=='__main__':main()
