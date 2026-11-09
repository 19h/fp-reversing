#!/usr/bin/env python3
"""Pin three error callers, shared status codec/dispatch, source and prior leads.
O(B+I+256R+F) time/space; no native target, API, Mach or PAC execution.
"""
import hashlib,json
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE,POOL,selected,verify_original_fixups
from recover_daemon_iokit_census import native
from probe_daemon_iokit_errors import RANGES
LABELS=['main_error','matching_error','open_error','status_adapter','nonpositive_gate','positive_status','status_lt100','status_lt256','status_lt_neg42000','status_lt_neg49998','status_default','status_store_return']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 spans=[native(n,*r)for n,r in zip(LABELS,RANGES)]+[native('open_saved_status',0x100478bb4,0x100478c14)];banks=[]
 for n,l,r,k,a,base,bias in [('main_error_adapter',0x100e99700,0x100f4e190,0x81,0xce6c,TABLE,0),('matching_error_adapter',0x100e99800,0x100f4e290,0x61,0xce9b,TABLE,0),('open_error_adapter',0x100fc4130,0x101031ea0,0xa3,0xce42,TABLE,0),('status_dispatch_root',0x100e99700,0x100f4e190,0x56,0x906,POOL,0xffffffffd0c4d1ee)]:
  b=selected(l,r,k,a,base,bias);b.update(label=n,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex());banks.append(b)
 assert [b['target']for b in banks]==['0x100422a60']*3+[hex(TABLE)]
 p=json.loads((ROOT/'daemon_iokit_errors_profiles.json').read_text());used={int(e['address'],16)for group in ['composed_cases','isolated_cases']for r in p[group]for e in r['source_fixup_reads']};used-={0x1010b1e18,0x1010a39c8};fix=verify_original_fixups(used)
 live=json.loads((ROOT/'daemon_iokit_errors_live_ida.json').read_text());matched=[]
 for row in live['disassembly']['results']:
  for i in row['instructions']:
   raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw;matched.append({'pc':i['address'],'size_bytes':len(raw)})
 prior=Path('/Users/___/Downloads/fpx/analysis');notes=[{'path':str(prior/n),'sha256':sha(prior/n),'contents':(prior/n).read_text(),'used_as':'Conditional prior leads; current source-derived proof and full selected composition checked independently.'}for n in ['arm_iokit_matching_services_followup_evidence.md','arm_iokit_open_failure_status_evidence.md','arm_iokit_open_failure_partition_evidence.md','arm_iokit_positive_open_result_evidence.md','arm_iokit_nonpositive_large_status_evidence.md','arm_iokit_positive_open_outer_result_evidence.md']]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_iokit_errors.py','daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_iokit_census.py','daemon_iokit_errors_live_ida.json','daemon_iokit_sync_contracts.json','daemon_iokit_objects_contracts.json']},'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':banks,'original_fixup_records':fix,'live_IDB_source_rows_matched':matched,'retained_prior_sources':notes,'normalization_mask32':'0x8b3dc651','status_control_plain32':'0x952a','native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_errors_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'banks':len(banks),'fixups':len(fix['records']),'live_IDB_rows':len(matched),'prior_leads':len(notes)}),flush=True)
if __name__=='__main__':main()
