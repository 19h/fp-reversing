#!/usr/bin/env python3
"""Original version-fallback source, dispatch/fixup and retained-note provenance.

O(B+I+256R+F) time,O(B+I+F) space. No native target or IDB mutation.
"""
import hashlib,json
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,POOL,TABLE,selected,verify_original_fixups
from recover_daemon_iokit_census import native
from probe_daemon_query_fallback import RANGES
SPANS=[('fallback_callee',*RANGES[0]),('byte3_equal_gate',*RANGES[1]),('byte2_high_gate',*RANGES[2]),('byte2_equal_gate',*RANGES[3]),('byte1_marker',*RANGES[4]),('result_store_return',*RANGES[5]),('marker_caller',*RANGES[6]),('capability_bit_update',*RANGES[7]),('input_record_pack',0x1000115a0,0x100011608)]
RULES=[('state_fixed_input_3A',0x100fc4130,0x101031ea0,0xbb,0x1c8,POOL,0xfffffffffeff1acd),('table_fixed_input_3A',0x101031da0,0x100e99900,0x0a,0x830,POOL,0xffffffffd0c4d1ee)]
SLOTS=[0x101070818,0x101070b20,0x10104d4a0,0x10104d3a8,0x10107d7e0,0x10107d698,0x10105f500,0x10105f7b8,0x1010570a8,0x10104d9a8]
PRIOR=Path('/Users/___/Downloads/fpx/analysis')
NOTES=['arm_iokit_helper_successors_evidence.md','arm_iokit_threshold_machine_evidence.md','arm_iokit_helper_successors_proof.py','arm_iokit_threshold_machine_proof.py']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 spans=[native(*s)for s in SPANS];banks=[]
 for label,l,r,key,add,base,bias in RULES:
  row=selected(l,r,key,add,base,bias);row.update(label=label,base=hex(base),source_byte_input=0x3a,left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex());banks.append(row)
 prof=json.loads((ROOT/'daemon_query_fallback_profiles.json').read_text());used={int(x['address'],16)for row in prof['cases']for x in row['source_fixup_reads']};used|=set(SLOTS);used.discard(0x1010b1e18);fix=verify_original_fixups(used)
 live=json.loads((ROOT/'daemon_query_fallback_live_ida.json').read_text());matched=[]
 for r in live['disassembly']['results']:
  for i in r['instructions']:
   raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw;matched.append({'pc':i['address'],'size_bytes':len(raw)})
 prior=[{'path':str(PRIOR/n),'sha256':sha(PRIOR/n),'contents':(PRIOR/n).read_text(),'used_as':'Prior analysis leads; independently source-checked and extended here; no old native/PAC claim adopted.'}for n in NOTES]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_iokit_census.py','probe_daemon_query_fallback.py','daemon_query_fallback_live_ida.json']},'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':banks,'dispatch_slots':[{'slot':hex(a),'original_word_hex':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in SLOTS],'original_fixup_records':fix,'live_IDB_source_rows_matched':matched,'retained_prior_sources':prior,'premises':'Inherit QS1-QS12 and exact guarded V/C words; zero-capability fallback receives the source-prepared16B input with initially unknown result at+0x10. Cached version encodings have the initial helper epoch. No native concurrency/PAC or full predecessor reachability.','native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_query_fallback_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_spans':len(spans),'bank_rules':len(banks),'original_fixups':len(fix['records']),'live_IDB_instruction_rows':len(matched),'retained_prior_sources':len(prior)}),flush=True)
if __name__=='__main__':main()
