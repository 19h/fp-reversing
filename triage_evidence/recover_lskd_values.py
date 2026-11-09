#!/usr/bin/env python3
"""Original u64 consumption, caller handoffs and query publication continuations.

O(B+I+256R) time/source space. No native target/API/crypto/IPC execution.
"""
import bisect,hashlib,json
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_kext_aes_handoff import function,starts
from recover_kext_cold_init import pointer
from recover_carrier_control import span
from lskd_values_spec import SPANS,HANDOFFS,VALUE_RETURNS
TABLE=0xfffffe000846c420
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e);parents=set();spans=[]
 for row in SPANS:
  a,z=int(row['start'],16),int(row['end'],16);s=span(k,a,z);assert IMAGE.read(a,z-a).hex()==s['bytes_hex'];ix=bisect.bisect_right(catalog,a)-1;assert z<=catalog[ix+1];parents.add(catalog[ix]);s.update(label=row['label'],compiler_start=hex(catalog[ix]),compiler_end=hex(catalog[ix+1]));spans.append(s)
 specs=[('query_append',0x791d3b0,0x7920e10,0xe3,0x937)]
 # Only the query append rule is declared here; additional handoffs retain
 # exact dynamic original-slot evidence in the fresh verifier.
 rules=[]
 for label,l,r,key,add in specs:
  l|=0xfffffe0000000000;r|=0xfffffe0000000000;b=selected(l,r,key,add,base=TABLE);assert b['target']=='0xfffffe000a54daf8';b.update(label=label,base=hex(TABLE),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 fs=[function(k,e,a)for a in sorted(parents)];caller=function(k,e,0xfffffe000a50550c);symbols=k.symbols([int(f['start'],16)for f in fs]+[0xfffffe000a50550c]+[int(h['target'],16)for h in HANDOFFS]);out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['lskd_values_spec.py','lskd_handlers_contracts.json','lskd_handlers_profiles.json','lskd_response_contracts.json','lskd_fields_contracts.json','kernel_native_reader.py','kext_port_tools.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','recover_carrier_control.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':fs,'spans':spans,'bank_rules':rules,'handoffs':HANDOFFS,'value_return_sites':VALUE_RETURNS,'query_caller_static':caller,'exact_symbols':symbols,'native_target_executed':False,'native_request_execution_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_values_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'compiler_envelopes':len(fs),'spans':len(spans),'banks':len(rules),'handoffs':len(HANDOFFS)}),flush=True)
if __name__=='__main__':main()
