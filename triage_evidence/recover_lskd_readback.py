#!/usr/bin/env python3
"""Extract bounded original readback source and exact typed-free metadata.

O(B+I+S log F) time, O(B+I) retained space. No target executes. Compiler
start envelopes are metadata; shared chunks are never assigned nearby names.
"""
import bisect,hashlib,json
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE
from recover_kext_aes_handoff import starts,function
from recover_carrier_control import span
from lskd_readback_spec import SPANS,GLOBALS,PURE_TARGETS
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e);spans=[]
 for row in SPANS:
  a,z=int(row['start'],16),int(row['end'],16);s=span(k,a,z);assert IMAGE.read(a,z-a).hex()==s['bytes_hex'];j=bisect.bisect_right(catalog,a)-1;assert z<=catalog[j+1];s.update(label=row['label'],compiler_start=hex(catalog[j]),compiler_end=hex(catalog[j+1]));spans.append(s)
 gl=[{'address':hex(a),'size_bytes':8,'original8_hex':k.read(a,8).hex()}for a in GLOBALS]
 addresses=PURE_TARGETS+[0xfffffe000a50550c,0xfffffe000c4ba368,0xfffffe000847af60,*GLOBALS,0xfffffe000a52f9f4,0xfffffe000a55ce30]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_readback_spec.py','kernel_native_reader.py','kext_port_tools.py','recover_kext_aes_handoff.py','recover_carrier_control.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'spans':spans,'query_caller_static':function(k,e,0xfffffe000a50550c),'additional_mutable_globals':gl,'exact_symbols':k.symbols(addresses),'typed_free_view':{'address':'0xfffffe000847af60','size_bytes':64,'original64_hex':k.read(0xfffffe000847af60,64).hex(),'runtime_link_bytes':16,'object_extent_bytes':160,'native_runtime_links_known':False},'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_readback_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'bounded_source_spans':len(spans),'exact_additional_controller_cells':len(gl)}),flush=True)
if __name__=='__main__':main()
