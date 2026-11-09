#!/usr/bin/env python3
"""Original positive-route index, retry, cached vector and nullable-slot windows.

O(B+I+256R) time, O(B+I) retained space. Exact compiler envelopes bound byte
provenance, not source-level functions. No target or IDB mutation executes.
"""
import hashlib,json,bisect
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import starts
T=0xfffffe000846c420
SPANS=[('vault_positive_index',0xfffffe000a54b194,0xfffffe000a54b1bc),('allowed_positive_index',0xfffffe000a511608,0xfffffe000a51162c),('vault_acquire_retry',0xfffffe000a57edfc,0xfffffe000a57ef04),('allowed_acquire_retry',0xfffffe000a572728,0xfffffe000a57283c),('vault_tag_retry',0xfffffe000a52265c,0xfffffe000a522690),('allowed_tag_retry',0xfffffe000a591b38,0xfffffe000a591b84),('vault_vector_slot',0xfffffe000a58b7cc,0xfffffe000a58b814),('allowed_vector_slot',0xfffffe000a57e26c,0xfffffe000a57e2d8),('vault_zero_tag',0xfffffe000a59bb00,0xfffffe000a59bb28),('allowed_zero_tag',0xfffffe000a535e3c,0xfffffe000a535e6c),('vault_null_slot',0xfffffe000a533214,0xfffffe000a533234),('allowed_null_slot',0xfffffe000a535820,0xfffffe000a535844),('vault_nonnull_consumer_prefix',0xfffffe000a525270,0xfffffe000a525298),('allowed_nonnull_consumer_prefix',0xfffffe000a528b10,0xfffffe000a528b38),('writer_frame_table_candidate',0xfffffe000a589908,0xfffffe000a58993c),('writer_store_candidate',0xfffffe000a548094,0xfffffe000a5480a4)]
SLOTS=[('vault_retry_fragment',0x6f1),('allowed_retry_fragment',0x34c),('vault_retry_callback',0x96),('allowed_retry_callback',0),('vault_tag_zero',0x86b),('vault_tag_nonzero',0x85c),('allowed_tag_zero',0x275),('allowed_tag_nonzero',0x2d0),('vault_slot_null',0x455),('vault_slot_nonnull',0x42b),('allowed_slot_null',0x515),('allowed_slot_nonnull',0x502)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');cat=starts(k,e);ss=[]
 for label,a,z in SPANS:
  s=span(k,a,z);assert IMAGE.read(a,z-a).hex()==s['bytes_hex'];j=bisect.bisect_right(cat,a)-1;assert z<=cat[j+1];s.update(label=label,compiler_start=hex(cat[j]),compiler_end=hex(cat[j+1]));ss.append(s)
 slots=[{'label':label,'index32':hex(ix),'pointer':pointer(k,T+ix*8)}for label,ix in SLOTS]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','recover_carrier_control.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py']},'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'spans':ss,'dispatch_slots':slots,'vector_root':{'cell_address':'0xfffffe000ccc78d0','original8_hex':k.read(0xfffffe000ccc78d0,8).hex(),'source_role':'Loaded as an eight-byte-slot array base in the declared positive route. Native initialization, extent, contents and ownership unknown.','native_runtime_pointer_known':False},'table_address':'0xfffffe000ccc7b08','indexed_vector_extent_bytes':8192,'vector_allocation_extent_proved':False,'writer_candidates':{'frame_table_store_PC':'0xfffffe000a589938','indexed_u32_store_PC':'0xfffffe000a5480a0','table_alias_or_reaching_definition_established':False,'missing_inputs':['SP+0xc28 byte-bank pointer','X26 second byte-bank pointer','same-frame reaching definition from SP+0xd28 producer to indexed store']},'exact_symbols':k.symbols([0xfffffe000ccc78d0,*[int(x['pointer']['target'],16)for x in slots]]),'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/'lskd_objects_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_spans':len(ss),'original_dispatch_slots':len(slots)}),flush=True)
if __name__=='__main__':main()
