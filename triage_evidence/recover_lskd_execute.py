#!/usr/bin/env python3
"""Workspace carrier, typed views, unsigned checker and first dispatch ABI.

Read-only original/normalized bytes. O(B+I+W+256R) time/source space. No native
heap/free, synchronization, request processing, crypto, IPC or IDB operation.
"""
import bisect,hashlib,json,struct
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_kext_aes_handoff import function,starts
from recover_kext_cold_init import pointer
from recover_carrier_control import span
from recover_lskd_fields import census
POOL=0xfffffe00084716e0;TABLE=0xfffffe000846c420
SPANS=[('wrapper',0xfffffe000a50c508,0xfffffe000a50c980),('bounds_checker',0xfffffe000a561058,0xfffffe000a56106c),('dispatcher_prefix',0xfffffe000a55f5e4,0xfffffe000a55f818),('null_output_return',0xfffffe000a510628,0xfffffe000a510650),('record_encode',0xfffffe000a50c7ac,0xfffffe000a50c808),('record_decode',0xfffffe000a55f6e4,0xfffffe000a55f744),('first_state',0xfffffe000a55f7e0,0xfffffe000a55f80c),('status_return',0xfffffe000a50c954,0xfffffe000a50c960)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e);parents=set();spans=[]
 for label,a,z in SPANS:
  r=span(k,a,z);assert IMAGE.read(a,z-a).hex()==r['bytes_hex'];ix=bisect.bisect_right(catalog,a)-1;assert z<=catalog[ix+1];parents.add(catalog[ix]);r.update(label=label,compiler_start=hex(catalog[ix]),compiler_end=hex(catalog[ix+1]));spans.append(r)
 specs=[('wrapper_stateA',0x791d3b0,0x7920e10,0xe3,-0x6b,POOL,-4),('wrapper_stateB',0x79172c0,0x7919cb0,0xb5,-0x4e,POOL,0),('wrapper_table',0x79174c0,0x7919db0,0x18,-0x54,POOL,-8),('allocate_view',0x791d3b0,0x7920e10,0x65,-0x60,POOL,-12),('wrapper_bounds',0x791d3b0,0x7920e10,0x3b,0x8ec,TABLE,0),('free_view',0x79171c0,0x7919bb0,0xea,-0xa,POOL,-4),('dispatcher_stateA',0x7920c10,0x79170c0,0x20,0x22,POOL,0),('dispatcher_stateB',0x79172c0,0x7919cb0,0x27,-0xf,POOL,0),('dispatcher_table',0x79172c0,0x7919cb0,0xff,-0x43,POOL,-8),('dispatcher_bounds',0x7920c10,0x79170c0,0x20,0x940,TABLE,0)]
 rules=[]
 for label,l,r,key,add,base,bias in specs:
  l|=0xfffffe0000000000;r|=0xfffffe0000000000;b=selected(l,r,key,add,base=base,bias=bias);b.update(label=label,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 targets={b['label']:int(b['target'],16)for b in rules};assert targets['wrapper_bounds']==targets['dispatcher_bounds']==0xfffffe000a561058;assert targets['allocate_view']==0xfffffe000847ae20 and targets['free_view']==0xfffffe000847aee0
 views=[]
 for kind,a in [('allocate',targets['allocate_view']),('free',targets['free_view'])]:
  raw=k.read(a,64);p=pointer(k,a+16);name=k.read(int(p['target'],16),80).split(b'\0')[0];flags,size=struct.unpack_from('<II',raw,40);assert name==b'site.AllocType'and flags==0xe4 and size==4096;views.append({'use':kind,'address':hex(a),'bytes64_hex':raw.hex(),'name_pointer':p,'name':name.decode(),'metadata_flags32':flags,'metadata_size32':size,'initial_runtime_links16_hex':raw[:16].hex()})
 assert views[0]['bytes64_hex']==views[1]['bytes64_hex'];slots=[{'index32':n,'original_pointer':pointer(k,TABLE+8*n)}for n in[0x563,0x57f]];assert[s['original_pointer']['target']for s in slots]==['0xfffffe000a510628','0xfffffe000a5247ac']
 roots=[pointer(k,POOL+n)for n in[0x150,0x2c0,0x210,0x530,0x308,0x420,0x4f0,0x600,0x2f8,0x630,0x510,0x1a0]];fs=[function(k,e,a)for a in sorted(parents)];exact=k.symbols([int(f['start'],16)for f in fs]+[0xfffffe000a5247ac,0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000c4b9a24]);scan=census(0xfffffe000a50c508)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','recover_carrier_control.py','recover_lskd_fields.py','lskd_fields_contracts.json','lskd_request_contracts.json']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':fs,'spans':spans,'bank_rules':rules,'original_bank_pointer_roots':roots,'typed_views':views,'first_dispatch_slots':slots,'additional_mutable_globals':[{'address':hex(a),'original8_hex':k.read(a,8).hex()}for a in[0xfffffe000ccc2e90,0xfffffe000ccc2c88]],'exact_symbols':exact,'execution_wrapper_census':scan,'native_target_executed':False,'native_heap_executed':False,'protected_operation_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_execute_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'compiler_envelopes':len(fs),'spans':len(spans),'new_rules':len(rules),'typed_views':len(views),'direct_execution_calls':len(scan['direct_calls'])}),flush=True)
if __name__=='__main__':main()
