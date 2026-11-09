#!/usr/bin/env python3
"""Two legacy record wrappers, internal bridges and original stack probe.

O(B+I+256R) time/source space. Read-only original code/chains and exhaustive
byte banks; no native API, crypto, heap, synchronization or IDB operation.
"""
import hashlib,json
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected,qword
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
P=0xfffffe00084716e0;T=0xfffffe000846c420
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 baseline=ROOT/'interface_manifest.json';assert sha(baseline)=='9e67568ee4535cca357cc0dad45c530ec5e5e220c74e88865115e8907f7856cf';(ROOT/'legacy_stack_prior_manifest.json').write_bytes(baseline.read_bytes())
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');aa=[0xfffffe000a50c2b0,0xfffffe000a50e618,0xfffffe000a52fd18,0xfffffe000a570cf4,0xfffffe000a5a1cc4,0xfffffe000a5a1ccc,0xfffffe000a55e8b0,0xfffffe000a561344];fs=[function(k,e,a)for a in aa]
 for f in fs:assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex']
 specs=[('outer32_table',0x79171c0,0x7919bb0,0xea,0x69,P,-8),('outer32_target',0x79171c0,0x7919bb0,0xea,0x9f7,T,0),('outer64_table',0x7920d10,0x79173c0,0x2f,0x54,P,-8),('outer64_target',0x791d3b0,0x7920e10,0x65,0x900,T,0),('bridge32_table',0x7920c10,0x79170c0,0xaa,-0x19,P,-8),('bridge32_target',0x79174c0,0x7919db0,0x18,0x936,T,0),('bridge64_table',0x79172c0,0x7919cb0,0x27,0x2a,P,-8),('bridge64_target',0x791d3b0,0x7920e10,0xe3,0x946,T,0),('outer32_stateA',0x7920d10,0x79173c0,0x2f,0x63,P,-4),('outer32_stateB',0x7920d10,0x79173c0,0x2f,0x1b,P,0),('bridge32_stateA',0x791d3b0,0x7920e10,0x3b,-0x5a,P,-4),('bridge32_stateB',0x7920d10,0x79173c0,0xbb,-0x91,P,0),('outer64_stateA',0x7920c10,0x79170c0,0xaa,-0xd,P,0),('outer64_stateB',0x79171c0,0x7919bb0,0xea,0x30,P,0),('outer64_displacement_seed',0x79171c0,0x7919bb0,0xea,0x18,P,0),('bridge64_stateA',0x79172c0,0x7919cb0,0x8d,-0xb,P,0),('bridge64_stateB',0x7920c10,0x79170c0,0x20,-0x24,P,0),('bridge64_scratch',0x791d3b0,0x7920e10,0xe3,-0xbe,P,0)]
 rules=[]
 for label,l,r,key,add,base,bias in specs:
  l|=0xfffffe0000000000;r|=0xfffffe0000000000;b=selected(l,r,key,add,base=base,bias=bias);b.update(label=label,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 targets={b['label']:int(b['target'],16)for b in rules};assert[targets[n]for n in['outer32_target','outer64_target','bridge32_target','bridge64_target']]==[aa[2],aa[3],aa[6],aa[7]];assert all(targets[n]==T for n in targets if n.endswith('_table'))
 mutable=sorted({targets[n]for n in targets if '_state'in n or n in['outer64_displacement_seed','bridge64_scratch']});bindings=[pointer(k,P+o)for o in[0x2f8,0x630,0x4f0,0x600,0x210,0x530,0x308,0x420]]+[pointer(k,a)for a in[0xfffffe000847c5f8,0xfffffe000847c610]]
 syms=k.symbols(aa+[int(p['target'],16)for p in bindings]);assert '___chkstk_darwin'in[x['name']for x in syms[hex(aa[4])]];guard=int(bindings[-2]['target'],16)
 census=json.loads((ROOT/'rw_lifecycle_contracts.json').read_text())['literal_modifier_census'];excluded=[dict(r,resolved_target=hex(a),resolution='internal_record_bridge')for r,a in[(census['rows'][0],aa[2]),(census['rows'][2],aa[3])]];assert all(r['modifier16']=='0x9d3a'for r in excluded)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','rw_lifecycle_contracts.json']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':fs,'bank_rules':rules,'original_bindings':bindings,'exact_symbols':syms,'mutable_globals':[{'address':hex(a),'original8_hex':k.read(a,8).hex()}for a in mutable],'guard':{'address':hex(guard),'original8_hex':k.read(guard,8).hex()},'reclassified_modifier_sites':excluded,'remaining_unresolved_modifier_candidates':6,'records':{'outer32':{'minimum_extent_bytes':32,'source_initialized_bytes':22,'output_offset':16,'output_width_bytes':4},'outer64':{'minimum_extent_bytes':64,'source_initialized_bytes':52,'output_offset':56,'output_width_bytes':4}},'native_target_executed':False,'cached_FairPlay_lock_publication_proved':False,'full_goal_complete':False};(ROOT/'legacy_stack_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(fs),'exhaustive_banks':len(rules),'mutable_globals':len(mutable),'reclassified_modifier_sites':2}),flush=True)
if __name__=='__main__':main()
