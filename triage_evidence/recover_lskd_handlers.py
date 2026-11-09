#!/usr/bin/env python3
"""Original handler preparation, compact lookup, initializer and random binding.

O(B+I+256R) time/source space. No native target/API/crypto/IPC operation.
"""
import bisect,hashlib,json
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,selected
from recover_kext_aes_handoff import function,starts
from recover_kext_cold_init import pointer
from recover_carrier_control import span
from lskd_handlers_spec import HANDLERS,SEARCH_BLOCKS,EXTRA_SPANS
TABLE=0xfffffe000846c420;POOL=0xfffffe00084716e0
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e);parents=set();spans=[]
 for row in [{'label':'handler_'+h['operation'],'start':h['entry'],'end':h['end']}for h in HANDLERS]+SEARCH_BLOCKS+EXTRA_SPANS:
  a,z=int(row['start'],16),int(row['end'],16);s=span(k,a,z);assert IMAGE.read(a,z-a).hex()==s['bytes_hex'];ix=bisect.bisect_right(catalog,a)-1
  if ix+1<len(catalog):
   assert z<=catalog[ix+1];parents.add(catalog[ix]);s.update(compiler_start=hex(catalog[ix]),compiler_end=hex(catalog[ix+1]))
  else:s.update(compiler_start=None,compiler_end=None,compiler_bounds_available=False)
  s['label']=row['label'];spans.append(s)
 specs=[('handler_'+h['operation'],*(int(h['bank'][n],16)for n in ['left','right','key','additive','base']))for h in HANDLERS if 'bank'in h]
 for label,l,r,key,add,base in [('stop_call',0x791d3b0,0x7920e10,0xe3,0x8b6,TABLE),('scalar_stateA',0x79171c0,0x7919bb0,0xea,0x55,POOL),('scalar_stateB',0x79172c0,0x7919cb0,0xff,-0x7c,POOL),('scalar_call',0x79172c0,0x7919cb0,0xb5,0x970,TABLE),('scalar_table',0x79172c0,0x7919cb0,0x8d,0x3f,POOL),('span_stateA',0x7920c10,0x79170c0,0xaa,-0x13,POOL),('span_stateB',0x79174c0,0x7919db0,0x18,-0x8d,POOL),('span_call',0x79174c0,0x7919db0,0x50,0x95b,TABLE),('span_table',0x79171c0,0x7919bb0,0xea,0x69,POOL),('search_table',0x7920d10,0x79173c0,0xbb,-0x58,POOL)]:specs.append((label,0xfffffe0000000000|l,0xfffffe0000000000|r,key,add,base))
 banks=[]
 for label,l,r,key,add,base in specs:
  b=selected(l,r,key,add,base=base);b.update(label=label,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));banks.append(b)
 stub=next(s for s in spans if s['label']=='random_stub');print(stub['instructions'],flush=True)
 # The explicit binding is checked from the original ADRP/LDR import stub.
 i=list(CS.disasm(bytes.fromhex(stub['bytes_hex']),int(stub['start'],16)));assert [x.mnemonic for x in i]==['adrp','add','ldr','braa'];slot=int(i[0].op_str.split('#')[1],16)+int(i[1].op_str.split('#')[1],16);binding=pointer(k,slot);symbols=k.symbols([int(binding['target'],16),0xfffffe000a508d6c]);assert any(s['name']=='_read_random'for s in symbols[binding['target']])
 fs=[function(k,e,a)for a in sorted(parents)];newglobals=[{'address':hex(a),'original8_hex':k.read(a,8).hex()}for a in [0xfffffe000ccc2e10,0xfffffe000ccc2db0,0xfffffe000ccc2ef8]]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['lskd_handlers_spec.py','lskd_consumer_contracts.json','lskd_consumer_profiles.json','lskd_request_contracts.json','kernel_native_reader.py','kext_port_tools.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','recover_carrier_control.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':fs,'spans':spans,'handlers':HANDLERS,'bank_rules':banks,'additional_mutable_globals':newglobals,'original_bank_pointer_roots':[pointer(k,POOL+v)for v in [0x150,0x2c0,0x308,0x420]],'random_import_binding':binding,'random_exact_symbols':symbols,'exact_symbols':k.symbols([int(f['start'],16)for f in fs]),'native_target_executed':False,'random_backend_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_handlers_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'compiler_envelopes':len(fs),'spans':len(spans),'banks':len(banks)}),flush=True)
if __name__=='__main__':main()
