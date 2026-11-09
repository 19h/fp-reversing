#!/usr/bin/env python3
"""Source-only span/u32 field ABIs and actual provider pre-execution paths.

O(B+I+W+256R) time/space; aligned B/BL and exact-qword census is bounded to
the normalized file-backed segments. No native/API/crypto/IPC execution.
"""
import bisect,hashlib,json,struct
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_kext_aes_handoff import function,starts
from recover_kext_cold_init import pointer
from recover_carrier_control import span
POOL=0xfffffe00084716e0;TABLE=0xfffffe000846c420
SPAN=0xfffffe000a50bdfc;U32=0xfffffe000a50df34
SPANS=[('span_wrapper',SPAN,0xfffffe000a50c048),('u32_wrapper',U32,0xfffffe000a50e170),('u32_bridge',0xfffffe000a54daf8,0xfffffe000a54df90),('span_key',0xfffffe000a50bef0,0xfffffe000a50bf30),('span_pack',0xfffffe000a50bf30,0xfffffe000a50bf84),('u32_outer_pack',0xfffffe000a50e024,0xfffffe000a50e0a8),('u32_decode_payload',0xfffffe000a54dbf4,0xfffffe000a54ddac),('u32_decode_tag_pack',0xfffffe000a54ddac,0xfffffe000a54decc)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def census(target):
 va,off,n=next(s for s in IMAGE.segments if s[0]<=target<s[0]+s[2]);raw=IMAGE.data[off:off+n];calls=[]
 for j,(w,)in enumerate(struct.iter_unpack('<I',raw[:n//4*4])):
  if w&0x7c000000!=0x14000000:continue
  d=w&0x3ffffff;d=d-(1<<26)if d&(1<<25)else d;a=va+4*j
  if(a+4*d)&((1<<64)-1)==target:calls.append({'pc':hex(a),'mnemonic':'bl'if w&0x80000000 else'b','bytes_hex':raw[4*j:4*j+4].hex()})
 matches=[]
 for va,off,n in IMAGE.segments:
  for j,(w,)in enumerate(struct.iter_unpack('<Q',IMAGE.data[off:off+n//8*8])):
   if w==target:matches.append({'address':hex(va+j*8),'classification':'metadata_match'if va>=0xfffffe000ce00000 else'raw_pointer_candidate'})
 return {'scope':'Aligned B/BL in target text segment and exact aligned qwords in file-backed segments; indirect/computed/biased references and other modules excluded.','target':hex(target),'text_words_scanned':len(raw)//4,'direct_calls':calls,'exact_qword_matches':matches}
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e);parents=set();spans=[]
 for label,a,z in SPANS:
  row=span(k,a,z);assert IMAGE.read(a,z-a).hex()==row['bytes_hex'];ix=bisect.bisect_right(catalog,a)-1;assert z<=catalog[ix+1];parents.add(catalog[ix]);row.update(label=label,compiler_start=hex(catalog[ix]),compiler_end=hex(catalog[ix+1]));spans.append(row)
 specs=[('span_stateA',0x79174c0,0x7919db0,0x0d,0x50,POOL),('span_stateB',0x79174c0,0x7919db0,0x50,-0x63,POOL),('span_target',0x79174c0,0x7919db0,0x0d,0xa08,TABLE),('span_table',0x79172c0,0x7919cb0,0x27,0x2a,POOL),('u32_stateA',0x7920c10,0x79170c0,0xaa,-5,POOL),('u32_stateB',0x791d3b0,0x7920e10,0x3b,-0x78,POOL),('u32_target',0x791d3b0,0x7920e10,0x65,0x93b,TABLE),('u32_table',0x79172c0,0x7919cb0,0xff,-0x43,POOL),('bridge_stateA',0x791d3b0,0x7920e10,0x3b,-0x2d,POOL),('bridge_stateB',0x79172c0,0x7919cb0,0xb5,-0x4e,POOL),('bridge_target',0x7920d10,0x79173c0,0xbb,0x932,TABLE),('bridge_table',0x791d3b0,0x7920e10,0xe3,-0x6d,POOL)]
 rules=[]
 for label,l,r,key,add,base in specs:
  l|=0xfffffe0000000000;r|=0xfffffe0000000000;b=selected(l,r,key,add,base=base);b.update(label=label,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 targets={b['label']:int(b['target'],16)for b in rules};assert targets['span_target']==targets['bridge_target']==0xfffffe000a55e8b0 and targets['u32_target']==0xfffffe000a54daf8;assert all(targets[n]==TABLE+8 for n in['span_table','u32_table','bridge_table'])
 roots=[pointer(k,POOL+n)for n in[0x308,0x420,0x210,0x530,0x150,0x2c0,0x2f8,0x630]];fs=[function(k,e,a)for a in sorted(parents)]
 prior=json.loads((ROOT/'lskd_request_contracts.json').read_text());providers=[]
 for p,call in zip(prior['providers'],[0xfffffe000a5058e0,0xfffffe000a505a2c,0xfffffe000a505c68,0xfffffe000a505eb4]):providers.append({**p,'execution_call':hex(call)})
 extra=[{'address':hex(a),'original8_hex':k.read(a,8).hex()}for a in[0xfffffe000ccc2ca0,0xfffffe000ccc2bb0,0xfffffe000ccc2de0]]
 scans=[census(a)for a in[SPAN,U32]];symbols=k.symbols([int(f['start'],16)for f in fs]);out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','recover_carrier_control.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':fs,'spans':spans,'bank_rules':rules,'original_bank_pointer_roots':roots,'providers':providers,'additional_mutable_globals':extra,'reference_census':scans,'exact_symbols':symbols,'native_target_executed':False,'request_execution_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_fields_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(fs),'spans':len(spans),'banks':len(rules),'direct_calls':[len(s['direct_calls'])for s in scans]}),flush=True)
if __name__=='__main__':main()
