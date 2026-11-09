#!/usr/bin/env python3
"""LSKDDispatchStream typed construction, four provider call sites and ABI.

Read-only original KC/normalized sources. O(B+I+W+256R) time/space; W is the
bounded aligned branch/pointer census. No native heap/execute/IPC operation.
"""
import bisect,hashlib,json,struct
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_kext_aes_handoff import function,starts
from recover_kext_cold_init import pointer
from recover_carrier_control import span
POOL=0xfffffe00084716e0;TABLE=0xfffffe000846c420;APPEND=0xfffffe000a50c2b0
SPANS=[('ctor_wrapper',0xfffffe000a50c048,0xfffffe000a50c2b0),('ctor_entry',0xfffffe000a54e4f0,0xfffffe000a54e6d8),('typed_allocate',0xfffffe000a529b5c,0xfffffe000a529c10),('after_allocate',0xfffffe000a5216a8,0xfffffe000a5218e4),('init_entry',0xfffffe000a547cd4,0xfffffe000a547e88),('init_fields',0xfffffe000a56e454,0xfffffe000a56e4f4),('init_return',0xfffffe000a5323c8,0xfffffe000a5323f0),('ctor_return',0xfffffe000a54af00,0xfffffe000a54af44),('publish',0xfffffe000a531914,0xfffffe000a531930),('dynamic_prefix',0xfffffe000a560c5c,0xfffffe000a560cbc),('fill_wrapper',0xfffffe000a508cec,0xfffffe000a508cf4),('fill_stub',0xfffffe000a69f344,0xfffffe000a69f354),('ctor_encode',0xfffffe000a50c140,0xfffffe000a50c1f4),('ctor_key',0xfffffe000a54e600,0xfffffe000a54e64c),('init_encode',0xfffffe000a52174c,0xfffffe000a52187c),('init_fields_symbolic',0xfffffe000a56e458,0xfffffe000a56e4cc)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def census():
 va,off,n=next(s for s in IMAGE.segments if s[0]<=APPEND<s[0]+s[2]);raw=IMAGE.data[off:off+n];calls=[]
 for j,(w,)in enumerate(struct.iter_unpack('<I',raw[:n//4*4])):
  if w&0x7c000000!=0x14000000:continue
  d=w&0x3ffffff;d=d-(1<<26)if d&(1<<25)else d;a=va+4*j
  if(a+4*d)&((1<<64)-1)==APPEND:calls.append({'pc':hex(a),'mnemonic':'bl'if w&0x80000000 else'b','bytes_hex':raw[4*j:4*j+4].hex()})
 words=[]
 for va,off,n in IMAGE.segments:
  for j,(v,)in enumerate(struct.iter_unpack('<Q',IMAGE.data[off:off+n//8*8])):
   if v==APPEND:words.append({'address':hex(va+j*8),'classification':'metadata_match'if va>=0xfffffe000ce00000 else'raw_pointer_candidate'})
 return {'scope':'All aligned B/BL in the normalized file-backed text segment containing the target; exact aligned qword values in all file-backed segments. Other targets/forms/modules and biased/computed pointers excluded.','text_words_scanned':len(raw)//4,'direct_calls':calls,'exact_qword_matches':words}
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e);spans=[];parents=set()
 for label,a,z in SPANS:
  row=span(k,a,z);assert IMAGE.read(a,z-a).hex()==row['bytes_hex'];ix=bisect.bisect_right(catalog,a)-1
  if ix+1<len(catalog):assert z<=catalog[ix+1];row.update(label=label,compiler_start=hex(catalog[ix]),compiler_end=hex(catalog[ix+1]));parents.add(catalog[ix])
  else:row.update(label=label,compiler_start=None,compiler_end=None,compiler_bounds_available=False)
  spans.append(row)
 providers=[]
 for name,a,pc,op,n,b,stop,target in[('scalar64',0xfffffe000a505848,0xfffffe000a5058b0,0x1b69,1,8,0xfffffe000a5058e0,0xfffffe000a50c508),('vault',0xfffffe000a505958,0xfffffe000a5059c4,0x1b6b,2,16,0xfffffe000a5059fc,0xfffffe000a50bdfc),('avd',0xfffffe000a505ac8,0xfffffe000a505b58,0x1b6a,5,44,0xfffffe000a505b90,0xfffffe000a50bdfc),('allowed',0xfffffe000a505de0,0xfffffe000a505e50,0x1b6c,2,12,0xfffffe000a505e84,0xfffffe000a50df34)]:
  parents.add(a);providers.append({'label':name,'start':hex(a),'append_call':hex(pc),'operation32':op,'entry_limit32':n,'payload_budget32':b,'capacity32':b+4*n,'boundary_call':hex(stop),'boundary_target':hex(target)})
 parents.update([0xfffffe000a508c78,0xfffffe000a50c508]);fs=[function(k,e,a)for a in sorted(parents)];prior=json.loads((ROOT/'legacy_tlv_contracts.json').read_text());rules=[]
 specs=[('ctor_table',0x791d3b0,0x7920e10,0x3b,-0x3f,POOL,-8),('ctor_target',0x791d3b0,0x7920e10,0x65,0x930,TABLE,0),('ctor_stateA',0x791d3b0,0x7920e10,0x3b,-0x20,POOL,-4),('ctor_stateB',0x7920d10,0x79173c0,0x2f,0x1b,POOL,0),('entry_table',0x79174c0,0x7919db0,0x18,-0x54,POOL,-8),('entry_stateA',0x79172c0,0x7919cb0,0xff,-0x89,POOL,-4),('entry_stateB',0x791d3b0,0x7920e10,0x3b,-0x78,POOL,0),('typed_allocate',0x79174c0,0x7919db0,0x0d,0x9dc,TABLE,0),('typed_view',0x791d3b0,0x7920e10,0x3b,-0xbf,POOL,-12),('fill',0x7920c10,0x79170c0,0x20,0x9a8,TABLE,0),('init_call',0x7920c10,0x79170c0,0x20,0x956,TABLE,0),('init_stateA',0x79174c0,0x7919db0,0x0d,0x9c,POOL,0),('init_stateB',0x79174c0,0x7919db0,0x18,-0x8d,POOL,0),('init_table',0x79172c0,0x7919cb0,0xff,-0x43,POOL,-8),('dynamic_allocate',0x79172c0,0x7919cb0,0xb5,0x94a,TABLE,0)]
 for label,l,r,key,add,base,bias in specs:
  l|=0xfffffe0000000000;r|=0xfffffe0000000000;b=selected(l,r,key,add,base=base,bias=bias);b.update(label=label,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 for label,l,r,key,add in[('execute_aligned_allocate',0xfffffe00079174c0,0xfffffe0007919db0,0x18,0x91b),('execute_typed_allocate',0xfffffe00079171c0,0xfffffe0007919bb0,0x58,0x95e),('execute_dispatch',0xfffffe00079172c0,0xfffffe0007919cb0,0x8d,0x98c),('execute_typed_free',0xfffffe0007920d10,0xfffffe00079173c0,0x2f,0x9d4),('execute_aligned_free',0xfffffe00079172c0,0xfffffe0007919cb0,0x27,0x996)]:
  b=selected(l,r,key,add,base=TABLE);b.update(label=label,base=hex(TABLE),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 targets={b['label']:int(b['target'],16)for b in rules};assert targets['typed_view']==0xfffffe000847b160 and targets['typed_allocate']==0xfffffe000c4ba154 and targets['init_call']==0xfffffe000a547cd4 and targets['dynamic_allocate']==0xfffffe000c4ba60c;assert[targets[n]for n in['execute_aligned_allocate','execute_typed_allocate','execute_dispatch','execute_typed_free','execute_aligned_free']]==[0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000a55f5e4,0xfffffe000c4ba368,0xfffffe000c4b9a24]
 state_addresses=sorted({targets[n]for n in targets if 'state'in n});assert state_addresses==[0xfffffe000ccc2c60,0xfffffe000ccc2c68,0xfffffe000ccc2e00,0xfffffe000ccc2ec8]
 view=targets['typed_view'];raw=k.read(view,64);p=pointer(k,view+16);name=k.read(int(p['target'],16),80).split(b'\0')[0];assert name==b'site.LSKDDispatchStream';flags,size=struct.unpack_from('<II',raw,40);assert size==160
 slots=[]
 for ix in[0x6a5,0x6ae,0x31c,0x330,0x542,0x569,0x34b,0x36c,0x5c0,0x5d8]:slots.append({'index32':ix,'original_pointer':pointer(k,TABLE+8*ix)})
 fill=pointer(k,0xfffffe000847c4d0);assert int(fill['target'],16)==0xfffffe000c648170;symbols=k.symbols([int(f['start'],16)for f in fs]+[0xfffffe000c648170,0xfffffe000c4ba154,0xfffffe000c4ba60c,0xfffffe000c4b9a08,0xfffffe000c4b9a24,0xfffffe000c4ba368]);scan=census();assert[r['pc']for r in scan['direct_calls']]==[p['append_call']for p in providers]
 globals=[{'address':hex(a),'original8_hex':k.read(a,8).hex()}for a in[0xfffffe000ccc2cb0,0xfffffe000ccc2c68,0xfffffe000ccc2e00,0xfffffe000ccc2ec8]]
 calls=ROOT.parent/'com.apple.driver.FairPlayIOKit_calls.txt';excerpt=''.join(calls.read_text().splitlines(keepends=True)[70:74]);assert'_zzLw2eOVu9pOHqpiNw1K4ki'in excerpt
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','recover_carrier_control.py','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':fs,'spans':spans,'kernel_functions':[k.function(0xfffffe000c648170)],'bank_rules':rules,'dispatch_slots':slots,'fill_binding':fill,'typed_view':{'address':hex(view),'bytes64_hex':raw.hex(),'name_pointer':p,'name':name.decode(),'metadata_flags32':flags,'metadata_size32':size,'initial_runtime_links16_hex':raw[:16].hex()},'additional_mutable_globals':globals,'providers':providers,'append_reference_census':scan,'exact_symbols':symbols,'supplied_calls_excerpt':{'path':str(calls),'sha256':sha(calls),'first_line':71,'last_line':74,'text':excerpt},'execution_wrapper_scope':'Static source/target bindings only; never executed in this increment.','native_target_executed':False,'typed_heap_executed':False,'request_execution_executed':False,'native_carrier_validity_proved':False,'full_goal_complete':False};(ROOT/'lskd_request_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(fs),'spans':len(spans),'banks':len(rules),'direct_provider_calls':len(providers),'typed_size':size}),flush=True)
if __name__=='__main__':main()
