#!/usr/bin/env python3
"""Input/output-sized allocations, entropy import and native callback registration.

O(B+I+256R) time,O(B+I) retained space. Source constructors and runtime-zero
cells are distinct evidence; no heap, entropy, registration or IPC executes.
"""
import hashlib,json,bisect,struct
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import starts,function
T=0xfffffe000846c420
SPANS=[('input_allocation_return',0xfffffe000a56d22c,0xfffffe000a56d268),('output_allocation',0xfffffe000a54409c,0xfffffe000a544164),('entropy_and_static_postcall',0xfffffe000a58c3bc,0xfffffe000a58c478),('entropy_wrapper',0xfffffe000a508d6c,0xfffffe000a508d74),('entropy_import_stub',0xfffffe000a69f394,0xfffffe000a69f3a4)]
CALLBACKS=[(0,0xfffffe000bace638,0x6961,0xfffffe000baf4a48,0xfffffe000c639428),(8,0xfffffe000baf3c08,0xf60a,0xfffffe000baf4a64,0xfffffe000c639458),(16,0xfffffe000bad1e24,0x5d01,0xfffffe000baf4a80,0xfffffe000c639488),(24,0xfffffe000ba97954,0x4d5f,0xfffffe000baf4a9c,0xfffffe000c6394b8),(32,0xfffffe000bacc7ec,0xedeb,0xfffffe000baf4ab8,0xfffffe000c6394e8),(40,0xfffffe000bacea44,0x3051,0xfffffe000baf4ad4,0xfffffe000c639518)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def generic(k,name,a,z):
 raw=k.read(a,z-a);ins=list(k.cs.disasm(raw,a));assert sum(i.size for i in ins)==len(raw);return {'label':name,'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]}
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');cat=starts(k,e);spans=[]
 for label,a,z in SPANS:
  s=span(k,a,z);assert IMAGE.read(a,z-a).hex()==s['bytes_hex'];j=bisect.bisect_right(cat,a)-1
  s.update(label=label,compiler_start=hex(cat[j])if j+1<len(cat)else None,compiler_end=hex(cat[j+1])if j+1<len(cat)else None)
  if j+1<len(cat):assert z<=cat[j+1]
  spans.append(s)
 banks=[]
 for name,l,r,key,add,target in [('output_allocation',0xfffffe00079172c0,0xfffffe0007919cb0,0x27,0x989,0xfffffe000c4ba60c),('entropy',0xfffffe000791d3b0,0xfffffe0007920e10,0x3b,0x947,0xfffffe000a508d6c)]:
  b=selected(l,r,key,add,base=T);assert int(b['target'],16)==target;b.update(label=name,base=hex(T),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));banks.append(b)
 native=[k.function(a)for a in[0xfffffe000be57d68,0xfffffe000c6393c4]];external=[generic(k,'kernel_read_random',int(native[0]['start'],16),int(native[0]['end'],16)),generic(k,'kernel_prng_registration',int(native[1]['start'],16),int(native[1]['end'],16)),generic(k,'corecrypto_callback_construction',0xfffffe000baf4a30,0xfffffe000baf4ae8),generic(k,'corecrypto_registration_import_stub',0xfffffe000bb04c0c,0xfffffe000bb04c1c)]
 cc=next(e for e in k.entries if e['name']=='com.apple.kec.corecrypto');ccstart=function(k,cc,0xfffffe000baf476c)
 callbacks=[{'source_table_offset_bytes':o,'global_callback_cell':hex(0xfffffe0007e6c988+o),'raw_function':hex(f),'PAC_diversity16':hex(d),'startup_store_PC':hex(p),'registration_store_PC':hex(q),'runtime_pointer_observed':False}for o,f,d,p,q in CALLBACKS]
 addresses=[0xfffffe000c4ba60c,0xfffffe000a508d6c,0xfffffe000be57d68,0xfffffe000c6393c4,0xfffffe000baf476c,0xfffffe000cdf0670,*[x[1]for x in CALLBACKS]]
 cells=[{'address':hex(a),'original8_hex':k.read(a,8).hex(),'native_value_known':False}for a in[0xfffffe0007e6c9a0,0xfffffe0007e6c9a8,0xfffffe000cb88f48]];assert all(c['original8_hex']=='00'*8 for c in cells)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','recover_carrier_control.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py']},'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'spans':spans,'external_source_spans':external,'native_functions':native,'corecrypto_start':ccstart,'corecrypto_entry_uuid':cc['uuid'],'bank_rules':banks,'dispatch_slots':[pointer(k,T+i*8)for i in[0x8de,0x4b3,0x47a,0x2bc]],'import_bindings':[pointer(k,a)for a in[0xfffffe000847c4f8,0xfffffe0008ab7cb8]],'source_callback_catalog':callbacks,'runtime_cells':cells,'exact_symbols':k.symbols(addresses),'read_random_abi':{'length_source':'low32(X1)','refresh_callback_cell':'0xfffffe0007e6c9a0','generate_callback_cell':'0xfffffe0007e6c9a8','context_cell':'0xfffffe000cb88f48','chunk_max_bytes':256,'generate_args':['context64','zero-extended u16[TPIDR_EL1+0x1B8]','chunk64','destination64'],'thread_field_semantic_name':'unknown','runtime_backend_observed':False},'entropy_request_bytes':28,'input_content_read':False,'native_target_executed':False,'native_registration_executed':False,'entropy_operation_executed':False,'model_memory_writes':0,'full_goal_complete':False};(ROOT/'lskd_input_buffers_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'kext_spans':len(spans),'external_spans':len(external),'native_functions':len(native),'source_callbacks':len(callbacks),'exhaustive_banks':len(banks)}),flush=True)
if __name__=='__main__':main()
