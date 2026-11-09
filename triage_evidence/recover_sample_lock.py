#!/usr/bin/env python3
"""Original sample lock adapters, caller envelopes and preparer entry gates.

O(B+I+256R+chain work) time and source space. Read-only original sources;
no lock, provider, crypto, native target or IDB operation executes.
"""
import hashlib,json
from pathlib import Path
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,selected
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from recover_carrier_control import span
ACQ=0xfffffe000a5b403c;REL=0xfffffe000a5bfc6c;PREP=0xfffffe000a621118;GLOBAL=0xfffffe000ccceab8
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');fs=[function(k,e,a)for a in[ACQ,REL,PREP,0xfffffe000a508dd4,0xfffffe000a508de4,0xfffffe000a508d94,0xfffffe000a508d9c]]
 for f in fs:assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex']
 family={'A':(0xfffffe0007949dd0,0xfffffe000792fbc0),'D':(0xfffffe000792fcc0,0xfffffe00079391f0),'E':(0xfffffe0007941f60,0xfffffe000794a0d0),'F':(0xfffffe000792fdc0,0xfffffe00079392f0)}
 specs=[('first_acquire','A',0xb4,0xe7b,TABLE,0,ACQ),('second_acquire','A',0x16,0xe61,TABLE,0,ACQ),('first_release','E',5,0xef5,TABLE,0,REL),('second_release','E',0x6d,0xf0f,TABLE,0,REL),('explicit_mutex_lock','F',0x93,0xea7,TABLE,0,0xfffffe000a508dd4),('fallback_lock_cell_acquire','F',0x93,-0x12,POOL,-4,GLOBAL),('fallback_RW_write','A',0x16,0xf12,TABLE,0,0xfffffe000a508d94),('explicit_mutex_unlock','E',0x98,0xf0d,TABLE,0,0xfffffe000a508de4),('fallback_lock_cell_release','D',0x87,-5,POOL,-4,GLOBAL),('fallback_RW_done','D',0x47,0xeaf,TABLE,0,0xfffffe000a508d9c)];rules=[]
 for name,fam,key,add,base,bias,target in specs:
  r=selected(*family[fam],key,add,base=base,bias=bias);assert int(r['target'],16)==target;r.update(label=name,base=hex(base),left256_hex=IMAGE.read(family[fam][0],256).hex(),right256_hex=IMAGE.read(family[fam][1],256).hex(),original_pointer=pointer(k,int(r['slot'],16)));rules.append(r)
 bindings=[]
 for label,wrapper,stub,slot,symbol in[('mutex_lock',0xfffffe000a508dd4,0xfffffe000a69f094,0xfffffe000847c378,'_IOLockLock'),('mutex_unlock',0xfffffe000a508de4,0xfffffe000a69f0b4,0xfffffe000847c388,'_IOLockUnlock'),('RW_write',0xfffffe000a508d94,0xfffffe000a69f144,0xfffffe000847c3d0,'_IORWLockWrite'),('RW_done',0xfffffe000a508d9c,0xfffffe000a69f134,0xfffffe000847c3c8,'_IORWLockUnlock')]:
  p=pointer(k,slot);symbols=k.symbols([int(p['target'],16)])[p['target']];assert symbol in[x['name']for x in symbols];bindings.append({'label':label,'wrapper':hex(wrapper),'wrapper_source':span(k,wrapper,wrapper+8),'stub_source':span(k,stub,stub+16),'original_pointer':p,'exact_symbols':symbols,'kernel_function':k.function(int(p['target'],16)),'native_primitive_executed':False})
 routes=[]
 for label,ix in[('preparer_nonnull',0xa07),('preparer_null',0xa4f),('acquire_explicit',0x736),('acquire_fallback',0x729),('acquire_fallback_present',0x545),('acquire_return',0x555),('release_explicit',0xc36),('release_fallback',0xc33),('release_return',0x53c)]:routes.append({'label':label,'index':hex(ix),'original_pointer':pointer(k,TABLE+8*ix)})
 specs=[('first_preparer_builder',0xfffffe000a64b148,0xfffffe000a64b220),('second_preparer_builder',0xfffffe000a68f334,0xfffffe000a68f41c),('first_preparer_return',0xfffffe000a64b220,0xfffffe000a64b284),('second_preparer_return',0xfffffe000a68f41c,0xfffffe000a68f448),('first_acquire_caller',0xfffffe000a64b284,0xfffffe000a64b348),('second_acquire_caller',0xfffffe000a68f448,0xfffffe000a68f510),('first_release_caller',0xfffffe000a64b49c,0xfffffe000a64b560),('second_release_caller',0xfffffe000a68f6b4,0xfffffe000a68f764),('bounds',0xfffffe000a687ecc,0xfffffe000a687ee0)];spans=[dict(span(k,a,z),label=n)for n,a,z in specs]
 old=json.loads((ROOT/'sample_caller_contracts.json').read_text());parents=[]
 for b in old['builder_contexts']:
  f=function(k,e,int(b['parent_compiler_start'],16));assert f['sha256']==b['parent_sha256'];parents.append({n:f[n]for n in['start','end','sha256']})
 h=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers/IOKit/IOLocks.h');lines=h.read_text().splitlines(keepends=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','recover_carrier_control.py','carrier_control_contracts.json','sample_caller_contracts.json']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':fs,'spans':spans,'bank_rules':rules,'primitive_bindings':bindings,'selected_routes':routes,'parent_contexts':parents,'lock_record':{'minimum_extent_bytes':12,'pointer_field_offset':0,'selector_field_offset':8,'acquire_key32':'(P XOR 0x6133a0c8) * 0x84d77373 mod 2^32','acquire_selector32':'word8 + key32 mod 2^32','release_key32':'(P XOR 0x734a22b2) * 0x8c229611 mod 2^32','release_selector32':'word8 XOR key32','context_selectors':{'preparer':'0xa07','acquire':'0x729','release':'0xc33'},'fallback_cell':hex(GLOBAL),'native_lock_lifetime_proved':False},'caller_contexts':{'first':{'state32':'0x510','preparer_selector':'state32+0x4f7','acquire_selector':'state32+0x219','release_selector':'state32+0x723','explicit_pointer_cell_operand':'*(u64 *)(SP+0x880)','saved_status_register':'W26'},'second':{'state32':'0x753','preparer_selector':'state32+0x2b4','acquire_selector':'state32-0x2a','release_selector':'state32+0x4e0','explicit_pointer_cell_operand':'*(u64 *)(SP+0x3c8)','saved_status_register':'W25'}},'preparer_gate':{'selector32':'0xa07','nonnull_target':'0xfffffe000a62135c','null_target':'0xfffffe000a62173c','source_word32_tags':{'0x85283019':'0xfffffe000a621720','0x42059342':'0xfffffe000a621388'},'unrecognized_target':'0xfffffe000a62173c','later_input_language_proved':False},'SDK_header':{'path':str(h),'sha256':sha(h),'excerpts':[{'first_line':a,'last_line':z,'text':''.join(lines[a-1:z])}for a,z in[(88,120),(284,315)]],'SDK_matches_kernel_build_proved':False},'native_target_executed':False,'crypto_operation_executed':False,'full_goal_complete':False};(ROOT/'sample_lock_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(fs),'spans':len(spans),'banks':len(rules),'primitive_bindings':len(bindings),'selected_routes':len(routes)}),flush=True)
if __name__=='__main__':main()
