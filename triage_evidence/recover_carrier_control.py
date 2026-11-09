#!/usr/bin/env python3
"""Source-pinned packed-carrier reset, common preparer and local producers.

Read-only original KC/normalized bytes. O(B+I+256R+chain work) time and
O(B+I) retained space. No target, provider, crypto, IPC or IDB execution.
"""
import hashlib,json
from pathlib import Path
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def span(k,a,z):
 raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a)
 return {'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]}
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 fs=[function(k,e,a)for a in[0xfffffe000a62309c,0xfffffe000a621118,0xfffffe000a67c54c,0xfffffe000a687d64]]
 for f in fs:assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex']
 families={'A':(0xfffffe0007949dd0,0xfffffe000792fbc0),'B':(0xfffffe0007949fd0,0xfffffe000792ffc0),'C':(0xfffffe0007949ed0,0xfffffe000792fec0),'D':(0xfffffe000792fcc0,0xfffffe00079391f0)}
 specs=[('first_builder_preparer','B',0x37,0xed4,0xfffffe000a64b21c,0xfffffe000a621118),('second_builder_preparer','A',0x5c,0xe3c,0xfffffe000a68f418,0xfffffe000a621118),('reset_fill_A','D',0x47,0xe6f,0xfffffe000a623244,0xfffffe000a687d64),('reset_fill_C','A',0x73,0xea3,0xfffffe000a623298,0xfffffe000a687d64),('reset_fill_B','A',0x5c,0xe18,0xfffffe000a6232ec,0xfffffe000a687d64),('wrapper_reset','C',0x92,0xeed,0xfffffe000a67c804,0xfffffe000a62309c)]
 rules=[]
 for label,family,key,add,call,target in specs:
  b=selected(*families[family],key,add);assert int(b['target'],16)==target
  b.update(label=label,call=hex(call),left256_hex=IMAGE.read(families[family][0],256).hex(),right256_hex=IMAGE.read(families[family][1],256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 pool=[]
 for off,bias in[(0x4f0,-4),(0x578,-4),(0x840,0),(0xbb8,0),(0xb70,0),(0xa10,0),(0x458,-8),(0x638,-12)]:
  p=pointer(k,POOL+off);assert int(p['target'],16)==qword(POOL+off);pool.append({'offset':hex(off),'bias':bias,'effective_pointer':hex(qword(POOL+off)+bias),'original_pointer':p})
 named=[('first_entry',0xfffffe000a635208,0xfffffe000a635258),('second_entry',0xfffffe000a6890dc,0xfffffe000a689104),('first_preparer_record',0xfffffe000a64b148,0xfffffe000a64b220),('second_preparer_record',0xfffffe000a68f334,0xfffffe000a68f41c),('heap_controls_11',0xfffffe000a69d954,0xfffffe000a69d978),('stack_controls_01',0xfffffe000a69825c,0xfffffe000a698278),('preparer_kind_zero',0xfffffe000a621490,0xfffffe000a6214a0),('preparer_kind_three',0xfffffe000a621a78,0xfffffe000a621a8c),('preparer_operation_zero',0xfffffe000a6221c4,0xfffffe000a6221cc),('bounds',0xfffffe000a687ecc,0xfffffe000a687ee0)]
 spans=[dict(span(k,a,z),label=n)for n,a,z in named]
 old=json.loads((ROOT/'sample_caller_contracts.json').read_text());parents=[]
 for b in old['builder_contexts']:
  f=function(k,e,int(b['parent_compiler_start'],16));assert f['sha256']==b['parent_sha256'];assert len(f['instructions'])==b['parent_instructions']
  writers=[]
  for i in f['instructions']:
   if i['mnemonic']in['add','sub','mov','ldp']and i['operands'].startswith(('sp,','x29,')):writers.append(i)
  parents.append({'name':b['name'],'start':f['start'],'end':f['end'],'sha256':f['sha256'],'instructions':len(f['instructions']),'literal_SP_FP_writers':writers,'all_stack_aliases_resolved':False})
 cpath=Path(str(SOURCE)+'.c');lines=cpath.read_text().splitlines(keepends=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','sample_caller_contracts.json','sample_state_contracts.json','sample_transfer_contracts.json']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':fs,'spans':spans,'bank_rules':rules,'pool_bindings':pool,'parent_contexts':parents,'exact_symbols':k.symbols([int(f['start'],16)for f in fs]),'reset_contract':{'pointer_argument':'H = *(u64 *)X0','access_extent_bytes':104,'zero_ranges_half_open':[[0,34],[36,89],[96,104]],'preserved_ranges_half_open':[[34,36],[89,96]],'zero_bytes':95,'preserved_bytes_within_extent':9,'fill_calls':[{'pc':'0xfffffe000a623244','destination_offset':2,'count_bytes':16,'value32':0},{'pc':'0xfffffe000a623298','destination_offset':18,'count_bytes':16,'value32':0},{'pc':'0xfffffe000a6232ec','destination_offset':57,'count_bytes':32,'value32':0}]},'preparer_partial_record':{'minimum_access_extent_bytes':64,'key64':'(P XOR 0xe10934e57abbf985) * 0xded29631 mod 2^64','selector32':'word30 XOR low32(key64)','fields':{'0x0':'opaque source pointer saved in X21','0x8':'saved pointer','0x10':'saved pointer','0x18':'packed carrier H','0x24':'output status on inspected return','0x28':'context pointer; +0x100 guarded at entry','0x30':'encoded selector32','0x38':'guard limit64'},'complete_record_schema_proved':False},'frame_arithmetic':{'first':{'FP_minus_entry_SP':-16,'body_SP_minus_entry_SP':-4336,'FP_minus_body_SP':4320,'H_minus_FP':-232,'H_minus_body_SP':4088,'conditional_on_stack_probe_contract':True},'second':{'FP_minus_entry_SP':-16,'body_SP_minus_entry_SP':-1632,'FP_minus_body_SP':1616,'candidate_H_minus_FP':-232,'candidate_H_minus_body_SP':1384,'candidate_not_linked_to_second_coordinator_carrier':True}},'associated_C':[{'path':str(cpath),'sha256':sha(cpath),'first_line':a,'last_line':z,'text':''.join(lines[a-1:z])}for a,z in[(189650,189691),(228532,228597)]],'native_target_executed':False,'crypto_operation_executed':False,'all_reaching_operation_bytes_boolean_proved':False,'full_goal_complete':False}
 (ROOT/'carrier_control_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(fs),'spans':len(spans),'banks':len(rules),'pool_bindings':len(pool),'parent_instructions':sum(p['instructions']for p in parents)}),flush=True)
if __name__=='__main__':main()
