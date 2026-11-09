#!/usr/bin/env python3
"""Original sample metadata, transfer and nominal provider ABI source pins.

Read-only KC/normalized source, symbols and selected chains. O(B+I+256R+chain)
time/source space. No descriptor, crypto, provider or native operation executes.
"""
import hashlib,json
from pathlib import Path
from kext_port_tools import ROOT,SOURCE,IMAGE,POOL,selected
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');addresses=[0xfffffe000a6247a4,0xfffffe000a509fe8,0xfffffe000a508484,0xfffffe000a508534,0xfffffe000a509ab0,0xfffffe000a509a60,0xfffffe000a508030];funcs=[function(k,entry,a)for a in addresses]
 for f in funcs:assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex']
 fam={'A':(0xfffffe0007949dd0,0xfffffe000792fbc0),'B':(0xfffffe0007949fd0,0xfffffe000792ffc0),'E':(0xfffffe0007941f60,0xfffffe000794a0d0)};specs=[('metadata_read','E',5,0xf10,None,0),('descriptor_crypto_bridge','A',0x73,0xf78,None,0),('last_block_read','B',0xac,0xf23,None,0),('bulk_read','A',0xd8,0xf09,None,0),('buffered_crypto_wrapper','E',5,0xf19,None,0),('cached_buffer_cell','E',5,0xd3,POOL,-4)];rules=[]
 for label,family,key,add,base,bias in specs:
  opts={'bias':bias}
  if base is not None:opts['base']=base
  b=selected(*fam[family],key,add,**opts);b.update(label=label,base=hex(base)if base is not None else'0xfffffe0008472f20',left256_hex=IMAGE.read(fam[family][0],256).hex(),right256_hex=IMAGE.read(fam[family][1],256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 assert rules[-1]['target']=='0xfffffe000ccc7848';old=json.loads((ROOT/'kext_aes_handoff_contracts.json').read_text());provider=next(s for s in old['nominal_slots']if s['kind']=='aes'and s['offset_from_vptr']==0x890);p=pointer(k,int(provider['slot'],16));assert all(provider[n]==v for n,v in p.items());symbols=k.symbols([int(provider['target'],16)]+addresses);assert symbols[provider['target']]==provider['exact_symbols']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','sample_state_contracts.json','sample_descriptor_contracts.json','kext_aes_handoff_contracts.json','kext_buffer_contracts.json']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':funcs,'bank_rules':rules,'nominal_provider_slot':provider,'exact_symbols':symbols,'carrier_roles':{'key_data_argument':'state object base','IV_argument':'state + 0xb0, source carrier + 0x12 copied 16 bytes','metadata_field':'state + 0xc4, raw little-endian u32','provider_pointer_cell':'0xfffffe000ccceb08','global_descriptor_cell':'0xfffffe000ccceb10','samples_descriptor_cell':'0xfffffe000ccc7860','cached_bytes_cell':'0xfffffe000ccc7848'},'local_word_contracts':{'aligned_size':'u32(size) & 0xfffffff0','direct_operation':'u8(header[0]) == 0','buffered_provider_operation':'zero_extend32(u8(header[0])) XOR 1','direct_offsets':'zero_extend64(saved u32 source offset), same for source and destination','metadata_offset':'4 * zero_extend64(u32 metadata index)','batch_threshold_bytes':8192,'workspace_mask_stride_bytes':16,'nominal_global_buffer_capacity_bytes':81920,'native_input_domain_proved':False},'native_target_executed':False,'crypto_operation_executed':False,'native_provider_class_proved':False,'full_goal_complete':False};(ROOT/'sample_transfer_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'original_functions':len(funcs),'exhaustive_bank_rules':len(rules),'nominal_provider_slots':1}),flush=True)
if __name__=='__main__':main()
