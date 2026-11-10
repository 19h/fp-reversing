#!/usr/bin/env python3
"""Recover the complete inner write/call census and nominal dispatch evidence."""
import json,re,hashlib
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT,SOURCE,IMAGE,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from recover_versioned_request_abi import FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
P='inner_write_frontier'
SCOPE='Complete compiler-envelope inner store/call census,source-bound nominal call selections,conditional private-frame footprints,hardware ABI and original discriminator reuse. Full reaching paths,external write bounds,provider effects and actual zero deltas remain unproved.'
BASE=0xfffffe000a680000
FUNCTIONS={'inner':0xfffffe000a687ee0,'fill':0xfffffe000a687d64,'copy_adapter':0xfffffe000a508cf4,'hardware':0xfffffe000a508484,'hardware_init':0xfffffe000a508030}
# site,start,bank,key,add,left byte load,right byte load,cut,table load,target register
CALLS=[(0x81dc,0x8180,'F',0x47,0xec5,0x8198,0x81b0,0x81c0,0x81c8,'x8'),(0x826c,0x8234,'E',0x98,0xe55,0x8238,0x8244,0x8250,0x8258,'x8'),(0x8360,0x8328,'E',5,0xefb,0x832c,0x833c,0x8348,0x8350,'x8'),(0x83c0,0x8384,'F',0x87,0xe49,0x838c,0x839c,0x83a8,0x83b0,'x8'),(0x8450,0x8414,'T',0x16,0xea0,0x841c,0x842c,0x8438,0x8440,'x8'),(0x8510,0x84d0,'F',0x47,0xead,0x84d8,0x84e8,0x84f4,0x84fc,'x8'),(0x858c,0x854c,'T',0x5c,0xe56,0x8554,0x8568,0x8574,0x857c,'x8'),(0x8608,0x85d0,'T',0x5c,0xe56,0x85d8,0x85e8,0x85f0,0x85f8,'x8'),(0x87cc,0x878c,'T',0x16,0xe62,0x8794,0x87a4,0x87b4,0x87bc,'x8'),(0x89cc,0x8984,'T',0xb4,0xeba,0x898c,0x899c,0x89a8,0x89b0,'x8'),(0x8ae4,0x8aa8,'E',5,0xefb,0x8ab0,0x8ac0,0x8ad0,0x8ad8,'x8'),(0x8bc0,0x8b80,'E',5,0xf19,0x8b88,0x8b98,0x8ba4,0x8bac,'x8'),(0x8ccc,0x8c84,'B',0x93,0xe3c,0x8c94,0x8ca8,0x8cb0,0x8cb8,'x10'),(0x8e80,0x8e44,'D',0xef,0xec7,0x8e54,0x8e68,0x8e70,0x8e78,'x8')]
DEPS=['core_stack_delta_abi_source.json','core_stack_delta_abi_checks.json','kext_aes_handoff_contracts.json','kext_cold_init_contracts.json','kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','validate_core_stack_delta_abi.py','validate_context_descriptor_task_flow.py','validate_userclient_context_lifecycle.py','validate_versioned_request_abi.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','validate_daemon_reader_container_origins.py','daemon_word_round_tools.py']
def build():
 assert sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');fs={}
 for n,a in FUNCTIONS.items():
  f=function(k,e,a);f['bytes']=f.pop('bytes_hex');assert IMAGE.read(a,len(bytes.fromhex(f['bytes'])))==bytes.fromhex(f['bytes']);fs[n]=f
 parent=json.loads(read(ROOT/'core_stack_delta_abi_source.json'))
 for n in ['inner','hardware_init']:assert fs[n]==parent['functions'][n]
 dc=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for n,a in [('copy_stub',0xfffffe000a69f334),('canary_stub',0xfffffe000a69f294)]:
  raw=k.read(a,16);ii=list(dc.disasm(raw,a));assert len(ii)==4
  fs[n]={'start':hex(a),'end':hex(a+16),'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii],'boundary':'exact four-instruction import stub'}
 pairs={'E':(qword(POOL+0xc08)-8,qword(POOL+0x158)-4),'F':(qword(POOL+0x458)-8,qword(POOL+0x638)-12),'T':(qword(POOL+0x840),qword(POOL+0xbb8)),'B':(qword(POOL+0xf50)-4,qword(POOL+0xf20)-4),'D':(qword(POOL+0x4f0)-4,qword(POOL+0x578)-4)}
 banks={n+s:{'address':hex(a),'bytes':IMAGE.read(a,256).hex()}for n,lr in pairs.items()for s,a in zip(['L','R'],lr)};rules=[];fr={};ii=fs['inner']['instructions'];at={int(i['ea'],16):i for i in ii}
 def fragment(n,a,z):
  f=next(f for f in fs.values()if int(f['start'],16)<=a<z<=int(f['end'],16));ins=[i for i in f['instructions']if a<=int(i['ea'],16)<z];assert len(ins)*4==z-a
  fr[n]={'start':hex(a),'end':hex(z),'bytes':k.read(a,z-a).hex(),'instructions':ins}
 for site,start,pair,key,add,lb,rb,cut,tab,tr in CALLS:
  n='call_'+format(site,'x');r=selected(*pairs[pair],key,add,TABLE,0);p=pointer(k,int(r['slot'],16));assert p['target']==r['target'];assert at[BASE+site]['mnemonic']=='blraa'and at[BASE+site]['operands']==tr+', x17'
  div=int(at[BASE+site-4]['operands'].split('#')[1],0);word=int(p['word'],16);assert p['authenticated']and int(p['diversity'],16)==div and(word>>49)&3==0 and(word>>48)&1==0
  r.update(name=n,pair=pair,call_site=hex(BASE+site),original_pointer=p,byte_load_sites=[hex(BASE+lb),hex(BASE+rb)],cut_site=hex(BASE+cut),table_load_site=hex(BASE+tab),target_register=tr,diversity=hex(div));rules.append(r);fragment(n,BASE+start,BASE+site)
 for n,a,z in [('hardware_ABI',0xfffffe000a50849c,0xfffffe000a5084f0),('late_copy_args',BASE+0x8e04,BASE+0x8e18),('scratch_copy_args',BASE+0x8a70,BASE+0x8a7c),('record_inputs',BASE+0x8048,BASE+0x8058),('record_save',BASE+0x81cc,BASE+0x81d0),('status_reload',BASE+0x87d4,BASE+0x87d8),('status_store',BASE+0x87e4,BASE+0x87e8),('private_state_root',BASE+0x83ec,BASE+0x83f0),('scratch_root',BASE+0x8718,BASE+0x874c)]:fragment(n,a,z)
 scratch=selected(*pairs['F'],0x87,0x21,POOL,-4);scratch['original_pointer']=pointer(k,int(scratch['slot'],16));assert(int(scratch['original_pointer']['target'],16)-4)==int(scratch['target'],16)==0xfffffe000ccc7848
 stores=[]
 for i in ii:
  if not i['mnemonic'].startswith('st'):continue
  mem=re.search(r'\[([^\]]+)\]',i['operands'])[1];parts=[x.strip()for x in mem.split(',')];base=parts[0];off=int(parts[1][1:],0)if len(parts)>1 else 0
  reg=i['operands'].split(',')[0];width=(1 if i['mnemonic'].endswith('b')else 4 if reg.startswith('w')else 8)*(2 if i['mnemonic']=='stp'else 1)
  if base in ['sp','x29']:
   lo=off+(0x1b0 if base=='x29'else 0);assert 0<=lo<lo+width<=0x1c0;kind='private_frame';extent=[lo,lo+width]
  elif i['ea']in ['0xfffffe000a687fe8','0xfffffe000a687fec']:kind='controller_global';extent=None
  elif i['ea']=='0xfffffe000a687ff8':kind='header_restore';extent=None
  else:assert i['ea']=='0xfffffe000a6887e4'and base=='x0'and off==8;kind='status_record';extent=[8,12]
  stores.append({**i,'class':kind,'base_register':base,'offset_bytes':off,'store_width_bytes':width,'relative_half_open_extent':extent})
 writes=[]
 for i in dc.disasm(bytes.fromhex(fs['inner']['bytes']),int(fs['inner']['start'],16)):
  m=i.mnemonic;ww={ {'fp':'x29','lr':'x30'}.get(i.reg_name(x),i.reg_name(x))for x in i.regs_access()[1]}
  if m in ['cmp','cmn','tst','ccmp','ccmn']:ww={x for x in ww if not re.fullmatch(r'[xw]\d+',x)}
  if 'sp'in ww or 'x29'in ww:writes.append({'ea':hex(i.address),'mnemonic':m,'operands':i.op_str,'writes':sorted(ww)})
 calls=[i for i in ii if i['mnemonic']in ['bl','blr','blraa','blrab']];jumps=[]
 for j,i in enumerate(ii):
  if i['mnemonic']=='braa':
   pred=ii[j-1];assert pred['mnemonic']=='mov'and pred['operands'].startswith('x17, #');jumps.append({**i,'literal_diversity':hex(int(pred['operands'].split('#')[1],0))})
 mods={int(r['literal_diversity'],16)for r in jumps};groups={hex(v):[]for v in sorted(mods)};a=0xfffffe000846a5b0;end=a+0x12070
 for addr in range(a,end,8):
  w=int.from_bytes(k.read(addr,8),'little');div=(w>>32)&0xffff
  if w>>63 and div in mods:
   p=pointer(k,addr);p['key_selector']=(w>>49)&3;p['address_diversity']=bool((w>>48)&1);assert p['key_selector']==0 and not p['address_diversity'];p['inside_inner_after_restore']=BASE+0x7ffc<=int(p['target'],16)<int(fs['inner']['end'],16);assert p['inside_inner_after_restore']or not int(fs['inner']['start'],16)<=int(p['target'],16)<int(fs['inner']['end'],16);groups[hex(div)].append(p)
 assert all(any(not p['inside_inner_after_restore']for p in rows)for rows in groups.values())
 imports=[pointer(k,a)for a in [0xfffffe000847c478,0xfffffe000847c4c8]];pr=[pointer(k,POOL+o)for o in [0xc08,0x158,0x458,0x638,0x840,0xbb8,0xf50,0xf20,0x4f0,0x578]];syms=k.symbols([int(r['target'],16)for r in rules]+[int(p['target'],16)for p in imports])
 for p in imports:p['exact_symbols']=syms[p['target']]
 counts={'captured_functions_and_stubs':len(fs),'captured_instructions':sum(len(f['instructions'])for f in fs.values()),'captured_code_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'source_fragments':len(fr),'inner_store_instructions':len(stores),'private_frame_store_instructions':sum(r['class']=='private_frame'for r in stores),'inner_call_instructions':len(calls),'selected_indirect_call_sites':len(rules),'additional_global_root_selections':1,'literal_bank_arrays':len(banks),'bank_input_cases':(len(rules)+1)*256,'inner_indirect_jump_sites':len(jumps),'jump_diversity_groups':len(groups),'original_matching_diversity_entries':sum(map(len,groups.values())),'matching_diversity_entries_outside_inner':sum(not p['inside_inner_after_restore']for rows in groups.values()for p in rows),'scanned_const_words':(end-a)//8}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'kext_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in DEPS},'functions':fs,'fragments':fr,'banks':banks,'bank_rules':rules,'scratch_root_selection':scratch,'pool_pointer_records':pr,'import_pointer_records':imports,'exact_symbols':syms,'direct_stores':stores,'SP_FP_writes':writes,'calls':calls,'indirect_jumps':jumps,'matching_diversity_entries':groups,'diversity_scan':{'start':hex(a),'end':hex(end),'stride_bytes':8,'scope':'Original file-backed kext __DATA_CONST only;matching entries include external targets. Discriminator equality is not a reaching-target proof.'},'new_IDA_access':False,'semantic_memory_claims_used':0,'verified_source_counts':counts,**{n:False for n in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
