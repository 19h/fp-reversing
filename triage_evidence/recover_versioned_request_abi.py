#!/usr/bin/env python3
"""Pin capability consumers and the complete selector21 call/provider ABI."""
import hashlib,json,struct,re
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,POOL,block,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import selected
from recover_daemon_iokit_census import text_section
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from kext_port_tools import IMAGE as KI,SOURCE as KS
P='versioned_request_abi'
SCOPE='Source-bound encoded-capability bit3/bit5/bit6/bit1 gates,conditional16-byte preparation,552-byte daemon selector21 call and complete UserClient/provider/core argument/status/count contracts. Same-frame/root/buffer joins,private-call delta/ownership,full extended preparation,native connection/provider/build pairing and core output bounds remain explicit unknowns.'
BLOCKS={'first_gate':0x1003763cc,'first_clear':0x1002693d8,'first_loop':0x1004692c8,'second_setup':0x1006349b0,'second_constructor':0x100552dac,'second_clear':0x1004d0e98,'second_loop_setup':0x10047a6b8,'second_loop':0x100636ad0,'second_post':0x10062ab4c,'fixed16':0x10056d8b0,'fixed_join':0x100316c48,'common_gate':0x100621460,'mode5_frontier':0x100487be4,'api_call':0x100478988}
CUTS={'pointer668':(0x1002903f8,0x100290414),'pointer80':(0x100634b44,0x100634b74),'entry_gate':(0x1006349b0,0x100634a0c),'second_gate':(0x100552fa0,0x100552fc4)}
ROOTS=[('CALL_L',0x6188,0xffffffffdc8ddf91,0x1c0),('CALL_R',0x3030,0xffffffffc6a5784a,0x1b8),('HEADER_L',0x2b50,0xfffffffff02ce87e,0x288),('HEADER_R',0x30f8,-0xd45667,0x280),('LOOP_L',0x60f0,0xffffffffa75b1642,0x278),('LOOP_R',0x2240,0xfffffffffa184636,0x298)]
EDGES=[(0x8af5,0x1002693d8,0x2920),(0x8b06,0x1004692c8,0x2920),(0xbc56,0x1004d0e98,0x6207),(0xbc5a,0x10047a6b8,0x6207),(0x4d4a,0x100636ad0,0xd2a9),(0x4d44,0x10062ab4c,0xd2a9),(0x4aa4,0x100487be4,0x1502),(0x4ab7,0x10056d8b0,0x1502),(0x3a30,0x100316c48,0x4f3e),(0x1d24,0x100621460,0x1557)]
DEPS=['kext_query_getter_values_source.json','kext_query_getter_values_checks.json','daemon_iokit_objects_contracts.json','daemon_iokit_census_contracts.json','kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py','daemon_word_round_tools.py','validate_kext_query_getter_values.py','validate_daemon_existing_scalar_reader.py','validate_daemon_constructor_inputs.py','validate_daemon_reader_container_origins.py','validate_daemon_list_output.py','daemon_receive_fixups.txt']
def capture(a,z):
 raw=IMAGE.read(a,z-a);from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
 ii=list(Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(raw,a));assert len(ii)*4==len(raw);return {'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
def census():
 a,n=text_section();raw=IMAGE.read(a,n);rows=[]
 from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
 dc=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
  if w&0xffc003e0!=0xf94003e0:continue
  off=((w>>10)&4095)*8
  if off not in[0x80,0x668]:continue
  ea=a+j*4;reg='xzr'if w&31==31 else'x'+str(w&31);ii=list(dc.disasm(IMAGE.read(ea,256),ea));hits=[]
  for ins in ii[1:]:
   if re.search(r'\['+reg+r'(?:,|\])',ins.op_str)and ins.mnemonic.startswith(('ld','st')):hits.append({'site':hex(ins.address),'mnemonic':ins.mnemonic,'operands':ins.op_str})
   m=ins.mnemonic
   if reg=='xzr'or m in['b','br','braa','brab','braaz','brabz','bl','blr','blraa','blrab','blraaz','blrabz','ret','retab','retaa','eret','eretaa','eretab','brk','hlt','svc','hvc','smc']or m.startswith(('b.','cb','tb')):break
   writes={ins.reg_name(r)for r in ins.regs_access()[1]}
   if m in['cmp','cmn','tst','ccmp','ccmn']:writes={r for r in writes if not re.fullmatch(r'[xw]\d+',r)}
   if {reg,'w'+reg[1:]}&writes:break
  rows.append({'site':hex(ea),'frame_offset':off,'register':reg,'raw_bytes':IMAGE.read(ea,4).hex(),'direct_consumers_before_clobber_or_branch':hits})
 assert len(rows)==368 and sum(r['frame_offset']==0x80 for r in rows)==312
 hits=[r for r in rows if any('#0x14]'in x['operands']for x in r['direct_consumers_before_clobber_or_branch'])];assert[r['site']for r in hits]==['0x1003763d0','0x100552fa0']
 return {'text_start':hex(a),'text_bytes':n,'aligned_words':n//4,'load_sites':rows,'direct_field14_hits':[r['site']for r in hits],'scope':'Exact unsigned-immediate64-bit LDR from SP+80/SP+668;bounded256-byte direct-register use until clobber/branch. Other frames,aliases,computed loads and broader readers are outside the census.'}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'and sha(KS)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';fs={}
 for n,a in BLOCKS.items():
  f=block(a,0x8000);fs[n]=capture(a,int(f['end'],16))
 for n,(a,z)in CUTS.items():fs[n]=capture(a,z)
 roots=[];values={}
 for name,off,bias,frameoff in ROOTS:
  a=POOL+off;value=(FIXUPS[a]['target']+bias)&((1<<64)-1);values[name]=value;roots.append({'name':name,'slot':hex(a),'source_bias_u64':hex(bias&((1<<64)-1)),'decoded_base':hex(value),'published_frame_offset':frameoff,'original_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]})
 families={'STATE':(0x100e99a00,0x100f4e390),'CALL':(values['CALL_L'],values['CALL_R']),'HEADER':(values['HEADER_L'],values['HEADER_R']),'LOOP':(values['LOOP_L'],values['LOOP_R'])};banks={};rules=[]
 for n,(l,r)in families.items():
  for side,a in[('L',l),('R',r)]:banks[n+side]={'address':hex(a),'bytes':IMAGE.read(a,256).hex()}
 for n,key,add,base in[('STATE',0x78,0x1e2,POOL),('CALL',0x81,0xcca2,TABLE),('HEADER',0xa,0xcb0a,TABLE),('LOOP',0xe4,0x868,POOL)]:
  row=selected(*families[n],key,add,base,0);row['name']=n;rules.append(row)
 assert rules[1]['target']=='IOKit/_IOConnectCallStructMethod'and rules[2]['target']=='0x100add594'
 data=(int(rules[3]['target'],16)+0xfffffffff6fc90b5)&((1<<64)-1);assert data==0x100f5bfb4;data16={'address':hex(data),'bytes':IMAGE.read(data,16).hex()}
 edges=[]
 for ix,target,div in EDGES:
  a=TABLE+8*ix;f=FIXUPS[a];assert f['target']==target and('div=0x'+format(div,'04X'))in f['annotation'];edges.append({'index':hex(ix),'slot':hex(a),'target':hex(target),'diversity':hex(div),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':f})
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');kf={}
 for n,a in[('UserClient',0xfffffe000a50500c),('provider_stub',0xfffffe000a504ea0)]:
  f=function(k,e,a);raw=bytes.fromhex(f.pop('bytes_hex'));assert KI.read(a,len(raw))==raw;f['bytes']=raw.hex();kf[n]=f
 descriptor=pointer(k,0xfffffe000846b810);record=int(descriptor['target'],16);fields=list(struct.unpack('<6Q',KI.read(record,48)));assert fields==[0,0xfffffe000a50500c,0,3,552,552];member=pointer(k,record+8);provider=pointer(k,0xfffffe000846c188);assert int(provider['target'],16)==0xfffffe000a504ea0
 cp=KS.parent/(KS.name+'.c');lines=cp.read_text().splitlines();csrc=[{'input_name':cp.name,'input_sha256':sha(cp),'first_line':a,'last_line':z,'text':'\n'.join(lines[a-1:z])}for a,z in[(8624,8641),(8791,8823)]];cc=census()
 counts={'daemon_ranges':len(fs),'daemon_range_instruction_instances':sum(len(f['instructions'])for f in fs.values()),'daemon_range_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'kext_ranges':len(kf),'kext_instructions':sum(len(f['instructions'])for f in kf.values()),'kext_bytes':sum(len(bytes.fromhex(f['bytes']))for f in kf.values()),'census_instruction_words':cc['aligned_words'],'census_slot_loads':368,'census_direct_field14_hits':2,'literal_bank_arrays':8,'bank_byte_inputs':1024,'literal_pool_roots':6,'branch_pointer_records':len(edges),'selector_record_bytes':48,'loop_image_bytes':16}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_sha256':sha(SOURCE),'kext_sha256':sha(KS),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in DEPS},'fragments':fs,'kext_fragments':kf,'slot_load_census':cc,'root_pointer_lineages':roots,'banks':banks,'bank_rules':rules,'loop_image_data':data16,'branch_pointer_records':edges,'selector21':{'descriptor_pointer':descriptor,'original_record48_bytes':k.read(record,48).hex(),'normalized_fields6':[hex(v)for v in fields],'member_pointer':member,'provider_slot':provider},'associated_C':csrc,'IDA_observation':{'target':'70f8437872ac','observation_date_UTC':'2026-11-10','bounded_function_metadata':[{'start':'0x1003763cc','end':'0x100376454'},{'start':'0x100552dac','end':'0x100552fc4'}],'pointer_annotations':[{'site':'0x100290400','text':'[obf] pool[0x283] -> unk_1010B6380 0x1010b6380'},{'site':'0x100634b60','text':'[obf] pool[0x283] -> unk_1010B6380 0x1010b6380'}],'knowledge_recall_matches':0,'semantic_claims_from_memory':0,'later_read_only_query_connection_failed':True,'IDB_mutation_requested':False,'metadata_not_reobserved_on_validation':True},'verified_source_counts':counts,'new_IDA_access':True,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
