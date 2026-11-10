#!/usr/bin/env python3
"""Original UserClient task/context lifecycle; read-only binary and fixup analysis."""
import hashlib,json,struct
from pathlib import Path
from kext_port_tools import ROOT,SOURCE,IMAGE,POOL,TABLE,qword,selected,block
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_versioned_request_abi import FLAGS
P='userclient_context_lifecycle'
SCOPE='Source-bound UserClient task publication and forwarding,start/stop provider adapters,typed24-byte context creation and empty-head cleanup. Populated-list teardown,framework task references,concurrency,native receiver/provider identity and successful daemon-kext transactions remain unproved.'
FUNCTIONS={'initializer':0xfffffe000a5040d4,'start':0xfffffe000a504320,'stop':0xfffffe000a5043e0,'close':0xfffffe000a50445c,'died':0xfffffe000a5044a0,'stop_adapter':0xfffffe000a505178,'start_adapter':0xfffffe000a505184,'create':0xfffffe000a5b62e0,'destroy':0xfffffe000a626648}
SPANS={'init_base_ABI':(0xfffffe000a5042a4,0xfffffe000a5042cc),'init_success':(0xfffffe000a5042e0,0xfffffe000a5042ec),'start_zero':(0xfffffe000a504338,0xfffffe000a50434c),'start_mode_clear':(0xfffffe000a504354,0xfffffe000a504358),'start_base':(0xfffffe000a504358,0xfffffe000a504378),'start_cast':(0xfffffe000a504380,0xfffffe000a504390),'start_provider':(0xfffffe000a50439c,0xfffffe000a5043c8),'start_return':(0xfffffe000a5043cc,0xfffffe000a5043d0),'stop_provider':(0xfffffe000a5043f4,0xfffffe000a504424),'stop_base':(0xfffffe000a504428,0xfffffe000a504448),'stop_clear':(0xfffffe000a50444c,0xfffffe000a504450),'died_tail':(0xfffffe000a5044a4,0xfffffe000a5044c4),'start_adapter':(0xfffffe000a505188,0xfffffe000a505194),'stop_adapter':(0xfffffe000a50517c,0xfffffe000a505180),'create_entry':(0xfffffe000a5b6300,0xfffffe000a5b644c),'create_alloc':(0xfffffe000a5b6454,0xfffffe000a5b64ec),'create_status':(0xfffffe000a5b64f0,0xfffffe000a5b6518),'create_publish':(0xfffffe000a5b6520,0xfffffe000a5b653c),'destroy_entry':(0xfffffe000a62667c,0xfffffe000a6267a4),'destroy_cell':(0xfffffe000a6267ac,0xfffffe000a6267c8),'destroy_head':(0xfffffe000a6267d0,0xfffffe000a626834),'destroy_free':(0xfffffe000a62683c,0xfffffe000a6268c4),'destroy_clear':(0xfffffe000a6268c8,0xfffffe000a6268dc),'destroy_return':(0xfffffe000a6268fc,0xfffffe000a626900)}
BRANCHES=[(0x4cf,0xfffffe000a5b6540,0x7e13),(0x4d4,0xfffffe000a5b6450,0x7e13),(0xca2,0xfffffe000a5b651c,0x35cc),(0xcaa,0xfffffe000a5b6540,0x35cc),(0xaab,0xfffffe000a6268e0,0x484b),(0xad5,0xfffffe000a6267a8,0x484b),(0x59e,0xfffffe000a6268e0,0x9e2),(0x59f,0xfffffe000a6267cc,0x9e2),(0x980,0xfffffe000a626838,0xc338),(0x9a4,0xfffffe000a6269e4,0xc338),(0x58c,0xfffffe000a6268e0,0xcb91)]
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','validate_versioned_request_abi.py','versioned_request_abi_source.json','versioned_request_abi_checks.json','kernel_iokit_open_source.json','kernel_iokit_open_checks.json','daemon_word_round_tools.py','validate_kext_query_getter_values.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','validate_daemon_reader_container_origins.py']
def build():
 assert sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');fs={}
 for n,a in FUNCTIONS.items():
  f=function(k,e,a);raw=bytes.fromhex(f.pop('bytes_hex'));assert IMAGE.read(a,len(raw))==raw;f['bytes']=raw.hex();fs[n]=f
 fragments={}
 for n,(a,z)in SPANS.items():
  f=next(f for f in fs.values()if int(f['start'],16)<=a<z<=int(f['end'],16));ii=[i for i in f['instructions']if a<=int(i['ea'],16)<z];raw=k.read(a,z-a);assert len(ii)*4==len(raw);fragments[n]={'start':hex(a),'end':hex(z),'bytes':raw.hex(),'instructions':ii}
 kernel={n:k.function(a)for n,a in [('allocate_adapter',0xfffffe000c4ba154),('free_adapter',0xfffffe000c4ba368),('base_died',0xfffffe000c5629b8)]}
 pooloffs=[0x840,0xbb8,0xb70,0xa10,0xf20,0xf50,0x458,0x638];pr=[]
 for off in pooloffs:
  p=pointer(k,POOL+off);assert int(p['target'],16)==qword(POOL+off);pr.append(p)
 pairs={'A':(0xfffffe0007949ed0,0xfffffe000792fec0),'B':(qword(POOL+0xf50)-4,qword(POOL+0xf20)-4),'T':(0xfffffe0007949dd0,0xfffffe000792fbc0),'F':(qword(POOL+0x458)-8,qword(POOL+0x638)-12)}
 banks={n+side:{'address':hex(a),'bytes':IMAGE.read(a,256).hex()}for n,ab in pairs.items()for side,a in zip(['L','R'],ab)}
 rules=[]
 for n,pair,key,add,base,bias in [('CA','A',0x32,-4,POOL,0),('CB','B',0x93,-0xd0,POOL,0),('CT','T',0x16,-0x55,POOL,-12),('ALLOC','T',0x16,0xe8b,TABLE,0),('ADESC','A',0x32,0xa5,POOL,0),('DA','T',0xb4,0x6f,POOL,-4),('DB','T',0xd8,-4,POOL,-4),('DT','T',0xd8,0x13,POOL,-12),('FREE','F',0x87,0xe4c,TABLE,0),('FDESC','B',0x93,-0xad,POOL,-12)]:
  r=selected(*pairs[pair],key,add,base,bias);r.update(name=n,pair=pair,original_pointer=pointer(k,int(r['slot'],16)));assert(int(r['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(r['target'],16);rules.append(r)
 branches=[]
 for ix,target,div in BRANCHES:
  p=pointer(k,TABLE+ix*8);assert int(p['target'],16)==target and int(p['diversity'],16)==div;p['index']=ix;branches.append(p)
 slots=[0xfffffe000846c2e0,0xfffffe000846c2e8,0xfffffe000847c5e0,0xfffffe0007f55fb8,0xfffffe0007f55c90,0xfffffe0007f55c98,0xfffffe0007f55fc8,0xfffffe000846b188,0xfffffe000847c418,0xfffffe000846b8b0]
 bindings=[pointer(k,a)for a in slots];addresses=[int(p['target'],16)for p in bindings]+list(FUNCTIONS.values())+[int(f['start'],16)for f in kernel.values()]+[int(r['target'],16)for r in rules if r['name']in['ALLOC','FREE']];syms=k.symbols(addresses)
 for p in bindings:p['exact_symbols']=syms[p['target']]
 descriptors=[]
 for a in[0xfffffe000847b860,0xfffffe000847c260]:
  raw=IMAGE.read(a,64);nameptr,sigptr=struct.unpack_from('<Q',raw,16)[0],struct.unpack_from('<Q',raw,32)[0];name=IMAGE.read(nameptr,64).split(b'\0')[0];sig=IMAGE.read(sigptr,64).split(b'\0')[0];flags,size=struct.unpack_from('<2I',raw,40);assert name==b'site.IOUCCtx'and size==24
  nptr,sptr=pointer(k,a+16),pointer(k,a+32);assert int(nptr['target'],16)==nameptr and int(sptr['target'],16)==sigptr and k.read(a+40,8)==raw[40:48]
  descriptors.append({'address':hex(a),'bytes64':raw.hex(),'original64_bytes':k.read(a,64).hex(),'name_pointer':nptr,'signature_pointer':sptr,'name_address':hex(nameptr),'name':name.decode(),'signature_address':hex(sigptr),'signature_text':sig.decode(),'flags_u32':flags,'size_u32':size})
 assert descriptors[0]['bytes64']==descriptors[1]['bytes64']
 cast_stub=block(0xfffffe000a69f1d4,16);assert k.read(0xfffffe000a69f1d4,16).hex()==cast_stub['bytes'];assert[(i['mnemonic'],i['operands'])for i in cast_stub['instructions']]==[('adrp','x17, #0xfffffe000847c000'),('add','x17, x17, #0x418'),('ldr','x16, [x17]'),('braa','x16, x17')];assert any(p['slot']=='0xfffffe000847c418'and p['target']=='0xfffffe000c442080'for p in bindings)
 cp=Path(str(SOURCE)+'.c');lines=cp.read_text().splitlines();cx=[{'input_name':cp.name,'input_sha256':sha(cp),'first_line':a,'last_line':z,'text':'\n'.join(lines[a-1:z])}for a,z in[(7563,7686),(7705,7766),(8875,8899),(143147,143228),(192390,192403)]]
 counts={'kext_functions':len(fs),'kext_instructions':sum(len(f['instructions'])for f in fs.values()),'kext_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'kernel_functions':len(kernel),'kernel_instructions':sum(len(f['instructions'])for f in kernel.values()),'source_fragments':len(fragments),'literal_bank_arrays':len(banks),'bank_rules':len(rules),'bank_input_cases':256*len(rules),'pool_pointers':len(pr),'branch_pointers':len(branches),'lifecycle_bindings':len(bindings),'typed_descriptors':2,'context_bytes':24,'cast_stub_bytes':16,'cast_stub_instructions':4}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'kext_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'kext_UUID':e['uuid'],'dependencies':{n:sha(ROOT/n)for n in DEPS},'functions':fs,'fragments':fragments,'kernel_functions':kernel,'safeMetaCast_stub':cast_stub,'banks':banks,'bank_rules':rules,'pool_pointer_records':pr,'branch_pointers':branches,'bindings':bindings,'exact_symbols':syms,'typed_descriptors':descriptors,'associated_C':cx,'IDA_observation':{'target':'71c5aa51f433','date_UTC':'2026-11-10','initializer_bounds':['0xfffffe000a5040d4','0xfffffe000a504320'],'close_bounds':['0xfffffe000a50445c','0xfffffe000a5044a0'],'died_bounds':['0xfffffe000a5044a0','0xfffffe000a5044c8'],'provider_name_query_matches':0,'recall_matches':1,'recalled_fact_relevance':'Unverified global port-import note;no task/context premise imported.','semantic_memory_claims_used':0,'read_only':True,'live_byte_identity_claim':False},'verified_source_counts':counts,**{n:False for n in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
