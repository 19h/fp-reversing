#!/usr/bin/env python3
"""Original MixedData metaclass,typed allocation,field initialization and retirement."""
import json,struct
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE
from recover_kext_cold_init import pointer
from resolve_kernel_collection_interfaces import commands
from recover_versioned_request_abi import FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
P='mixed_data_lifecycle';G=0xfffffe000c530000;META=0xfffffe000cb53030;TYPE=0xfffffe0007e56498;VT=0xfffffe0007f43440;MVT=0xfffffe0007f43590
SCOPE='Source-bound identification of _IOMemoryDescriptorMixedData,its40-byte typed/fallback owner allocation,explicit zeroed data/used/capacity fields,creator join and two-level retirement/accounting interfaces. Native allocations,reference lifetimes,backing-record zeroing and complete constructor/transaction identity remain unproved.'
FUNCTIONS={'initializer':G+0x9e34,'allocator':G+0x9908,'free':G+0x97f0,'delete':G+0x9894,'invalidator':G+0x98f8,'get_meta':G+0x9884,'base_meta_ctor':0xfffffe000c441ec0,'instance_destructed':0xfffffe000c44350c,'creator':G+0x7394,'helper':G+0x6f94}
SPANS={'metaclass_args':(G+0x9f5c,G+0x9f78),'metaclass_install':(G+0x9f7c,G+0x9f98),'base_meta_save':(0xfffffe000c441edc,0xfffffe000c441ee4),'base_meta_fields':(0xfffffe000c441f00,0xfffffe000c441f10),'base_meta_name':(0xfffffe000c441f28,0xfffffe000c441f30),'base_meta_return':(0xfffffe000c442024,0xfffffe000c442028),'alloc_selector':(G+0x9914,G+0x9928),'alloc_fallback':(G+0x9928,G+0x9940),'alloc_typed':(G+0x9948,G+0x9954),'alloc_debug':(G+0x9958,G+0x9968),'alloc_fields':(G+0x9968,G+0x9994),'get_meta':(G+0x9884,G+0x9894),'creator_dispatch':(G+0x73a8,G+0x73c8),'creator_fresh_read':(G+0x73cc,G+0x73d8),'creator_fresh_gate':(G+0x7408,G+0x7410),'creator_heap_args':(G+0x7410,G+0x7430),'creator_publish':(G+0x7434,G+0x744c),'free_args':(G+0x9800,G+0x9818),'free_clear':(G+0x981c,G+0x9824),'free_get_meta':(G+0x9824,G+0x9848),'free_instance_gate':(G+0x984c,G+0x9850),'free_delete_dispatch':(G+0x9854,G+0x986c),'free_delete_modifier':(G+0x9878,G+0x9880),'delete_poison':(G+0x98a0,G+0x98ac),'delete_selector':(G+0x98ac,G+0x98c0),'delete_fallback':(G+0x98c0,G+0x98cc),'delete_typed':(G+0x98d4,G+0x98dc),'delete_debug':(G+0x98e0,G+0x98f0),'invalidate':(G+0x98fc,G+0x9904),'class_count_add':(G+0x9994,G+0x99a8),'class_count_parent':(G+0x99a8,G+0x99b0),'class_count_sub':(0xfffffe000c443524,0xfffffe000c44353c),'destroy_parent':(0xfffffe000c44353c,0xfffffe000c443544)}
DEPS=['dma_map_constraints_source.json','dma_map_constraints_checks.json','buffer_construction_flow_source.json','kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','validate_dma_map_constraints.py','validate_buffer_construction_flow.py','validate_core_stack_delta_abi.py','validate_context_descriptor_task_flow.py','validate_userclient_context_lifecycle.py','validate_versioned_request_abi.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','daemon_word_round_tools.py']
FUNCTIONS['retain_count']=0xfffffe000c445230
SPANS['retain_count_read']=(0xfffffe000c445234,0xfffffe000c445238)
DEPS.append('resolve_kernel_collection_interfaces.py')
def initializer_section(k):
 sections=[]
 for at,cmd,n in commands(k.data,k.kernel['header_offset']):
  if cmd!=0x19:continue
  count=struct.unpack_from('<I',k.data,at+64)[0]
  for j in range(count):
   off=at+72+80*j;raw=k.data[off:off+80];name=raw[:16].split(b'\0')[0].decode();segment=raw[16:32].split(b'\0')[0].decode();address,size=struct.unpack_from('<QQ',raw,32);flags=struct.unpack_from('<I',raw,64)[0]
   if name=='__mod_init_func'and segment=='__DATA_CONST':sections.append({'section':name,'segment':segment,'start':hex(address),'end':hex(address+size),'size_bytes':size,'flags':flags,'original_section_header_bytes':raw.hex()})
 assert len(sections)==1 and sections[0]['flags']&255==9;return sections[0]
def materializers(k):
 seg=next(s for s in k.kernel['segments']if s['name']=='__TEXT_EXEC');a=seg['address'];raw=k.read(a,seg['file_size']);ww=struct.unpack('<'+str(len(raw)//4)+'I',raw);pages=[];refs=[]
 for j,w in enumerate(ww[:-1]):
  if w&0x9f000000!=0x90000000:continue
  imm=((w>>29)&3)|(((w>>5)&0x7ffff)<<2);imm-=1<<21 if imm&(1<<20)else 0;pc=a+4*j;page=((pc&~4095)+(imm<<12))&((1<<64)-1)
  if page!=META&~4095:continue
  pages.append(hex(pc));nw=ww[j+1]
  if nw&0xffc00000==0x91000000 and(nw>>5)&31==w&31 and(nw>>10)&4095==META&4095:refs.append({'site':hex(pc),'bytes8':raw[j*4:j*4+8].hex(),'ADRP_register':w&31,'ADD_register':nw&31,'target':hex(META)})
 assert [r['site']for r in refs]==[hex(G+0x73a8),hex(G+0x9888),hex(G+0x9994),hex(G+0x9f5c)]
 return {'segment_start':hex(a),'segment_file_bytes':len(raw),'aligned_words_scanned':len(ww),'ADRP_target_page_sites':pages,'adjacent_ADRP_ADD_materializers':refs,'scope':'Complete aligned kernel __TEXT_EXEC scan for ADRP and immediately following64-bit ADD-immediate with unshifted offset0x30 and matching source register. Not an all-alias/all-xref census.'}
def build():
 assert sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';k=Kernel();fs={n:k.function(a)for n,a in FUNCTIONS.items()};old=json.loads(read(ROOT/'dma_map_constraints_source.json'))
 for n,parent in [('creator','metadata_creator'),('helper','metadata_helper')]:assert fs[n]==old['functions'][parent]
 fr={}
 for n,(a,z)in SPANS.items():
  f=next(f for f in fs.values()if int(f['start'],16)<=a<z<=int(f['end'],16));ii=[i for i in f['instructions']if a<=int(i['ea'],16)<z];assert len(ii)*4==z-a;fr[n]={'start':hex(a),'end':hex(z),'bytes':k.read(a,z-a).hex(),'instructions':ii}
 strings={}
 for n,a in [('registered_class_name',0xfffffe00070de463),('allocation_site_name',0xfffffe00070de480),('allocation_metadata_string',0xfffffe00070dfcfa)]:
  raw=k.read(a,128).split(b'\0')[0]+b'\0';strings[n]={'address':hex(a),'bytes':raw.hex(),'text':raw[:-1].decode(),'size_bytes':len(raw)}
 assert strings['registered_class_name']['text']=='_IOMemoryDescriptorMixedData'and strings['allocation_site_name']['text']=='site.'+strings['registered_class_name']['text']
 slots=[]
 for role,base,off in [('metaclass_alloc',MVT,0xa8),('instance_destructor',VT,0),('instance_delete',VT,8),('instance_get_meta',VT,0x38),('instance_free',VT,0xb0),('instance_release',VT,0x28),('instance_retain_count',VT,0x18),('base_delete_control',0xfffffe0007f8a030,8),('base_free_control',0xfffffe0007f8a030,0xb0)]:
  p=pointer(k,base+off);p.update(role=role,nominal_vptr=hex(base),offset_bytes=off);slots.append(p)
 section=initializer_section(k);assert section['start']=='0xfffffe0007f95b50'and section['end']=='0xfffffe0007f95e28';init=[pointer(k,a)for a in range(int(section['start'],16),int(section['end'],16),8)];selected=[p for p in init if p['target']==hex(FUNCTIONS['initializer'])];assert len(selected)==1 and selected[0]['slot']=='0xfffffe0007f95d10'
 raw=k.read(TYPE,64);tp=[pointer(k,TYPE+o)for o in [0x10,0x20]];flags,size=struct.unpack_from('<II',raw,0x28);assert(flags,size)==(0x61,40)
 syms=k.symbols(list(FUNCTIONS.values())+[int(p['target'],16)for p in slots]+[0xfffffe000cb5bfc0,0xfffffe000cb5b638,0xfffffe000bcfe5b8,0xfffffe000bcfeb8c,0xfffffe000bcfec48,0xfffffe000bcffaac]);scan=materializers(k)
 for p in slots:p['exact_symbols']=syms[p['target']]
 census={n:{'stores':[i for i in fs[n]['instructions']if i['mnemonic'].startswith('st')],'calls':[i for i in fs[n]['instructions']if i['mnemonic']in ['bl','blraa','blr','blrab']],'atomic_adds':[i for i in fs[n]['instructions']if i['mnemonic']=='ldadd']}for n in ['allocator','free','delete','instance_destructed']}
 counts={'captured_functions':len(fs),'captured_instructions':sum(len(f['instructions'])for f in fs.values()),'captured_code_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'source_fragments':len(fr),'original_vtable_slots':len(slots),'original_initializer_entries':len(init),'matching_initializer_entries':len(selected),'kernel_text_words_scanned':scan['aligned_words_scanned'],'ADRP_page_candidates':len(scan['ADRP_target_page_sites']),'adjacent_metaclass_materializers':len(scan['adjacent_ADRP_ADD_materializers']),'registered_class_name_bytes':strings['registered_class_name']['size_bytes'],'owner_instance_size_bytes':size,'constraint_record_size_bytes':48,'complete_store_call_censuses':len(census)}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'kext_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in DEPS},'functions':fs,'fragments':fr,'strings':strings,'nominal_slots':slots,'initializer_array':{**section,'entries':init,'selected':selected,'selected_index':56,'native_invocation_unknown':True},'typed_descriptor':{'address':hex(TYPE),'bytes64':raw.hex(),'flags_u32':flags,'size_u32':size,'string_pointer_records':tp},'metaclass_source_bytes':k.read(META,40).hex(),'exact_symbols':syms,'materializer_scan':scan,'lifecycle_censuses':census,'new_IDA_access':False,'semantic_memory_claims_used':0,'verified_source_counts':counts,**{n:False for n in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
