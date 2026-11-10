#!/usr/bin/env python3
"""Original shared-buffer construction,allocation-request and preparation flow."""
import json,re
from kext_port_tools import ROOT,SOURCE,IMAGE,qword
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from recover_versioned_request_abi import FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
P='buffer_construction_flow'
SCOPE='Source-bound specialization of the FairPlay81920-byte/options0x13 buffer construction route,metadata capacity/length/range publications,three allocation-request alternatives,base preparation and DMA-command/setLength boundaries. Actual backing,zeroed allocation,all constructor paths,callee noninterference and native lifetime remain unproved.'
C=0xfffffe000c520000;G=0xfffffe000c530000;F=0xfffffe000a500000
KERNEL={'factory':C+0x6070,'buffer_init':C+0x4bdc,'base_init':G+0x7720,'class_alloc':C+0x5694,'bare_constructor':C+0x5cd0,'capacity':C+0x4b98,'set_length':C+0x4bbc,'getter':C+0x4b60,'prepare':G+0x53b4,'dma_operation':G+0x65e8}
SPANS={'caller_factory':(F+0x80a4,F+0x80d4),'factory_args':(C+0x60dc,C+0x60f8),'buffer_entry':(C+0x4c04,C+0x4c1c),'old_range_gate':(C+0x4c20,C+0x4c2c),'new_range':(C+0x4c74,C+0x4c84),'mapper_bool':(C+0x4cdc,C+0x4ce4),'alignment':(C+0x4cec,C+0x4d40),'round_size':(C+0x4d44,C+0x4d54),'buffer_flags':(C+0x4d54,C+0x4d74),'task_gate':(C+0x4d7c,C+0x4d90),'allocation_flags':(C+0x4d9c,C+0x4da8),'allocation_choice':(C+0x4df4,C+0x4e38),'ordinary_args':(C+0x4e3c,C+0x4e58),'aligned_args':(C+0x4e5c,C+0x4e64),'byte_args':(C+0x4fa0,C+0x4fa4),'contiguous_args':(C+0x4fac,C+0x4fc0),'buffer_publish':(C+0x4fc4,C+0x4fd4),'mapping_gate':(C+0x4fd4,C+0x4fe0),'skip_mapping':(C+0x5044,C+0x504c),'range_publish':(C+0x5064,C+0x50a4),'dma_call':(C+0x50ac,C+0x50e8),'final_length':(C+0x5234,C+0x5258),'base_flags':(G+0x7928,G+0x793c),'base_publish':(G+0x7974,G+0x7980),'borrow_ranges':(G+0x7a58,G+0x7a64),'base_length':(G+0x7db8,G+0x7dc0),'base_prepare_call':(G+0x7ea8,G+0x7ed0),'base_success':(G+0x7dd4,G+0x7ddc),'length_gate':(C+0x4bc0,C+0x4bcc),'length_publish':(C+0x4bcc,C+0x4bd8),'capacity_read':(C+0x4b9c,C+0x4ba0),'getter_indirect':(C+0x4b84,C+0x4b8c),'getter_flags':(C+0x4b64,C+0x4b7c),'bare_metadata':(C+0x5cd4,C+0x5ce4),'base_prepare_gate':(G+0x7e90,G+0x7ea8),'base_iteration_length':(G+0x7d78,G+0x7d84),'dma_selector':(G+0x660c,G+0x6628)}
DEPS=['inner_write_frontier_source.json','inner_write_frontier_checks.json','kext_buffer_contracts.json','kext_aes_handoff_contracts.json','kext_cold_init_contracts.json','sample_descriptor_contracts.json','kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','validate_core_stack_delta_abi.py','validate_context_descriptor_task_flow.py','validate_userclient_context_lifecycle.py','validate_versioned_request_abi.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','validate_daemon_reader_container_origins.py','daemon_word_round_tools.py']
SPANS['base_prepare_gate']=(G+0x7e90,G+0x7e98)
SPANS['base_prepare_bit3']=(G+0x7ea4,G+0x7ea8)
SPANS['final_length']=(C+0x5234,C+0x5254)
def build():
 assert sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');fs={n:k.function(a)for n,a in KERNEL.items()};f=function(k,e,F+0x8030);f['bytes']=f.pop('bytes_hex');assert IMAGE.read(F+0x8030,len(bytes.fromhex(f['bytes'])))==bytes.fromhex(f['bytes']);fs['kext_init']=f
 parent=json.loads(read(ROOT/'inner_write_frontier_source.json'));assert f==parent['functions']['hardware_init'];old=json.loads(read(ROOT/'kext_buffer_contracts.json'));old_by={f['start']:f for f in old['kernel_functions']}
 for f in fs.values():
  if f['start']in old_by:assert f==old_by[f['start']]
 fr={}
 for n,(a,z)in SPANS.items():
  f=next(f for f in fs.values()if int(f['start'],16)<=a<z<=int(f['end'],16));ii=[i for i in f['instructions']if a<=int(i['ea'],16)<z];assert len(ii)*4==z-a;fr[n]={'start':hex(a),'end':hex(z),'bytes':k.read(a,z-a).hex(),'instructions':ii}
 slots=[]
 for off in [0x150,0x218,0x268,0x2f0,0x300,0x308]:
  p=pointer(k,0xfffffe0007f85d80+off);p['vptr_base']='0xfffffe0007f85d80';p['offset_bytes']=off;slots.append(p)
 imports=[pointer(k,a)for a in [0xfffffe000847c608,0xfffffe000847c5b0,0xfffffe000847c428]];targets=[int(p['target'],16)for p in slots+imports]+list(KERNEL.values())+[0xfffffe000c4b9328,0xfffffe000c4b9628,0xfffffe000c4b9b8c,0xfffffe000cb5b840,0xfffffe000caac278];syms=k.symbols(targets)
 for p in slots+imports:p['exact_symbols']=syms[p['target']]
 census={}
 for n in ['buffer_init','base_init','class_alloc','bare_constructor','prepare']:
  ii=fs[n]['instructions'];ss=[i for i in ii if i['mnemonic'].startswith('st')];census[n]={'stores':ss,'calls':[i for i in ii if i['mnemonic']in ['bl','blraa','blr','blrab']],'scope':'Complete compiler-envelope syntactic inventory. Explicit self-register fields require the stated source aliases;callee and arbitrary-pointer effects are separate obligations.'}
 derived=[]
 for i in fs['buffer_init']['instructions']:
  if i['mnemonic'].startswith('st')and any(v in i['operands']for v in ['[x0, #0xc0]','[x19, #0xc0]','[x0, #0xd0]','[x19, #0xd0]','[x19, #0xe0]']):derived.append(i)
 counts={'captured_functions':len(fs),'captured_instructions':sum(len(f['instructions'])for f in fs.values()),'captured_code_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'source_fragments':len(fr),'nominal_descriptor_slots':len(slots),'original_import_pointers':len(imports),'complete_store_call_censuses':len(census),'buffer_init_instructions':len(fs['buffer_init']['instructions']),'base_init_instructions':len(fs['base_init']['instructions']),'dma_operation_instructions':len(fs['dma_operation']['instructions'])}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'kext_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in DEPS},'functions':fs,'fragments':fr,'nominal_slots':slots,'import_pointer_records':imports,'exact_symbols':syms,'store_call_censuses':census,'derived_field_literal_stores':derived,'allocation_backend_targets':[hex(a)for a in [0xfffffe000c4b9328,0xfffffe000c4b9628,0xfffffe000c4b9b8c]],'new_IDA_access':False,'semantic_memory_claims_used':0,'verified_source_counts':counts,**{n:False for n in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
