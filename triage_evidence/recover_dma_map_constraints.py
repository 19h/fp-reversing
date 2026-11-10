#!/usr/bin/env python3
"""Original operation04000000 metadata graph and its source-built40-byte request."""
import json,re,subprocess,tempfile,plistlib
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE
from recover_kext_cold_init import pointer
from recover_versioned_request_abi import FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
P='dma_map_constraints';G=0xfffffe000c530000;C=0xfffffe000c520000
SCOPE='Source-bound40-byte DMA mapping specification,operation04000000 selected control graph,min/max metadata updates and lazy metadata allocation/helper footprints. Native mappings,hardware transfers,full lower allocation/reference effects and complete constructor noninterference remain unproved.'
FUNCTIONS={'dma_operation':G+0x65e8,'metadata_helper':G+0x6f94,'metadata_creator':G+0x7394,'buffer_init':C+0x4bdc}
SPANS={'request_zero':(C+0x4da8,C+0x4db4),'request_bit_choice':(C+0x4db4,C+0x4dcc),'request_bit_store':(C+0x4df0,C+0x4df4),'request_call':(C+0x50d4,C+0x50e8),'selector':(G+0x660c,G+0x662c),'case3_select':(G+0x6680,G+0x6688),'size_guard':(G+0x6704,G+0x6714),'bit_read':(G+0x671c,G+0x6730),'bit_store':(G+0x6730,G+0x6734),'alignment_read':(G+0x6734,G+0x6744),'alignment_store':(G+0x6744,G+0x674c),'lazy_args':(G+0x68cc,G+0x68dc),'lazy_result':(G+0x68e0,G+0x68f4),'success':(G+0x691c,G+0x6924),'no_memory':(G+0x6b10,G+0x6b18),'return_status':(G+0x6f10,G+0x6f14),'helper_initialize':(G+0x7124,G+0x714c),'helper_size_guard':(G+0x6f98,G+0x6fa4),'helper_reuse_guard':(G+0x6fd4,G+0x6fe4),'helper_reset':(G+0x7000,G+0x7008),'helper_heap_args':(G+0x7010,G+0x702c),'helper_heap_publish':(G+0x7030,G+0x703c),'helper_reset_used':(G+0x703c,G+0x7048),'helper_creator_arg':(G+0x7048,G+0x704c),'helper_owner_publish':(G+0x7078,G+0x7080),'helper_append':(G+0x7080,G+0x70b4),'helper_resize_args':(G+0x70b4,G+0x70d0),'helper_resize_publish':(G+0x70d4,G+0x70e4),'creator_heap_args':(G+0x7410,G+0x7430),'creator_publish':(G+0x7434,G+0x744c)}
DEPS=['buffer_construction_flow_source.json','buffer_construction_flow_checks.json','inner_write_frontier_checks.json','kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','validate_buffer_construction_flow.py','validate_core_stack_delta_abi.py','validate_context_descriptor_task_flow.py','validate_userclient_context_lifecycle.py','validate_versioned_request_abi.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','daemon_word_round_tools.py']
SPANS.pop('helper_append')
SPANS.update(helper_append_existing=(G+0x7080,G+0x7094),helper_append_empty=(G+0x7098,G+0x70a4),helper_append_capacity=(G+0x70a4,G+0x70b4),helper_size_guard=(G+0x6f98,G+0x6fa0),helper_bad_size=(G+0x6fa0,G+0x6fa4))
PROBE='''#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOReturn.h>
#include <stddef.h>
static_assert(sizeof(IODMAMapSpecification)==40);
static_assert(offsetof(IODMAMapSpecification,alignment)==0);
static_assert(offsetof(IODMAMapSpecification,device)==8);
static_assert(offsetof(IODMAMapSpecification,options)==16);
static_assert(offsetof(IODMAMapSpecification,numAddressBits)==20);
static_assert(offsetof(IODMAMapSpecification,resvA)==21);
static_assert(offsetof(IODMAMapSpecification,resvB)==24);
static_assert(sizeof(((IODMAMapSpecification*)0)->alignment)==8);
static_assert(sizeof(((IODMAMapSpecification*)0)->numAddressBits)==1);
static_assert(kIOReturnUnderrun==0xe00002e7U);
static_assert(kIOReturnNoMemory==0xe00002bdU);
static_assert(kIOReturnBadArgument==0xe00002c2U);
'''
def sdk_context():
 p=subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],capture_output=True,text=True);assert p.returncode==0 and not p.stderr;sdk=Path(p.stdout.strip());head=sdk/'System/Library/Frameworks/Kernel.framework/Headers';compiler=subprocess.run(['xcrun','--find','clang++'],capture_output=True,text=True);assert compiler.returncode==0;cc=Path(compiler.stdout.strip())
 with tempfile.TemporaryDirectory(prefix='fp-dma-spec-')as td:
  src=Path(td)/'probe.cpp';src.write_text(PROBE);p=subprocess.run([str(cc),'-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-I',str(head),'-DKERNEL','-std=c++17','-fsyntax-only',str(src)],capture_output=True,text=True);assert p.returncode==0 and not p.stderr,(p.returncode,p.stderr)
 hs=[]
 for rel,a,z in [('IOKit/IOMemoryDescriptor.h',168,176),('IOKit/IOReturn.h',93,104),('IOKit/IOReturn.h',140,145)]:
  h=head/rel;lines=h.read_text().splitlines();hs.append({'header':rel,'sha256':sha(h),'first_line':a,'last_line':z,'excerpt':'\n'.join(lines[a-1:z])})
 settings=plistlib.loads((sdk/'SDKSettings.plist').read_bytes());return {'layout_scope':'Installed SDK corroboration only;not proof of historical private layout or native validity.','SDK_version':settings['Version'],'SDK_canonical_name':settings['CanonicalName'],'compiler':'clang++','compiler_sha256':sha(cc),'probe_source':PROBE,'syntax_only_exit':p.returncode,'stderr_empty':not p.stderr,'primary_headers':hs,'target':'arm64e-apple-macos13.0','target_executed':False}
def selected_graph(f):
 at={int(i['ea'],16):i for i in f['instructions']};overrides={G+0x6628:True,G+0x6684:True,G+0x6710:False};todo=[int(f['start'],16)];seen=set();edges=[];calls=[]
 while todo:
  a=todo.pop()
  if a in seen:continue
  seen.add(a);i=at[a];m=i['mnemonic'];p=i['operands'];targets=[]
  if m in ['ret','retab','retaa']:continue
  if m in ['bl','blraa','blr','blrab']:assert m=='bl'and p=='#'+hex(G+0x6f94);calls.append(i);targets=[a+4]
  elif m=='b':targets=[int(p[1:],0)]
  elif m.startswith('b.')or m in ['cbz','cbnz','tbz','tbnz']:
   target=int(p.rsplit('#',1)[1],0);choice=overrides.get(a);targets=[target]if choice is True else[a+4]if choice is False else[target,a+4]
  else:assert m not in ['br','braa','brab'];targets=[a+4]
  for t in targets:assert t in at;edges.append({'from':hex(a),'to':hex(t)});todo.append(t)
 return {'sites':[hex(a)for a in sorted(seen)],'edges':edges,'ordinary_return_call_frontiers':calls,'selected_branch_overrides':{hex(a):v for a,v in overrides.items()},'store_instructions':[at[a]for a in sorted(seen)if at[a]['mnemonic'].startswith('st')],'return_instructions':[at[a]for a in sorted(seen)if at[a]['mnemonic']in ['ret','retab','retaa']],'scope':'Conservative graph for literal operation0x04000000 and dataSize40;three selector/size branch decisions require fresh source proofs. All other conditions admit both edges. The sole helper call is an ordinary-return frontier;its internals are a separate graph.'}
def build():
 assert sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';k=Kernel();fs={n:k.function(a)for n,a in FUNCTIONS.items()};old=json.loads(read(ROOT/'buffer_construction_flow_source.json'))
 for n in ['dma_operation','buffer_init']:assert fs[n]==old['functions'][n]
 fr={}
 for n,(a,z)in SPANS.items():
  f=next(f for f in fs.values()if int(f['start'],16)<=a<z<=int(f['end'],16));ii=[i for i in f['instructions']if a<=int(i['ea'],16)<z];assert len(ii)*4==z-a;fr[n]={'start':hex(a),'end':hex(z),'bytes':k.read(a,z-a).hex(),'instructions':ii}
 graph=selected_graph(fs['dma_operation']);slot=pointer(k,0xfffffe0007f85ed0);assert slot['target']==hex(G+0x65e8)and slot['authenticated']and slot['diversity']=='0xa8a7';syms=k.symbols(list(FUNCTIONS.values())+[G+0x6f94,G+0x7394,0xfffffe000bcfe5b8,0xfffffe000bcff0b8,0xfffffe000bcfec48,0xfffffe000caac278,0xfffffe000cb53030]);census={n:{'stores':[i for i in fs[n]['instructions']if i['mnemonic'].startswith('st')],'calls':[i for i in fs[n]['instructions']if i['mnemonic']in ['bl','blraa','blr','blrab']]}for n in ['metadata_helper','metadata_creator']};sdk=sdk_context()
 counts={'captured_functions':len(fs),'captured_instructions':sum(len(f['instructions'])for f in fs.values()),'captured_code_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'source_fragments':len(fr),'selected_graph_instruction_sites':len(graph['sites']),'selected_graph_edges':len(graph['edges']),'selected_graph_call_frontiers':len(graph['ordinary_return_call_frontiers']),'selected_graph_store_instructions':len(graph['store_instructions']),'selected_graph_returns':len(graph['return_instructions']),'fresh_branch_overrides':len(graph['selected_branch_overrides']),'helper_instructions':len(fs['metadata_helper']['instructions']),'creator_instructions':len(fs['metadata_creator']['instructions']),'SDK_syntax_only_exit':sdk['syntax_only_exit']}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'kext_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in DEPS},'functions':fs,'fragments':fr,'selected_operation_graph':graph,'nominal_slot':slot,'exact_symbols':syms,'helper_censuses':census,'metaclass_source_word':{'address':'0xfffffe000cb53030','bytes':k.read(0xfffffe000cb53030,8).hex(),'runtime_initialized_vptr_unknown':True},'SDK_context':sdk,'new_IDA_access':False,'semantic_memory_claims_used':0,'verified_source_counts':counts,**{n:False for n in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
