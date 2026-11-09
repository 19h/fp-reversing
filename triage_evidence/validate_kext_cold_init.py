#!/usr/bin/env python3
"""Independent descriptor, heap, timeout, provider and failure-return checks.

Eight distinct fresh original-prefix replays; native APIs remain abstract.
O(B+V+E+S) work/space plus bounded pointer-chain and SDK compilation work.
"""
import collections,hashlib,json,struct,subprocess
from pathlib import Path
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,qword
from kernel_native_reader import Kernel
from probe_kext_cold_init import Cold,HEAP,ALLOC,MATCH,WAIT,FREE,DICTIONARY
from recover_kext_cold_init import pointer
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 counts=collections.Counter();p=json.loads((ROOT/'kext_cold_init_profiles.json').read_text());c=json.loads((ROOT/'kext_cold_init_contracts.json').read_text());deps={'probe_kext_cold_init.py','recover_kext_cold_init.py','kext_cold_init_profiles.json','kext_cold_init_contracts.json','probe_kext_close.py','kext_cold_init_layouts.c'}
 for obj,producer in[(p,'probe_kext_cold_init.py'),(c,'recover_kext_cold_init.py')]:
  assert obj['generator_sha256']==sha(ROOT/producer)and obj['source_sha256']==sha(SOURCE)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h;deps.add(n)
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']and k.kernel['uuid']==c['kernel_uuid']
 for r in c['kernel_functions']:assert k.function(int(r['start'],16))==r;counts['kernel_functions']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for r in c['kext_ranges']:
  a=int(r['start'],16);z=int(r['end'],16);raw=IMAGE.read(a,z-a);assert raw.hex()==r['bytes']and hashlib.sha256(raw).hexdigest()==r['sha256'];assert r['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)];counts['kext_ranges']+=1
 for e in c['typed_descriptors']:
  a=int(e['address'],16);raw=IMAGE.read(a,64);assert raw.hex()==e['bytes64_hex'];assert struct.unpack_from('<2I',raw,40)==(e['flags_word_at40'],e['size_word_at44'])==(100,104);assert e['fallback_size24']==104;assert IMAGE.read(int(e['site_name_pointer'],16),128).split(b'\0')[0]==e['site_name'].encode()==b'site.FPAESParameters';counts['typed_descriptors']+=1
 for e in c['original_bindings']:assert IMAGE.read(int(e['slot'],16),8).hex()==e['word_hex']and qword(int(e['slot'],16))==int(e['target'],16)and k.symbols([int(e['target'],16)])[e['target']]==e['symbols'];counts['original_import_data_bindings']+=1
 for e in c['nominal_reference_slots']:
  actual=pointer(k,int(e['slot'],16));assert all(e[n]==v for n,v in actual.items());names=[s['name']for s in k.symbols([int(e['target'],16)])[e['target']]];assert names==['__ZNK8OSObject6retainEv'if e['nominal_vptr_offset']==32 else'__ZNK8OSObject7releaseEv'];counts['nominal_reference_slots']+=1
 assert IMAGE.read(0xfffffe000790ba3c,17).hex()==c['matching_string']['bytes_hex'];assert k.read(0xfffffe0007e6d9c0,4).hex()==c['PAGE_SHIFT_CONST']['original_word_hex'];assert c['conditional_buffer_capacity_bytes']==81920
 sdk=c['SDK_probe'];assert sha(ROOT/sdk['path'])==sdk['sha256']and sha(Path(sdk['header_path']))==sdk['header_sha256'];r=subprocess.run(['clang','-target','arm64e-apple-macos13.0','-isysroot','/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk','-fsyntax-only',str(ROOT/sdk['path'])],capture_output=True,text=True);assert r.returncode==0;counts['SDK_compile_exit']=0
 expected={0:1,1:1,56:0,**{i:0 for i in range(18,34)},**{i:v for i,v in enumerate(struct.pack('<III',0,4096,0),36)}};assert len(expected)==31
 pool={}
 for e in p['source_instructions']:assert IMAGE.read(int(e['ea'],16),4).hex()==e['bytes'];pool[int(e['ea'],16)]=bytes.fromhex(e['bytes'])
 fresh=[];summaries=[]
 for row in p['cases']:
  mode=row['allocation_mode'];stage=row['continuation_stage'];q=Cold(mode,stage);r=q.run();assert r==row;fresh.append(r);counts['fresh_runs']+=1;counts['fresh_source_visits']+=len(r['source_visits']);assert not r['native_target_executed']and not r['native_API_executed']and not r['idb_mutated'];assert all(int(a,16)in pool for a in r['source_visits'])
  writes=[e for e in r['source_writes']if HEAP<=int(e['address'],16)<HEAP+104];ledger={}
  for e in writes:
   off=int(e['address'],16)-HEAP;raw=bytes.fromhex(e['after_hex']);assert off+len(raw)<=104 and len(raw)==e['size_bytes'];ledger.update({off+j:v for j,v in enumerate(raw)})
  assert ledger==expected;counts['source_heap_store_events']+=len(writes);counts['source_written_heap_bytes']+=len(ledger);mask=bytes.fromhex(r['allocation_known_mask_hex']);assert mask==bytes(1 if mode=='zero_known'or i in ledger else 0 for i in range(104))
  observed=bytes.fromhex(r['allocation_final_hex']);assert len(observed)==104
  for off,v in ledger.items():assert observed[off]==v
  assert[(e['offset_bytes'],e['size_bytes'],e['bytes_hex'])for e in r['source_heap_reads']]==[(40,4,'00100000'),(36,4,'00000000')];counts['source_heap_read_events']+=2
  assert r['final_flag_byte_hex']=='00'and r['final_global_pointer_hex']=='0000000000000000'
  alloc=[e for e in r['events']if e['kind']=='typed_allocation_result_model'];assert len(alloc)==1 and alloc[0]['declared_extent_bytes']==104 and not alloc[0]['native_API_executed'];counts['modeled_allocations']+=1
  for wait in r['wait_observations']:
   assert wait['source_call']=='0xfffffe000a508078'and wait['dictionary']==hex(DICTIONARY)and wait['words32']==[0,1]and wait['timeout8_hex']=='0000000001000000';ptr=int(wait['timeout_pointer'],16);call=next(e for e in r['calls']if e['pc']=='0xfffffe000a508078');epoch={}
   for e in r['source_writes']:
    if e['source_visit_index']>=call['source_visit_index']:continue
    a=int(e['address'],16);raw=bytes.fromhex(e['after_hex'])
    for j,v in enumerate(raw):
     if ptr<=a+j<ptr+8:epoch[a+j-ptr]=v
   assert bytes(epoch[j]for j in range(8)).hex()==wait['timeout8_hex'];counts['source_timeout_bytes']+=8;counts['wait_records']+=1
  if stage=='matching_boundary':assert r['events'][-1]['target']==hex(MATCH);counts['matching_boundaries']+=1
  elif stage=='wait_boundary':assert r['events'][-1]['target']==hex(WAIT);counts['wait_boundaries']+=1
  elif stage=='provider_absent':assert r['events'][-1]['target']==hex(FREE)and r['events'][-1]['arguments'][:2]==['0xfffffe000847b3a0',hex(HEAP)];counts['release_boundaries']+=1
  else:assert stage=='provider_absent_retire'and r['stop_reason']=='wrapper_return'and r['events'][-1]['X0_return_u64']=='0xffff5bea'and r['allocation_retired_in_model'];counts['complete_failure_returns']+=1
  if stage.startswith('provider_absent'):
   adapter=next(e for e in r['calls']if e['target']=='0xfffffe000a508030');assert adapter['returned_X0']=='0xffffffd8';counts['adapter_failure_returns']+=1
  summaries.append({'mode':mode,'stage':stage,'source_written_heap_bytes':31,'heap_read_offsets':[40,36],'timeout_words32':[e['words32']for e in r['wait_observations']],'stop_reason':r['stop_reason'],'flag_after':'00','global_pointer_after':'0000000000000000','retired_in_model':r['allocation_retired_in_model']})
 for stage in['matching_boundary','wait_boundary','provider_absent','provider_absent_retire']:
  pair=[e for e in p['cases']if e['continuation_stage']==stage];assert pair[0]['source_visits']==pair[1]['source_visits'];assert[(e['pc'],e['target'],e['registers31'])for e in pair[0]['calls']]==[(e['pc'],e['target'],e['registers31'])for e in pair[1]['calls']];counts['allocation_mode_path_pairs']+=1
 counts['source_instructions']=len(pool);(ROOT/'kext_cold_init_replays.json').write_text(json.dumps({'scope':'Eight distinct fresh private continuations;no native API/provider effect.','generator_sha256':sha(Path(__file__)),'cases':fresh,'native_target_executed':False},indent=2)+'\n');out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'verified_counts':dict(counts),'case_summaries':summaries,'fresh_replays_sha256':sha(ROOT/'kext_cold_init_replays.json'),'native_target_executed':False,'provider_success_executed':False,'complete_initialization_proved':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'kext_cold_init_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
