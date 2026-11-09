#!/usr/bin/env python3
"""Recover finite initialization effects, original code/fixups and API boundaries.
O(source visits+effects+original bytes) time; O(largest journal) space.
Native incoming frame, request identity and publication remain unknown.
"""
import json,hashlib
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from recover_daemon_object_creation import sha,span
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_context_lock import ida_output
from replay_daemon_descriptor_producers import unpack,IMPORTS
from daemon_import_bindings import binding

def summarize(r):
 t=unpack(r);F=int(t['entry_SP'],16);O=0x6800005000;events=t['events'];writes=[e for e in events if e['kind']=='write'];reads=[e for e in events if e['kind']=='read'];sampler=[e for e in writes if e['pc']=='0x100b8e7e0'and F+0x3a50<=int(e['address'],16)<F+0x3c9b];objectsample=[e for e in writes if e['pc']=='0x100b8e7e0'and O+0x2c2<=int(e['address'],16)<O+0x2d2];obj=[e for e in writes if O<=int(e['address'],16)<O+872];imports=[]
 for name in ['IOKit/_kIOMainPortDefault','CoreFoundation/_kCFAllocatorDefault','CoreFoundation/_kCFAllocatorNull']:
  a=IMPORTS[name];rs=[e for e in reads if int(e['address'],16)==a];assert len(rs)==2
  slots=[int(x,16)for x in t['used_fixups']if FIXUPS[int(x,16)]['target']==name];assert len(slots)<=1
  imports.append({'name':name,'private_data_address':hex(a),'original_binding':binding(slots[0])if slots else None,'binding_candidates':[binding(a)for a,x in FIXUPS.items()if x['target']==name],'binding_provenance':'read in this prefix'if slots else'incoming/saved pointer; no original bind read in this prefix','reads':rs})
 return {'configuration':r['configuration'],'source_visits':r['source_visits'],'read_effects':len(reads),'write_effects':len(writes),'distinct_source_opcodes':len(t['source_pool']),'logical_edges':len(t['edges']),'API_models':t['api_models'],'boundary':r['boundary'],'cursor_after':t['cursor_after'],'scratch48_final_hex':t['scratch48_hex'],'scratch48_initial_hex':''.join(e['after_hex']for e in writes if e['pc']=='0x100a19cbc'),'scratch48_writes':[e for e in writes if F+0x3a20<=int(e['address'],16)<F+0x3a50],'cursor_writes':[e for e in writes if int(e['address'],16)==F+0x3620],'input_copy_reads':[e for e in reads if 0x6800032000<=int(e['address'],16)<0x6800032100],'imported_data':imports,'object_writes':obj,'buffer48_writes':[e for e in writes if e['pc']=='0x100daba8c'],'object_sampler16':{'attempts':len(objectsample),'zero_retries':sum(e['after_hex']=='00'for e in objectsample),'extent_bytes':16},'sampler':{'attempts':len(sampler),'zero_retries':sum(e['after_hex']=='00'for e in sampler),'extent_bytes':587,'base':hex(F+0x3a50),'first_write':sampler[0],'last_write':sampler[-1]},'state_word_writes':sum(0x1010c784c<=int(e['address'],16)<0x1010c820c for e in writes),'state_write_sites':dict(Counter(e['pc']for e in writes if 0x1010c784c<=int(e['address'],16)<0x1010c820c)),'self_text_reads':dict(Counter(e['pc']for e in reads if e['pc']in ['0x100b8e7a8','0x100b8e7c4'])),'arbitrary_heap_reads':len(t['arbitrary_heap_reads'])},t

def main():
 ctx=json.loads((ROOT/'daemon_object_initialization_context.json').read_text());profiles=json.loads((ROOT/'daemon_object_initialization_profiles.json').read_text());rows=[];pool={};fix={0x10109ff20}
 for r in profiles['cases']:
  row,t=summarize(r);rows.append(row);pool.update(t['source_pool']);fix.update(int(x,16)for x in t['used_fixups']);del t
 live=[];capture=json.loads((ROOT/'daemon_object_initialization_ida_bytes.json').read_text());assert not capture.get('isError')
 for x in ida_output(capture)['results']:
  a=int(x['address'],16);b=bytes.fromhex(x['bytes']);assert IMAGE.read(a,len(b))==b
  for i in x['instructions']:assert IMAGE.read(int(i['address'],16),len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes'])
  live.append({'start':hex(a),'size_bytes':len(b),'display_rows':len(x['instructions']),'partial_macro_rows':sum(len(bytes.fromhex(i['bytes']))<i['size']for i in x['instructions']if 'size'in i),'undecoded_byte_rows':sum('size'not in i for i in x['instructions'])})
 specs=[('imported_data_reads',0x100bd718c,0x100bd7234),('object_word_codec',0x100b1e860,0x100b1e90c),('state_extraction_index',0x100a41c68,0x100a41c80),('counter_temper',0x100bd81d4,0x100bd8254),('self_text_sampler',0x100b8e770,0x100b8e81c),('time_boundary',0x100bad49c,0x100bad4cc),('buffer48_fill_setup',0x100b06de0,0x100b06f34),('buffer48_fill',0x100dab9a4,0x100dabaac)]
 spans=ctx['spans']+[span(n,a,z)for n,a,z in specs]
 deps=['daemon_object_initialization_context.json','daemon_object_initialization_profiles.json','daemon_object_initialization_ida_bytes.json','probe_daemon_object_initialization.py','daemon_receive_fixups.txt','daemon_import_bindings.py']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'distinct_source_pool':pool,'original_fixups':verify_used_fixups(fix),'contexts':rows,'live_IDB_matches':live,'time_boundary_binding':binding(0x10109ff20),'source_object_fields':[{'offset':hex(o),'width_bytes':n,'value':v,'store_PC':hex(pc)}for o,n,v,pc in [(0x350,4,'0',0x10094c690),(0x310,8,'0',0x10094c694),(0xd8,8,'declared malloc(48) return, including NULL',0x10094c704),(0xe0,4,'44',0x10094c70c),(0x104,4,'0x8b3dc644',0x10094c718),(0x118,4,'0x8b3dc641',0x10094c728),(0x2f4,4,'32',0x10094c734),(0xcc,4,'raw classifier H; reached in the three non-NULL-buffer cases',0x100957864)]],'object24_codec':'Four observed groups at +2F8/+300/+308 and later +D0; each source byte leaf encodes BE64(X9 XOR FF590BE3C05A7786), under its source-shaped base/offset inputs. X9 native meaning unknown.','new_port_emission_established':False,'native_AEE_caller':'unknown','native_registry_publication':'unknown','native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_initialization_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_spans':len(spans),'source_opcodes':len(pool),'original_fixups':len(out['original_fixups']['records']),'contexts':len(rows),'IDB_bytes':sum(x['size_bytes']for x in live)}),flush=True)
if __name__=='__main__':main()
