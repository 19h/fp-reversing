#!/usr/bin/env python3
"""Recover conditional registry layouts, imported edges and fresh IDB matches.
O(source events+fixups+256*bank rules) time/space. Fixtures do not establish native
population, caller phases, object types, port roles or lifetime.
"""
import json,hashlib
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,TABLE,selected,qword
from replay_daemon_descriptor_producers import unpack
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_context_lock import ida_output

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def integer(s):return int.from_bytes(bytes.fromhex(s['hex']),'little')
def main():
 source=json.loads((ROOT/'daemon_registry_lookup_source.json').read_text());datasets=['daemon_registry_lookup_profiles.json','daemon_registry_lookup_payloads.json'];fix=set();paths=[];pool={};retired=set();bindings=[]
 for dataset in datasets:
  rows=json.loads((ROOT/dataset).read_text())['cases']
  for j,r in enumerate(rows):
   t=unpack(r);F=int(t['initial_SP'],16);cfg=r['configuration'];events=[];calls=[];fix.update(int(x,16)for x in t['used_fixups']);pool.update({pc:s['bytes_hex']for pc,s in t['source_pool'].items()});retired.update(s['pc']for s in t['steps'])
   for e in r['prefix']['source_reads']:
    a=int(e['address'],16)
    if a in FIXUPS and e['size_bytes']==8:fix.add(a)
   for s in t['steps']:
    if s['pc']in['0x1009d0304','0x1009f0168','0x1009f016c','0x100975790','0x100bb01f0','0x100b0c644','0x100b0c648','0x100963cb8','0x100963cc0','0x10095e950','0x100b328c8','0x100c744c0','0x1009e2e30','0x100a264dc','0x100b31cec','0x100a2ae2c','0x100c70ca8','0x10095f074']:
     events.append({'pc':s['pc'],'events':s['events'],'registers_after':s['registers_after']})
   for m in t['api_models']:calls.append({'pc':m['pc'],'name':m['name'],'binding_slot':m['binding']['slot'],'arguments2':m['arguments8'][:2]})
   paths.append({'dataset':dataset,'case_index':j,'configuration':cfg,'source_visits':len(t['steps']),'F':hex(F),'events':events,'API_calls':calls,'boundary':{k:v for k,v in t['boundary'].items()if k not in['registers31','SIMD32']},'arbitrary_private_byte_origins':len(t['origins']),'arbitrary_API_byte_origins':len(t['API_origins']),'retired_owners':t['retired_owners']})
 live=[]
 for name in ['daemon_registry_lookup_live_ida.json','daemon_registry_lookup_more_ida.json','daemon_registry_lookup_unlink_ida.json']:
  r=json.loads((ROOT/name).read_text());assert not r.get('isError')
  for row in ida_output(r)['results']:
   a=int(row['address'],16);b=bytes.fromhex(row['bytes']);assert IMAGE.read(a,len(b))==b
   for i in row['instructions']:
    raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw
    if'size'in i:assert len(raw)<=i['size']
    else:assert i.get('decoded')is False and len(raw)==1
   live.append({'address':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'display_rows_checked':len(row['instructions']),'partial_macro_rows':sum(len(bytes.fromhex(i['bytes']))<i['size']for i in row['instructions']if'size'in i),'undecoded_byte_rows':sum('size'not in i for i in row['instructions'])})
 rules=[('candidate_malloc320',0x100e99a00,0x100f4e390,0x9c,0xcbdf,'X10=0x100F4E390 and savedSP+2998=0x100E99A00; actual incoming candidate phase unknown'),('candidate_malloc_variable',0x101031da0,0x100e99900,0x9a,0xcb28,'savedSP+2960/+2968 retain the captured registry-entry roots; native incoming phase unknown')];banks=[]
 for n,l,r,k,add,pre in rules:
  b=selected(l,r,k,add,TABLE);assert b['target']=='libSystem/_malloc';banks.append({'label':n,'premise':pre,**b});fix.add(int(b['slot'],16))
 indices=[0x41e9,0xa16e,0x26e4,0x26e8,0x7aeb,0x7aec,0x7ccd,0x7cfd,0x3327,0x32b1,0xadfe,0xae11,0xab17,0xab3f,0x465c,0x4673,0x2d40,0x2d6e];dispatch=[{'index':hex(i),'slot':hex(TABLE+i*8),'target':hex(qword(TABLE+i*8))}for i in indices];fix.update(int(x['slot'],16)for x in dispatch)
 deps=['daemon_registry_lookup_source.json',*datasets,'daemon_registry_lookup_live_ida.json','daemon_registry_lookup_more_ida.json','daemon_registry_lookup_ida_refs.json','daemon_registry_lookup_unlink_ida.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'source_spans':source['spans'],'original_fixups':verify_used_fixups(fix),'banks_exhaustive256':banks,'dispatch_slots':dispatch,'paths':paths,'live_IDB_matches':live,'distinct_continuation_retired_opcodes':len(retired),'distinct_continuation_inspected_opcodes':len(pool),'representation_contract':{'SP2A70_before_reuse':'BE64(input8) XOR0x9898989898989898 XOR0xE3B88695C0D52DBC','unmask_PC':'0x1009f016c','SP3630':'BE64(input8) XOR0x9898989898989898','outer_query':'low32(SP3630 word)','prior_copy_narrative_corrected':True,'prior_source_proof_artifacts_changed':False},'key_record':{'stride_bytes':16,'encoded_key64_offset':0,'encoded_tag32_offset':8,'raw_header_token32_offset':12,'key_XOR64':'0xe3b88695c0d52dbc','tag_XOR32':'0x8b3dc651','header_decoding':'unknown; source compares raw u32 values','outer_bound_u32_global':'0x1010c67d0','array_pointer_global':'0x1010c67a8'},'payload_record':{'stride_bytes':32,'encoded_key64_offset':0,'object_pointer64_offset':16,'inner_bound_u32_global':'0x1010ca2b0','array_pointer_global':'0x1010c9288','uninspected_other_field_types':'unknown'},'object_partial_layout':{'header32_offset':0,'observed_pointer_width_offsets':[216,784,864],'minimum_accessed_extent_bytes':872,'native_type':'unknown','native_owner_extent':'unknown'},'bounded_writer_graph_complete':False,'native_population_reachability':'unknown','native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_registry_lookup_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'paths':len(paths),'spans':len(source['spans']),'fixups':len(out['original_fixups']['records']),'banks256':len(banks),'IDB_bytes':sum(x['size_bytes']for x in live),'retired_opcodes':len(retired),'inspected_opcodes':len(pool)}),flush=True)
if __name__=='__main__':main()
