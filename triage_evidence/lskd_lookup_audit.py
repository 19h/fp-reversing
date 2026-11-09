#!/usr/bin/env python3
"""Independent byte reconstruction with nonzero-cache dead-load certificates.

Unknown bytes remain unknown: only the declared eight-byte load at a certified
origin may be inspected as a value that is never used before overwrite.
All other private value reads require fixture/source initialization.
O(V+E) retained events/state, plus source mapping lookups; no target executes.
"""
import struct
from kext_port_tools import IMAGE
from probe_lskd_response import P,M64,OUT,PARAM
from probe_lskd_request import OTHER_OUT
def audit(r,c,prior,ctor,fields,execute,k,counts,handlers_contract):
 state={};known=set();prov={};initial={};events={};snaps={};case=r['input'];globals=prior['mutable_globals']+ctor['additional_mutable_globals']+fields['additional_mutable_globals']+execute['additional_mutable_globals']+c['additional_mutable_globals']+handlers_contract['additional_mutable_globals']
 for j,d in enumerate(globals):
  a=int(d['address'],16);v=int.from_bytes(bytes.fromhex(d['original8_hex']),'little')if case['global_fixture']=='original'else 0 if case['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&M64;initial.update({a+n:b for n,b in enumerate(struct.pack('<Q',v))})
 fixtures=[(OUT,struct.pack('<Q',case['out_initial64'])),(OTHER_OUT,bytes(8)),(PARAM,bytes.fromhex(r['initial_params256_hex']))]+[(int(s['address'],16),bytes.fromhex(s['bytes_hex']))for s in r['fixture_additions']]
 for a,raw in fixtures:
  for x,v in enumerate(raw,a):initial[x]=v;known.add(x);prov[x]=3
 guard=int(prior['guard']['address'],16);initial.update({guard+n:b for n,b in enumerate(bytes.fromhex(prior['guard']['original8_hex']))})
 def base(a):
  if a in initial:return initial[a]
  if P<=a<P+0x20000:return 0xa5
  try:return IMAGE.read(a,1)[0]
  except ValueError:return k.read(a,1)[0]
 def bytes_at(a,n):return bytes(state.get(x,base(x))for x in range(a,a+n))
 def snap(s):
  a=int(s['address'],16);n=s['size_bytes'];assert bytes_at(a,n).hex()==s['bytes_hex'];assert bytes(int(x in known)for x in range(a,a+n)).hex()==s['known_mask_hex'];assert bytes(prov.get(x,0)for x in range(a,a+n)).hex()==s['provenance_hex']
 for e in r['source_reads']:events.setdefault(e['source_visit_index'],[]).append(('read',e))
 for e in r['source_writes']:events.setdefault(e['source_visit_index'],[]).append(('write',e))
 for call in r['source_calls']:snaps.setdefault(call['source_visit_index'],[]).extend(call[n]for n in['record','out_reference','object_before','payload','destination_before','argument_bytes','workspace_header','response_before','candidate_before','delta_cell']if n in call)
 for o in r['observations']:snaps.setdefault(o['source_visit_index'],[]).extend(o[n]for n in['out_reference','object']if n in o)
 if r['execution_input']is not None:
  x=r['execution_input'];snaps.setdefault(x['source_visit_index'],[]).extend([x['response_reference'],x['request']])
 if r['shared_prepare_entry'] is not None:
  x=r['shared_prepare_entry'];snaps.setdefault(x['source_visit_index'],[]).extend([x['operation_scratch'],x['auxiliary_frame_cell']])
 for name,fields_to_check in [('handler_entry',['request','response_before']),('field_search_return',['record','length_output','pointer_output']),('response_initializer_return',['record','response']),('prepared_handler_call',['record'])]:
  if r[name] is not None:
   x=r[name];snaps.setdefault(x['source_visit_index'],[]).extend(x[n]for n in fields_to_check if n in x)
 for x in r['value_bridge_returns']:
  snaps.setdefault(x['source_visit_index'],[]).extend(x[n]for n in ['record','value_output','pointer_output','length_output']if n in x)
 if r['next_record_handoff']is not None:
  x=r['next_record_handoff'];snaps.setdefault(x['source_visit_index'],[]).extend([x['record']]if 'record'in x else [])
 if r['response_publication']is not None:
  x=r['response_publication'];snaps.setdefault(x['source_visit_index'],[]).extend(x[n]for n in ['out_reference_before','candidate','frame_out_reference','frame_candidate'])
 for v in r['source_visits']:
  ix=v['source_visit_index'];assert k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_byte_checks']+=4
  for s in snaps.get(ix,[]):snap(s)
  for kind,e in events.get(ix,[]):
   assert e['pc']==v['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':
    assert bytes_at(a,n).hex()==e['bytes_hex']
    if e['probe_only']:assert e['pc']in['0xfffffe000a5a1cdc','0xfffffe000a5a1cf0']and n==1;counts['discarded_probe_read_epochs']+=1
    if P<=a<a+n<=P+0x20000 and not e['probe_only']:
     if e.get('discarded_dead_load'):
      assert n==8 and not any(x in known for x in range(a,a+n));matches=[w for w in r['state_dead_load_windows']if w['origin']['source_visit_index']==ix and w['origin']['pc']==e['pc']and int(w['unknown_address'],16)==a];assert len(matches)==1 and matches[0]['kill']is not None and matches[0]['cache_predicate']['value64']==hex(P+0xe800);counts['discarded_unknown_load_epochs']+=1
     else:assert all(x in known for x in range(a,a+n))
    counts['read_epochs']+=1
   else:
    b=bytes.fromhex(e['after_hex']);assert len(b)==n
    if not P<=a<a+n<=P+0x20000:assert any(int(d['address'],16)<=a<a+n<=int(d['address'],16)+8 for d in globals)
    for x,byte in enumerate(b,a):state[x]=byte;known.add(x);prov[x]=1
    counts['source_write_epochs']+=1
 for s in snaps.get(len(r['source_visits']),[]):snap(s)
 for n in['workspace','auxiliary','actual_auxiliary','response','object','params','out_reference','execution_response_reference_final']:snap(r[n])
 assert not any(v==2 for v in prov.values());counts['byte_reconstructed_cases']+=1
