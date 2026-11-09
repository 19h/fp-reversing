#!/usr/bin/env python3
"""Independent byte/provenance reconstruction for input/output-sized regions and entropy preparation.

O(V+E) time/space in visits and byte-event extents. WZR stack probes discard
values; all other private reads require initialization. No target executes.
"""
import json,struct
from kext_port_tools import ROOT,IMAGE
from probe_legacy_stack import P,M64
def audit(r,k,counts,bank=False):
 old=json.loads((ROOT/'legacy_stack_contracts.json').read_text());initial={};state={};known=set();prov={};events={};case=r['input']
 for j,g in enumerate(old['mutable_globals']):
  a=int(g['address'],16);v=int.from_bytes(bytes.fromhex(g['original8_hex']),'little')if case['global_fixture']=='original'else 0 if case['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&M64;initial.update({a+n:b for n,b in enumerate(struct.pack('<Q',v))})
 for x in r.get('extra_initial_globals',[]):initial.update({int(x['address'],16)+j:b for j,b in enumerate(bytes.fromhex(x['bytes_hex']))})
 if bank:
  f=r['initial_bank_fixture'];a=int(f['address'],16)
  for j,b in enumerate(bytes.fromhex(f['bytes_hex'])):initial[a+j]=b;known.add(a+j);prov[a+j]=3
 guard=old['guard'];initial.update({int(guard['address'],16)+j:b for j,b in enumerate(bytes.fromhex(guard['original8_hex']))})
 def base(a):
  if a in initial:return initial[a]
  if P<=a<P+0x60000:return 0xa5
  return IMAGE.read(a,1)[0]
 def at(a,n):return bytes(state.get(j,base(j))for j in range(a,a+n))
 def snapshot(s):
  a=int(s['address'],16);n=s['size_bytes'];assert at(a,n).hex()==s['bytes_hex']and bytes(int(j in known)for j in range(a,a+n)).hex()==s['known_mask_hex']and bytes(prov.get(j,0)for j in range(a,a+n)).hex()==s['provenance_hex']
 for name,kind in [('source_reads','read'),('source_writes','write')]:
  for e in r[name]:events.setdefault(e['source_visit_index'],[]).append((kind,e))
 allowed=[(int(g['address'],16),int(g['address'],16)+8)for g in old['mutable_globals']]+[(0xfffffe000ccc2d98,0xfffffe000ccc2da0)]
 for v in r['source_visits']:
  ix=v['source_visit_index'];assert k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_instruction_byte_checks']+=4
  for kind,e in events.get(ix,[]):
   assert e['pc']==v['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':
    assert at(a,n).hex()==e['bytes_hex']
    if e['probe_only']:assert e['pc']in['0xfffffe000a5a1cdc','0xfffffe000a5a1cf0']and n==1;counts['discarded_stack_probe_reads']+=1
    elif P<=a<a+n<=P+0x60000:assert all(j in known for j in range(a,a+n))
    counts['source_read_epochs']+=1
   else:
    b=bytes.fromhex(e['after_hex']);assert len(b)==n
    if not P<=a<a+n<=P+0x60000:assert any(x<=a<a+n<=z for x,z in allowed)
    for j,byte in enumerate(b,a):state[j]=byte;known.add(j);prov[j]=1
    counts['source_write_epochs']+=1
 if bank:snapshot(r['saved_table_pointer'])
 else:
  for name in['frame','saved_left_bank','saved_right_bank','workspace','typed_auxiliary','input_data_buffer','output_data_buffer']:snapshot(r[name])
  if r.get('source_input_buffer')is not None:snapshot(r['source_input_buffer'])
 counts['byte_reconstructed_cases']+=1
