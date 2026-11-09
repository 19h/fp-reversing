#!/usr/bin/env python3
"""Audit saved-pointer provenance in frozen short-path models.
O(parent groups+retained effects) time and O(largest retained journal) space.
No stopped context is resumed and no missing frame field is assigned.
"""
import json
from collections import Counter
from functools import lru_cache
from daemon_receive_tools import ROOT
from replay_daemon_descriptor_producers import unpack
from daemon_digest_completion_model import SAVED
@lru_cache(maxsize=1)
def retained():
 parents=json.loads((ROOT/'daemon_identity_cache_context.json').read_text())
 parents={x['cache_case_index']:x for x in parents['contexts']}
 profiles=json.loads((ROOT/'daemon_identity_cache_profiles.json').read_text())
 rows=[];counts=Counter();wanted={0x3278:8,0x2f00:8,0x32e8:8,0x31a8:8,
  0x3610:8,0x26e0:8,0x3238:8,0x3620:8,**{a:4 if a==0x2edc else 8 for a in SAVED}}
 for idx,row in enumerate(profiles['cases']):
  cfg=row['configuration']
  if not(cfg['identity_present']and cfg['buffer_nonnull']and cfg['conversion_success']and cfg['UTF16_length']<64):continue
  t=unpack(row);F=int(t['entry_SP'],16);parent=parents[t['cache_case_index']]
  initial={int(g['address'],16)+j:b for g in parent['known_byte_groups']for j,b in enumerate(bytes.fromhex(g['bytes_hex']))}
  watched={F+off+j for off,n in wanted.items()for j in range(n)}
  data={a:b for a,b in initial.items()if a in watched};writers={a:'verified frozen entry groups'for a in data}
  for e in t['events']:
   a=int(e['address'],16);n=e['size_bytes'];overlap=watched.intersection(range(a,a+n))
   if not overlap:continue
   b=bytes.fromhex(e['after_hex']if e['kind']=='write'else e['bytes_hex']);assert len(b)==n
   if e['kind']=='read':
    assert all(x in data and data[x]==b[x-a]for x in overlap);counts['tracked_read_effects']+=1
   else:
    for x in overlap:data[x]=b[x-a];writers[x]=e['pc']
    counts['tracked_write_effects']+=1
  def value(off):return int.from_bytes(bytes(data[F+off+j]for j in range(wanted[off])),'little')
  assert value(0x3278)==value(0x2f00)==value(0x32e8)==F+0x3c30
  assert value(0x3238)==value(0x3610)==F+0x3c70
  assert value(0x31a8)==F+0x3ce0 and value(0x3620)==0x310
  assert value(0x26e0)==0x1010c67f8 and all(value(off)==v for off,v in SAVED.items())
  assert row['boundary']['pc']=='0x100abee7c'
  rows.append({'case_index':idx,'parent_payload_sha256':row['payload_sha256'],
   'SP':hex(F),'saved_values':{hex(off):hex(value(off))for off in wanted},
   'last_field_writers':{hex(off):sorted({writers[F+off+j]for j in range(n)})for off,n in wanted.items()},
   'source_frontier_unchanged':row['boundary']['pc'],'native_continuity_established':False})
  counts['retained_short_cases']+=1;counts['retained_effects_inspected']+=len(t['events'])
 assert len(rows)==288
 return rows,dict(counts)
