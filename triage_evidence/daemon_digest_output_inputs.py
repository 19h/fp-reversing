#!/usr/bin/env python3
"""Audit retained prepared blocks without resuming unknown-frame frontiers.
O(retained visits/effects) time; O(compressed input+largest decoded journal)
space. Output values are conditional component compositions, never native data.
"""
import hashlib,json,struct
from functools import lru_cache
from collections import Counter
from daemon_receive_tools import ROOT
from replay_daemon_descriptor_producers import unpack
from daemon_sha1_core_model import IV,STATE_XOR,pad
def serialized(state,selector,size):
 if size==0:return b''
 assert(selector,size)in [(1,16),(2,20)]
 b=struct.pack(('<4I'if selector==1 else'>5I'),*state[:size//4]);return bytes(x^0x98 for x in b)
@lru_cache(maxsize=1)
def retained_short():
 p=json.loads((ROOT/'daemon_identity_cache_profiles.json').read_text());rows=[];counts=Counter()
 for idx,row in enumerate(p['cases']):
  cfg=row['configuration']
  if not(cfg['identity_present']and cfg['buffer_nonnull']and cfg['conversion_success']and cfg['UTF16_length']<64):continue
  t=unpack(row);F=int(t['entry_SP'],16);C=F+0x3c70;known={}
  assert row['boundary']['pc']=='0x100abee7c'and row['boundary']['detail']['address']==hex(F+0x2e50)
  for e in t['events']:
   if e['kind']=='write':known.update({int(e['address'],16)+j:b for j,b in enumerate(bytes.fromhex(e['after_hex']))})
  ctx=bytes(known[C+j]for j in range(100));st=next(x for x in t['API_models']if x['binding']['symbol']=='_strlen');prefix=bytes.fromhex(st['read_prefix_hex']);N=int(st['returned_X0'],16);assert len(prefix)==N+1 and prefix[-1]==0;message=prefix[:-1];assert bytes(x^0x98 for x in ctx[:64])==pad(message);state=[x^STATE_XOR for x in struct.unpack_from('<5I',ctx,0x48)];assert state==IV and struct.unpack_from('<II',ctx,0x5c)==(20,2)
  rows.append({'case_index':idx,'parent_payload_sha256':row['payload_sha256'],'message_hex':message.hex(),'prepared_context100_hex':ctx.hex(),'original_SP':hex(F),'original_context':hex(C),'unchanged_frontier':row['boundary']['pc'],'conditional_expected_output20_hex':bytes(x^0x98 for x in hashlib.sha1(message).digest()).hex(),'native_path_completed':False});counts['retained_short_cases_checked']+=1;counts['retained_visits_inspected']+=len(t['steps']);counts['retained_effects_inspected']+=len(t['events'])
 assert len(rows)==288;counts['distinct_prepared_messages']=len({x['message_hex']for x in rows});assert counts['distinct_prepared_messages']==3;return rows,dict(counts)
def pipeline_configurations():
 rows,counts=retained_short();unique={}
 for row in rows:unique.setdefault(row['message_hex'],row)
 for message,row in sorted(unique.items()):
  for offset in [0,0x100]:yield {'kind':'conditional_core_serializer','message_hex':message,'prepared_context100_hex':row['prepared_context100_hex'],'retained_case_index':row['case_index'],'parent_payload_sha256':row['parent_payload_sha256'],'offset':offset}
