#!/usr/bin/env python3
"""Compose known short-path state and source-produced digest output values.
O(retained visits/effects+known bytes) time; O(parent profiles+largest journal
+captured known groups) space. No native or unknown-frame continuation.
"""
import json,hashlib
from pathlib import Path
from collections import Counter
from functools import lru_cache
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_MEM
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from recover_daemon_object_creation import sha
from replay_daemon_descriptor_producers import unpack
from capture_daemon_object_clock import memory_width,groups
from validate_daemon_object_clock import logical_read
from recover_daemon_object_clock import sections
from daemon_digest_completion_model import seed
from daemon_digest_output_access import key,register_access
@lru_cache(maxsize=1)
def output_values():
 p=json.loads((ROOT/'daemon_digest_output_profiles.json').read_text());out={}
 for j,r in enumerate(p['conditional_pipelines']):
  t=unpack(r);message=t['configuration']['message_hex'];fmt=t['serializer_trace'];n=fmt['configuration']['output_size'];assert n==20 and fmt['output_defined_mask32']==[True]*20+[False]*12
  value=fmt['output_hex32'][:40];assert bytes(x^0x98 for x in bytes.fromhex(value))==hashlib.sha1(bytes.fromhex(message)).digest()
  if message in out:assert out[message]['encoded_output20_hex']==value
  else:out[message]={'encoded_output20_hex':value,'parent_pipeline_index':j,'parent_payload_sha256':r['payload_sha256']}
 assert len(out)==3;return out
def rebuild(parent,t):
 data={int(g['address'],16)+j:b for g in parent['known_byte_groups']for j,b in enumerate(bytes.fromhex(g['bytes_hex']))};writers={a:'verified frozen entry group'for a in data};counts=Counter();cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
 pool={int(a,16):next(cs.disasm(bytes.fromhex(r['bytes_hex']),int(a,16)))for a,r in t['source_pool'].items()};apis={int(m['pc'],16):m for m in t['API_models']};writable=[s for s in sections()if s['segment']=='__DATA'];pos=0
 def put(a,b,why):
  for j,v in enumerate(b):data[a+j]=v;writers[a+j]=why
 def invalidate(a,n):
  for j in range(n):data.pop(a+j,None);writers.pop(a+j,None)
 for e in t['extension_fixtures']:put(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'retained declared extension')
 for pc,raw in t['steps']:
  i=pool[pc];assert bytes(i.bytes).hex()==raw and IMAGE.read(pc,4).hex()==raw;counts['retained_source_visits']+=1
  if pc in apis:
   m=apis[pc];assert not m['native_call_executed'];name=m['binding']['symbol']
   if name=='_malloc':
    a=int(m['returned_X0'],16)
    if a:invalidate(a,m['requested_bytes'])
   if 'invalidated_range'in m:r=m['invalidated_range'];invalidate(int(r['address'],16),r['size_bytes'])
   for e in m.get('writes',[]):put(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'retained declared API '+hex(pc))
   counts['retained_API_summaries']+=1;continue
  if not any(o.type==ARM64_OP_MEM for o in i.operands):continue
  n=memory_width(i);done=0
  while done<n:
   e=t['events'][pos];pos+=1;assert e['pc']==hex(pc);a=int(e['address'],16);nb=e['size_bytes'];done+=nb;b=bytes.fromhex(e['after_hex']if e['kind']=='write'else e['bytes_hex']);assert len(b)==nb
   if e['kind']=='write':put(a,b,e['pc']);counts['retained_ordered_writes']+=1
   else:
    if all(a+j in data for j in range(nb)):assert bytes(data[a+j]for j in range(nb))==b
    else:assert not 0x6800000000<=a<a+nb<=0x6800100000 and not any(s['start']<=a<a+nb<=s['start']+s['size_bytes']for s in writable);assert logical_read(a,nb)==b
    counts['retained_ordered_reads']+=1
  assert done==n
 assert pos==len(t['events']);return data,writers,dict(counts)
def fp_audit():
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;rows=[]
 for name in ['daemon_compression_frame_contracts.json','daemon_sha1_core_contracts.json','daemon_digest_output_contracts.json','daemon_digest_completion_contracts.json']:
  p=ROOT/name;c=json.loads(p.read_text());ins=0
  for s in c['spans']:
   for i in cs.disasm(bytes.fromhex(s['bytes_hex']),int(s['start'],16)):
    assert not any(key(i.reg_name(r))=='x29'for r in register_access(i)[1]);ins+=1
  rows.append({'source_file':name,'sha256':sha(p),'named_spans':len(c['spans']),'instructions_checked':ins,'writes_X29':0,'scope':'Named source spans only; no claim of complete native path coverage.'})
 return rows
def build():
 pp=json.loads((ROOT/'daemon_identity_cache_context.json').read_text());parents={c['cache_case_index']:c for c in pp['contexts']};profiles=json.loads((ROOT/'daemon_identity_cache_profiles.json').read_text());values=output_values();rows=[];totals=Counter()
 for j,r in enumerate(profiles['cases']):
  cfg=r['configuration']
  if not(cfg['identity_present']and cfg['buffer_nonnull']and cfg['conversion_success']and cfg['UTF16_length']<64):continue
  t=unpack(r);parent=parents[t['cache_case_index']];data,writers,counts=rebuild(parent,t);F=int(t['entry_SP'],16);FP=int(t['boundary']['registers31'][29],16);assert FP==F+0xdf40
  st=next(m for m in t['API_models']if m['binding']['symbol']=='_strlen');message=bytes.fromhex(st['read_prefix_hex'])[:-1];value=values[message.hex()];O=F+0x3ce0;C=F+0x3c70;D=F+0x3c30
  assert all(a not in data for off in [0x3050,0x2e50]for a in range(F+off,F+off+8));cache=int(t['cache_owner_address'],16);assert not any(cache+k in data for k in range(36))
  def word(off):return int.from_bytes(bytes(data[F+off+k]for k in range(8)),'little')
  assert word(0x3610)==C and word(0x31a8)==O and word(0x32e8)==D and word(0x3620)==0x310 and word(0x3650)==0x6d00006000
  injected=[{'address':hex(O),'bytes_hex':value['encoded_output20_hex'],'provenance':'actual source serializer output across explicit component value boundary',**value},{'address':hex(F+0x2a70),'bytes_hex':C.to_bytes(8,'little').hex(),'provenance':'declared saved-context handover from preceding serializer contract B30120'}]
  for e in injected:
   for k,b in enumerate(bytes.fromhex(e['bytes_hex'])):data[int(e['address'],16)+k]=b;writers[int(e['address'],16)+k]=e['provenance']
  inputs={'sp':F,'x29':FP,'x30':0x101039ef0,'w27':0x471c,'w11':0x8204ce66,'w2':0x7e8c,'x8':0x3705faa50a75fa00,'w9':0xbb74a819,'x13':seed(F)}
  rows.append({'identity_case_index':j,'cache_case_index':t['cache_case_index'],'parent_payload_sha256':r['payload_sha256'],'original_frontier_unchanged':r['boundary']['pc'],'parent_identity_configuration':cfg,'message_hex':message.hex(),'SP':hex(F),'entry_PC':'0x100bb1620','entry_defined_GPRs':{n:hex(v)for n,v in inputs.items()},'known_byte_groups':groups(data,writers),'known_bytes':len(data),'allocated_owners':t['allocated_owners'],'owner_snapshots':t['owner_snapshots'],'cache_owner_address':hex(cache),'composed_values':injected,'retained_rebuild_counts':counts,'native_continuity_established':False})
  totals.update(counts)
 assert len(rows)==288;return rows,dict(totals),fp_audit()
def main():
 rows,counts,fp=build();deps=['daemon_identity_cache_context.json','daemon_identity_cache_profiles.json','daemon_identity_cache_checks.json','daemon_digest_output_profiles.json','daemon_digest_output_checks.json','daemon_digest_completion_checks.json','daemon_digest_completion_model.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'contexts':rows,'retained_counts':counts,'FP_named_span_audit':fp,'unavailable_state':['native caller continuity','six root/saved fields at earlier barrier','native CF object bytes and effects','pre-entry NZCV/vector state'],'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache_publication_context.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'contexts':len(rows),'counts':counts,'FP_spans':sum(x['named_spans']for x in fp)}),flush=True)
if __name__=='__main__':main()
