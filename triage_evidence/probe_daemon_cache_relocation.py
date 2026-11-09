#!/usr/bin/env python3
"""Controlled private cache-owner relocation with all other known bytes fixed.
Three baseline contexts and two relocated owners each: nine source executions.
O(nine visits/effects) time, O(compressed nine cases+one journal) space.
No native allocation, pointer patching or retained-frontier resume occurs.
"""
import json,copy,hashlib
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE
from recover_daemon_object_creation import sha
from probe_daemon_cache_publication import outcomes,packed
from daemon_cache_publication_replay import execute
from recover_daemon_cache_publication import summary
from validate_daemon_cache_publication import trace
def selected():
 contexts=json.loads((ROOT/'daemon_cache_publication_context.json').read_text())['contexts'];out={}
 for c in contexts:out.setdefault(c['message_hex'],c)
 assert len(out)==3;return [out[k]for k in sorted(out)]
def relocate(c,address):
 c=copy.deepcopy(c);old=int(c['cache_owner_address'],16);root=0x1010c6840;before={int(g['address'],16)+j:b for g in c['known_byte_groups']for j,b in enumerate(bytes.fromhex(g['bytes_hex']))};assert int.from_bytes(bytes(before[root+j]for j in range(8)),'little')==old
 assert not any(old+j in before or address+j in before for j in range(36));patched=set()
 for g in c['known_byte_groups']:
  a=int(g['address'],16);b=bytearray.fromhex(g['bytes_hex'])
  for j,v in enumerate(address.to_bytes(8,'little')):
   if a<=root+j<a+len(b):b[root+j-a]=v;patched.add(root+j)
  g['bytes_hex']=b.hex()
 assert patched==set(range(root,root+8));after={int(g['address'],16)+j:b for g in c['known_byte_groups']for j,b in enumerate(bytes.fromhex(g['bytes_hex']))};assert set(before)==set(after)and {a for a in before if before[a]!=after[a]}.issubset(patched)
 extent=c['allocated_owners'].pop(hex(old));snapshot=c['owner_snapshots'].pop(hex(old));assert extent==36 and len(snapshot)==72
 assert not any(address<h+n and h<address+36 for a,n in c['allocated_owners'].items()for h in [int(a,16)])
 c['allocated_owners'][hex(address)]=extent;c['owner_snapshots'][hex(address)]=snapshot;c['cache_owner_address']=hex(address)
 return c,{'root_cell':hex(root),'old_owner':hex(old),'new_owner':hex(address),'owner_size_bytes':36,'only_changed_known_byte_addresses':[hex(a)for a in sorted(before)if before[a]!=after[a]],'known_byte_domain_unchanged':True,'other_entry_registers_unchanged':True,'cache_bytes_initially_undefined':True}
def configurations():
 for c in selected():
  yield c,{'kind':'baseline','original_identity_case_index':c['identity_case_index']}
  for address in [0x680003a000,0x680003a100]:
   new,patch=relocate(c,address);yield new,{'kind':'relocated','original_identity_case_index':c['identity_case_index'],'patch':patch}
def main():
 cases=[];counts=Counter();bases={};cfg=next(outcomes())
 for c,spec in configurations():
  t=execute(c,cfg);s=summary(t,c);violations=trace(t,c,counts);assert not violations
  if spec['kind']=='baseline':bases[c['identity_case_index']]=s
  else:
   b=bases[c['identity_case_index']];assert s['padded_input32_hex']==b['padded_input32_hex']and s['cache32_hex']!=b['cache32_hex'];assert s['consumer_intermediate32_hex']==b['consumer_intermediate32_hex']and s['recovered_encoded20_hex']==b['recovered_encoded20_hex']and s['next_input_address']==b['next_input_address']
  cases.append({'specification':spec,'profile':packed(t),'summary':s});print(json.dumps({'cases':len(cases),'kind':spec['kind'],'identity_case_index':c['identity_case_index']}),flush=True)
 assert len(cases)==9
 deps=['daemon_cache_publication_context.json','daemon_cache_publication_replay.py','probe_daemon_cache_publication.py','recover_daemon_cache_publication.py','validate_daemon_cache_publication.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':cases,'byte_audit_counts':dict(counts),'causal_relocation_cases':6,'native_relocation_tested':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache_relocation_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'controlled_relocations':6,'baseline_runs':3,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
