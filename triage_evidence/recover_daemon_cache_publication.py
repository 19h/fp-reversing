#!/usr/bin/env python3
"""Recover cleanup, padded identity cache, consumer codec and next-input ABI.
O(all visits/effects+source bytes) time, O(compressed profiles+one decoded
case+source inventory) space. Cipher identity/native continuity stay unknown.
"""
import json,struct,subprocess,hashlib
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from recover_daemon_object_creation import sha,span
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_cache36 import ida_matches
from replay_daemon_descriptor_producers import unpack
from daemon_cache_publication_model import EXTRA_SPECS,DECODER_CONSTANTS,COPY_CONSTANTS
def contiguous(pool):
 out=[]
 for a in sorted(int(a,16)for a in pool):
  if out and a==out[-1][1]:out[-1][1]+=4
  else:out.append([a,a+4])
 return out
def summary(t,context):
 F=int(t['entry_SP'],16);D=F+0x3c30;K=int(t['cache_owner'],16);known={int(g['address'],16)+j:b for g in context['known_byte_groups']for j,b in enumerate(bytes.fromhex(g['bytes_hex']))};pad=[];kw=[];kr=[];wr=[];sr=[];sw=[];tw=[];pw=[]
 for e in t['events']:
  a=int(e['address'],16);n=e['size_bytes'];pc=int(e['pc'],16)
  if e['kind']=='write':
   b=bytes.fromhex(e['after_hex']);known.update({a+j:v for j,v in enumerate(b)})
   if pc==0x100b8e7e0 and D+20<=a<D+32:pad.append(e)
   if K<=a<K+36:kw.append(e)
   if 0x100ac1c7c<=pc<0x100ac7cc4 and n==1:sw.append(e)
   if pc==0x100be0a68:tw.append(e)
   if pc==0x100d59ba0:pw.append(e)
  else:
   if K<=a<K+36:kr.append(e)
   if 0x100a3ce28<=pc<0x100a41330 and D<=a<D+32:wr.append(e)
   if pc==0x100be0a60:sr.append(e)
 def read(a,n):return bytes(known[a+j]for j in range(n))
 def field(off):return int.from_bytes(read(F+off,8),'little')
 C=field(0x30b8);B=field(0x3178);S=min(int(e['address'],16)for e in sw);T=min(int(e['address'],16)for e in tw);base=field(0x2f08)
 assert (C,B,S,T)==(F+0x3ad8,F+0x3ab0,F+0x3b3c,F+0x3c00)
 assert C==B+0x28 and S==B+0x8c and T==B+0x150
 assert len(kw)==len(kr)==len(wr)==len(sw)==32 and len(sr)==len(tw)==len(pw)==20
 assert {int(e['address'],16)-K for e in kw}=={int(e['address'],16)-K for e in kr}==set(range(32));assert t['cache_defined_mask36']==[True]*32+[False]*4
 assert {int(e['address'],16)-D for e in wr}==set(range(32));assert {int(e['address'],16)-S for e in sw}==set(range(32))
 assert {int(e['address'],16)-D for e in pad}==set(range(20,32));assert all(read(D+j,1)!=b'\0'for j in range(20,32))
 digest=hashlib.sha1(bytes.fromhex(t['message_hex'])).digest();encoded=bytes(x^0x98 for x in digest);assert read(D,20)==digest and read(T,20)==read(C,20)==encoded
 assert read(C+0x40,8)==struct.pack('<II',0,20);assert [v^0xf4f92df7 for v in struct.unpack('<5I',read(C+0x48,20))]==[0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0];assert read(C+0x5c,8)==struct.pack('<II',20,2)
 assert t['boundary']['pc']=='0x10095eb00'and t['boundary']['kind']=='before_unknown_external_read'and int(t['boundary']['detail']['address'],16)==base+0x238 and t['boundary']['detail']['size_bytes']==1
 def order(es,origin):return [int(e['address'],16)-origin for e in es]
 for es,origin in [(kw,K),(kr,K),(wr,D),(sw,S)]:assert order(es[:16],origin)==[j-16 for j in order(es[16:],origin)]
 return {'identity_case_index':t['identity_case_index'],'configuration':t['configuration'],'message_hex':t['message_hex'],'SP':hex(F),'cache_owner':hex(K),'decoded_digest20_hex':digest.hex(),'padded_input32_hex':read(D,32).hex(),'cache32_hex':read(K,32).hex(),'consumer_intermediate32_hex':read(S,32).hex(),'recovered_encoded20_hex':read(T,20).hex(),'next_context':hex(C),'next_record_base':hex(base),'next_input_address':hex(base+0x238),'next_requested_bytes':20,'unchanged_foreign_frontier':t['boundary']['pc'],'sampler_stores':len(pad),'sampler_zero_retries':sum(bytes.fromhex(e['after_hex'])==b'\0'for e in pad),'writer_input_order16':order(wr[:16],D),'writer_output_order16':order(kw[:16],K),'consumer_input_order16':order(kr[:16],K),'consumer_output_order16':order(sw[:16],S),'writer_store_PCs16':[e['pc']for e in kw[:16]],'consumer_store_PCs16':[e['pc']for e in sw[:16]],'writer_input_PCs16':[e['pc']for e in wr[:16]],'consumer_input_PCs16':[e['pc']for e in kr[:16]],'API_requests':[{'pc':a['pc'],'symbol':a['binding']['symbol'],'arguments1':a['arguments1']}for a in t['API_models']],'cache_tail_source_defined':False,'native_continuity_established':False}
def sampled_ABIs(samples):
 out={}
 for role,constants in [('consumer_byte_unmask',DECODER_CONSTANTS),('next_context_prefix_copy',COPY_CONSTANTS)]:
  rows=[s for c in samples['cases']for s in c['samples']if s['role']==role];assert len(rows)==40
  for r in rows:
   for reg,v in constants.items():assert int(r['registers31'][int(reg[1:])],16)==v,(role,reg)
  out[role]={'sample_count':len(rows),'constant_registers':{r:hex(v)for r,v in constants.items()}}
 return out
def sdk():
 root=Path(subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],capture_output=True,text=True,check=True).stdout.strip());headers=[root/'System/Library/Frameworks/CoreFoundation.framework/Headers/CFBase.h',root/'usr/include/stdlib.h'];assert 'void CFRelease(CFTypeRef cf);'in headers[0].read_text()
 command=['xcrun','--sdk','macosx','clang','-target','arm64-apple-macos13','-O1','-S',str(ROOT/'daemon_cache_publication_sdk.c'),'-o',str(ROOT/'daemon_cache_publication_sdk.s')];p=subprocess.run(command,capture_output=True,text=True);assert p.returncode==0,p.stderr
 return {'command':command,'exit_code':p.returncode,'SDK':str(root),'headers':{str(p):sha(p)for p in headers},'source_sha256':sha(ROOT/'daemon_cache_publication_sdk.c'),'assembly_sha256':sha(ROOT/'daemon_cache_publication_sdk.s'),'target_build_SDK_established':False,'native_calls_executed':False}
def main():
 profiles=json.loads((ROOT/'daemon_cache_publication_profiles.json').read_text());contexts={c['identity_case_index']:c for c in json.loads((ROOT/'daemon_cache_publication_context.json').read_text())['contexts']};pool={};slots=set();routes={};totals=Counter();cases=[]
 for row in profiles['cases']:
  t=unpack(row);c=contexts[t['identity_case_index']];cases.append(summary(t,c));totals.update({'cases':1,'source_visits':len(t['steps']),'read_effects':sum(e['kind']=='read'for e in t['events']),'write_effects':sum(e['kind']=='write'for e in t['events']),'logical_edges':len(t['edges']),'API_models':len(t['API_models'])})
  for a,r in t['source_pool'].items():assert a not in pool or pool[a]==r;pool[a]=r
  slots.update(int(a,16)for a in t['used_fixups'])
  for e in t['edges']:
   if e['slot']is not None:
    d=routes.setdefault(e['pc'],{});assert e['target']not in d or d[e['target']]==e['slot'];d[e['target']]=e['slot']
  if len(cases)%96==0:print(json.dumps({'summarized_cases':len(cases)}),flush=True)
 first=cases[0]
 for c in cases:
  for k in ['writer_input_order16','writer_output_order16','consumer_input_order16','consumer_output_order16','writer_store_PCs16','consumer_store_PCs16','writer_input_PCs16','consumer_input_PCs16','API_requests']:assert c[k]==first[k]
 ranges=contiguous(pool);spans=[span('observed_'+str(j),a,z)for j,(a,z)in enumerate(ranges)]+[span(n,a,z)for n,a,z in EXTRA_SPECS];samples=json.loads((ROOT/'daemon_cache_publication_interfaces.json').read_text());live=[]
 for n in ['daemon_cache_publication_ida_bytes.json','daemon_cache_publication_ida_codec_bytes.json']:live.extend(ida_matches(n))
 deps=['daemon_cache_publication_profiles.json','daemon_cache_publication_context.json','daemon_cache_publication_interfaces.json','daemon_cache_publication_model.py','daemon_cache_publication_ida_bytes.json','daemon_cache_publication_ida_codec_bytes.json','daemon_cache_publication_sdk.c'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'source_pool':pool,'route_slots':routes,'original_fixups':verify_used_fixups(slots),'live_IDB_matches':live,'sampled_ABIs':sampled_ABIs(samples),'cases':cases,'totals':dict(totals),'SDK':sdk(),'new_port_emission_established':False,'native_cache_or_driver_continuity_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache_publication_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_ranges':len(ranges),'unique_source_words':len(pool),'fixups':len(out['original_fixups']['records']),'IDB_bytes':sum(r['size_bytes']for r in live),'totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
