#!/usr/bin/env python3
"""Independently check source bytes, proofs, byte provenance and finite recurrences.
O(source visits+effects+solver resources) time, O(largest journal) space.
One entire private A64 case is recomputed; native entry/PAC/APIs remain unknown.
"""
import json,hashlib,struct
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from recover_daemon_object_creation import sha,span
from recover_daemon_descriptor_producers import verify_used_fixups
from replay_daemon_descriptor_producers import unpack,IMPORTS
from prove_daemon_object_initialization import obligations
from daemon_object_initialization_model import word
from probe_daemon_object_initialization import Run,cases

def checked(n,g):
 r=json.loads((ROOT/n).read_text());assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r
def unsat(p):
 s=z3.Solver();s.set(timeout=30000);s.add(p);assert str(s.check())=='unsat'
def integer(e):return int.from_bytes(bytes.fromhex(e['after_hex'if e['kind']=='write'else'bytes_hex']),'little')
def main():
 c=checked('daemon_object_initialization_contracts.json','recover_daemon_object_initialization.py');ctx=checked('daemon_object_initialization_context.json','capture_daemon_object_initialization.py');p=checked('daemon_object_initialization_proofs.json','prove_daemon_object_initialization.py');r=checked('daemon_object_initialization_profiles.json','probe_daemon_object_initialization.py');assert c['source_sha256']==ctx['source_sha256']==r['source_sha256']==sha(SOURCE)
 counts=Counter();totals=Counter();fix={int(x['address'],16)for x in c['original_fixups']['records']}
 for s in c['spans']:assert span(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 for pc,row in c['distinct_source_pool'].items():assert IMAGE.read(int(pc,16),4).hex()==row['bytes_hex'];counts['distinct_original_opcodes']+=1
 assert verify_used_fixups(fix)==c['original_fixups'];counts['original_fixups']=len(fix)
 qs,lifts,constants=obligations(ctx);assert lifts==p['source_lift_counts']and p['source_derived_mixer_constants']=={n:hex(x)for n,x in constants.items()}
 for (n,pred),row in zip(qs,p['proofs'],strict=True):
  assert n==row['name']and row['result']=='unsat';unsat(pred);counts['rebuilt_source_obligations_unsat']+=1
  for fk,hk in [('original_file','original_sha256'),('file','sha256')]:
   f=ROOT/row[fk];assert sha(f)==row[hk];forms=z3.parse_smt2_file(str(f));assert len(forms)==1;unsat(forms[0]);unsat(z3.Xor(forms[0],pred));counts['SMT_files_unsat_and_formula_matched']+=1
 assert len(qs)==22;counts['source_lift_visits']=sum(lifts.values())
 configs=list(cases());assert configs==[x['configuration']for x in r['cases']];fresh=[]
 for k,(saved,cfg,summary)in enumerate(zip(r['cases'],configs,c['contexts'],strict=True)):
  t=unpack(saved);F=int(t['entry_SP'],16);O=0x6800005000;provider=ctx['coherent_provider_snapshots'][cfg['provider_case']];cache=bytes.fromhex(provider['published_buffer512_hex']);S=F+0x3a20
  assert t['configuration']==cfg and len(t['steps'])==saved['source_visits'];assert t['boundary']==saved['boundary']==summary['boundary'];
  if cfg['buffer_nonnull']:assert t['boundary']['kind']=='before_unmodeled_import'and t['boundary']['pc']=='0x100bad4c8'and t['boundary']['detail']['symbol']=='libSystem/_gettimeofday'and t['boundary']['detail']['arguments8'][:2]==[hex(F+0x3ca0),'0x0']
  else:assert t['boundary']['kind']=='before_unowned_external_write'and t['boundary']['pc']=='0x100daba8c'and t['boundary']['detail']=={'address':'0x2f','size_bytes':1}
  for pc,b in t['steps']:assert c['distinct_source_pool'][hex(pc)]['bytes_hex']==b
  assert not t['arbitrary_heap_reads'];assert t['cursor_after']==('0x2c0'if cfg['buffer_nonnull']else'0x2b0');assert [x['requested_bytes']for x in t['api_models']]==[872,48];assert t['api_models'][1]['returned']==(hex(0x6800028000)if cfg['buffer_nonnull']else'0x0')
  expected=bytearray()
  for j in range(48):
   A=(S+j)&~7;index=((A&0xffffffff)+0x466d4638)&255;assert index%8==0 and index<=248;cached=int.from_bytes(cache[index:index+8],'little');raw=word(A,cached,constants,False);compact=word(A,cached,constants,True);assert raw==compact;expected.append((compact>>(8*((S+j)&7)))&255)
  initial_scratch=bytes.fromhex(''.join(e['after_hex']for e in t['events']if e['kind']=='write'and e['pc']=='0x100a19cbc'));assert expected==initial_scratch and expected.hex()==summary['scratch48_initial_hex'];counts['compact_scratch_bytes_matched']+=48
  state=list(struct.unpack('<624I',bytes.fromhex(provider['state_bytes_hex'])));next_word=0;passes=0;extracts=0;index=provider['index32'];counter=provider['counter32'];accepted=[0,0];retries=[0,0];readbacks=[0,0];pending=None;sample=[bytearray(587),bytearray(16)];bufferwrites=[];objwrites=[];importreads=[];textreads=0;tempmemory={};mask=32767;base=int(provider['encoded_window_base64'],16)^0x12af5504870a589f
  for e in t['events']:
   a=int(e['address'],16);n=e['size_bytes'];v=integer(e);pc=e['pc']
   if e['kind']=='write':
    b=bytes.fromhex(e['after_hex'])
    if 0x1010c784c<=a<0x1010c820c:
     i=(a-0x1010c784c)//4;assert n==4 and i==next_word;following=state[(i+1)%624];far=state[(i+397)%624];y=(state[i]&0x80000000)|(following&0x7fffffff);wanted=far^(y>>1)^(0x9908b0df if following&1 else 0);assert v==wanted,(k,i,hex(v),hex(wanted));state[i]=v;next_word=(next_word+1)%624;counts['finite_twist_word_updates_checked']+=1
     if next_word==0:passes+=1
    elif a==0x1010c67dc:
     assert pc=='0x100a41c7c'and n==4 and next_word==0 and passes==extracts;assert v==index+1;index=v
    elif a==0x1010c8258:
     assert pc=='0x100bd81dc'and n==4 and v==counter+1;counter=v
    if pc=='0x100b8e7e0':
     epoch=0 if F+0x3a50<=a<F+0x3c9b else 1;extent=587 if epoch==0 else 16;start=F+0x3a50 if epoch==0 else O+0x2c2;assert pending is None and n==1 and a==start+extent-1-accepted[epoch];pending=(a,v,epoch)
     if v:sample[epoch][extent-1-accepted[epoch]]=v;accepted[epoch]+=1
     else:retries[epoch]+=1
    if pc=='0x100daba8c':bufferwrites.append(e)
    if O<=a<O+872:objwrites.append(e)
    for j,x in enumerate(b):tempmemory[a+j]=x
   else:
    if pc=='0x100a41c74':assert n==4 and a==0x1010c784c+4*index and v==state[index]and passes==extracts+1;extracts+=1
    if pc=='0x100b8e7ec':assert pending is not None and pending[:2]==(a,v)and n==1;readbacks[pending[2]]+=1;pending=None
    if pc in ['0x100b8e7a8','0x100b8e7c4']:assert n==1 and base<=a<=base+mask and IMAGE.read(a,1)==bytes.fromhex(e['bytes_hex']);textreads+=1
    if a in IMPORTS.values():importreads.append(e)
    if all(a+j in tempmemory for j in range(n)):assert bytes(tempmemory[a+j]for j in range(n)).hex()==e['bytes_hex'];counts['ordered_readback_effects_checked']+=1
  assert next_word==0 and passes==extracts==index-provider['index32']==counter-provider['counter32'];assert accepted==[587,16]and pending is None and all(readbacks[j]==accepted[j]+retries[j]and 0 not in sample[j]for j in range(2))
  assert [tempmemory[F+0x3a50+j]for j in range(587)]==list(sample[0]);assert summary['sampler']['attempts']==readbacks[0]and summary['sampler']['zero_retries']==retries[0];assert [tempmemory[O+0x2c2+j]for j in range(16)]==list(sample[1])
  assert len(objwrites)==[154,352,189,151][k]and objwrites==summary['object_writes'];assert [(int(e['address'],16)-O,e['size_bytes'])for e in objwrites[:7]]==[(0x350,4),(0x310,8),(0xd8,8),(0xe0,4),(0x104,4),(0x118,4),(0x2f4,4)]
  assert [int(e['address'],16)-O for e in objwrites[7:31]]==list(range(0x2f8,0x310));classifier=[e for e in objwrites if e['pc']=='0x100957864'];assert len(classifier)==int(cfg['buffer_nonnull']);assert not classifier or classifier[0]['address']==hex(O+0xcc)and integer(classifier[0])==cfg['decoded']^0x8b3dc651
  assert len(bufferwrites)==(48 if cfg['buffer_nonnull']else 0)and [int(e['address'],16)for e in bufferwrites]==([0x6800028000+47-j for j in range(48)]if cfg['buffer_nonnull']else[])
  counts['buffer48_bytes_written_checked']+=len(bufferwrites)
  assert bytes(tempmemory[S+j]for j in range(48)).hex()==t['scratch48_hex']==summary['scratch48_final_hex'];assert len(summary['scratch48_writes'])==96
  if cfg['buffer_nonnull']:
   d=cfg['decoded'];assert bytes(tempmemory[O+4+j]for j in range(d))==bytes((j*29+7)&255 for j in range(d));assert sum(e['size_bytes']for e in summary['input_copy_reads'])==d;counts['input_copy_bytes_checked']+=d
  for imp in summary['imported_data']:
   assert len(imp['reads'])==2 and all(e in importreads and e['size_bytes']==(4 if imp['name'].endswith('kIOMainPortDefault')else 8)for e in imp['reads']);counts['imported_data_reads_checked']+=2
  assert sum(int(e['address'],16)==F+0x2a18 and e['size_bytes']==4 and e['after_hex']=='00000000'for e in t['events']if e['kind']=='write')==2
  counts.update({'persisted_private_A64_cases':1,'nonzero_sampler_bytes':sum(accepted),'stack_sampler587_bytes':accepted[0],'object_sampler16_bytes':accepted[1],'zero_retry_readbacks':sum(retries),'complete_twist_passes':passes,'object_field_effects_checked':len(objwrites),'self_text_byte_reads_checked':textreads,'source_visits_checked':len(t['steps'])});totals.update({'source_visits':len(t['steps']),'read_effects':sum(e['kind']=='read'for e in t['events']),'write_effects':sum(e['kind']=='write'for e in t['events']),'logical_edges':len(t['edges']),'modeled_allocator_calls':len(t['api_models'])})
  print(json.dumps({'case_checked':k,'source_visits':len(t['steps']),'twist_passes':passes,'accepted_bytes':accepted,'retries':retries}),flush=True)
  del t
 cfg=configs[0];new=Run(cfg).run();assert new==r['cases'][0];fresh.append({'configuration':cfg,'source_visits':new['source_visits'],'boundary':new['boundary']['pc'],'exact_journal_recomputed':True});counts['fresh_complete_private_A64_cases']=1;print(json.dumps({'fresh_case_recomputed':0}),flush=True)
 counts['live_IDB_ranges']=len(c['live_IDB_matches']);counts['live_IDB_raw_bytes']=sum(x['size_bytes']for x in c['live_IDB_matches'])
 deps=['daemon_object_initialization_contracts.json','daemon_object_initialization_context.json','daemon_object_initialization_proofs.json','daemon_object_initialization_profiles.json','prove_daemon_object_initialization.py','probe_daemon_object_initialization.py','daemon_object_initialization_model.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'fresh_recomputed_cases':fresh,'source_lift_counts':lifts,'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False};(ROOT/'daemon_object_initialization_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
