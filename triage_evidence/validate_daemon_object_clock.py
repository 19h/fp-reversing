#!/usr/bin/env python3
"""Rebuild parent snapshots/proofs and audit all continuation bytes/effects.
O(parent+new source visits+effects+solver resources) time, O(largest journal)
space. All96 private cases are freshly recomputed; source models remain bounded.
"""
import json,struct,hashlib
from pathlib import Path
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_MEM
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from daemon_import_bindings import binding
from replay_daemon_descriptor_producers import unpack,IMPORTS
from recover_daemon_object_creation import sha,span
from recover_daemon_object_clock import sections,ida_rows
from recover_daemon_descriptor_producers import verify_used_fixups
from capture_daemon_object_clock import restore,memory_width,canonical
from probe_daemon_object_clock import Run
from prove_daemon_object_clock import obligations
P=0x6800000000;O=P+0x5000
def checked(n,g):
 r=json.loads((ROOT/n).read_text());assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r
def unsat(p):
 s=z3.Solver();s.set(timeout=30000);s.add(p);assert str(s.check())=='unsat'
def logical_read(a,n):
 b=bytearray(IMAGE.read(a,n))
 for at in range(a&~7,a+n,8):
  if at in FIXUPS:
   r=FIXUPS[at];target=r['target'];v=IMPORTS[target]+binding(at)['total_addend']if isinstance(target,str)else target;word=(v&((1<<64)-1)).to_bytes(8,'little');lo=max(a,at);hi=min(a+n,at+8);b[lo-a:hi-a]=word[lo-at:hi-at]
 return bytes(b)
def initial_bytes(ctx,t):
 old=json.loads((ROOT/'daemon_object_initialization_context.json').read_text());F=int(ctx['boundary']['SP'],16);data={}
 def put(a,b):data.update({a+j:x for j,x in enumerate(b)})
 for r in old['source_frame_fields']:put(F+int(r['offset'],16),bytes.fromhex(r['bytes_hex']))
 for off,n,v in [(0x2a48,8,P+0x32000),(0x2a50,4,ctx['configuration']['decoded']^0x8b3dc651),(0x2a58,8,0x1122334455667788),(0x2a60,8,0x9988776655443322),(0x2a70,8,0x123456789abcdef0),(0x273c,4,0x471c)]:put(F+off,v.to_bytes(n,'little'))
 provider=old['coherent_provider_snapshots'][ctx['configuration']['provider_case']];put(P+0x30000,bytes.fromhex(provider['published_buffer512_hex']));put(P+0x32000,bytes((j*29+7)&255 for j in range(256)));put(P+0x1000,(0x0123456789abcdef).to_bytes(8,'little'))
 for a,n,v in [(0x1010c8268,8,P+0x30000),(0x1010c67d4,4,255),(0x1010c8254,1,1),(0x1010c4e18,4,0),(0x1010c4670,4,0x87654321),(0x1010c6800,8,int(provider['encoded_window_mask64'],16)),(0x1010ca2a8,8,int(provider['encoded_window_base64'],16)),(IMPORTS['IOKit/_kIOMainPortDefault'],4,0),(IMPORTS['CoreFoundation/_kCFAllocatorDefault'],8,0),(IMPORTS['CoreFoundation/_kCFAllocatorNull'],8,0x6e00001000)]:put(a,v.to_bytes(n,'little'))
 for r in ctx['source_memory_groups']+t['extension_fixtures']:put(int(r['address'],16),bytes.fromhex(r['bytes_hex']))
 return data
def main():
 c=checked('daemon_object_clock_contracts.json','recover_daemon_object_clock.py');ctx=checked('daemon_object_clock_context.json','capture_daemon_object_clock.py');p=checked('daemon_object_clock_proofs.json','prove_daemon_object_clock.py');r=checked('daemon_object_clock_profiles.json','probe_daemon_object_clock.py');assert c['source_sha256']==ctx['source_sha256']==r['source_sha256']==sha(SOURCE);counts=Counter();totals=Counter();parents=json.loads((ROOT/'daemon_object_initialization_profiles.json').read_text())
 for saved in ctx['contexts']:
  original=unpack(parents['cases'][saved['parent_case_index']]);rebuilt=restore(original)
  for k,v in rebuilt.items():assert saved[k]==v,(saved['parent_case_index'],k)
  counts['parent_source_visits_reconstructed']+=rebuilt['source_visits_consumed'];counts['parent_effects_reconstructed']+=rebuilt['events_consumed'];counts['restored_parent_contexts']+=1
 for s in c['spans']:assert span(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 for pc,row in c['source_pool'].items():assert IMAGE.read(int(pc,16),4).hex()==row['bytes_hex'];counts['distinct_original_opcodes']+=1
 assert verify_used_fixups({int(x['address'],16)for x in c['original_fixups']['records']})==c['original_fixups'];counts['original_fixups']=len(c['original_fixups']['records'])
 bank=c['cold_cache_bank256'];left=IMAGE.read(int(bank['left'],16),256);right=IMAGE.read(int(bank['right'],16),256);assert {i^right[left[i]^int(bank['key'],16)]for i in range(256)}=={int(bank['constant'],16)};counts['exhaustive_bank_inputs']=256
 live=[]
 for name in ['daemon_object_clock_ida_retry.json','daemon_object_clock_ida_more.json']:live.extend(ida_rows(json.loads((ROOT/name).read_text())))
 assert live==c['live_IDB_matches'];counts['live_IDB_ranges']=len(live);counts['live_IDB_raw_bytes']=sum(x['size_bytes']for x in live)
 qs,lifts,derived=obligations(c);assert lifts==p['source_lift_counts']and derived==p['derived']
 for (n,pred),row in zip(qs,p['proofs'],strict=True):
  assert n==row['name']and row['result']=='unsat';unsat(pred);counts['rebuilt_source_obligations_unsat']+=1
  for fk,hk in [('original_file','original_sha256'),('file','sha256')]:
   f=ROOT/row[fk];assert sha(f)==row[hk];forms=z3.parse_smt2_file(str(f));assert len(forms)==1;unsat(forms[0]);unsat(z3.Xor(forms[0],pred));counts['SMT_files_unsat_and_formula_matched']+=1
 counts['source_lift_visits']=sum(lifts.values());cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;pool={int(pc,16):next(cs.disasm(bytes.fromhex(row['bytes_hex']),int(pc,16)))for pc,row in c['source_pool'].items()};writable=[s for s in sections()if s['segment']=='__DATA'];cases=[];certificates=[]
 for k,(saved,summary)in enumerate(zip(r['cases'],c['cases'],strict=True)):
  t=unpack(saved);parent=ctx['contexts'][saved['parent_case_index']];o=saved['outcome'];F=int(t['entry_SP'],16);data=initial_bytes(parent,t);state=list(struct.unpack('<624I',bytes(data[0x1010c784c+j]for j in range(2496))));index=int.from_bytes(bytes(data[0x1010c67dc+j]for j in range(4)),'little');counter=int.from_bytes(bytes(data[0x1010c8258+j]for j in range(4)),'little');initialindex=index;wordindex=passes=extracts=pos=0;apis={int(x['pc'],16):x for x in t['API_models']};sampler_pending=None;sampler=[];first_active=False;first_x0_tainted=False;before_second=[]
  def put(a,b):data.update({a+j:x for j,x in enumerate(b)})
  def invalidate(a,n):
   for j in range(n):data.pop(a+j,None)
  for pc,raw in t['steps']:
   i=pool[pc];assert bytes(i.bytes).hex()==raw
   if pc in apis:
    m=apis[pc];name=m['binding']['symbol']
    if name=='_gettimeofday':
     assert m['arguments2']==[hex(F+0x3ca0),'0x0'];sample=m['sample'];first=pc==0x100bad4c8;assert sample==({'seconds':o['first_seconds'],'microseconds':o['first_microseconds'],'status32':o['first_status32']}if first else{k:o[k]for k in ['seconds','microseconds','status32']});assert int(m['returned_X0'],16)&0xffffffff==sample['status32']&0xffffffff
     for e in m['writes']:put(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
     invalidate(F+0x3cac,4)
     if first:first_active=True;first_x0_tainted=True
     else:first_active=False;assert not first_x0_tainted;counts['first_clock_unused_result_paths_checked']+=1
    else:
     effect=m['opaque_effect'];invalidate(int(effect['address'],16),effect['size_bytes']);assert name in ['_pthread_once','_pthread_rwlock_wrlock','_pthread_rwlock_unlock'];assert m['status32']==(0 if name=='_pthread_once'else o['primitive_status32']);counts['opaque_sync_API_models_checked']+=1
    counts['clock_API_models_checked'if name=='_gettimeofday'else'other_API_models_checked']+=1;continue
   if first_active:
    reads,writes=i.regs_access();assert not(first_x0_tainted and any(canonical(i.reg_name(x))=='x0'for x in reads));first_x0_tainted&=not any(canonical(i.reg_name(x))=='x0'for x in writes);before_second.append(pc)
   es=[]
   if any(x.type==ARM64_OP_MEM for x in i.operands):
    need=memory_width(i);got=0
    while got<need:
     e=t['events'][pos];pos+=1;assert e['pc']==hex(pc);got+=e['size_bytes'];es.append(e)
    assert got==need
   for e in es:
    a=int(e['address'],16);n=e['size_bytes'];key='bytes_hex'if e['kind']=='read'else'after_hex';b=bytes.fromhex(e[key]);value=int.from_bytes(b,'little')
    if e['kind']=='read':
     if all(a+j in data for j in range(n)):assert bytes(data[a+j]for j in range(n))==b,(k,e)
     else:
      assert not P<=a<a+n<=P+0x100000 and not any(s['start']<=a<a+n<=s['start']+s['size_bytes']for s in writable),(k,'undefined read',e)
      assert logical_read(a,n)==b,(k,e)
     if first_active:assert a+n<=F+0x3ca0 or a>=F+0x3cb0
     if pc==0x100a41c74:assert a==0x1010c784c+4*index and value==state[index]and passes==extracts+1;extracts+=1
     if pc==0x100b8e7ec:assert sampler_pending==(a,value);sampler_pending=None;counts['sampler_readbacks_checked']+=1
     counts['ordered_source_reads_checked']+=1
    else:
     if 0x1010c784c<=a<0x1010c820c:
      j=(a-0x1010c784c)//4;assert n==4 and j==wordindex;nextword=state[(j+1)%624];y=(state[j]&0x80000000)|(nextword&0x7fffffff);want=state[(j+397)%624]^(y>>1)^(0x9908b0df if nextword&1 else 0);assert value==want;state[j]=value;wordindex=(wordindex+1)%624;passes+=wordindex==0;counts['finite_twist_word_updates_checked']+=1
     elif a==0x1010c67dc:assert value==index+1 and passes==extracts;index=value
     elif a==0x1010c8258:assert value==counter+1;counter=value
     if pc==0x100b8e7e0:assert sampler_pending is None;sampler_pending=(a,value);sampler.append((a,value))
     put(a,b);counts['ordered_source_writes_checked']+=1
  assert pos==len(t['events'])and sampler_pending is None and wordindex==0 and passes==extracts==index-initialindex
  assert len(before_second)==40;certificates.append({'case_index':k,'first_result_X0_unused_before_overwrite':True,'first_timeval_not_read_before_second_call':True,'source_visits_between_calls':len(before_second)})
  expected_seconds=(o['seconds']&0xffffffff)if o['status32']==0 else 0;obj=summary['object_writes'];assert [(int(e['address'],16)-O,e['size_bytes'])for e in obj]==[(0x354,4),(0x358,8),(0x360,8)];assert [int.from_bytes(bytes.fromhex(e['after_hex']),'little')for e in obj]==[expected_seconds,0x123456789abcdef0,0];assert not any(e['kind']=='write'for e in summary['table_effects']);assert not t['arbitrary_heap_reads'];counts['tail_field_stores_checked']+=3
  if not o['lock_cell64']:assert saved['boundary']['pc']=='0x10019385c'and saved['boundary']['detail']['arguments8'][0]=='0xc8'and len(t['API_models'])==2;counts['lock_creator_frontiers_checked']+=1
  else:
   assert len(t['API_models'])==6;mode=o['registry_mode'];outputs=summary['lookup_outputs'];value=next(e for e in outputs if e['pc']=='0x100c11a30');status=next(e for e in outputs if e['pc']=='0x1009512b4');matched=mode in ['match_first','match_last'];v=0x44440000+int(mode=='match_last')if matched else 0;assert int.from_bytes(bytes.fromhex(value['after_hex']),'little')==v;assert int.from_bytes(bytes.fromhex(status['after_hex']),'little')==(0x8b3dc651 if matched else 0x74c29f00)
   reads=[e for e in summary['table_effects']if e['pc']=='0x10095e950'];expected_reads=0 if mode=='empty'else 1 if mode=='match_first'else 2;assert len(reads)==expected_reads
   if matched:assert saved['boundary']['pc']=='0x1009c0148'and saved['boundary']['detail']['arguments8'][0]=='0x24';idx=next(e for e in outputs if e['pc']=='0x100b328c8');assert int.from_bytes(bytes.fromhex(idx['after_hex']),'little')==int(mode=='match_last');assert len({a for a,v in sampler if v})==18;counts['matched_value_paths_checked']+=1
   else:assert saved['boundary']['pc']=='0x100abd698'and not sampler;counts['empty_or_missing_value_paths_checked']+=1
  for a,v in sampler:
   if v:assert data[a]!=0
  counts.update({'persisted_A64_cases':1,'source_visits_checked':len(t['steps']),'complete_twist_passes':passes,'nonzero_sampler_bytes':sum(v!=0 for a,v in sampler),'sampler_zero_retries':sum(v==0 for a,v in sampler),'private_padding_reads':0});totals.update({'source_visits':len(t['steps']),'read_effects':sum(e['kind']=='read'for e in t['events']),'write_effects':sum(e['kind']=='write'for e in t['events']),'API_models':len(t['API_models']),'logical_edges':len(t['edges'])})
  new=Run(parent,o).run();assert new==saved;counts['freshly_recomputed_A64_cases']+=1
  if k%8==7:print(json.dumps({'cases_checked_and_recomputed':k+1,'source_visits_checked':counts['source_visits_checked']}),flush=True)
 assert dict(totals)=={k:v for k,v in c['totals'].items()if k!='cases'};assert len(r['cases'])==96 and len(qs)==25
 deps=['daemon_object_clock_context.json','daemon_object_clock_contracts.json','daemon_object_clock_profiles.json','daemon_object_clock_proofs.json','probe_daemon_object_clock.py','prove_daemon_object_clock.py','capture_daemon_object_clock.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'first_clock_independence_certificates':certificates,'source_lift_counts':lifts,'all_checks_pass':True,'new_object_publication_established':False,'new_port_emission_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_clock_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
