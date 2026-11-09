#!/usr/bin/env python3
"""Audit every source/effect stream and freshly replay the full cohort.
O(parent+new visits/effects+source bytes+solver resources) time;
O(compressed profiles+one decoded/fresh case+decoder cache+SMT DAG) space.
Native calls, object bytes at the foreign frontier and IPC remain unavailable.
"""
import json,struct,hashlib
from pathlib import Path
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from recover_daemon_object_creation import sha,span
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_cache36 import ida_matches
from validate_daemon_object_clock import checked,logical_read
from replay_daemon_descriptor_producers import unpack
from capture_daemon_cache_publication import build
from recover_daemon_cache_publication import summary,sampled_ABIs
from prove_daemon_cache_publication import obligations
from daemon_cache_publication_model import byte_value,word_index,DECODER_CONSTANTS,COPY_CONSTANTS
from daemon_cache_publication_replay import execute,equivalent,instruction,WRITABLE,P,SIZE
from probe_daemon_cache_publication import outcomes
from capstone.arm64_const import ARM64_OP_MEM
from capture_daemon_object_clock import memory_width
def trace(t,context,counts):
 F=int(t['entry_SP'],16);K=int(t['cache_owner'],16);D=F+0x3c30;data={int(g['address'],16)+j:b for g in context['known_byte_groups']for j,b in enumerate(bytes.fromhex(g['bytes_hex']))};api={int(m['pc'],16):m for m in t['API_models']};pos=0;known=set();taint=set();violations=[];mask=base=word_read=byte_read=None;pending_sample=None
 for n in t['entry_defined_GPRs']:known.add('x'+n[1:]if n.startswith('w')else n)
 assert known=={'sp','x29','x30','x27','x11','x2','x8','x9','x13'}
 state=list(struct.unpack('<624I',bytes(data[0x1010c784c+j]for j in range(2496))));wi=0
 def put(a,b):data.update({a+j:v for j,v in enumerate(b)})
 for pc,raw in t['steps']:
  i,rr,ww,row=instruction(pc);assert row['bytes_hex']==raw and t['source_pool'][hex(pc)]==row;assert all(r in known for r in rr),(hex(pc),rr,known)
  if pc in api:
   m=api[pc];assert m['binding']['symbol']in ['_CFRelease','_free']and int(m['returned_X0'],16)==t['configuration']['void_result64'];assert not m['native_call_executed'];assert m['preserved_GPR_SP']['sp']==F and m['preserved_GPR_SP']['x29']==F+0xdf40
   if taint.intersection(set(rr)|{'x0'}):violations.append({'pc':hex(pc),'registers':sorted(taint.intersection(set(rr)|{'x0'}))})
   if 'invalidated_range'in m:
    r=m['invalidated_range'];a=int(r['address'],16)
    for j in range(r['size_bytes']):data.pop(a+j,None)
   taint=set(['x'+str(j)for j in range(18)]+['nzcv']);known.update(['x'+str(j)for j in range(18)]+['x30','nzcv']);counts['void_API_summaries_checked']+=1;continue
  if taint.intersection(rr):violations.append({'pc':hex(pc),'registers':sorted(taint.intersection(rr))})
  taint.difference_update(ww);known.update(ww);counts['defined_source_visits_checked']+=1
  if not any(o.type==ARM64_OP_MEM for o in i.operands):continue
  need=memory_width(i);got=0
  while got<need:
   e=t['events'][pos];pos+=1;assert e['pc']==hex(pc);a=int(e['address'],16);n=e['size_bytes'];got+=n;b=bytes.fromhex(e['after_hex']if e['kind']=='write'else e['bytes_hex']);assert len(b)==n;value=int.from_bytes(b,'little')
   if e['kind']=='read':
    if all(a+j in data for j in range(n)):assert bytes(data[a+j]for j in range(n))==b
    else:assert not P<=a<a+n<=P+SIZE and not any(s['start']<=a<a+n<=s['start']+s['size_bytes']for s in WRITABLE);assert logical_read(a,n)==b
    if K<=a<K+36:assert a+n<=K+32;counts['defined_cache_read_bytes']+=n
    if pc==0x100b8e7ec:assert pending_sample==(a,value);pending_sample=None;counts['sampler_readbacks_checked']+=1
    if pc==0x100be09a8:mask=value;assert mask==255
    if pc==0x100be09b0:base=value
    if pc==0x100be09c0:assert n==8;word_read=(a,value)
    if pc==0x100be0a60:
     assert word_read and word_read[0]==base+word_index(a,mask);byte_read=(a,value);counts['codec_lookup_addresses_checked']+=1
    counts['ordered_source_reads_checked']+=1
   else:
    if 0x1010c784c<=a<0x1010c820c:
     j=(a-0x1010c784c)//4;assert n==4 and j==wi;y=(state[j]&0x80000000)|(state[(j+1)%624]&0x7fffffff);want=state[(j+397)%624]^(y>>1)^(0x9908b0df if y&1 else 0);assert value==want,(hex(pc),j,value,want);state[j]=value;wi=(wi+1)%624;counts['independent_MT_word_updates_checked']+=1;counts['complete_MT_twists_checked']+=wi==0
    if pc==0x100b8e7e0:assert pending_sample is None;pending_sample=(a,value);assert D+20<=a<D+32;counts['padding_sampler_stores_checked']+=1;counts['padding_zero_retries']+=value==0
    if pc==0x100be0a68:
     assert byte_read and word_read;src,v=byte_read;assert value==byte_value(src,word_read[1],v);byte_read=word_read=None;counts['independent_codec_byte_values_checked']+=1
    put(a,b);counts['ordered_source_writes_checked']+=1
  assert got==need
 assert pos==len(t['events'])and pending_sample is None and word_read is None and byte_read is None and wi==0
 counts['cases_byte_ledgers_checked']+=1;counts['volatile_register_reads_before_overwrite']+=len(violations)
 return violations
class Observation:
 context=None;counts=None
def observed_factory(original):
 def factory(*args,**kwargs):
  u=original(*args,**kwargs);add=u.hook_add
  def hook_add(kind,callback,*aa,**kk):
   if kind!=uc.UC_HOOK_CODE:return add(kind,callback,*aa,**kk)
   def observed(u,a,n,d):
    c=Observation.context;F=int(c['SP'],16)
    def get(reg):return u.reg_read(getattr(ar,'UC_ARM64_REG_'+reg.upper()))
    if a==0x100be097c:
     for r,v in DECODER_CONSTANTS.items():assert get(r)==v,(hex(a),r)
     assert get('x11')==F+0x3b3c and get('x8')==F+0x3c00 and 1<=get('x13')<=20;Observation.counts['fresh_decoder_ABI_entries_checked']+=1
    if a==0x100d59b88:
     for r,v in COPY_CONSTANTS.items():assert get(r)==v,(hex(a),r)
     assert get('x12')==F+0x3c00 and get('x4')==F+0x3ad8 and get('x16')==20 and get('x0')<20 and get('w10')==(get('x0')-0xe98c785d)&0xffffffff;Observation.counts['fresh_prefix_copy_ABI_entries_checked']+=1
    if a==0x100aee670:assert get('w12')==0x51e5 and get('x1')==0x280;Observation.counts['fresh_context_initializers_checked']+=1
    return callback(u,a,n,d)
   return add(kind,observed,*aa,**kk)
  u.hook_add=hook_add
  return u
 return factory

def main():
 ctx=checked('daemon_cache_publication_context.json','capture_daemon_cache_publication.py');p=checked('daemon_cache_publication_profiles.json','probe_daemon_cache_publication_fast.py');c=checked('daemon_cache_publication_contracts.json','recover_daemon_cache_publication.py');proofs=checked('daemon_cache_publication_proofs.json','prove_daemon_cache_publication.py');cmp=checked('daemon_cache_publication_executor_comparison.json','compare_daemon_cache_publication_executors.py');samples=checked('daemon_cache_publication_interfaces.json','sample_daemon_cache_publication.py');counts=Counter();totals=Counter();assert c['source_sha256']==ctx['source_sha256']==p['source_sha256']==sha(SOURCE)
 rebuilt,rc,fp=build();assert rebuilt==ctx['contexts']and rc==ctx['retained_counts']and fp==ctx['FP_named_span_audit'];counts.update(rc);counts['restored_component_contexts']=len(rebuilt);counts['FP_named_spans_checked']=sum(x['named_spans']for x in fp)
 for s in c['spans']:assert span(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['source_inventory_spans_checked']+=1
 for a,row in c['source_pool'].items():assert IMAGE.read(int(a,16),4).hex()==row['bytes_hex'];counts['unique_source_words_checked']+=1
 assert verify_used_fixups([int(r['address'],16)for r in c['original_fixups']['records']])==c['original_fixups'];counts['original_fixups_checked']=len(c['original_fixups']['records'])
 live=[]
 for n in ['daemon_cache_publication_ida_bytes.json','daemon_cache_publication_ida_codec_bytes.json']:live.extend(ida_matches(n))
 assert live==c['live_IDB_matches'];counts['live_IDB_ranges']=len(live);counts['live_IDB_bytes']=sum(r['size_bytes']for r in live);assert sampled_ABIs(samples)==c['sampled_ABIs'];counts['sampled_ABI_entries_checked']=sum(r['sample_count']for r in c['sampled_ABIs'].values())
 for f,h in c['SDK']['headers'].items():assert sha(Path(f))==h
 assert c['SDK']['exit_code']==0 and sha(ROOT/'daemon_cache_publication_sdk.c')==c['SDK']['source_sha256']and sha(ROOT/'daemon_cache_publication_sdk.s')==c['SDK']['assembly_sha256'];counts['SDK_signature_compile_checked']=1
 qs,lifts=obligations(c);assert lifts==proofs['source_lift_counts']
 for(name,pred),r in zip(qs,proofs['proofs'],strict=True):
  assert name==r['name'];a=ROOT/r['original_file'];b=ROOT/r['file'];assert sha(a)==r['original_sha256']and sha(b)==r['sha256'];aa=z3.parse_smt2_file(str(a));bb=z3.parse_smt2_file(str(b));assert len(aa)==len(bb)==1;assert z3.eq(z3.simplify(aa[0],bv_sort_ac=True),z3.simplify(pred,bv_sort_ac=True)),name
  for q in [pred,z3.Xor(aa[0],bb[0])]:s=z3.Solver();s.set(timeout=30000);s.add(q);assert str(s.check())=='unsat',name
  counts['source_obligations_rebuilt_unsat']+=1;counts['normalized_SMT_equivalences_unsat']+=1;counts['SMT_artifacts_verified']+=2
 n=z3.BitVec('publication_N64',64);j=z3.BitVec('publication_i64',64)
 for pre in [z3.And(z3.UGE(n,1),z3.ULE(n,20)),z3.And(z3.UGE(n,1),z3.ULE(n,20),z3.ULT(j,n))]:s=z3.Solver();s.add(pre);assert str(s.check())=='sat';counts['nonempty_loop_domains']=counts.get('nonempty_loop_domains',0)+1
 counts['source_lift_visits']=sum(lifts.values());assert cmp['all_checks_pass']and len(cmp['cases'])==12 and all(r['streams_equal']and r['legacy_semantic_sha256']==r['cached_semantic_sha256']for r in cmp['cases']);counts['legacy_full_stream_comparisons_checked']=12
 contexts={r['identity_case_index']:r for r in ctx['contexts']};expect=[(r['identity_case_index'],o)for r in ctx['contexts']for o in outcomes()];assert [(r['identity_case_index'],r['configuration'])for r in p['cases']]==expect;violations=[];old_Uc=uc.Uc;uc.Uc=observed_factory(old_Uc)
 try:
  for k,(r,cs)in enumerate(zip(p['cases'],c['cases'],strict=True)):
   t=unpack(r);parent=contexts[t['identity_case_index']];assert summary(t,parent)==cs;v=trace(t,parent,counts);violations.extend({'case_index':k,**x}for x in v)
   Observation.context=parent;Observation.counts=counts;fresh=execute(parent,t['configuration']);assert equivalent(t,fresh);counts['fresh_complete_A64_cases_recomputed']+=1
   totals.update({'source_visits':len(t['steps']),'modeled_internal_edges':len(t['edges']),'modeled_import_calls':len(t['API_models']),'read_effects':sum(e['kind']=='read'for e in t['events']),'write_effects':sum(e['kind']=='write'for e in t['events'])})
   if k%48==47:print(json.dumps({'cases_checked_and_recomputed':k+1,'source_visits':totals['source_visits']}),flush=True)
 finally:uc.Uc=old_Uc
 assert len(p['cases'])==576;totals['A64_executed_instructions']=totals['source_visits']-totals['modeled_internal_edges']-totals['modeled_import_calls'];assert totals['source_visits']==42073344
 deps=['daemon_cache_publication_context.json','daemon_cache_publication_profiles.json','daemon_cache_publication_contracts.json','daemon_cache_publication_proofs.json','daemon_cache_publication_interfaces.json','daemon_cache_publication_executor_comparison.json','daemon_cache_publication_model.py','daemon_cache_publication_replay.py','capture_daemon_cache_publication.py','probe_daemon_cache_publication_fast.py','prove_daemon_cache_publication.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'source_lift_counts':lifts,'volatile_reads_requiring_further_interpretation':violations,'all_checks_pass':True,'new_port_emission_established':False,'native_cache_or_driver_continuity_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache_publication_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'counts':dict(counts),'totals':dict(totals),'volatile_read_sites':len(violations)}),flush=True)
if __name__=='__main__':main()
