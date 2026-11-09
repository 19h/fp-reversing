#!/usr/bin/env python3
"""Local producer windows and shared return ABI; no target execution."""
import copy,json,subprocess
from recover_daemon_context_input_producers import ROOT,P,SCOPE,FLAGS,sha,build
from validate_daemon_existing_scalar_reader import make as parent_make,bv,DECL,prefix,neq,z
SOLVER='/opt/homebrew/bin/z3'
def make(f,name,r=None,loads=None,branch=False):
 # STUR has the same address/value effect as STR for these non-writeback windows.
 ff=copy.deepcopy(f)
 for i in ff['instructions']:
  if i['mnemonic']=='stur':i['mnemonic']='str'
 end=int(ff['instructions'][-1]['ea'],16)if branch else int(ff['end'],16)
 return parent_make({'fragments':{name:ff}},name,r=r,loads=loads,end=end,ns=name+'_')
def solve(n,body,scope,result='unsat'):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+body+'\n(check-sat)\n';p=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert p.returncode==0 and not p.stderr and p.stdout.strip()==result,(n,p.stdout,p.stderr);return {'name':n,'query':q,'result':result,'scope':scope}
def certificates(s):
 pp=[];tr={};summ=[]
 def add(n,g,tt,scope):pp.append(solve(n,prefix(g)+'(assert (or '+' '.join(tt)+'))',scope));tr[n]=g.record()
 for q in s['producer_candidates']:
  n='producer_'+q['target'];g=make(s['windows'][q['target']],n);st=next(r for r in g.stores if r['site']==q['source_store']);assert st['width_bits']==q['target_extent_bytes']*8 and q['width_bytes']==q['target_extent_bytes']and q['target_offset']==q['store_offset'];addr=f'(bvadd K {bv(int(q["target_offset"],16))})'
  add(n,g,[neq(st['address'],addr),neq(g.get('sp'),'K')],'Local window entered at its first captured instruction. Exact SP-relative address and full field width; not a same-epoch reaching-definition or alias-exhaustiveness proof.')
 for row in s['tag_return_interfaces']:
  n='tag_stage_'+row['target'];f=s['stages'][row['stage']];loads={}
  for i in f['instructions']:
   if i['mnemonic']!='ldr':continue
   if i['operands'].endswith('[sp, #0x9d0]'):loads[i['ea']]=(bv(0x6cf4),64)
   elif i['operands'].endswith('[sp, #0x9d8]'):loads[i['ea']]=('TABLE',64)
   elif i['ea']==row['next_word_key_load_site']:loads[i['ea']]=('O',64)
   elif i['operands'].startswith('x10, [x13, w10,'):loads[i['ea']]=('FN',64);target_site=i['ea']
  g=make(f,n,r={24:z('TAG'),28:'U'},loads=loads,branch=True);tag=next(r for r in g.stores if r['site']==next(q['source_store']for q in s['producer_candidates']if q['target']==row['target']));working=next(r for r in g.stores if r['site']==row['working_tag_store_site']);assert tag['width_bits']==16 and working['width_bits']==32
  target=next(r for r in g.reads if r['site']==target_site);key=next(r for r in g.reads if r['site']==row['next_word_key_load_site'])
  tt=[neq(tag['address'],f'(bvadd K {bv(int(row["tag_frame_offset"],16))})'),neq(tag['value'],'((_ extract 15 0) TAG)'),neq(working['address'],f'(bvadd K {bv(int(row["working_tag_frame_offset"],16))})'),neq(working['value'],'TAG'),neq(g.get('x1'),f'(bvadd K {bv(int(row["buffer_pointer_cell_offset"],16))})'),neq(key['address'],f'(bvadd K {bv(int(row["next_word_key_frame_offset"],16))})'),neq(g.get('x4'),'O'),neq(g.get('x6'),'U'),neq(g.get('w16'),bv(int(row['next_word_return_selector'],16),32)),neq(g.get('x22'),bv(0x6cf4)),neq(target['address'],f'(bvadd TABLE {bv(8*0x3a31)})'),neq(g.get('x10'),'FN'),neq(g.get('x17'),bv(0x73a))]
  add(n,g,tt,'Selected phase6cf4 and arbitrary raw W24 tag,carried X28 round-key value and loaded next-word key. Stores low16 and raw32 in distinct cells,then supplies pointer-cell/key/return selector to shared530d34. Native owners and proper preparation epochs remain premises.')
  summ.append({**row,'raw_tag_value':'TAG/u32','saved_tag_value':'low16(TAG)','carried_round_key':'X28->X6','target_index':'0x3a31','native_reachability_proved':False})
 tg=make(s['tag_dispatch_prefix'],'tag_dispatch',r={16:z('IX')},loads={'0x1005122cc':('O',64),'0x1005122d0':('BUF',64),'0x1005122d4':('TABLE',64),'0x1005122d8':('FN',64)})
 add('generic_tag_continuation_load',tg,[neq(tg.reads[-1]['address'],'(bvadd TABLE (bvshl ((_ sign_extend 32) IX) #x0000000000000003))'),neq(tg.get('x4'),'FN')],'The original tag body has no later X4/W4 definition; checked source liveness carries this pointer to final BRAA with IA271f. Arbitrary IX does not imply a valid table slot.')
 wg=make(s['word_dispatch_prefix'],'word_dispatch',r={16:z('IX')},loads={'0x100800004':('TABLE',64),'0x100800008':('FN',64)})
 add('generic_word_continuation_load',wg,[neq(wg.reads[-1]['address'],'(bvadd TABLE (bvshl ((_ sign_extend 32) IX) #x0000000000000003))'),neq(wg.get('x22'),'FN')],'The checked original word body preserves loaded X22 to its final BRAA with IA232d. Source slot metadata,not modifier equality alone,identifies the six next frontiers.')
 call=make(s['common_word_call'],'word_call',r={22:bv(0x6cf4),16:z('IX'),1:'CELL',4:'O',6:'U'},loads={'0x100530d3c':('BUF',64),'0x100530d40':('TABLE',64),'0x100530d44':('FN',64)},branch=True)
 add('common_word_call_interface',call,[neq(call.reads[0]['address'],'CELL'),neq(call.reads[-1]['address'],f'(bvadd TABLE {bv(8*0x8c3f)})'),neq(call.get('x1'),'BUF'),neq(call.get('x4'),'O'),neq(call.get('w16'),'IX'),neq(call.get('x6'),'U'),neq(call.get('x10'),'FN'),neq(call.get('x17'),bv(0xd6ff))],'All six stages use the common pointer-cell dereference and original word-reader slot; key,selector and carried round key survive this caller.')
 pp.append(solve('raw32_tag_cache_is_not_zero_extended_saved16','(assert (= TAG #xabcd9777))\n(assert (distinct TAG ((_ zero_extend 16) ((_ extract 15 0) TAG))))','Abstract source-stage input counterexample: low16 store and raw32 store are not interchangeable. This raw input is not claimed reachable from a native decoder.','sat'))
 return pp,tr,summ
def verify(s):return s==build()
def alterations(s):
 # Callers first verify this immutable baseline against a fresh source/census build.
 ops=[('wrong_field_offset',lambda t:t['producer_candidates'][0].__setitem__('target_offset','0x0')),('missing_producer',lambda t:t['producer_candidates'].pop()),('wrong_width',lambda t:t['producer_candidates'][0].__setitem__('target_extent_bytes',4)),('promote_reaching_definition',lambda t:t['producer_candidates'][0].__setitem__('same_active_frame_reaching_definition_proved',True)),('invent_retained_occurrence',lambda t:t['retained_candidate_writer_occurrences'].append('0x1004e2ef0')),('use_unverified_IDA_fact',lambda t:t['read_only_IDA_knowledge'].__setitem__('semantic_facts_used',True))];out=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=s;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert verify(s);pp,tr,summ=certificates(s);aa=alterations(s);k=s['read_only_IDA_knowledge'];assert not k['semantic_facts_used']and [q['result']['count']for q in k['queries']]==[7,0]and all(f['verification']=='unverified'for f in k['queries'][0]['result']['facts'])
 counts={**s['verified_source_counts'],'queries_unsat':34,'counterexamples_sat':1,'translated_instruction_instances':sum(r['SSA_definitions']*0+len(r['source_sites'])for r in tr.values()),'SSA_definitions':sum(r['SSA_definitions']for r in tr.values()),'rejected_alterations':len(aa)};assert len(pp)==35 and sum(p['result']=='unsat'for p in pp)==34
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'source_recapture_match':True,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_existing_scalar_reader.py':sha(ROOT/'validate_daemon_existing_scalar_reader.py')},'proofs':pp,'translations':tr,'tag_stage_summaries':summ,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'all_checks_pass':True,'all_aliases_excluded':False,'same_active_frame_reaching_definition_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
