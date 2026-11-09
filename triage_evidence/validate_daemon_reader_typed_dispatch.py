#!/usr/bin/env python3
"""Source-composed finite typed-dispatch contracts; no target execution."""
import copy,json,re,subprocess
from recover_daemon_reader_typed_dispatch import ROOT,P,SCOPE,FLAGS,sha,build
from recover_daemon_reader_context_footprint import engine
from validate_daemon_reader_extent_families import make
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix
from validate_daemon_reader_context_footprint import declarations
SOLVER='/opt/homebrew/bin/z3'
def solve(n,body,decl,scope,result='unsat'):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+decl+body+'\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr);return {'name':n,'query':q,'result':result,'scope':scope}
def certificates(s):
 pp=[];tr={};summ=[];pr,inp=engine(s['preparation'],ns='prep_');decl=declarations(inp,'N');tr['preparation']=pr.record();cells={q['offset_bytes']:a['value']for q,a in zip(s['preparation_write_ledger'],pr.stores)}
 assert [v^0x4799 for v in [0xc31c,0xd0ee,0x1742]]==[0x8485,0x9777,0x50db]
 def frame(o):return f'(bvadd K {bv(o)})'
 def at(ix):return f'(bvadd TABLE {bv(int(ix,16)*8 if isinstance(ix,str)else ix*8)})'
 def add(n,gs,tt,cc,scope):
  body=prefix(*gs)+''.join('(assert '+x+')\n'for x in cc)+'(assert (or '+' '.join(tt)+'))';pp.append(solve(n,body,decl,scope))
 def extend(row,gs,a,role,extra=None):
  f=s['fragments'][a];ll={};n=row['name']+'_'+role
  for i in f['instructions']:
   if i['mnemonic']!='ldr':continue
   m=re.fullmatch(r'[xw]\d+, \[sp, #(0x[0-9a-f]+)\]',i['operands'])
   if not m:continue
   off=int(m[1],16);bits=32 if i['operands'].startswith('w')else 64
   v='(concat ((_ extract 63 32) Z30) #x00006cf4)'if off==0x9d0 else'TABLE'if off==0x9d8 else'TAG'if off==int(row['parent']['working_tag_offset'],16)else'BUF'if off==int(row['buffer_cell'],16)else cells.get(off)
   if v:ll[i['ea']]=(v,bits)
  ll.update(extra or{});rr={1:z('(bvxor PL #x8ec35f08)'),4:z('(bvxor PL #x8b3dc651)')}if len(gs)==1 else{j:gs[-1].get('x'+str(j))for j in range(31)};g=make(f,n,r=rr,loads=ll);tr[n]=g.record();return gs+[g]
 def indexed(row,gs,a):
  f=s['fragments'][a];pc=next(i['ea']for i in f['instructions']if i['mnemonic']=='ldr'and'sxtw #3'in i['operands']);return next(q for q in gs[-1].reads if q['site']==pc)['address']
 t='((_ extract 15 0) TAG)';sg=f'((_ sign_extend 16) {t})';lower=f'(bvslt {sg} #xffffd0ee)';mid=f'(bvslt {sg} #x00001742)';tag=lambda v:f'(= {t} {bv(v,16)})';scope='Source-composed preparation/gate/bridge/type registers under low32 phase6cf4 with arbitrary upper32. Valid/cache-consistent frame and successful authenticated transfer remain premises; no native route is executed.'
 for row in s['families']:
  n=row['name'];base=[pr]
  for role in ['gate','fit_bridge','type_prefix']:base=extend(row,base,row['parent'][role],role)
  lo=extend(row,base,row['low'],'lower');hi=extend(row,base,row['high'],'upper')
  add(n+'_exact_lower_tag',lo,[neq(indexed(row,lo,row['low']),f'(ite {tag(0xc31c)} {at(row["low_indices"][0])} {at(row["low_indices"][1])})')],[lower],scope+' Lower tags select the recognized64 route exactly at c31c; remaining lower tags reject.')
  add(n+'_signed_upper_split',hi,[neq(indexed(row,hi,row['high']),f'(ite {mid} {at(row["high_indices"][0])} {at(row["high_indices"][1])})')],[f'(not {lower})'],scope+' Nonlower tags split at signed1742,including equality in the upper arm.')
  uc=extend(row,hi,row['u32_exact'],'u32_exact');sc=extend(row,hi,row['span_exact'],'span_exact')
  add(n+'_exact_u32_tag',uc,[neq(indexed(row,uc,row['u32_exact']),f'(ite {tag(0xd0ee)} {at(row["u32_indices"][0])} {at(row["u32_indices"][1])})')],[f'(not {lower})',mid],scope+' Exact d0ee selects the u32 extent gate; other middle tags reject.')
  add(n+'_exact_span_tag',sc,[neq(indexed(row,sc,row['span_exact']),f'(ite {tag(0x1742)} {at(row["span_indices"][0])} {at(row["span_indices"][1])})')],[f'(not {lower})',f'(not {mid})'],scope+' Exact1742 selects the recognized-span route; other upper tags reject.')
  ue=extend(row,uc,row['u32_extent'],'u32_extent');add(n+'_exact_u32_extent',ue,[neq(indexed(row,ue,row['u32_extent']),f'(ite (= PL #x00000004) {at(row["u32_extent_indices"][0])} {at(row["u32_extent_indices"][1])})')],[tag(0xd0ee)],scope+' All u32 extents are checked; exact4 B enters the payload caller.')
  calla=row['u32_extent_targets'][0];call=extend(row,ue,calla,'u32_call');g=call[-1];st=g.stores;assert len(st)==1 and st[0]['width_bits']==32;keyread=next(q for q in g.reads if q['site']==next(i['ea']for i in s['fragments'][calla]['instructions']if i['mnemonic']=='ldr'and i['operands'].startswith('x4, [sp,')));expectedkey=f'(bvadd {cells[int(row["parent"]["length_key_cache_offset"],16)]} {bv(4)})';tt=[neq(indexed(row,call,calla),at(0x3a31)),neq(g.get('x1'),frame(int(row['buffer_cell'],16))),neq(g.get('x4'),expectedkey),neq(keyread['address'],frame(int(row['payload_key_cell'],16))),neq(g.get('w16'),bv(int(row['u32_selector'],16),32)),neq(g.get('x6'),'Z28'),neq(g.get('x22'),bv(0x6cf4)),neq(st[0]['address'],frame(int(row['parent']['working_tag_offset'],16))),neq(st[0]['value'],'#x0000d0ee')];add(n+'_u32_payload_caller',call,tt,[tag(0xd0ee),'(= PL #x00000004)'],scope+' Caller stages pointer-cell,key four bytes beyond length key,carried X28,word-return selector and canonical working tag. It enters shared530d34; source word return pointer has IA232d,without native PAC/owner/publication proof.')
  if n=='N19':
   ve=extend(row,lo,row['u64_extent'],'u64_extent');add(n+'_exact_u64_extent',ve,[neq(indexed(row,ve,row['u64_extent']),f'(ite (= PL #x00000008) {at(row["u64_extent_indices"][0])} {at(row["u64_extent_indices"][1])})')],[tag(0xc31c)],scope+' Exact8 B is required on N19 recognized64 route.')
   va=row['u64_extent_targets'][0];vc=extend(row,ve,va,'u64_call');v=vc[-1];add(n+'_u64_entry_abi',vc,[neq(indexed(row,vc,va),at(0xbe63)),neq(v.get('x0'),'N0'),neq(v.get('x10'),frame(0x4120)),neq(v.get('x3'),'Z20'),neq(v.get('w8'),'#x000008c4')],[tag(0xc31c),'(= PL #x00000008)'],scope+' Entry to588cb0 with raw cursorN0,pointer-cell address,carried X20 and control W8=8c4. Complete helper semantics/return are not inferred.')
   sa=row['span_targets'][0];sv=extend(row,sc,sa,'span_pointer');v=sv[-1];assert len(v.stores)==1 and v.stores[0]['width_bits']==64;add(n+'_span_payload_pointer',sv,[neq(v.stores[0]['address'],frame(0x63a0)),neq(v.stores[0]['value'],f'(bvadd BUF N0 {bv(10)})'),neq(indexed(row,sv,sa),at(0x746b))],[tag(0x1742)],scope+' Stages BUF+N0+10 modulo64 at frame63a0. No allocation,copy,extent dereference,ownership or complete span result is proved.')
  else:
   for label,chain,tv in [('u64',lo,0xc31c),('span',sc,0x1742)]:
    a=row['low_targets'][0];al=extend(row,chain,a,'alternate_'+label);v=al[-1];assert len(v.stores)==1 and v.stores[0]['width_bits']==64;cur=row['parent']['cursor_input'];tt=[neq(v.stores[0]['address'],frame(int(row['alternate_cursor_cell'],16))),neq(v.stores[0]['value'],f'(bvadd {cur} {bv(10)} {z("PL")})'),neq(v.get('x22'),bv(0x6cf4)),neq(indexed(row,al,a),at({'N20':0x27b6,'N21':0x3631,'N22':0x33fb,'N23':0x36bf}[n]))]
    if n in('N20','N22'):tt.append(neq(v.get('w6'),'#x74c29cd6'))
    else:tt.append(neq(v.get('x6'),chain[-1].get('x6')))
    add(n+'_alternate_'+label+'_first_effects',al,tt,[tag(tv)],scope+' Recognized alternate tag advances/stages encoded end with no exact P8 requirement in this checked local route. N20/N22 stage marker74c29cd6; N21/N23 preserve X6 until their next rejection block.')
    if n in('N21','N23'):
     ba=row['alternate_next'];bf=s['fragments'][ba];li=[i for i in bf['instructions']if i['mnemonic']=='ldr'][:2];br=extend(row,al,ba,'after_alternate_'+label,{li[0]['ea']:('U',64),li[1]['ea']:('V',64)});v=br[-1];oo=(0x8318,0x26c4,0x6f18)if n=='N21'else(0x1bf0,0x1744,0x8d98);vv=[bv(0),'#x8b3dc651',bv(0x510df273a0723664 if n=='N21'else 0x799f55970eba2bcd)];tt=[neq(v.get('w6'),'#x74c29d88'),neq(v.reads[1]['address'],'U')]
     for q,o,value in zip(v.stores,oo,vv):tt.extend([neq(q['address'],frame(o)),neq(q['value'],value)])
     add(n+'_after_alternate_'+label+'_rejection',br,tt,[tag(tv)],scope+' Composed next block clears/stages local cells and W6=74c29d88 after the saved end cursor was written. Valid context-head dereference remains a premise; complete cleanup/return is unresolved.')
   if n=='N20':
    body=prefix(*lo)+'(assert '+tag(0xc31c)+')\n(assert (= PL #x00000008))\n(assert '+neq(indexed(row,lo,row['low']),at(row['u32_indices'][0]))+')';pp.append(solve('reject_one_payload_path_for_all_recognized_tags',body,decl,'Source-bound abstract counterexample: N20 recognized64 tag goes to alternate continuation rather than the u32 extent/payload route. No target/native input is constructed.','sat'))
  summ.append({'family':n,'recognized_reader_tags_u16':['0xc31c','0xd0ee','0x1742'],'recognized_wire_tags_u16':['0x8485','0x9777','0x50db'],'reader_tag_xor':'0x4799','u32_required_extent_bytes':4,'u64_required_extent_bytes':8 if n=='N19'else None,'u32_payload_selector':row['u32_selector'],'u32_return_frontier':row['u32_return'],'complete_accessor_semantics_proved':False,'native_buffer_owner_proved':False})
 recognized=f'(or (and {lower} {tag(0xc31c)}) (and (not {lower}) {mid} {tag(0xd0ee)}) (and (not {lower}) (not {mid}) {tag(0x1742)}))';exact=f'(or {tag(0xc31c)} {tag(0xd0ee)} {tag(0x1742)})';pp.append(solve('finite_tag_partition_exact_recognized_set',f'(assert (distinct {recognized} {exact}))',decl,'All raw32 tags,including all65536 low16 patterns and arbitrary upper16. This establishes exact recognition partitions,not payload validity or successful accessor results.'))
 return pp,tr,summ
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_u32_extent_destination',lambda t:t['families'][0]['u32_extent_indices'].__setitem__(0,t['families'][0]['u32_extent_indices'][1])),('wrong_payload_key_cell',lambda t:t['families'][2].__setitem__('payload_key_cell','0x8f8')),('wrong_word_return_selector',lambda t:t['families'][1].__setitem__('u32_selector','0xef')),('wrong_type_branch',lambda t:t['families'][3]['low_indices'].reverse()),('invent_complete_accessor',lambda t:t.__setitem__('complete_accessor_semantics_proved',True)),('missing_span_pointer_block',lambda t:t['fragments'].pop(t['families'][0]['span_targets'][0]))];aa=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=s;aa.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return aa
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert verify(s);pp,tr,summ=certificates(s);aa=alterations(s);sites={pc for r in tr.values()for pc in r['source_sites']};expected={i['ea']for f in[s['preparation']]+list(s['fragments'].values())for i in f['instructions'][:-1]};assert sites==expected,(len(sites),len(expected),expected-sites)
 counts={**s['verified_source_counts'],'queries_unsat':sum(q['result']=='unsat'for q in pp),'counterexamples_sat':sum(q['result']=='sat'for q in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(r['source_sites'])for r in tr.values()),'SSA_definitions':sum(r['SSA_definitions']for r in tr.values()),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_reader_extent_families.py':sha(ROOT/'validate_daemon_reader_extent_families.py'),'validate_daemon_reader_context_footprint.py':sha(ROOT/'validate_daemon_reader_context_footprint.py')},'source_recapture_match':True,'proofs':pp,'translations':tr,'family_summaries':summ,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'complete_accessor_semantics_proved':False,'native_buffer_owner_proved':False,'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
