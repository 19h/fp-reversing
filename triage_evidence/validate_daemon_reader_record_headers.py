#!/usr/bin/env python3
"""Static N19 admission/allocation/header joins;no target execution."""
import copy,json,re,subprocess
from recover_daemon_reader_record_headers import ROOT,P,SCOPE,FLAGS,sha,build
from validate_daemon_reader_container_origins import SSA as ParentSSA,lut
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix,WORD_BASE
SOLVER='/opt/homebrew/bin/z3';PH='(concat ((_ extract 63 32) Z30) #x00006cf4)';WBASE=0x71134a47fbd9f0b7
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in [('CUR',64),('NODE',64),('REC',64),('HRAW',32),('T',16),('CP0',64),('CP1',64),('CTRL0',32),('CTRL1',32)])+''.join(f'(declare-fun HAVOC_{n}_{j} () (_ BitVec 64))\n'for n in['NODE','REC']for j in list(range(1,19))+[30])
BANK_SITE={0x1005f3b70:('NL',0x100fc4230),0x1005f3b84:('NR',0x101031fa0),0x1004d62b8:('RL',0x100fc4130),0x1004d62c8:('RR',0x101031ea0)}
class SSA(ParentSSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc in BANK_SITE:
    name,base=BANK_SITE[pc];p=split(i['operands']);a=self.address(p[1]);self.loads[i['ea']]=(f'(LUT_{name} ((_ extract 7 0) (bvsub {a} {bv(base)})))',8)
   super().run({'instructions':[i]},pc+4)
  return self
from validate_daemon_existing_scalar_reader import split
def certificates(s):
 pp=[];tr={};summ=[];fs=s['fragments'];b=s['banks'];ld=''.join(lut(pre+x,bytes.fromhex(row[key]))for row,pre in zip(b,['N','R'])for x,key in[('L','left_bytes'),('R','right_bytes')])
 def solve(n,body,scope,result='unsat'):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+ld+body+'\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr);pp.append({'name':n,'query':q,'result':result,'scope':scope,'reused_codec_lemma':False})
 def frame(o):return f'(bvadd K {bv(o)})'
 def at(ix):return f'(bvadd TABLE {bv(ix*8)})'
 def part(n,label,r=None,loads=None,chain=None,start=None,end=None):
  f=fs[n];start=start or int(f['start'],16);end=end or int(f['instructions'][-1]['ea'],16);ii=[i for i in f['instructions']if start<=int(i['ea'],16)<end];ll={};dd=[]
  for i in ii:
   if i['mnemonic']in('ldr','ldrb','ldrh','ldrsh','ldur'):
    bits=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']in('ldrh','ldrsh')else 32 if i['operands'].startswith('w')else 64;v=None
    for o,value in[(0x9d8,'TABLE'),(0x9d0,PH),(0x9b0,bv(0x100fc4230)),(0x9a8,bv(0x101031fa0)),(0x968,bv(0x100fc4130)),(0x960,bv(0x101031ea0)),(0x9c8,'CP0'),(0x9c0,'CP1')]:
     if i['operands'].endswith(f'[sp, #{hex(o)}]'):v=value
    if v is None:v=label+'_L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {bits}))')
    ll[i['ea']]=(v,bits)
  ll.update(loads or{});rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update({j:chain[-1].get('x'+str(j))for j in range(31)}if chain else r or{});g=SSA(rr,ll,namespace=label+'_');g.run({'instructions':ii},end);g.declarations='\n'.join(dd)+'\n';tr[label]=g.record();return(chain or[])+[g]
 def rd(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
 def add(n,gs,tt,scope,cc=()):solve(n,prefix(*gs)+''.join('(assert '+c+')\n'for c in cc)+'(assert (or '+' '.join(tt)+'))',scope)
 def after(pre,result):return {0:result,**{j:f'HAVOC_{result}_{j}'for j in list(range(1,19))+[30]},**{j:pre[-1].get('x'+str(j))for j in range(19,30)}}
 scope='Conditional source component;valid/cache-consistent frame/buffer/heap owners,normal allocation return preserving SP/X19-X29 and successful PAC remain premises. No target call or request is executed.'
 size=z('SIZE');encP='(bvxor PL #x8b3dc651)';inrange=f'(bvult CUR {size})';room=f'(bvuge (bvsub {size} CUR) {bv(10)})'
 lo=part('loop','input_loop',r={8:'CUR',12:bv(0xb350),19:z('(bvxor SIZE #x8b3dc651)')});g=lo[-1];add('decoded_extent_and_remaining_input',lo,[neq(g.get('x11'),size),neq(g.get('x10'),f'(bvsub {size} CUR)'),neq(g.get('w13'),'#x00006ff5'),neq(rd(g,0x1004ddb1c)['address'],f'(ite (bvugt {size} CUR) {at(0xb358)} {at(0xb350)})')],scope+' Private loop modeW12=b350 and cursor register X8 are component inputs;later back-edge production is not proved.')
 bu=part('buffer','input_buffer',loads={'0x10052b4a0':('BUF',64)},chain=lo);g=bu[-1];add('nonnull_buffer_gate',bu,[neq(g.stores[0]['address'],frame(0x4120)),neq(g.stores[0]['value'],'BUF'),neq(rd(g,0x10052b4c8)['address'],f'(ite (= BUF {bv(0)}) {at(0x701f)} {at(0x6ff5)})'),neq(g.get('w9'),'#x0000185d')],scope,[inrange])
 ad=part('admit','header_admission',chain=bu);g=ad[-1];tt=[neq(g.stores[0]['address'],frame(0xa608)),neq(g.stores[0]['value'],size),neq(g.stores[1]['address'],frame(0xa610)),neq(g.stores[1]['value'],'CUR'),neq(g.get('w16'),'#x000000af'),neq(rd(g,0x1004dbd40)['address'],f'(ite {room} {at(0x1ba2)} {at(0x185d)})')];add('ten_byte_admission_and_cursor_limit_producers',ad,tt,scope+' N0/N24 are current cursor and decoded total extent on this path.',[inrange,f'(distinct BUF {bv(0)})'])
 rc=part('read_call','first_word_call',chain=ad);g=rc[-1];add('admitted_first_word_read_interface',rc,[neq(g.get('x1'),'BUF'),neq(g.get('x4'),f'(bvadd CUR {bv(WORD_BASE)})'),neq(g.get('w8'),'#x00008c3f'),neq(g.get('w16'),'#x000000af'),neq(rd(g,0x1004f81bc)['address'],at(0x2520))],scope+' Read-key identity is bounded to the admitted u32 cursor domain.',[inrange,room])
 un=part('read_call','unbounded_word_call',r={8:'CUR',16:bv(0xaf)},loads={'0x1004f81b8':('TABLE',64)});solve('unbounded_u64_read_key_identity_is_false',prefix(*un)+'(assert '+neq(un[-1].get('x4'),f'(bvadd CUR {bv(WORD_BASE)})')+')',scope+' Abstract counterexample outside the established admitted domain;no native input/fault fixture is constructed.','sat')
 old=json.loads((ROOT/'daemon_reader_context_footprint_source.json').read_text());ll={}
 for q in old['read_ledger']:
  if q['address_base']=='TABLE':ll[q['site']]=('FN',64)
  elif q['offset_bytes']==0x9d8:ll[q['site']]=('TABLE',64)
  elif q['offset_bytes']==0xa610:ll[q['site']]=('CUR',64)
  elif q['offset_bytes']==0xa608:ll[q['site']]=(size,64)
 prep=part('read_prepare','read_cache',chain=rc,loads=ll);g=prep[-1];wrows=old['write_ledger'];byoff={r['offset_bytes']:next(q for q in g.stores if q['site']==r['site'])for r in wrows};tt=[neq(g.get('x1'),'BUF'),neq(g.get('x4'),f'(bvadd CUR {bv(WORD_BASE)})'),neq(g.get('w16'),'#x000000af')]
 for off,val in[(0x830,f'(bvadd CUR {bv(WORD_BASE+6)})'),(0x810,f'(bvadd CUR {bv(WORD_BASE+10)})'),(0x828,f'(bvadd CUR {bv(10)})'),(0x820,size)]:tt.extend([neq(byoff[off]['address'],frame(off)),neq(byoff[off]['value'],val)])
 add('actual_cursor_and_extent_read_cache_bindings',prep,tt,scope+' Other context reads remain named arbitrary inputs and still require valid memory.',[inrange,room])
 tg=part('read_tag','N19_tag_footprint',r={1:bv(0x79b09650c3f6825c),4:frame(0x4120),22:frame(0xa610),16:bv(0x1fa)},loads={'0x1005122cc':('CUR',64),'0x1005122d0':('BUF',64),'0x1005122d4':('TABLE',64),'0x1005122d8':('FN',64)});g=tg[-1];tt=[neq(rd(g,0x1005122cc)['address'],frame(0xa610)),neq(rd(g,0x1005122d0)['address'],frame(0x4120)),neq(rd(g,0x1005122d8)['address'],at(0x1fa))]
 for j,q in enumerate([q for q in g.reads if q['width_bits']==8]):tt.append(neq(q['address'],f'(bvadd BUF CUR {bv(4+j)})'))
 add('N19_tag_two_byte_addresses',tg,tt,scope+' Footprint only;existing canonical reader-mask/register preconditions remain required for decoded tag semantics.',[inrange,room])
 terms=[f'(bvuge (bvadd CUR {bv(j)}) {size})'for j in range(10)];solve('all_ten_header_offsets_within_extent','(assert '+inrange+')\n(assert '+room+')\n(assert (or '+' '.join(terms)+'))',scope+' Logical byte-offset bounds;physical BUF+extent ownership/nonwrapping is not proved.')
 end=f'(bvadd CUR {bv(10)} {z("PL")})';wide=f'(bvadd ((_ zero_extend 64) CUR) {bv(10,128)} ((_ zero_extend 96) PL))';claims=[f'(bvugt {wide} {bv((1<<64)-1,128)})',f'(and (bvule {end} {size}) (or (bvule {end} CUR) (bvugt PL #xfffffff5)))'];solve('bounded_offset_no_wrap_and_fit_progress','(assert '+inrange+')\n(assert '+room+')\n(assert (or '+' '.join(claims)+'))',scope+' Under u32 total extent,cursor range and header admission,offset addition cannot wrap64. A fitting end strictly advances and implies PL<=fffffff5;actual back edge is unproved.')
 guard=part('length_guard','ordinary_length',r={10:bv(0xb8e4),21:z(encP),22:z('HRAW')});g=guard[-1];ok='(bvule PL #xfffffff5)';add('ordinary_record_extent_guard',guard,[neq(rd(g,0x1005beb1c)['address'],f'(ite {ok} {at(0x8753)} {at(0x701f)})'),neq(g.get('w27'),'#x00007b3b'),neq(g.get('w24'),'#x00006cf4')],scope+' Guard is exact for every u32 declared extent.')
 for row,pre in zip(b,['N','R']):
  solve(pre+'_bank_all_256',f'(assert (distinct (bvxor B0 (LUT_{pre}R (bvxor (LUT_{pre}L B0) {bv(row["key_u8"],8)}))) {bv(row["results_256"][0],8)}))',scope+' Exact original bank bytes;native mutable bank contents remain a premise.')
 np=part('node_alloc','node_pre',chain=guard,end=0x1005f3bac,loads={'0x1005f3b44':('CTRL0',32),'0x1005f3b4c':('CTRL1',32),'0x1005f3ba0':('FN',64)});g=np[-1];add('record_node_malloc32_interface',np,[neq(g.get('x0'),bv(32)),neq(rd(g,0x1005f3ba0)['address'],at(0xcc0d)),neq(g.get('x17'),bv(0x6aa4))],scope,[ok])
 nq=part('node_alloc','node_post',r=after(np,'NODE'),start=0x1005f3bb0);g=nq[-1];add('record_node_result_frontiers',[*np,g],[neq(g.stores[0]['address'],frame(0x5440)),neq(g.stores[0]['value'],'NODE'),neq(rd(g,0x1005f3bd0)['address'],f'(ite (= NODE {bv(0)}) {at(0x7b61)} {at(0x7b3b)})')],scope+' Failure continuation is recorded only as a frontier;no cleanup dereference or fault fixture is evaluated.',[ok])
 bp=part('record_alloc','record_pre',chain=nq,end=0x1004d62ec,loads={'0x1004d6298':('CTRL0',32),'0x1004d62a0':('CTRL1',32),'0x1004d62e4':('FN',64)});g=bp[-1];add('record_buffer_extent_and_node_initialization',[*np,*bp],[neq(g.stores[0]['address'],'NODE'),neq(g.stores[0]['value'],bv(0)),neq(g.stores[1]['address'],f'(bvadd NODE {bv(8)})'),neq(g.stores[1]['value'],bv(0)),neq(g.stores[2]['address'],f'(bvadd NODE {bv(16)})'),neq(g.stores[2]['value'],'(bvadd PL #x0000000a)'),neq(g.get('x0'),f'(bvadd {z("PL")} {bv(10)})'),neq(rd(g,0x1004d62e4)['address'],at(0xcc0d))],scope+' Normal allocation return and valid nonnull32 B node are explicit premises. Raw64 framea630 store is recorded without assigning semantics.',[ok,f'(distinct NODE {bv(0)})'])
 bq=part('record_alloc','record_post',r=after(bp,'REC'),start=0x1004d62f0);g=bq[-1];add('record_buffer_pointer_and_result_frontiers',[*np,*bp,g],[neq(g.stores[0]['address'],f'(bvadd NODE {bv(24)})'),neq(g.stores[0]['value'],'REC'),neq(rd(g,0x1004d6308)['address'],f'(ite (= REC {bv(0)}) {at(0x27fc)} {at(0x27f2)})')],scope+' Stops at cleanup frontier for a failed result;does not establish native failure behavior.',[ok,f'(distinct NODE {bv(0)})'])
 wc=part('write_call','N19_write_call',chain=bq);g=wc[-1];add('N19_identifier_writer_interface',[*np,*bp,*wc],[neq(g.get('x16'),f'(bvadd NODE {bv(24)})'),neq(g.get('w21'),'#x00006cf4'),neq(g.get('w24'),'#x0000027b'),neq(g.get('w22'),'(bvxor HRAW #x01263f51)'),neq(rd(g,0x1005bfcd0)['address'],at(0x54e5))],scope,[ok,f'(distinct NODE {bv(0)})',f'(distinct REC {bv(0)})'])
 setup=part('write_prepare','N19_write_cache',chain=wc,loads={'0x1008ecba4':('NODE',64),'0x1008ecbb4':('T',16),'0x1008ecc34':(encP,32),'0x1008ecc20':('FN',64)});g=setup[-1];byPC={q['site']:q for q in g.stores};want=[(0x1008ecbac,0x9a0,f'(bvadd NODE {bv(24)})'),(0x1008ecbb8,0x970,'((_ sign_extend 16) T)'),(0x1008ecbc0,0x950,'(bvxor ((_ sign_extend 16) T) #xffffcbf9)'),(0x1008ecc38,0x980,encP),(0x1008ecc78,0x938,'#x0000adb6')];tt=[]
 for pc,off,value in want:q=byPC[hex(pc)];tt.extend([neq(q['address'],frame(off)),neq(q['value'],value)])
 tt.extend([neq(g.get('w24'),'#x0000027b'),neq(g.get('w22'),'(bvxor HRAW #x01263f51)'),neq(g.get('x19'),bv(WBASE)),neq(g.get('w21'),'#x000030b3'),neq(g.get('w7'),'#x01263f51'),neq(rd(g,0x1008ecc20)['address'],at(0x9da7))]);add('N19_shared_writer_cache_and_key_arguments',[*np,*bp,*setup],tt,scope+' Unrelated eager frame loads remain arbitrary but valid. Shared helper/cache addresses are mode-dependent.',[ok,f'(distinct NODE {bv(0)})',f'(distinct REC {bv(0)})'])
 ai=part('after_identifier','N19_after_identifier',loads={'0x1007b1fbc':('(bvxor ((_ sign_extend 16) T) #xffffcbf9)',32),'0x1007b1fe0':(f'(bvadd NODE {bv(24)})',64)});g=ai[-1];add('N19_tag_writer_arguments',ai,[neq(g.get('w16'),'(bvxor ((_ sign_extend 16) T) #xffffcbf9)'),neq(g.get('w22'),'#x00000a48'),neq(g.get('w19'),'(bvand (bvlshr (bvxor ((_ sign_extend 16) T) #xffffcbf9) #x00000008) #x000000ff)'),neq(g.get('x24'),f'(bvadd NODE {bv(24)})'),neq(rd(g,0x1007b1fdc)['address'],at(0x2cff))],scope+' Prior word writer preserves the key/input registers required by this continuation.')
 ta=part('after_tag','N19_after_tag',r={21:bv(0x30b3),7:bv(0x1263f51)},loads={'0x1005ffd80':(f'(bvadd NODE {bv(24)})',64),'0x1005ffd94':(encP,32)});g=ta[-1];add('N19_extent_word_writer_arguments',ta,[neq(g.get('x16'),f'(bvadd NODE {bv(24)})'),neq(g.get('w24'),'#x0000029b'),neq(g.get('x19'),bv(WBASE+6)),neq(g.get('w20'),encP),neq(rd(g,0x1005ffd7c)['address'],at(0x1824))],scope)
 word=part('word_call','N19_extent_common_word',chain=ta);g=word[-1];add('N19_extent_common_word_input',word,[neq(g.get('w22'),f'(bvxor {encP} #x01263f51)'),neq(rd(g,0x100615010)['address'],at(0x9da7))],scope+' W21/W7 are source-preparer literals;tag helper liveness is a pinned prior codec premise.')
 ae=part('after_extent','N19_after_extent',loads={'0x100517a10':('#x0000adb6',32)});add('N19_payload_router_frontier',ae,[neq(rd(ae[-1],0x100517a14)['address'],at(0xadb6))],scope+' Stops at payload router;complete payload reconstruction/list insertion is unproved.')
 solve('N19_unmasked_header_field_preservation','(assert (or '+neq('(bvxor HRAW #x01263f51 #x8a1bf900)','(bvxor HRAW #x8b3dc651)')+' '+neq('(bvxor T #xcbf9 #x8c60)','(bvxor T #x4799)')+' '+neq(f'(bvxor {encP} #x01263f51 #x8a1bf900)','PL')+'))',scope+' These are pre-mask field values;actual stored bytes include destination-address masks. Reader tag semantics/register preconditions are inherited from prior source contracts.')
 old=json.loads((ROOT/'daemon_header_codec_checks.json').read_text());excluded={'identifier_call_phase_and_arguments','tag_frame_encoding','tag_call_arguments','after_tag_word_arguments','scalar_call_word_arguments','common_word_call'};selected=[q for q in old['proofs']if q['name']not in excluded];assert len(selected)==66
 for q in selected:
  v=subprocess.run([SOLVER,'-in'],input=q['query'],text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()=='unsat';pp.append({**q,'name':'reused_'+q['name'],'reused_codec_lemma':True,'prior_checks_sha256':sha(ROOT/'daemon_header_codec_checks.json')})
 return pp,tr,summ
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_admission_target',lambda t:t['branch_edges'][0].__setitem__('index','0x0')),('wrong_bank_key',lambda t:t['banks'][0].__setitem__('key_u8',0)),('drop_read_prepare',lambda t:t['fragments'].pop('read_prepare')),('invent_full_parser',lambda t:t.__setitem__('complete_parser_proved',True)),('wrong_node_store',lambda t:t['fragments']['record_alloc']['instructions'][6].__setitem__('operands','xzr, [x0]')),('omit_prior_reference',lambda t:t['prior_source_recaptures'].pop())];aa=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=s;aa.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return aa
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert verify(s);pp,tr,summ=certificates(s);aa=alterations(s);sites={pc for q in tr.values()for pc in q['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']not in('braa','blraa')};assert sites==expected,(len(sites),len(expected),expected-sites)
 counts={**s['verified_source_counts'],'new_queries_unsat':sum(q['result']=='unsat'and not q.get('reused_codec_lemma')for q in pp),'reused_codec_queries_unsat':sum(q.get('reused_codec_lemma',False)for q in pp),'counterexamples_sat':sum(q['result']=='sat'for q in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(q['source_sites'])for q in tr.values()),'SSA_definitions':sum(q['SSA_definitions']for q in tr.values()),'rejected_alterations':len(aa)};c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_reader_container_origins.py':sha(ROOT/'validate_daemon_reader_container_origins.py'),'daemon_header_codec_checks.json':sha(ROOT/'daemon_header_codec_checks.json')},'proofs':pp,'translations':tr,'family_summaries':summ,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'normal_allocation_return_is_premise':True,'complete_parser_proved':False,'source_recapture_match':True,'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
