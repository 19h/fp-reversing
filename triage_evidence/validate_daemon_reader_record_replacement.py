#!/usr/bin/env python3
"""Source-linked lookup, splice and normal-return retirement proofs;no target execution."""
import copy,json,re,subprocess
from recover_daemon_reader_record_replacement import ROOT,P,SCOPE,FLAGS,sha,read,build
from validate_daemon_reader_record_payloads import Engine as ParentEngine
from validate_daemon_reader_container_origins import lut
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix,split,WORD_BASE
from validate_daemon_constructor_lookup import CUTS as WORD_CUTS
SOLVER='/opt/homebrew/bin/z3';PH='(concat ((_ extract 63 32) Z30) #x00006cf4)'
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in [('CTX',64),('NODE',64),('OLD',64),('PREV',64),('NEXT',64),('OLD_BUF',64),('LINK',64),('CAND',64),('HRAW',32),('D',32),('STATUS',32),('END',64),('CP0',64),('CP1',64),('CTRL0',32),('CTRL1',32)])+''.join(f'(declare-fun HAVOC_{tag}_{j} () (_ BitVec 64))\n'for tag in['BUFFER','NODE']for j in list(range(19))+[30])
BANK_SITE={0x1006c7754:('BL',0x100e99a00),0x1006c7764:('BR',0x100f4e390),0x1008b317c:('NL',0x100e99700),0x1008b3194:('NR',0x100f4e190)}
class Engine(ParentEngine):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc in BANK_SITE:
    n,base=BANK_SITE[pc];a=self.address(split(i['operands'])[1]);self.loads[i['ea']]=(f'(LUT_{n} ((_ extract 7 0) (bvsub {a} {bv(base)})))',8)
   super().run({'instructions':[i]},pc+4)
  return self

def certificates(s):
 pp=[];tr={};fs=s['fragments'];ld=''.join(lut(pre+x,bytes.fromhex(row[key]))for row,pre in zip(s['banks'],['B','N'])for x,key in[('L','left_bytes'),('R','right_bytes')]);at=lambda ix:f'(bvadd TABLE {bv(ix*8)})';frame=lambda off:f'(bvadd K {bv(off)})'
 scope='Conditional source contract with low32 phase6cf4,valid stable disjoint frame/list/buffer owners,coherent links,original file-backed bank roots and successful PAC. Free calls are not executed;normal return preserves SP/X19-X29 and the designated frame/list cells. Other caller-saved registers are fresh.'
 def solve(n,body,result='unsat',note=''):
  q='(set-option :timeout 15000)\n(set-logic '+('QF_AUFBV'if'(Array 'in body else'QF_BV')+')\n'+DECL+EXTRA+ld+body+'\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr);pp.append({'name':n,'query':q,'result':result,'scope':scope+' '+note,'reused_lemma':False});print(n,result,flush=True)
 def part(n,label=None,r=None,loads=None,chain=None,a=None,end=None,cuts=None):
  label=label or n;f=fs[n];a=a or int(f['start'],16);end=end or int(f['instructions'][-1]['ea'],16);ii=[i for i in f['instructions']if a<=int(i['ea'],16)<end];ll={};dd=[]
  fixed={0x9d8:'TABLE',0x9d0:PH,0x9c8:'CP0',0x9c0:'CP1',0x600:bv(0x100e99a00),0x5f8:bv(0x100f4e390),0x870:bv(0x100e99700),0x868:bv(0x100f4e190)}
  for i in ii:
   if i['mnemonic']in('ldr','ldrb','ldrh','ldrsh','ldur'):
    w=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']in('ldrh','ldrsh')else 32 if i['operands'].startswith('w')else 64;v=None;m=re.fullmatch(r'[xw][0-9]+, \[sp, #(0x[0-9a-f]+)\]',i['operands'])
    if m:v=fixed.get(int(m[1],16))
    if v is None:v=label+'_L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {w}))')
    ll[i['ea']]=(v,w)
  ll.update(loads or{});rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K'
  if chain:rr.update({j:chain[-1].get('x'+str(j))for j in range(31)})
  rr.update(r or{});g=Engine(rr,ll,namespace=label+'_');g.cuts=cuts or{};g.run({'instructions':ii},end);g.declarations='\n'.join(dd)+'\n';tr[label]=g.record();return(chain or[])+[g]
 def rd(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
 def add(n,gs,tt,cc=(),note=''):solve(n,prefix(*gs)+''.join('(assert '+x+')\n'for x in cc)+'(assert (or '+' '.join(tt)+'))',note=note)
 def resume(gs,tag):return {j:gs[-1].get('x'+str(j))if j in range(19,30)else f'HAVOC_{tag}_{j}'for j in range(31)}
 post=part('post_payload',r={22:bv(0x6cf4)},loads={'0x1005c6368':('CTX',64),'0x1005c6370':('HRAW',32)});ent=part('entry',chain=post,loads={'0x1006fd1c0':('CONT',64)});g=ent[-1];tt=[]
 for st,(off,v)in zip(g.stores,[(0x7060,'CONT'),(0xaa5c,'HRAW'),(0xaa60,frame(0xde8))]):tt.extend([neq(st['address'],frame(off)),neq(st['value'],v)])
 tt.extend([neq(rd(g,0x1006fd1c0)['address'],at(0x1308)),neq(rd(g,0x1006fd1ec)['address'],f'(ite (= CTX {bv(0)}) {at(0xc157)} {at(0xc1ca)})'),neq(g.get('w6'),'#x74c29d88')]);add('N19_lookup_snapshot_and_null_context',ent,tt)
 non=part('nonnull',chain=ent);add('N19_lookup_initial_nonnull_dispatch',non,[neq(non[-1].get('x8'),'CTX'),neq(rd(non[-1],0x10070d1f8)['address'],at(0x5e28))],['(distinct CTX '+bv(0)+')'])
 nxt=part('next',r={8:'LINK',22:PH},loads={'0x100697198':('CAND',64)});g=nxt[-1];add('lookup_next_link_and_exhaustion_state',nxt,[neq(rd(g,0x100697198)['address'],'LINK'),neq(g.stores[0]['address'],frame(0xaa68)),neq(g.stores[0]['value'],'CAND'),neq(g.get('x8'),bv(0)),neq(g.get('w9'),'#x00008209'),neq(g.get('w11'),'#x74c29ded'),neq(rd(g,0x1006971c4)['address'],f'(ite (= CAND {bv(0)}) {at(0x582e)} {at(0x57d4)})')])
 cand=part('candidate',chain=nxt,loads={'0x100914e54':('BUF',64)});g=cand[-1];add('candidate_first_word_decode_call',cand,[neq(rd(g,0x100914e54)['address'],f'(bvadd CAND {bv(24)})'),neq(g.get('x1'),'BUF'),neq(g.get('x4'),bv(WORD_BASE)),neq(g.get('w16'),'#x000000c8'),neq(g.get('w8'),'#x00008c3f'),neq(rd(g,0x100914e68)['address'],at(0x2520))],['(distinct CAND '+bv(0)+')'])
 prep=part('prepare',chain=cand);g=prep[-1];add('lookup_decoder_preparation_preserves_actual_arguments',prep,[neq(g.get('x1'),'BUF'),neq(g.get('x4'),bv(WORD_BASE)),neq(g.get('w16'),'#x000000c8'),neq(rd(g,0x1006f708c)['address'],at(0x8c3f))],note='Full386-instruction preparation;other eager context reads remain named and require valid memory.')
 cuts={pc:'U'+str(j)if j<3 else'(bvxor U3 #x5353535353535353)'for j,pc in enumerate(WORD_CUTS)}
 dec=part('decode',chain=prep,loads={'0x100800008':('FN',64),**{hex(pc):('B'+str(j),8)for j,pc in enumerate([0x100800204,0x100800258,0x100800594,0x100800760])}},cuts=cuts);g=dec[-1];bs=[];tt=[]
 for j,pc in enumerate([0x100800204,0x100800258,0x100800594,0x100800760]):
  a=f'(bvadd BUF {bv(j)})';mask=f'((_ extract 7 0) (bvlshr U{j} (bvshl (bvand {a} {bv(7)}) {bv(3)})))';bs.append(f'(bvxor B{j} {mask})');tt.append(neq(rd(g,pc)['address'],a))
 wire='(concat '+' '.join(bs)+')';draw=f'(bvxor {wire} #x8b3dc651)';tt.extend([neq(g.get('w4'),draw),neq(rd(g,0x100800008)['address'],at(0xc8))]);add('candidate_encoded_identifier_and_four_addresses',dec,tt,note='Four canonical mask cuts are justified by32 replayed seed/round lemmas;no candidate type or full record extent check is inferred.')
 # Compare arbitrary returned D to the saved encoded key; caller-specific fields stay explicit.
 cmp=part('compare',r={4:z('D')},loads={'0x100615a30':('HRAW',32),'0x100615a3c':('CAND',64)});g=cmp[-1];add('first_match_comparison_and_found_state',cmp,[neq(rd(g,0x100615a30)['address'],frame(0xaa5c)),neq(rd(g,0x100615a3c)['address'],frame(0xaa68)),neq(g.get('x8'),'CAND'),neq(g.get('w11'),'#x8b3dc651'),neq(g.get('w9'),'#x00008209'),neq(rd(g,0x100615a58)['address'],f'(ite (= D HRAW) {at(0xa924)} {at(0xa93d)})')])
 adv=part('advance',chain=cmp);again=part('next','next_after_mismatch',chain=adv,loads={'0x100697198':('NEXT',64)});g=again[-1];add('mismatch_advances_candidate_next',again,[neq(rd(adv[-1],0x1005bb1bc)['address'],at(0x5e28)),neq(rd(g,0x100697198)['address'],'CAND'),neq(g.stores[0]['value'],'NEXT'),neq(g.get('w11'),'#x74c29ded')],['(distinct D HRAW)'])
 for label,path,load,cc,status in [('found',cmp,'CAND',['(= D HRAW)'],'#x8b3dc651'),('absent',nxt,bv(0),['(= CAND '+bv(0)+')'],'#x74c29ded')]:
  pub=part('publish',label+'_publish',chain=path,loads={'0x100914a10':(frame(0xde8),64),'0x100914a18':('CONT',64)});med=part('mediator',label+'_mediator',chain=pub);g=med[-1];add('N19_'+label+'_lookup_result_and_continuation',med,[neq(rd(pub[-1],0x100914a10)['address'],frame(0xaa60)),neq(pub[-1].stores[0]['address'],frame(0xde8)),neq(pub[-1].stores[0]['value'],load),neq(g.get('w6'),status),neq(g.get('x10'),'CONT'),neq(g.get('x17'),bv(0x68f))],cc)
 # Connect the complete lookup result contract to N19's existing disposition tree.
 ret=part('returned',r={6:z('STATUS')});statusg=part('status',chain=ret);found=part('found',chain=statusg);absent=part('absent',chain=statusg)
 add('N19_lookup_status_dispositions',statusg,[neq(rd(statusg[-1],0x1006b9768)['address'],f'(ite (bvslt STATUS #x74c29ded) {at(0x4124)} {at(0x411a)})')])
 add('N19_found_replacement_selection',found,[neq(rd(found[-1],0x10086c804)['address'],at(0xbd96)),neq(found[-1].get('w11'),'#x00009307')],['(= STATUS #x8b3dc651)'])
 add('N19_absent_append_selection',absent,[neq(rd(absent[-1],0x100767bac)['address'],at(0x1c48))],['(= STATUS #x74c29ded)'])
 rep=part('replace',chain=found,loads={'0x10076e3c4':('OLD',64),'0x10076e3c8':('PREV',64),'0x10076e3cc':('NODE',64),'0x10076e3d4':('NEXT',64)});g=rep[-1];add('replacement_inherits_found_neighbors',rep,[neq(g.stores[0]['address'],f'(bvadd NODE {bv(8)})'),neq(g.stores[0]['value'],'PREV'),neq(g.stores[1]['address'],'NODE'),neq(g.stores[1]['value'],'NEXT'),neq(g.get('w10'),'#x0000c04a'),neq(g.get('w12'),'#xb3d597fb'),neq(rd(g,0x10076e404)['address'],f'(ite (= PREV {bv(0)}) {at(0x9384)} {at(0x9307)})')],['(= STATUS #x8b3dc651)'])
 prev=part('prev_patch',chain=rep,loads={'0x1004ea810':('NEXT',64)});g=prev[-1];add('nonnull_previous_neighbor_patch',prev,[neq(g.stores[0]['address'],'PREV'),neq(g.stores[0]['value'],'NODE'),neq(rd(g,0x1004ea810)['address'],'NODE'),neq(g.get('w10'),'#x0000c04a'),neq(rd(g,0x1004ea848)['address'],at(0x9384))],['(= STATUS #x8b3dc651)','(distinct PREV '+bv(0)+')'])
 ng=part('next_gate',chain=rep);g=ng[-1];add('next_neighbor_patch_partition',ng,[neq(g.get('w11'),'#x00007224'),neq(g.get('w12'),'#x0000af42'),neq(rd(g,0x1007423b0)['address'],f'(ite (= NEXT {bv(0)}) {at(0xc04a)} {at(0xc052)})')],['(= STATUS #x8b3dc651)'])
 np=part('next_patch',chain=ng);g=np[-1];add('nonnull_next_neighbor_patch',np,[neq(g.stores[0]['address'],f'(bvadd NEXT {bv(8)})'),neq(g.stores[0]['value'],'NODE'),neq(g.get('w11'),'#x00007224'),neq(rd(g,0x1006efc2c)['address'],at(0xaf42))],['(= STATUS #x8b3dc651)','(distinct NEXT '+bv(0)+')'])
 hg=part('head_gate',chain=ng,loads={'0x1008143d8':('PREV',64)});g=hg[-1];add('head_update_partition',hg,[neq(rd(g,0x1008143d8)['address'],f'(bvadd NODE {bv(8)})'),neq(g.get('w10'),'#x00002705'),neq(rd(g,0x1008143f8)['address'],f'(ite (= PREV {bv(0)}) {at(0xa663)} {at(0x7224)})')],['(= STATUS #x8b3dc651)'])
 hp=part('head_patch',chain=hg,loads={'0x1008cb954':('CTX',64)});g=hp[-1];add('head_endpoint_patch',hp,[neq(rd(g,0x1008cb954)['address'],frame(0x8760)),neq(g.stores[0]['address'],'CTX'),neq(g.stores[0]['value'],'NODE'),neq(g.get('w10'),'#x00002705'),neq(rd(g,0x1008cb960)['address'],at(0x7224))],['(= STATUS #x8b3dc651)','(= PREV '+bv(0)+')'])
 tg=part('tail_gate',chain=hg,loads={'0x100700230':('NEXT',64)});g=tg[-1];add('tail_update_partition',tg,[neq(rd(g,0x100700230)['address'],'NODE'),neq(g.get('w9'),'#x00008ef5'),neq(rd(g,0x100700250)['address'],f'(ite (= NEXT {bv(0)}) {at(0x7eda)} {at(0x2705)})')],['(= STATUS #x8b3dc651)'])
 tp=part('tail_patch',chain=tg,loads={'0x1006bb370':('CTX',64)});g=tp[-1];add('tail_endpoint_patch',tp,[neq(g.stores[0]['address'],f'(bvadd CTX {bv(8)})'),neq(g.stores[0]['value'],'NODE'),neq(rd(g,0x1006bb37c)['address'],at(0x2705))],['(= STATUS #x8b3dc651)','(= NEXT '+bv(0)+')'])
 retire=part('retire',chain=tg,loads={'0x1006cc860':('OLD',64),'0x1006cc864':('OLD_BUF',64)});g=retire[-1];add('old_owner_retirement_and_optional_buffer_partition',retire,[neq(rd(g,0x1006cc860)['address'],frame(0xde8)),neq(rd(g,0x1006cc864)['address'],f'(bvadd OLD {bv(24)})'),neq(g.get('x0'),'OLD'),neq(g.get('w19'),'#x00009467'),neq(rd(g,0x1006cc890)['address'],f'(ite (= OLD_BUF {bv(0)}) {at(0x8ef5)} {at(0x8f00)})')],['(= STATUS #x8b3dc651)'])
 for row,pre in zip(s['banks'],['B','N']):solve(pre+'_retirement_bank_all_256',f'(assert (distinct (bvxor B0 (LUT_{pre}R (bvxor (LUT_{pre}L B0) {bv(row["key_u8"],8)}))) {bv(row["results_256"][0],8)}))')
 bp=part('free_buffer','buffer_pre',chain=retire,end=0x1006c7788,loads={'0x1006c7728':('CTRL0',32),'0x1006c7730':('CTRL1',32),'0x1006c777c':('FN',64)});g=bp[-1];add('old_buffer_free_call_interface',bp,[neq(g.get('x0'),'OLD_BUF'),neq(g.get('w19'),'#x00009467'),neq(rd(g,0x1006c777c)['address'],at(0xcc08)),neq(g.get('x17'),bv(0x46a2))],['(= STATUS #x8b3dc651)','(distinct OLD_BUF '+bv(0)+')'])
 bq=part('free_buffer','buffer_post',a=0x1006c778c,r=resume(bp,'BUFFER'),loads={'0x1006c778c':('OLD',64)});g=bq[-1];add('old_buffer_normal_return_clear_and_node_dispatch',[*bp,*bq],[neq(g.stores[0]['address'],f'(bvadd OLD {bv(24)})'),neq(g.stores[0]['value'],bv(0)),neq(rd(g,0x1006c77bc)['address'],at(0x3405)),neq(g.get('x0'),'OLD')],['(= STATUS #x8b3dc651)'])
 # Both buffer-present and buffer-NULL routes enter the same node release interface.
 for label,path in [('after_buffer',bq),('without_buffer',retire)]:
  ep=part('free_node',label+'_node_pre',chain=path,end=0x1008b31b8,loads={'0x1008b3150':('CTRL0',32),'0x1008b3158':('CTRL1',32),'0x1008b31b0':('FN',64)});g=ep[-1];deps=[*bp,*ep]if label=='after_buffer'else ep
  add(label+'_old_node_free_call_interface',deps,[neq(g.get('x0'),'OLD'),neq(g.get('w19'),'#x00009467'),neq(g.get('w20'),'#x00003599'),neq(rd(g,0x1008b31b0)['address'],at(0xcc08)),neq(g.get('x17'),bv(0x46a2))],['(= STATUS #x8b3dc651)'])
  eq=part('free_node',label+'_node_post',a=0x1008b31bc,r=resume(ep,'NODE'));loop=part('loop_return',label+'_replacement_back_edge',chain=eq,loads={'0x1009a1810':('END',64),'0x1009a1814':('(bvxor SIZE #x8b3dc651)',32)});g=loop[-1];add(label+'_normal_retirement_actual_cursor_back_edge',[*deps,*loop],[neq(eq[-1].stores[0]['address'],frame(0xde8)),neq(eq[-1].stores[0]['value'],bv(0)),neq(rd(eq[-1],0x1008b31c0)['address'],at(0x9467)),neq(g.get('x8'),'END'),neq(g.get('w19'),'(bvxor SIZE #x8b3dc651)'),neq(g.get('w12'),'#x0000b350'),neq(rd(g,0x1009a181c)['address'],at(0x3599))],['(= STATUS #x8b3dc651)'],note='Saved fitting END comes from the earlier N19 contract. No actual free,heap-lifetime effect or native loop execution occurs.')
 # Stitch the four actual position paths instead of assuming phase equivalence.
 for prev_nil,next_nil,name in[(True,True,'singleton'),(True,False,'head'),(False,True,'tail'),(False,False,'middle')]:
  path=rep;stages=[rep[-1]]
  if not prev_nil:path=part('prev_patch',name+'_prev',chain=path,loads={'0x1004ea810':('NEXT',64)});stages.append(path[-1])
  path=part('next_gate',name+'_next_gate',chain=path)
  if not next_nil:path=part('next_patch',name+'_next',chain=path);stages.append(path[-1])
  path=part('head_gate',name+'_head_gate',chain=path,loads={'0x1008143d8':('PREV',64)})
  if prev_nil:path=part('head_patch',name+'_head',chain=path,loads={'0x1008cb954':('CTX',64)});stages.append(path[-1])
  path=part('tail_gate',name+'_tail_gate',chain=path,loads={'0x100700230':('NEXT',64)})
  if next_nil:path=part('tail_patch',name+'_tail',chain=path,loads={'0x1006bb370':('CTX',64)});stages.append(path[-1])
  path=part('retire',name+'_retire',chain=path,loads={'0x1006cc860':('OLD',64),'0x1006cc864':('OLD_BUF',64)})
  want=[(f'(bvadd NODE {bv(8)})','PREV'),('NODE','NEXT')]+([]if prev_nil else[('PREV','NODE')])+([]if next_nil else[(f'(bvadd NEXT {bv(8)})','NODE')])+([('CTX','NODE')]if prev_nil else[])+([(f'(bvadd CTX {bv(8)})','NODE')]if next_nil else[]);stores=[st for g0 in stages for st in g0.stores];assert len(stores)==len(want)==4;tt=[]
  for st,(addr,value)in zip(stores,want):tt.extend([neq(st['address'],addr),neq(st['value'],value)])
  tt.extend([neq(path[-1].get('w19'),'#x00009467'),neq(rd(path[-1],0x1006cc890)['address'],f'(ite (= OLD_BUF {bv(0)}) {at(0x8ef5)} {at(0x8f00)})')]);cc=['(= STATUS #x8b3dc651)',f'({"="if prev_nil else"distinct"} PREV {bv(0)})',f'({"="if next_nil else"distinct"} NEXT {bv(0)})'];add(name+'_complete_source_link_store_order_and_retire_join',path,tt,cc)
 # Independent word-cell model, in the actual source store order: prev then next.
 model='(declare-fun M () (Array (_ BitVec 64) (_ BitVec 64)))\n(declare-fun probe () (_ BitVec 64))\n';owners=[('CTX',16),('OLD',32),('NODE',32),('PREV',32),('NEXT',32)]
 for owner,n in owners:
  present=f'(distinct {owner} {bv(0)})'
  if owner in('CTX','OLD','NODE'):model+='(assert '+present+')\n'
  model+=f'(assert (=> {present} (and (= (bvand {owner} {bv(7)}) {bv(0)}) (bvule {owner} {bv((1<<64)-n-1)}))))\n'
 for j,(a,an)in enumerate(owners):
  for b,bn in owners[j+1:]:model+=f'(assert (=> (and (distinct {a} {bv(0)}) (distinct {b} {bv(0)})) (or (bvule (bvadd {a} {bv(an)}) {b}) (bvule (bvadd {b} {bv(bn)}) {a}))))\n'
 model+=f'(assert (= (select M OLD) NEXT))\n(assert (= (select M (bvadd OLD {bv(8)})) PREV))\n'
 model+=f'(assert (ite (= PREV {bv(0)}) (= (select M CTX) OLD) (= (select M PREV) OLD)))\n'
 model+=f'(assert (ite (= NEXT {bv(0)}) (= (select M (bvadd CTX {bv(8)})) OLD) (= (select M (bvadd NEXT {bv(8)})) OLD)))\n'
 steps=[('NODE',8,'PREV',None),('NODE',0,'NEXT',None),('PREV',0,'NODE',f'(distinct PREV {bv(0)})'),('NEXT',8,'NODE',f'(distinct NEXT {bv(0)})'),('CTX',0,'NODE',f'(= PREV {bv(0)})'),('CTX',8,'NODE',f'(= NEXT {bv(0)})')];last='M';changed=[]
 for j,(base,off,value,cond)in enumerate(steps):
  addr=f'(bvadd {base} {bv(off)})';store=f'(store {last} {addr} {value})';name='splice'+str(j);model+=f'(define-fun {name} () (Array (_ BitVec 64) (_ BitVec 64)) '+(store if cond is None else f'(ite {cond} {store} {last})')+')\n';last=name;changed.append((addr,cond))
 claims=[neq(f'(select {last} NODE)','NEXT'),neq(f'(select {last} (bvadd NODE {bv(8)}))','PREV')]
 for off in[16,24]:claims.append(neq(f'(select {last} (bvadd NODE {bv(off)}))',f'(select M (bvadd NODE {bv(off)}))'))
 claims.append(f'(ite (= PREV {bv(0)}) {neq(f"(select {last} CTX)","NODE")} (or {neq(f"(select {last} PREV)","NODE")} {neq(f"(select {last} CTX)","(select M CTX)")}))')
 claims.append(f'(ite (= NEXT {bv(0)}) {neq(f"(select {last} (bvadd CTX {bv(8)}))","NODE")} (or {neq(f"(select {last} (bvadd NEXT {bv(8)}))","NODE")} {neq(f"(select {last} (bvadd CTX {bv(8)}))",f"(select M (bvadd CTX {bv(8)}))")}))')
 untouched='(and '+' '.join(f'(not (and {cond or "true"} (= probe {addr})))'for addr,cond in changed)+')';claims.append(f'(and {untouched} {neq(f"(select {last} probe)","(select M probe)")})');solve('independent_source_order_four_position_word_splice',model+'(assert (or '+' '.join(claims)+'))',note='Abstract aligned word-cell model with disjoint nonwrapping16 B head/tail projection and32 B nodes;not a byte-memory,allocator or concurrency proof.')
 solve('omitting_tail_endpoint_update_is_not_equivalent',model+f'(assert (= NEXT {bv(0)}))\n(assert {neq("(select splice4 (bvadd CTX "+bv(8)+"))","NODE")})','sat','Abstract logical mutation counterexample only;no native request or fault fixture is built.')
 add('constructed_identifier_and_lookup_representation_agree',[],[neq('(bvxor HRAW #x8b3dc651 #x8b3dc651)','HRAW')],note='Prior canonical header writer and current four-byte decoder share the address-indexed codec. This equality concerns the saved encoded identifier representation,not an application meaning.')
 # Generic decoder seed/round facts are source-recaptured and replayed,not assumed from names.
 old=json.loads(read(ROOT/'daemon_constructor_lookup_checks.json'));selected=[q for q in old['proofs']if re.fullmatch(r'byte[0-3]_(seed|round[1-7])',q['name'])];assert len(selected)==32
 for q0 in selected:
  v=subprocess.run([SOLVER,'-in'],input=q0['query'],text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()=='unsat';pp.append({**q0,'name':'reused_'+q0['name'],'reused_lemma':True,'prior_checks_sha256':sha(ROOT/'daemon_constructor_lookup_checks.json')})
 return pp,tr

def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_lookup_output',lambda t:t['fragments']['publish']['instructions'][1].__setitem__('operands','xzr, [x10]')),('omit_next_patch',lambda t:t['fragments'].pop('next_patch')),('swap_bank_families',lambda t:t['banks'][0].__setitem__('left',t['banks'][1]['left'])),('wrong_free_target',lambda t:t['pointer_records'][-1]['fixup'].__setitem__('target',0)),('invent_native_retirement',lambda t:t.__setitem__('target_executed',True)),('omit_reaching_definition_limit',lambda t:t['initializer_bank_root_references'][0].__setitem__('scope','native reaching definition proved'))];out=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=s;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr=certificates(s);aa=alterations(s);sites={pc for q in tr.values()for pc in q['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']not in('braa','blraa')};assert expected<=sites,(len(expected),len(sites),expected-sites)
 counts={**s['verified_source_counts'],'new_queries_unsat':sum(q['result']=='unsat'and not q.get('reused_lemma')for q in pp),'reused_queries_unsat':sum(q.get('reused_lemma',False)for q in pp),'counterexamples_sat':sum(q['result']=='sat'for q in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(q['source_sites'])for q in tr.values()),'SSA_definitions':sum(q['SSA_definitions']for q in tr.values()),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_reader_record_payloads.py':sha(ROOT/'validate_daemon_reader_record_payloads.py'),'daemon_constructor_lookup_checks.json':sha(ROOT/'daemon_constructor_lookup_checks.json')},'proofs':pp,'translations':tr,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'normal_free_return_is_premise':True,'selected_replacement_back_edge_proved':True,'complete_parser_proved':False,'source_recapture_match':True,'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
