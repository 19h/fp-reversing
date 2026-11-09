#!/usr/bin/env python3
"""Static lookup/word-codec/commit certificate; no target execution."""
import copy,json,subprocess
from recover_daemon_constructor_lookup import ROOT,P,SCOPE,FLAGS,IMAGE,CS,sha,h,build
from validate_daemon_constructor_inputs import SSA,make,prefix,bv,split
KEYS=[0x324a764c67af2e0e,0xe70987b7a1f527b0,0x9032dc5079388982,0x144db9b1af6b5721,0xeb8e58819a88bf30,0x7faaf81a732f68b4,0x4f99108510ad96e0]
CUTS=[0x10080024c,0x1008003a0,0x100800598,0x100800754]
DECL=''.join('(declare-fun '+n+' () (_ BitVec 64))\n'for n in['K','C','OUT','CONT','TABLE','FN','BUF','O','A','U','V','OLD','NEW','PREV','NEXT','OLD_BUF','LINK','NODE','U0','U1','U2','U3']+['Z'+str(j)for j in range(31)])+''.join('(declare-fun '+n+' () (_ BitVec 32))\n'for n in['KEY','D','STATUS','IX'])+''.join('(declare-fun B'+str(j)+' () (_ BitVec 8))\n'for j in range(4))
def z32(e):return'((_ zero_extend 32) '+e+')'
def neq(a,b):return'(distinct '+a+' '+b+')'
def mismatch(terms):return'(assert (or '+' '.join(terms)+'))'
def solve(n,body,scope):
 q='(set-option :timeout 15000)\n(set-logic '+('QF_AUFBV' if '(Array 'in body else 'QF_BV')+')\n'+DECL+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20)
 assert r.returncode==0 and not r.stderr and r.stdout.strip()=='unsat',(n,r.stdout,r.stderr)
 return{'name':n,'query':q,'result':'unsat','scope':scope}
def cut(s,n,a,z):return{'instructions':[i for i in s['fragments'][n]['instructions']if a<=int(i['ea'],16)<z]}
def constants(s):return SSA({},namespace='k_').run(cut(s,'prepare_decoder',0x1006f70d8,0x1006f71f0),0x1006f71f0)
LOADS={'0x100800204':('B0',8),'0x100800258':('B1',8),'0x100800594':('B2',8),'0x100800760':('B3',8),'0x100800004':('TABLE',64),'0x100800008':('FN',64)}
def codec_parts(s):
 ii=s['fragments']['decode']['instructions'];seeds=[j for j,i in enumerate(ii)if i['mnemonic']=='and'and'#0xfffffffffffffff8'in i['operands']];eors=[j for j,i in enumerate(ii)if i['mnemonic']=='eor'and'ror #61'in i['operands']];ends=[next(j for j,i in enumerate(ii)if int(i['ea'],16)==pc)for pc in CUTS]
 assert len(seeds)==4 and len(eors)==24
 return ii,seeds,eors,ends
def written(i):
 if i['mnemonic'].startswith('str')or i['mnemonic']in('cmp','cmn','braa'):return set()
 return{i['operands'].split(',')[0].lstrip('xw')}
class WordCuts(SSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc in CUTS:
    j=CUTS.index(pc);value='U'+str(j)
    if j==3:value='(bvxor U3 #x5353535353535353)'
    self.put(split(i['operands'])[0],value);self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def verify(s):
 assert s['static_scope']==SCOPE and len(s['retained_profiles'])==12;codec_parts(s)
 for f in s['fragments'].values():
  b=bytes.fromhex(f['bytes']);a=int(f['start'],16);assert IMAGE.read(a,len(b))==b and h(b)==f['sha256']
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]
 assert not {'x1','w1','x4','w4','x16','w16'}&set(s['register_write_sets']['prepare_decoder'])
 for p in s['retained_profiles']:
  assert not p['native_evidence']and p['replacement_occurrences']==0 and len(p['lookup_episodes'])==5 and p['candidate_comparisons']==4
  assert[e['candidate_comparisons']for e in p['lookup_episodes']]==[0,1,2,0,1]
  for e in p['lookup_episodes']:
   cc=[q for q in e['events']if q['site']=='0x100615a68'];assert len(cc)==e['candidate_comparisons']and all(q['target']=='0x1005bb1b0'for q in cc)
   assert all(q['authentication']=='bypassed in private synthetic model'for q in e['events'])
  assert p['other_lookup_episode']['candidate_comparisons']==2
 for b in s['retirement_banks']:
  l,r=bytes.fromhex(b['left_bytes']),bytes.fromhex(b['right_bytes']);vv=[i^r[l[i]^b['key_u8']]for i in range(256)]
  assert vv==b['results_256']and len(set(vv))==1 and b['target']=='libSystem/_free'and b['slot']=='0x10109ff30'and b['modifier_u16']==0x46a2
 assert s['free_binding']['symbol']=='_free'and s['free_binding']['total_addend']==0
 return True
def codec_proofs(s):
 c=constants(s);pp=[];tr={'codec_constants':[c.record()]};ii,seeds,eors,ends=codec_parts(s)
 def ini():
  r={j:'Z'+str(j)for j in range(31)};r.update(c.r);r['sp']='K';return r
 R='((_ rotate_right 8) (bvand A #xfffffffffffffff8))';B=f'(bvadd {R} #x622c5d3364e5d59f)';X=f'(bvxor {B} #xa7bebfcf1750d389)';Y=f'(bvxor {B} #xb6dc5654307e7f72)'
 for b,(a,z)in enumerate(zip(seeds,ends)):
  ee=eors[6*b:6*b+6];yr=split(ii[ee[0]]['operands'])[0];mix=next(j for j in range(ee[0]-1,a,-1)if ii[j]['mnemonic']=='add'and split(ii[j]['operands'])[2]==yr);ops=split(ii[mix]['operands'])
  r=ini();r[int(split(ii[a]['operands'])[1][1:])]='A';g=SSA(r,LOADS,namespace='s_').run({'instructions':ii[a:mix]},int(ii[mix]['ea'],16))
  name='byte'+str(b)+'_seed';pp.append(solve(name,c.prefix()+g.prefix()+mismatch([neq(g.get(ops[1]),f'((_ rotate_right 8) {X})'),neq(g.get(yr),Y)]),'Exact byte-specific source seed under pinned tail constants; arbitrary u64 A and other registers/bytes.'));tr[name]=[g.record()];start=mix
  for j in range(7):
   stop=ee[j]+1 if j<6 else z+1;r=ini()
   if j==0:r[int(ops[1][1:])]='((_ rotate_right 8) U)';r[int(yr[1:])]='V'
   else:
    old=split(ii[ee[j-1]]['operands']);xr,yr0=old[1],old[0];r[int(xr[1:])]='U';r[int(yr0[1:])]='V'
    for k in range(start):
     q=ii[k];p=split(q['operands'])
     if q['mnemonic']=='ror'and p[1]==xr and p[2]=='#8'and p[0]!=yr0 and all(xr[1:]not in written(v)and p[0][1:]not in written(v)for v in ii[k+1:start]):r[int(p[0][1:])]='((_ rotate_right 8) U)'
   g=SSA(r,LOADS,namespace='r_').run({'instructions':ii[start:stop]},int(ii[stop-1]['ea'],16)+4);key=KEYS[j]^(0x5353535353535353 if b==3 and j==6 else 0);F=f'(bvxor (bvadd ((_ rotate_right 8) U) V) {bv(key)})'
   if j<6:
    op=split(ii[ee[j]]['operands']);terms=[neq(g.get(op[1]),F),neq(g.get(op[0]),f'(bvxor ((_ rotate_left 3) V) {F})')]
   else:terms=[neq(g.get(split(ii[z]['operands'])[0]),F)]
   name='byte'+str(b)+'_round'+str(j+1);pp.append(solve(name,c.prefix()+g.prefix()+mismatch(terms),'Arbitrary u64 round states, explicit carried rotates; fourth-byte final word differs by uniform XOR5353, accounted for at the cut.'));tr[name]=[g.record()];start=stop
 r=ini();r.update({1:'BUF',4:'(bvadd O #x661a590b302baf96)',16:bv(0xc8)})
 g=WordCuts(r,LOADS,namespace='m_').run(s['fragments']['decode'],0x10080078c);g.declarations=''
 bs=[]
 for j in range(4):
  a=f'(bvadd BUF O {bv(j)})';m=f'((_ extract 7 0) (bvlshr U{j} (bvshl (bvand {a} #x0000000000000007) #x0000000000000003)))';bs.append(f'(bvxor B{j} {m})')
 word=bs[0]
 for b in bs[1:]:word=f'(concat {word} {b})'
 terms=[neq(g.get('w4'),f'(bvxor {word} #x8b3dc651)')]
 reads=[r for r in g.reads if r['width_bits']==8];assert len(reads)==4
 terms.extend(neq(r['address'],f'(bvadd BUF O {bv(j)})')for j,r in enumerate(reads))
 pp.append(solve('decoder_merge_and_four_addresses',c.prefix()+g.prefix()+mismatch(terms),'Universal four-word cut, justified by the seed/round lemmas; four exact byte reads and BE32/XOR8b3 result. No whole-path/native proof.'));tr['decoder_merge_and_four_addresses']=[g.record()]
 return pp,tr
def proofs(s):
 pp,tr=codec_proofs(s)
 def add(n,g,terms,scope):
  gs=g if isinstance(g,list)else[g];pp.append(solve(n,prefix(*gs)+mismatch(terms),scope));tr[n]=[v.record()for v in gs]
 def mem(g,site):return next(r for r in g.reads if r['site']==site)['address']
 def inp(g,site):return next(r for r in g.reads if r['site']==site)['input']
 def slot(table,ix):return f'(bvadd {table} {bv(ix*8)})'
 entry=make(s,'entry',0x1006fd1b8,0x1006fd1ec,{8:'C',9:z32('KEY'),11:'OUT',10:z32('IX'),22:bv(0x6cf4),'sp':'K'},{'0x1006fd1bc':('TABLE',64),'0x1006fd1c0':('CONT',64)},'e_')
 exp=[(0x7060,'CONT',64),(0xaa5c,'KEY',32),(0xaa60,'OUT',64)];tt=[]
 for st,(off,value,width)in zip(entry.stores,exp):assert st['width_bits']==width;tt.extend([neq(st['address'],f'(bvadd K {bv(off)})'),neq(st['value'],value)])
 tt.extend([neq(entry.get('w9'),'(ite (= C #x0000000000000000) #x0000c157 #x0000c1ca)'),neq(entry.get('x10'),'CONT')]);add('lookup_entry_snapshot_partition',entry,tt,'Internal lookup ABI under phase6cf4. Null container selects continuation mediator without writing OUT; pointer validity/native phase remain separate.')
 nxt=make(s,'next',0x100697188,0x1006971d8,{8:'LINK',22:bv(0x6cf4),'sp':'K'},{'0x100697198':('NODE',64)},'n_')
 table=inp(nxt,'0x1006971c0');tt=[neq(nxt.stores[0]['address'],'(bvadd K #x000000000000aa68)'),neq(nxt.stores[0]['value'],'NODE'),neq(nxt.get('x8'),bv(0)),neq(nxt.get('w9'),'#x00008209'),neq(nxt.get('w11'),'#x74c29ded'),neq(mem(nxt,'0x1006971c4'),f'(ite (= NODE #x0000000000000000) {slot(table,0x582e)} {slot(table,0x57d4)})')]
 add('next_link_and_miss_state',nxt,tt,'LINK is initially container, then current node; each load follows +0. End-of-chain publishes NULL/not-found. Finite stable acyclic chain is a termination premise.')
 cand=make(s,'candidate',0x100914e3c,0x100914e80,{10:'NODE',22:bv(0x6cf4),'sp':'K'},{'0x100914e54':('BUF',64)},'c_')
 add('candidate_decoder_interface',cand,[neq(cand.get('x1'),'BUF'),neq(cand.get('w16'),'#x000000c8'),neq(cand.get('w8'),'#x00008c3f'),neq(cand.get('x4'),bv(0x661a590b302baf96)),neq(mem(cand,'0x100914e54'),'(bvadd NODE #x0000000000000018)'),neq(mem(cand,'0x100914e68'),slot(inp(cand,'0x100914e64'),0x2520))],'Prepared node buffer, encoded offset0 and original decoder continuations. Preparation body must complete with valid frame/context reads; it preserves X1/X4/X16.')
 cmp=make(s,'compare',0x100615a1c,0x100615a68,{4:z32('D'),'sp':'K'},{'0x100615a20':(bv(0x6cf4),64),'0x100615a30':('KEY',32),'0x100615a3c':('NODE',64)},'q_')
 t=inp(cmp,'0x100615a54');add('identifier_comparison_and_first_match',cmp,[neq(cmp.get('x8'),'NODE'),neq(cmp.get('w9'),'#x00008209'),neq(cmp.get('w11'),'#x8b3dc651'),neq(mem(cmp,'0x100615a58'),f'(ite (= D KEY) {slot(t,0xa924)} {slot(t,0xa93d)})')],'Comparison is exact u32 equality, independent of type/extent; equal stops, other follows next node. First match requires stable well-formed links.')
 pub=make(s,'publish',0x100914a10,0x100914a2c,{14:'(bvadd K #x0000000000009000)',8:'NODE',11:z32('STATUS'),9:bv(0x8209),'sp':'K'},{'0x100914a10':('OUT',64),'0x100914a18':('CONT',64)},'o_')
 add('lookup_result_publication',pub,[neq(pub.stores[0]['address'],'OUT'),neq(pub.stores[0]['value'],'NODE'),neq(pub.get('w6'),'STATUS'),neq(pub.get('x10'),'CONT')],'OUT receives candidate on match or zero at end; raw status is transferred to W6 and saved continuation survives mediator. Native return not inferred.')
 gate=make(s,'status_gate',0x100742a30,0x100742a70,{8:bv(0x7278),6:z32('STATUS'),'sp':'K'},ns='g_');t=inp(gate,'0x100742a64')
 add('caller_signed_status_partition',gate,[neq(gate.get('w9'),'#x00003c99'),neq(mem(gate,'0x100742a68'),f'(ite (bvslt STATUS #x74c29ded) {slot(t,0x72b4)} {slot(t,0x7278)})')],'All u32 raw statuses; classifier uses signed LT. Exact success and not-found gates follow separately.')
 miss=make(s,'miss_gate',0x1009a0b64,0x1009a0ba8,{9:bv(0x3c99),6:z32('STATUS'),'sp':'K'},ns='m0_');t=inp(miss,'0x1009a0b9c')
 add('miss_selects_append',miss,[neq(miss.get('w8'),'#x00009c85'),neq(miss.get('w22'),'#x00006cf4'),neq(mem(miss,'0x1009a0ba0'),f'(ite (= STATUS #x74c29ded) {slot(t,0xbea6)} {slot(t,0x3c99)})')],'Exact not-found marker selects established append interface. Other raw statuses are not assigned public meanings.')
 found=make(s,'found_gate',0x10069a114,0x10069a168,{8:bv(0x7278),6:z32('STATUS'),'sp':'K'},ns='f0_');t=inp(found,'0x10069a15c')
 add('success_selects_replacement',found,[neq(found.get('w11'),'#x00004308'),neq(found.get('w22'),'#x00006cf4'),neq(mem(found,'0x10069a160'),f'(ite (= STATUS #x8b3dc651) {slot(t,0x3cc1)} {slot(t,0x3c99)})')],'Exact lookup success selects replacement; null/error markers do not select it. Failure cleanup remains outside this increment.')
 rep=make(s,'replace',0x100873ecc,0x100873f40,{11:bv(0x4308),'sp':'K'},{'0x100873f00':('OLD',64),'0x100873f04':('PREV',64),'0x100873f08':('NEW',64),'0x100873f10':('NEXT',64)},'r0_');t=inp(rep,'0x100873f34')
 add('replacement_inherits_neighbors',rep,[neq(rep.stores[0]['address'],'(bvadd NEW #x0000000000000008)'),neq(rep.stores[0]['value'],'PREV'),neq(rep.stores[1]['address'],'NEW'),neq(rep.stores[1]['value'],'NEXT'),neq(rep.get('w9'),'#x00009ada'),neq(rep.get('w12'),'#x0000434f'),neq(mem(rep,'0x100873f38'),f'(ite (= PREV #x0000000000000000) {slot(t,0x434f)} {slot(t,0x4308)})')],'Source-only matched path; old/new nodes disjoint and neighbors stable are premises for replacement interpretation.')
 prev=make(s,'prev_patch',0x1008d776c,0x1008d7788,{12:bv(0x434f),13:'PREV',8:'NEW','sp':'K'},{'0x1008d7778':('NEXT',64)},'p0_')
 ng=make(s,'next_gate',0x100850478,0x1008504b4,{9:bv(0x9ada),10:'NEXT',8:'NEW','sp':'K'},ns='p1_');t=inp(ng,'0x1008504a8')
 np=make(s,'next_patch',0x1005d2758,0x1005d2778,{9:bv(0x9ada),10:'NEXT',8:'NEW','sp':'K'},ns='p2_')
 add('neighbor_patches_and_next_gate',[prev,ng,np],[neq(prev.stores[0]['address'],'PREV'),neq(prev.stores[0]['value'],'NEW'),neq(prev.get('w9'),'#x00009ada'),neq(ng.get('w11'),'#x00006b95'),neq(mem(ng,'0x1008504ac'),f'(ite (= NEXT #x0000000000000000) {slot(t,0x9add)} {slot(t,0x9ada)})'),neq(np.stores[0]['address'],'(bvadd NEXT #x0000000000000008)'),neq(np.stores[0]['value'],'NEW'),neq(np.get('w11'),'#x00006b95')],'Nonzero neighbors are patched conditionally; nil branches skip their stores. No concurrent/atomic list guarantee.')
 hg=make(s,'head_gate',0x10072d140,0x10072d170,{11:bv(0x6b95),8:'NEW','sp':'K'},{'0x10072d148':('PREV',64)},'h0_');t=inp(hg,'0x10072d164')
 hp=make(s,'head_patch',0x1006e4168,0x1006e418c,{11:bv(0x6b95),8:'NEW','sp':'K'},{'0x1006e4178':('C',64)},'h1_')
 add('head_update_partition',[hg,hp],[neq(hg.get('w9'),'#x00009fbf'),neq(mem(hg,'0x10072d168'),f'(ite (= PREV #x0000000000000000) {slot(t,0x6b9b)} {slot(t,0x6b95)})'),neq(hp.stores[0]['address'],'C'),neq(hp.stores[0]['value'],'NEW'),neq(hp.get('w9'),'#x00009fbf')],'Well-formed list premise identifies no previous neighbor with old head; exact conditional head store is source-only.')
 tg=make(s,'tail_gate',0x100843e64,0x100843e9c,{9:bv(0x9fbf),8:'NEW','sp':'K'},{'0x100843e74':('NEXT',64)},'t0_');t=inp(tg,'0x100843e90')
 tp=make(s,'tail_patch',0x10075118c,0x1007511b0,{9:bv(0x9fbf),8:'NEW','sp':'K'},{'0x10075119c':('C',64)},'t1_')
 add('tail_update_partition',[tg,tp],[neq(tg.get('w10'),'#x0000c3be'),neq(mem(tg,'0x100843e94'),f'(ite (= NEXT #x0000000000000000) {slot(t,0xc43c)} {slot(t,0x9fbf)})'),neq(tp.stores[0]['address'],'(bvadd C #x0000000000000008)'),neq(tp.stores[0]['value'],'NEW'),neq(tp.get('w10'),'#x0000c3be')],'Well-formed list premise identifies no next neighbor with old tail; all four nil/non-nil neighbor combinations remain explicit.')
 retire=make(s,'retire',0x100831528,0x100831578,{10:bv(0xc3be),'sp':'K'},{'0x100831548':('OLD',64),'0x10083154c':('OLD_BUF',64)},'d0_');t=inp(retire,'0x10083156c')
 add('retirement_inputs',retire,[neq(retire.get('x0'),'OLD'),neq(retire.get('x8'),'OLD_BUF'),neq(retire.get('w19'),'#x0000b8dc'),neq(retire.get('w20'),'#x000079f1'),neq(mem(retire,'0x100831570'),f'(ite (= OLD_BUF #x0000000000000000) {slot(t,0xc3d2)} {slot(t,0xc3be)})')],'Matched-node output cell supplies old owner; branch skips buffer release for NULL. Valid decoded old header requires a readable buffer.')
 fb=make(s,'free_buffer',0x1006c1034,0x1006c10ac,{8:'OLD_BUF',19:bv(0xb8dc),'sp':'K'},ns='d1_')
 fc=make(s,'free_buffer',0x1006c10b0,0x1006c10bc,{'sp':'K'},{'0x1006c10b4':('OLD',64)},'d2_')
 fn=make(s,'free_node',0x100747e28,0x100747e84,{0:'OLD','sp':'K'},ns='d3_')
 end=make(s,'free_node',0x100747e88,0x100747ea0,{20:bv(0x79f1),19:'TABLE','sp':'K'},ns='d4_')
 add('retirement_call_arguments_and_success',[fb,fc,fn,end],[neq(fb.get('x0'),'OLD_BUF'),neq(fb.get('w20'),'#x000079f1'),neq(fc.get('x0'),'OLD'),neq(fc.stores[0]['address'],'(bvadd OLD #x0000000000000018)'),neq(fc.stores[0]['value'],bv(0)),neq(fn.get('x0'),'OLD'),neq(end.stores[0]['address'],'(bvadd K #x00000000000080b8)'),neq(end.stores[0]['value'],bv(0)),neq(end.get('w6'),'#x8b3dc651'),neq(mem(end,'0x100747e90'),slot('TABLE',0x79f1))],'Buffer and node call arguments/order, old buffer-field clear and saved old-cell clear; original _free mapping is conditional on pinned roots and normal call ABI. Native effects not inferred.')
 # Independent word-cell composition of the proved link stores. This is an
 # abstract list model, not an additional machine-memory or lifetime proof.
 model='(declare-fun M () (Array (_ BitVec 64) (_ BitVec 64)))\n(declare-fun probe () (_ BitVec 64))\n'
 owners=[('C',16),('OLD',32),('NEW',32),('PREV',32),('NEXT',32)]
 for p,n in owners:
  present=f'(distinct {p} {bv(0)})'
  if p in('C','OLD','NEW'):model+=f'(assert {present})\n'
  model+=f'(assert (=> {present} (and (= (bvand {p} {bv(7)}) {bv(0)}) (bvule {p} {bv((1<<64)-n-1)}))))\n'
 for j,(a,an)in enumerate(owners):
  for b,bn in owners[j+1:]:model+=f'(assert (=> (and (distinct {a} {bv(0)}) (distinct {b} {bv(0)})) (or (bvule (bvadd {a} {bv(an)}) {b}) (bvule (bvadd {b} {bv(bn)}) {a}))))\n'
 model+='(assert (= (select M OLD) NEXT))\n(assert (= (select M (bvadd OLD #x0000000000000008)) PREV))\n'
 model+='(assert (ite (= PREV #x0000000000000000) (= (select M C) OLD) (= (select M PREV) OLD)))\n'
 model+='(assert (ite (= NEXT #x0000000000000000) (= (select M (bvadd C #x0000000000000008)) OLD) (= (select M (bvadd NEXT #x0000000000000008)) OLD)))\n'
 stages=[('NEW','#x0000000000000000','NEXT',None),('NEW','#x0000000000000008','PREV',None),('PREV','#x0000000000000000','NEW','(distinct PREV #x0000000000000000)'),('NEXT','#x0000000000000008','NEW','(distinct NEXT #x0000000000000000)'),('C','#x0000000000000000','NEW','(= PREV #x0000000000000000)'),('C','#x0000000000000008','NEW','(= NEXT #x0000000000000000)')]
 last='M';changed=[]
 for j,(base,off,val,condition)in enumerate(stages):
  addr=f'(bvadd {base} {off})';store=f'(store {last} {addr} {val})';name='link'+str(j)
  model+=f'(define-fun {name} () (Array (_ BitVec 64) (_ BitVec 64)) '+(store if condition is None else f'(ite {condition} {store} {last})')+')\n';last=name;changed.append((addr,condition))
 claims=[neq(f'(select {last} NEW)','NEXT'),neq(f'(select {last} (bvadd NEW #x0000000000000008))','PREV'),neq(f'(select {last} (bvadd NEW #x0000000000000010))','(select M (bvadd NEW #x0000000000000010))'),neq(f'(select {last} (bvadd NEW #x0000000000000018))','(select M (bvadd NEW #x0000000000000018))')]
 claims.append(f'(ite (= PREV {bv(0)}) {neq(f"(select {last} C)","NEW")} (or {neq(f"(select {last} PREV)","NEW")} {neq(f"(select {last} C)","(select M C)")}))')
 claims.append(f'(ite (= NEXT {bv(0)}) {neq(f"(select {last} (bvadd C {bv(8)}))","NEW")} (or {neq(f"(select {last} (bvadd NEXT {bv(8)}))","NEW")} {neq(f"(select {last} (bvadd C {bv(8)}))",f"(select M (bvadd C {bv(8)}))")}))')
 untouched='(and '+' '.join(f'(not (and {cond or "true"} (= probe {addr})))'for addr,cond in changed)+')'
 claims.append(f'(and {untouched} {neq(f"(select {last} probe)","(select M probe)")})')
 pp.append(solve('abstract_four_boundary_splice',model+mismatch(claims),'Word-cell model of the proved local link stores with aligned, nonwrapping, disjoint owners and coherent old neighbor/endpoints. Covers all four previous/next NIL partitions; excludes allocator effects and native concurrency.'))
 return pp,tr
def alterations(s):
 ops=[('source_byte',lambda t:t['fragments']['decode'].__setitem__('bytes','00'+t['fragments']['decode']['bytes'][2:])),('replacement_as_observed',lambda t:t['retained_profiles'][0].__setitem__('replacement_occurrences',1)),('lookup_count',lambda t:t['retained_profiles'][0]['lookup_episodes'].pop()),('comparison_count',lambda t:t['retained_profiles'][0].__setitem__('candidate_comparisons',5)),('hit_in_miss',lambda t:next(q for e in t['retained_profiles'][0]['lookup_episodes']for q in e['events']if q['site']=='0x100615a68').__setitem__('target','0x100914a10')),('aux_count',lambda t:t['retained_profiles'][0]['other_lookup_episode'].__setitem__('candidate_comparisons',0)),('bank_result',lambda t:t['retirement_banks'][0]['results_256'].__setitem__(0,0)),('input_clobber',lambda t:t['register_write_sets']['prepare_decoder'].append('x1'))]
 out=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t)
  try:verify(t)
  except AssertionError:out.append({'name':n,'rejected':True})
  else:raise AssertionError(n)
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build()and verify(s);pp,tr=proofs(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'component_queries_unsat':len(pp),'decoder_seed_lemmas':4,'decoder_round_lemmas':28,'translated_instruction_instances':sum(len(g['source_sites'])for gs in tr.values()for g in gs),'SSA_definitions':sum(g['SSA_definitions']for gs in tr.values()for g in gs),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_constructor_inputs.py':sha(ROOT/'validate_daemon_constructor_inputs.py')},'source_recapture_match':True,'proofs':pp,'translations':tr,'decoder_word_cuts':[{'site':hex(pc),'fourth_word_xor_delta':hex(0x5353535353535353 if j==3 else 0)}for j,pc in enumerate(CUTS)],'alterations':aa,'verified_counts':counts,'static_scope':SCOPE,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
