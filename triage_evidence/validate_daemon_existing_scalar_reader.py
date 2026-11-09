#!/usr/bin/env python3
"""Source-linked scalar/tag/extent/output components; no target execution."""
import copy,json,subprocess
from recover_daemon_existing_scalar_reader import ROOT,P,SCOPE,FLAGS,sha,build
from validate_daemon_constructor_inputs import SSA as ParentSSA,bv,split
from validate_daemon_constructor_lookup import constants,KEYS,CUTS as WORD_CUTS,written
class SSA(ParentSSA):
 def compare(self,a,b,w,cmn=False):
  super().compare(a,b,w,cmn)
  if not cmn:self.flags.update(gt=f'(bvsgt {a} {b})',le=f'(bvsle {a} {b})')
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   p=split(i['operands']);m=i['mnemonic']
   if pc in getattr(self,'cuts',{}):self.put(p[0],self.cuts[pc]);self.sites.append(i['ea'])
   elif m=='ldrh':
    value,bits=self.loads[i['ea']];assert bits==16;self.reads.append({'site':i['ea'],'address':self.address(p[1]),'width_bits':16,'input':value});self.put(p[0],f'((_ zero_extend 16) {value})');self.sites.append(i['ea'])
   elif m=='ldur':super().run({'instructions':[{**i,'mnemonic':'ldr'}]},pc+4)
   elif m=='bfi':
    w=32 if p[0].startswith('w')else 64;lsb,n=int(p[2][1:],0),int(p[3][1:],0);assert lsb+n<=w;mask=((1<<n)-1)<<lsb;self.put(p[0],f'(bvor (bvand {self.get(p[0],w)} {bv(~mask,w)}) (bvshl (bvand {self.get(p[1],w)} {bv((1<<n)-1,w)}) {bv(lsb,w)}))');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
DECL=''.join('(declare-fun '+n+' () (_ BitVec 64))\n'for n in ['K','BUF','TABLE','FN','CONT','OUT','CELL','A','O','U','V']+['U'+str(j)for j in range(4)]+['Z'+str(j)for j in range(31)])+''.join('(declare-fun '+n+' () (_ BitVec 32))\n'for n in ['SIZE','PL','TAG','VALUE','IX'])+''.join('(declare-fun B'+str(j)+' () (_ BitVec 8))\n'for j in range(4))
CURSOR=0x797188010b5fa78c;WORD_BASE=0x661a590b302baf96
def z(e,bits=32):return f'((_ zero_extend {64-bits}) {e})'
def low(e,bits=32):return f'((_ extract {bits-1} 0) {e})'
def neq(a,b):return f'(distinct {a} {b})'
def at(ix):return f'(bvadd TABLE {bv(ix*8)})'
def frame(off):return f'(bvadd K {bv(off)})'
def prefix(*gs):return ''.join(getattr(g,'declarations','')+g.prefix()for g in gs)
def make(s,n,r=None,loads=None,a=None,end=None,ns=None,cuts=None):
 f=s['fragments'][n];a=int(f['start'],16)if a is None else a;end=int(f['instructions'][-1]['ea'],16)if end is None else end;ii=[i for i in f['instructions']if a<=int(i['ea'],16)<end];ns=ns or n+'_';ll=dict(loads or{});dd=[]
 for i in ii:
  if i['mnemonic']in('ldr','ldrb','ldrh','ldur')and i['ea']not in ll:
   bits=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']=='ldrh'else 32 if i['operands'].startswith('w')else 64;v=ns+'L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {bits}))');ll[i['ea']]=(v,bits)
 rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=SSA(rr,ll,namespace=ns);g.cuts=cuts or{};g.run({'instructions':ii},end);g.declarations='\n'.join(dd)+'\n';return g
def read(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
def addr(g,pc):return read(g,pc)['address']
def solve(name,body,scope):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20);assert r.returncode==0 and not r.stderr and r.stdout.strip()=='unsat',(name,r.stdout,r.stderr)
 return {'name':name,'query':q,'result':'unsat','scope':scope}
def proofs(s):
 pp=[];tr={};prior=json.loads((ROOT/'daemon_constructor_lookup_source.json').read_text());c=constants(prior);tr['codec_constants']=[c.record()]
 def add(n,g,tt,scope,deps=(),extra=''):
  gg=g if isinstance(g,list)else[g];pp.append(solve(n,prefix(*deps,*gg)+extra+'(assert (or '+' '.join(tt)+'))',scope));tr[n]=[q.record()for q in gg]
 prep=make(s,'prepare',r={8:bv(0x8c3f),1:'BUF',4:bv(WORD_BASE),16:bv(0x74)},loads={'0x1006f6bfc':(bv(CURSOR),64),'0x1006f6c38':(z('SIZE'),64),'0x1006f7088':('TABLE',64),'0x1006f708c':('FN',64)})
 def st(g,pc):return next(q for q in g.stores if q['site']==hex(pc))
 tt=[]
 for pc,off,value in [(0x1006f6c1c,0x978,bv(CURSOR+10)),(0x1006f6c34,0x970,bv(0xd68943be)),(0x1006f6c44,0x958,z('SIZE')),(0x1006f6c4c,0x950,f'(bvadd {z("SIZE")} #x00000000d68943b4)'),(0x1006f6c94,0x818,bv(WORD_BASE+10)),(0x1006f6f1c,0x8f8,bv(WORD_BASE+6))]:
  q=st(prep,pc);tt.extend([neq(q['address'],frame(off)),neq(q['value'],value)])
 tt.extend([neq(addr(prep,0x1006f6bfc),frame(0xa640)),neq(addr(prep,0x1006f6c38),frame(0xa638)),neq(addr(prep,0x1006f708c),at(0x8c3f)),neq(prep.get('x1'),'BUF'),neq(prep.get('x4'),bv(WORD_BASE)),neq(prep.get('w16'),'#x00000074'),neq(prep.get('x6'),bv(KEYS[0]))])
 add('reader_prepare_cursor_size_offsets',prep,tt,'Entry cursor0 and u32 SIZE. Full preparation is translated with unrelated loads named; valid frame/context reads and no aliasing remain premises.')
 # Universal word decoder merge uses four mask cuts already proved by the pinned prior 32 seed/round lemmas.
 ini={j:'Z'+str(j)for j in range(31)};ini.update(c.r);ini.update({'sp':'K',1:'BUF',4:f'(bvadd O {bv(WORD_BASE)})',16:z('IX')})
 loads={'0x100800004':('TABLE',64),'0x100800008':('FN',64),**{hex(pc):('B'+str(j),8)for j,pc in enumerate([0x100800204,0x100800258,0x100800594,0x100800760])}}
 cuts={pc:'U'+str(j)if j<3 else'(bvxor U3 #x5353535353535353)'for j,pc in enumerate(WORD_CUTS)}
 w=make(s,'word',r=ini,loads=loads,cuts=cuts);bs=[]
 for j in range(4):
  a=f'(bvadd BUF O {bv(j)})';m=f'((_ extract 7 0) (bvlshr U{j} (bvshl (bvand {a} #x0000000000000007) #x0000000000000003)))';bs.append(f'(bvxor B{j} {m})')
 wire='(concat '+' '.join(bs)+')';tt=[neq(w.get('w1'),f'(bvxor {wire} #x8ec35f08)'),neq(w.get('w4'),f'(bvxor {wire} #x8b3dc651)'),neq(w.get('x28'),bv(KEYS[0]))]
 for j,pc in enumerate([0x100800204,0x100800258,0x100800594,0x100800760]):tt.append(neq(addr(w,pc),f'(bvadd BUF O {bv(j)})'))
 add('word_reader_dual_output_and_addresses',w,tt,'Prior canonical mask cuts; arbitrary O,bytes and mask words. W1 and W4 use different XOR representations. Full native read validity is not inferred.',deps=(c,))
 # Two original tag mask blocks, each with a seed and seven round components.
 ii=s['fragments']['tag']['instructions'];seeds=[j for j,i in enumerate(ii)if i['mnemonic']=='and'and'#0xfffffffffffffff8'in i['operands']];eors=[j for j,i in enumerate(ii)if i['mnemonic']=='eor'and'ror #61'in i['operands']];ends=[next(j for j,i in enumerate(ii)if i['ea']==hex(pc))for pc in [0x100512444,0x1005125c4]];assert len(seeds)==2 and len(eors)==12
 def ci():
  r={j:'Z'+str(j)for j in range(31)};r.update(c.r);r['sp']='K';r[28]=c.get('x6');return r
 R='((_ rotate_right 8) (bvand A #xfffffffffffffff8))';B=f'(bvadd {R} #x622c5d3364e5d59f)';X=f'(bvxor {B} #xa7bebfcf1750d389)';Y=f'(bvxor {B} #xb6dc5654307e7f72)'
 for b,(a,last)in enumerate(zip(seeds,ends)):
  ee=eors[6*b:6*b+6];yr=split(ii[ee[0]]['operands'])[0];mix=next(j for j in range(ee[0]-1,a,-1)if ii[j]['mnemonic']=='add'and split(ii[j]['operands'])[2]==yr);ops=split(ii[mix]['operands']);r=ci();r[int(split(ii[a]['operands'])[1][1:])]='A';g=make(s,'tag',r=r,a=int(ii[a]['ea'],16),end=int(ii[mix]['ea'],16),ns='ts_')
  add('tag_byte'+str(b)+'_seed',g,[neq(g.get(ops[1]),f'((_ rotate_right 8) {X})'),neq(g.get(yr),Y)],'Original seed equals canonical address-mask seed for every u64 A.',deps=(c,));start=mix
  for j in range(7):
   stop=ee[j]+1 if j<6 else last+1;r=ci()
   if j==0:r[int(ops[1][1:])]='((_ rotate_right 8) U)';r[int(yr[1:])]='V'
   else:
    old=split(ii[ee[j-1]]['operands']);xr,yr0=old[1],old[0];r[int(xr[1:])]='U';r[int(yr0[1:])]='V'
    for k in range(start):
     q=ii[k];p=split(q['operands'])
     if q['mnemonic']=='ror'and p[1]==xr and p[2]=='#8'and p[0]!=yr0 and all(xr[1:]not in written(v)and p[0][1:]not in written(v)for v in ii[k+1:start]):r[int(p[0][1:])]='((_ rotate_right 8) U)'
   g=make(s,'tag',r=r,a=int(ii[start]['ea'],16),end=int(ii[stop-1]['ea'],16)+4,ns='tr_');F=f'(bvxor (bvadd ((_ rotate_right 8) U) V) {bv(KEYS[j])})'
   if j<6:op=split(ii[ee[j]]['operands']);tt=[neq(g.get(op[1]),F),neq(g.get(op[0]),f'(bvxor ((_ rotate_left 3) V) {F})')]
   else:tt=[neq(g.get(split(ii[last]['operands'])[0]),F)]
   add('tag_byte'+str(b)+'_round'+str(j+1),g,tt,'Arbitrary u64 round states and explicit carried rotates; source-key match to canonical mask.',deps=(c,));start=stop
 r=ci();r.update({1:bv(0x003f0e4fb896dad0),4:'CELL',22:'OUT',16:bv(0x212)})
 tg=make(s,'tag',r=r,loads={'0x1005122cc':(f'(bvadd O {bv(CURSOR)})',64),'0x1005122d0':('BUF',64),'0x1005122d4':('TABLE',64),'0x1005122d8':('FN',64),'0x100512300':('B0',8),'0x10051246c':('B1',8)},cuts={0x100512444:'U0',0x1005125c4:'U1'},ns='tm_');bs=[]
 for j in range(2):
  a=f'(bvadd BUF O {bv(j+4)})';m=f'((_ extract 7 0) (bvlshr U{j} (bvshl (bvand {a} #x0000000000000007) #x0000000000000003)))';bs.append(f'(bvxor B{j} {m})')
 add('tag_reader_merge_and_addresses',tg,[neq(low(tg.get('w24'),16),f'(bvxor (concat {bs[0]} {bs[1]}) #x4799)'),neq(addr(tg,0x100512300),'(bvadd BUF O #x0000000000000004)'),neq(addr(tg,0x10051246c),'(bvadd BUF O #x0000000000000005)'),neq(addr(tg,0x1005122d8),at(0x212)),neq(tg.get('x28'),bv(KEYS[0]))],'Full tag merge under newly proved two mask cuts. Only low16 of W24 is the tag representation; upper16 are not assigned semantic meaning.',deps=(c,))
 # Structural continuations. Each named-load join refers to a proved producer or explicit frame premise.
 hd=make(s,'header_return',loads={'0x10051e2c4':(bv(0x6cf4),64),'0x10051e2d4':('TABLE',64)})
 add('header_return_tag_interface',hd,[neq(hd.get('w16'),'#x00000212'),neq(hd.get('x1'),bv(0x003f0e4fb896dad0)),neq(hd.get('x4'),frame(0x3710)),neq(hd.get('x22'),frame(0xa640)),neq(addr(hd,0x10051e2d8),at(0x1f39))],'Exact entry through header decoder return74; first identifier value is not re-compared here.')
 rt=make(s,'tag_return',r={24:z('TAG'),28:bv(KEYS[0])},loads={'0x1004e2ef8':(bv(0x6cf4),64),'0x1004e2f04':('TABLE',64),'0x1004e2f18':(bv(WORD_BASE+6),64)})
 add('tag_snapshot_length_word_interface',rt,[neq(st(rt,0x1004e2ef0)['address'],frame(0x959e)),neq(st(rt,0x1004e2ef0)['value'],low('TAG',16)),neq(st(rt,0x1004e2f14)['value'],'TAG'),neq(st(rt,0x1004e2f14)['address'],frame(0x980)),neq(rt.get('w16'),'#x000000ef'),neq(rt.get('x4'),bv(WORD_BASE+6)),neq(rt.get('x6'),bv(KEYS[0])),neq(addr(rt,0x1004e2f08),at(0x3a31))],'Saved tag is low16 at959e and raw W24 at980; length read uses offset6 and constant first round key.')
 call=make(s,'word_call',r={22:bv(0x6cf4),16:z('IX'),1:frame(0x3710),4:f'(bvadd O {bv(WORD_BASE)})'},loads={'0x100530d3c':('BUF',64),'0x100530d40':('TABLE',64)})
 add('shared_word_call_preserves_offset_selector',call,[neq(addr(call,0x100530d3c),frame(0x3710)),neq(addr(call,0x100530d44),at(0x8c3f)),neq(call.get('x1'),'BUF'),neq(call.get('w16'),'IX'),neq(call.get('x4'),f'(bvadd O {bv(WORD_BASE)})')],'Common continuation for length/payload words; read aliases and lifetime remain premises.')
 guard=make(s,'length_guard',r={1:z('(bvxor PL #x8ec35f08)')},loads={'0x10052b3f0':(z('SIZE'),64),'0x10052b40c':(bv(CURSOR+10),64),'0x10052b424':(bv(0xd68943be),64),'0x10052b438':(f'(bvadd {z("SIZE")} #x00000000d68943b4)',64),'0x10052b458':(bv(0x6cf4),64),'0x10052b464':('TABLE',64)})
 add('length_fit_gate_and_next_cursor',guard,[neq(st(guard,0x10052b418)['address'],frame(0x95a0)),neq(st(guard,0x10052b418)['value'],f'(bvadd {bv(CURSOR+10)} {z("PL")})'),neq(addr(guard,0x10052b468),f'(ite (bvule (bvadd {z("PL")} #x000000000000000a) {z("SIZE")}) {at(0xb4dd)} {at(0xb4bf)})'),neq(guard.get('w10'),'#x00006cf4'),neq(guard.get('x16'),f'(bvadd {bv(CURSOR+10)} {z("PL")})')],'All u32 SIZE and declared PL under entry cursor0; exact PL+10<=SIZE in u64 arithmetic, not a wrapping u32 addition.')
 splitg=make(s,'split',r={28:bv(KEYS[0])},loads={'0x10052af18':(bv(0x6cf4),64),'0x10052af34':('TAG',32),'0x10052af58':('TABLE',64)})
 signed='((_ sign_extend 16) ((_ extract 15 0) TAG))'
 add('type_signed_lower_partition',splitg,[neq(addr(splitg,0x10052af5c),f'(ite (bvslt {signed} #xffffd0ee) {at(0x9a43)} {at(0x9a1c)})'),neq(splitg.get('w4'),'#x0000642b'),neq(splitg.get('w22'),'#x000008df'),neq(splitg.get('w10'),'#x0000698a'),neq(splitg.get('x6'),bv(KEYS[0]))],'Every raw W24 tag, including upper16 garbage; partition depends only on signed low16.')
 high=make(s,'split_high',r={j:splitg.get('x'+str(j))for j in [4,10,22,24,28]},loads={'0x10058eaf8':('TABLE',64)})
 add('type_signed_upper_partition',high,[neq(addr(high,0x10058eafc),f'(ite (bvslt {signed} #x00001742) {at(0x6999)} {at(0x698a)})'),neq(high.get('w4'),'#x0000642b'),neq(high.get('w22'),'#x00000017')],'Input registers compose from lower split; applies on its nonlower branch.',deps=(splitg,))
 u64=make(s,'u64_check',r={4:splitg.get('x4'),22:splitg.get('x22'),28:splitg.get('x28')},loads={'0x1004d6aa0':('TABLE',64)})
 add('u64_exact_tag_marker_route',u64,[neq(addr(u64,0x1004d6aa4),f'(ite (= ((_ extract 15 0) TAG) #xc31c) {at(0x642b)} {at(0x643c)})'),neq(u64.get('w8'),'#x00006cf4'),neq(u64.get('w10'),'#x00006cf4')],'Reader tagc31c is wire8485 XOR4799; recognized alternate type, not u32 success.',deps=(splitg,))
 span=make(s,'span_check',r={j:high.get('x'+str(j))for j in [4,10,22,24,28]},loads={'0x100513810':('TABLE',64)})
 add('span_exact_tag_marker_route',span,[neq(addr(span,0x100513814),f'(ite (= ((_ extract 15 0) TAG) #x1742) {at(0x642b)} {at(0x643c)})'),neq(span.get('w8'),'#x00006cf4'),neq(span.get('w10'),'#x00006cf4')],'Reader tag1742 is wire50db XOR4799; recognized alternate type.',deps=(splitg,high))
 u32=make(s,'u32_check',r={j:high.get('x'+str(j))for j in [4,10,22,24,28]},loads={'0x1004d203c':('TABLE',64)})
 add('u32_exact_tag_payload_route',u32,[neq(addr(u32,0x1004d2040),f'(ite (= ((_ extract 15 0) TAG) #xd0ee) {at(0x9fe7)} {at(0x643c)})'),neq(u32.get('w16'),'#x0000b4bf'),neq(u32.get('w10'),'#x00006cf4')],'Actual upper-split register outputs compose; a core-phase substitution here selects unrelated code and is rejected by this certificate.',deps=(splitg,high))
 extent=make(s,'u32_extent',r={16:u32.get('x16'),1:z('(bvxor PL #x8ec35f08)')},loads={'0x10057a760':('TABLE',64)})
 add('u32_exact_four_byte_extent',extent,[neq(addr(extent,0x10057a764),f'(ite (= PL #x00000004) {at(0xb81e)} {at(0xb4bf)})'),neq(extent.get('w16'),'#x0000b4bf')],'Recognized u32 requires exact declared PL4 after the earlier fit gate.',deps=(splitg,high,u32))
 pc=make(s,'payload_call',r={16:bv(0xb4bf)},loads={'0x1005be694':('TABLE',64),'0x1005be6ac':(bv(WORD_BASE+10),64)})
 add('payload_offset_ten_and_saved_tag',pc,[neq(pc.get('w22'),'#x00006cf4'),neq(pc.get('w16'),'#x000000b3'),neq(pc.get('x4'),bv(WORD_BASE+10)),neq(st(pc,0x1005be6a8)['address'],frame(0x980)),neq(st(pc,0x1005be6a8)['value'],'#x0000d0ee'),neq(addr(pc,0x1005be698),at(0x3a31))],'Selected payload read uses offset10 and returnb3; saved959e tag survives separately.')
 pr=make(s,'payload_return',r={4:z('(bvxor VALUE #x8b3dc651)')},loads={'0x10053010c':(bv(0x6cf4),64),'0x100530120':(f'(bvadd {bv(CURSOR+10)} {z("PL")})',64),'0x100530124':('((_ extract 15 0) TAG)',16),'0x100530150':('TABLE',64)})
 add('payload_stage_and_tag_recheck',pr,[neq(st(pr,0x100530118)['address'],frame(0x84cc)),neq(st(pr,0x100530118)['value'],'(bvxor VALUE #x8b3dc651)'),neq(st(pr,0x10053012c)['address'],frame(0x8048)),neq(st(pr,0x10053012c)['value'],f'(bvadd {bv(CURSOR+10)} {z("PL")})'),neq(addr(pr,0x100530154),f'(ite (= ((_ extract 15 0) TAG) #xd0ee) {at(0x68cb)} {at(0x3cc0)})'),neq(pr.get('w6'),'#x74c29cd6'),neq(pr.get('w8'),'#x00003cc0')],'VALUE is decoded BE32 wire payload before internal decoder XOR; saved tag is rechecked before output publication.')
 pub=make(s,'publish',r={8:pr.get('x8')},loads={'0x100506a18':('(bvxor VALUE #x8b3dc651)',32),'0x100506a1c':('OUT',64),'0x100506a34':('TABLE',64)})
 add('borrowed_output_is_wire_scalar',pub,[neq(addr(pub,0x100506a18),frame(0x84cc)),neq(addr(pub,0x100506a1c),frame(0x4ca0)),neq(st(pub,0x100506a30)['address'],'OUT'),neq(st(pub,0x100506a30)['value'],'VALUE'),neq(pub.get('w6'),'#x8b3dc651'),neq(addr(pub,0x100506a38),at(0x3cc0))],'Source double-XOR cancellation publishes BE32 wire payload as a u32, not the constructor internal scalar operand.',deps=(pr,))
 bad=make(s,'invalid',r={10:bv(0x6cf4)},loads={'0x1008eb308':('TABLE',64)})
 add('invalid_marker_saved_return',bad,[neq(bad.get('w6'),'#x74c29d8f'),neq(addr(bad,0x1008eb30c),at(0x2a7b))],'Extent/unknown-tag/wrong-u32-extent routes share this raw marker and do not themselves write OUT.')
 mm=make(s,'type_mismatch',r={8:bv(0x6cf4),16:'O'},loads={'0x100555188':('TABLE',64)})
 add('recognized_other_type_marker',mm,[neq(mm.get('w6'),'#x74c29cd6'),neq(st(mm,0x100555184)['address'],frame(0x8048)),neq(st(mm,0x100555184)['value'],'O'),neq(addr(mm,0x10055518c),at(0x3cc0))],'Known u64/span tags preserve the prepared encoded end cursor and return a distinct raw marker; no u32 output store occurs.')
 ret=make(s,'return',r={6:'O'},loads={'0x1006f76a8':('CONT',64)})
 add('final_saved_continuation_and_full_status',ret,[neq(addr(ret,0x1006f76a8),frame(0x7af0)),neq(ret.get('x8'),'CONT'),neq(ret.get('x6'),'O')],'Shared raw-status relay is reused after every selected reader outcome.')
 tag='((_ extract 15 0) TAG)';sx=f'((_ sign_extend 16) {tag})';eq=lambda n:f'(= {tag} #x{n:04x})';fit=f'(bvule (bvadd {z("PL")} #x000000000000000a) {z("SIZE")})';bad='#x74c29d8f';other='#x74c29cd6';ok='#x8b3dc651'
 forest=f'(ite {fit} (ite (bvslt {sx} #xffffd0ee) (ite {eq(0xc31c)} {other} {bad}) (ite (bvslt {sx} #x00001742) (ite {eq(0xd0ee)} (ite (= PL #x00000004) {ok} {bad}) {bad}) (ite {eq(0x1742)} {other} {bad}))) {bad})'
 expected=f'(ite {fit} (ite (and {eq(0xd0ee)} (= PL #x00000004)) {ok} (ite (or {eq(0xc31c)} {eq(0x1742)}) {other} {bad})) {bad})'
 pp.append(solve('composed_type_extent_status_grammar','(assert '+neq(forest,expected)+')','Composition of the preceding source-proved gates under shared TAG/PL/SIZE epochs. Entry/null/miss guards and valid stable memory remain separate premises.'));tr['composed_type_extent_status_grammar']=[]
 return pp,tr
def verify(s):return s==build()
def alterations(s):
 ops=[('source_byte',lambda t:t['fragments']['publish'].__setitem__('bytes','00'+t['fragments']['publish']['bytes'][2:])),('invent_found_observation',lambda t:t['retained_profiles'][0].__setitem__('found_value_entries_observed',1)),('pointer_target',lambda t:t['pointer_records'][0]['fixup'].__setitem__('target',0)),('tag_representation',lambda t:t['fragments']['tag']['instructions'][-3].__setitem__('operands','w24, w10, #0')),('output_width',lambda t:t['fragments']['publish']['instructions'][9].__setitem__('operands','x9, [x11]'))]
 original=build();out=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=original;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert verify(s);pp,tr=proofs(s);aa=alterations(s);sites=[pc for gs in tr.values()for g in gs for pc in g['source_sites']];expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};assert expected<=set(sites)
 counts={**s['verified_source_counts'],'queries_unsat':len(pp),'tag_seed_lemmas':2,'tag_round_lemmas':14,'translated_instruction_instances':len(sites),'distinct_nonbranch_source_sites_covered':len(expected),'SSA_definitions':sum(g['SSA_definitions']for gs in tr.values()for g in gs),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'source_recapture_match':True,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_constructor_inputs.py':sha(ROOT/'validate_daemon_constructor_inputs.py'),'validate_daemon_constructor_lookup.py':sha(ROOT/'validate_daemon_constructor_lookup.py')},'proofs':pp,'translations':tr,'alterations':aa,'source_coverage_scope':'All nonbranch sites covered; tag merge/seed/round ledgers intentionally overlap. Four word-mask cuts reuse pinned prior seed/round lemmas. Named loads require valid stable owners and correct reaching stores. No whole-program memory alias proof.','verified_counts':counts,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
