#!/usr/bin/env python3
"""Source-composed value consumers and borrowed-pointer output; no target execution."""
import copy,json,re,subprocess
from recover_daemon_reader_value_consumers import ROOT,P,SCOPE,FLAGS,sha,build
from validate_daemon_reader_extent_families import SSA as ParentSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix
from recover_daemon_reader_context_footprint import engine
from validate_daemon_reader_context_footprint import declarations
SOLVER='/opt/homebrew/bin/z3';PH='(concat ((_ extract 63 32) Z30) #x00006cf4)'
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in [('END',64),('CTX',64),('HEAD',64),('RAW64',64),('SPAN',64),('HRAW',32),('LRAW',32),('VAL32',32),('VALB',32),('EXP70',32),('EXP74',32),('STAG',16),('FLAG',8)])
class SSA(ParentSSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='ccmp':
    ps=i['operands'].split(', ');w=32 if ps[0].startswith('w')else 64;cond=self.flags[ps[3]];v=int(ps[2][1:],0);n,zz,c,ov=[bool(v&b)for b in[8,4,2,1]];fallback={'eq':zz,'ne':not zz,'lo':not c,'hi':c and not zz,'lt':n!=ov,'ge':n==ov,'gt':not zz and n==ov,'le':zz or n!=ov};self.compare(self.get(ps[0],w),self.get(ps[1],w),w);self.flags={k:f'(ite {cond} {e} {str(fallback[k]).lower()})'for k,e in self.flags.items()};self.sites.append(i['ea'])
   elif i['mnemonic']=='mvn':
    rd,rs=i['operands'].split(', ');self.put(rd,f'(bvnot {self.get(rs,32 if rd.startswith("w")else 64)})');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def make(f,n,r=None,loads=None):
 ll=dict(loads or{});dd=[];end=int(f['instructions'][-1]['ea'],16)
 for i in f['instructions'][:-1]:
  if i['mnemonic']in('ldr','ldrb','ldrh','ldur')and i['ea']not in ll:
   w=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']=='ldrh'else 32 if i['operands'].startswith('w')else 64;v=n+'_L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {w}))');ll[i['ea']]=(v,w)
 rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=SSA(rr,ll,namespace=n+'_');g.run(f,end);g.declarations='\n'.join(dd)+'\n';return g
def solve(n,body,decl,scope,result='unsat'):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+decl+body+'\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr);return {'name':n,'query':q,'result':result,'scope':scope}
def certificates(s):
 pp=[];tr={};summ=[];pr,inp=engine(s['preparation'],ns='prep_');decl=declarations(inp,'N');tr['preparation']=pr.record();fs=s['fragments']
 def frame(x):return f'(bvadd K {bv(x)})'
 def at(x):return f'(bvadd TABLE {bv(x*8)})'
 def common(f):
  return {i['ea']:(PH if i['operands'].endswith('[sp, #0x9d0]')else'TABLE',64)for i in f['instructions']if i['mnemonic']=='ldr'and i['operands'].endswith(('[sp, #0x9d0]','[sp, #0x9d8]'))}
 def new(a,n,r=None,loads=None,chain=None):
  f=fs[hex(a)];ll=common(f);ll.update(loads or{});r={j:chain[-1].get('x'+str(j))for j in range(31)}if chain else r;g=make(f,n,r=r,loads=ll);tr[n]=g.record();return (chain or[])+[g]
 def index(a,g):
  pc=next(i['ea']for i in fs[hex(a)]['instructions']if i['mnemonic']=='ldr'and'sxtw #3'in i['operands']);return next(q['address']for q in g.reads if q['site']==pc)
 def add(n,gs,tt,scope,cc=()):pp.append(solve(n,prefix(*gs)+''.join('(assert '+c+')\n'for c in cc)+'(assert (or '+' '.join(tt)+'))',decl,scope))
 enc='(bvxor VALUE #x8b3dc651)';scope='Named-load source contract under low32 phase6cf4,arbitrary phase upper32 and valid/cache-consistent frame/borrowed owners. This does not establish native initialization,lifetime,PAC,endpoint or successful exchange.'
 spec={'N20':(0x26c4,0x8f80,0x8f7e,0x6f18,0x100570604,0x100570608),'N21':(0x6d14,0x8f70,0x8f6e,0x4828,0x10052c2e8,0x10052c2ec),'N22':(0x1744,0x8f58,0x8f56,0x8d98,0x100509180,0x100509184),'N23':(0x1a60,0x8f48,0x8f46,0x3d58,0x10047c474,0x10047c478)}
 returns={}
 for row in s['families']:
  n=row['name'];a=int(row['entry'],16);ll={}
  if n!='N19':o,eo,to,dest,ep,tp=spec[n];ll={hex(ep):('END',64),hex(tp):('STAG',16)}
  gs=new(a,n+'_return',r={4:z(enc)},loads=ll);returns[n]=gs;g=gs[-1]
  if n=='N19':tt=[neq(g.stores[0]['address'],frame(0x7df0)),neq(g.stores[0]['value'],enc),neq(index(a,g),at(0x746b)),neq(g.get('w9'),'#x00006cf4')]
  else:
   o,eo,to,dest,ep,tp=spec[n];tt=[neq(g.stores[0]['address'],frame(o)),neq(g.stores[0]['value'],enc),neq(g.stores[1]['address'],frame(dest)),neq(g.stores[1]['value'],'END')]
   for pc,off in[(ep,eo),(tp,to)]:tt.append(neq(next(q['address']for q in g.reads if q['site']==hex(pc)),frame(off)))
   tt.append(neq(index(a,g),f'(ite (= STAG #xd0ee) {at(int(row["indices"][0],16))} {at(int(row["indices"][1],16))})'))
   tt.extend([neq(g.get('x8'if n in('N20','N21')else'x9'),frame(o)),neq(g.get('w9'if n in('N20','N21')else'w8'),'#x000051e2'if n in('N20','N21')else'#x00005f85')])
  add(n+'_payload_staging_and_recheck',gs,tt,scope+' Encoded u32 payload is staged;four families copy a saved end and recheck persistent tagd0ee before selecting caller continuation.')
  summ.append({'family':n,'entry':row['entry'],'payload_encoding':'VALUE XOR8b3dc651','native_output_owner_proved':False})
 for n in['N20','N21']:
  a=0x1004d5adc;g0=returns[n];ll={'0x1004d5af0':(enc,32),'0x1004d5afc':('CTX',64),'0x1004d5b00':('FLAG',8)};gs=new(a,n+'_consumer',loads=ll,chain=g0);g=gs[-1];off=spec[n][0]
  add(n+'_shared_value_and_flag_consumer',gs,[neq(g.reads[0]['address'],frame(off)),neq(g.reads[1]['address'],frame(0x5e50)),neq(g.reads[2]['address'],'(bvadd CTX #x0000000000000068)'),neq(g.stores[0]['address'],frame(0x7390)),neq(g.stores[0]['value'],enc),neq(index(a,g),f'(ite (= FLAG #x00) {at(0x51e2)} {at(0x521b)})')],scope+' Both incoming readers converge on value cell7390 and context byte68;zero/nonzero selects different expected-word checks.')
  for ca,name,ll,cond,left,right,eqix,neix,addr1,addr2 in[(0x100540018,'word70',{'0x10054004c':(enc,32),'0x100540050':('EXP70',32)},'(= FLAG #x00)',enc,'EXP70',0x9790,0x2fc8,frame(0x7390),'(bvadd CTX #x0000000000000070)'),(0x1005fa760,'word74',{'0x1005fa780':('VALB',32),'0x1005fa784':('EXP74',32)},'(distinct FLAG #x00)','VALB','EXP74',0xcb5d,0x6959,frame(0x78f0),'(bvadd CTX #x0000000000000074)')]:
   cs=new(ca,n+'_'+name,loads=ll,chain=gs);v=cs[-1];add(n+'_'+name+'_equality',cs,[neq(v.reads[0]['address'],addr1),neq(v.reads[1]['address'],addr2),neq(index(ca,v),f'(ite (= {left} {right}) {at(eqix)} {at(neix)})'),neq(v.get('w6'),'#x74c29ccb')],scope+' Composes actual caller registers;comparisons use raw u32 representations,not an inferred identity/policy meaning.',[cond])
 for n in['N22','N23']:
  a=0x1007f43b4;gs=new(a,n+'_consumer',loads={'0x1007f43c4':(enc,32),'0x1007f43d0':('HEAD',64)},chain=returns[n]);g=gs[-1];add(n+'_shared_second_value_and_context',gs,[neq(g.reads[0]['address'],frame(spec[n][0])),neq(g.reads[1]['address'],frame(0x7d98)),neq(g.stores[0]['address'],frame(0x78f0)),neq(g.stores[0]['value'],enc),neq(g.stores[1]['address'],frame(0x21b0)),neq(g.stores[1]['value'],'HEAD'),neq(index(a,g),f'(ite (= HEAD {bv(0)}) {at(0x5f85)} {at(0x5f87)})'),neq(g.get('w6'),'#x74c29d88')],scope+' Both incoming readers converge on value cell78f0 and stage a context pointer at21b0. Nonzero pointer controls the next caller branch.')
 header=new(0x1005cf720,'preceding_word',r={4:z('HRAW')});g=header[-1];add('N19_preceding_word_to_tag_interface',header,[neq(g.stores[0]['address'],frame(0x9584)),neq(g.stores[0]['value'],'HRAW'),neq(g.get('w16'),'#x000001fa'),neq(g.get('x1'),bv(0x79b09650c3f6825c)),neq(g.get('x4'),frame(0x4120)),neq(g.get('x22'),frame(0xa610)),neq(index(0x1005cf720,g),at(0x1f39))],scope+' Original word-return slotaf stores raw W4 and stages the N19 tag read;the preceding word byte-offset producer is not joined.')
 uf=new(0x100588cb0,'eight_byte_reader',r={0:'O',10:'CELL',8:bv(0x8c4)},loads={'0x100588cb0':('TABLE',64),'0x100588cb4':('FN',64),'0x100588cbc':('BUF',64)});g=uf[-1];tt=[neq(g.reads[0]['address'],frame(0x9d8)),neq(g.reads[1]['address'],at(0x8c4)),neq(g.reads[2]['address'],'CELL'),neq(g.get('x8'),'FN')];bs=[q for q in g.reads if q['width_bits']==8];assert len(bs)==8 and not g.stores
 for j,q in enumerate(bs):tt.append(neq(q['address'],f'(bvadd BUF O {bv(10+j)})'))
 add('eight_byte_reader_footprint_and_continuation',uf,tt,scope+' All eight byte addresses and carried return pointer are checked through the entire885-instruction body. No decoded X9 value/transform formula is claimed.')
 ur=new(0x1004cdeac,'eight_byte_return',chain=uf);g=ur[-1];add('eight_byte_result_staging',ur,[neq(g.stores[0]['address'],frame(0x12c8)),neq(g.stores[0]['value'],uf[-1].get('x9')),neq(g.get('w9'),'#x00006cf4'),neq(index(0x1004cdeac,g),at(0x746b))],scope+' Returned X9 is staged as raw64 and joins the common block;its value encoding remains uninterpreted.')
 joinloads={'0x10047310c':('END',64),'0x100473114':('HRAW',32),'0x100473118':('STAG',16),'0x10047312c':('CTX',64)}
 special='(and (= HRAW #x8b3dc651) (= STAG #x1742))'
 def joint(gs,label):return new(0x1004730ec,label,loads=joinloads,chain=gs)
 j=joint(returns['N19'],'N19_u32_join');g=j[-1];add('N19_common_conditional_compare',j,[neq(g.stores[0]['address'],frame(0xdb8)),neq(g.stores[0]['value'],'END'),neq(index(0x1004730ec,g),f'(ite {special} {at(0x7042)} {at(0x70a6)})'),neq(g.get('w10'),'#x0000b8e4')],scope+' CCMP with NZCV fallback0 makes the special arm require both encoded-zero preceding word and saved span tag.')
 add('N19_u32_stable_tag_ordinary_arm',j,[neq(index(0x1004730ec,g),at(0x70a6))],scope+' Stable persistent u32 tagd0ee excludes the special span arm.',['(= STAG #xd0ee)'])
 uj=joint(ur,'N19_u64_join');add('N19_u64_stable_tag_ordinary_arm',uj,[neq(index(0x1004730ec,uj[-1]),at(0x70a6))],scope+' Stable persistent recognized64 tagc31c excludes the special span arm.',['(= STAG #xc31c)'])
 pack=new(0x10056deb8,'N19_value_prefix',loads={'0x10056debc':('LRAW',32),'0x10056dee4':('VAL32',32),'0x10056deec':('RAW64',64),'0x10056def4':('SPAN',64)},chain=j);g=pack[-1];want=[(0x8760,'CTX'),(0xa618,'HRAW'),(0xa61e,'STAG'),(0xa620,'LRAW'),(0xa624,'VAL32'),(0xa628,'RAW64'),(0x57a0,'SPAN')];assert len(g.stores)==len(want);tt=[]
 for q,(o,v)in zip(g.stores,want):tt.extend([neq(q['address'],frame(o)),neq(q['value'],v)])
 tt.append(neq(index(0x10056deb8,g),f'(ite (= CTX {bv(0)}) {at(0xb913)} {at(0xb8e4)})'));add('N19_all_variant_cache_copies',pack,tt,scope+' Leading24 B field positions match constructor metadata offsets,but complete object/type equivalence is not proved. Both scalar caches and span pointer are copied independently of active type.')
 sp=new(0x1007f6f54,'N19_special_success',chain=j);pub=new(0x10058816c,'N19_special_pointer_output',loads={'0x100588170':('OUT',64),'0x100588178':('CONT',64)},chain=sp);g=pub[-1];add('N19_zero_word_span_borrowed_pointer_publication',pub,[neq(sp[-1].stores[0]['address'],frame(0x2b1c)),neq(sp[-1].stores[0]['value'],'#x8b3dc651'),neq(g.reads[0]['address'],frame(0x8398)),neq(g.stores[0]['address'],'OUT'),neq(g.stores[0]['value'],'CTX'),neq(g.get('x6'),bv(0x8b3dc651)),neq(g.get('x21'),'CONT'),neq(index(0x10058816c,g),at(0x7613))],scope+' Borrowed OUT must be valid and not clobber later frame reads. Saved context pointer is written on the zero-word/span arm;its semantic owner and final return remain unknown.',[special])
 # Recompose the existing N19 span path instead of assuming its incoming W9 phase.
 row=s['families'][0]['parent'];cells={q['offset_bytes']:a['value']for q,a in zip(s['preparation_write_ledger'],pr.stores)};sg=[pr]
 for role,a in[(k,row['parent'][k])for k in['gate','fit_bridge','type_prefix']]+[('high',row['high']),('span_exact',row['span_exact']),('span_pointer',row['span_targets'][0])]:
  f=s['span_context'][a];ll=common(f)
  for i in f['instructions']:
   if i['mnemonic']!='ldr':continue
   m=re.fullmatch(r'[xw]\d+, \[sp, #(0x[0-9a-f]+)\]',i['operands'])
   if not m:continue
   off=int(m[1],16);w=32 if i['operands'].startswith('w')else 64;v='TAG'if off==0x9b8 else'BUF'if off==0x4120 else cells.get(off)
   if v:ll[i['ea']]=(v,w)
  rr={1:z('(bvxor PL #x8ec35f08)'),4:z('(bvxor PL #x8b3dc651)')}if len(sg)==1 else{v:sg[-1].get('x'+str(v))for v in range(31)};v=make(f,'span_'+role,r=rr,loads=ll);tr['span_'+role]=v.record();sg.append(v)
 g=sg[-1];add('N19_span_path_join_phase',sg,[neq(g.get('w9'),'#x00006cf4')],scope+' Exact prior span source chain establishes the join phase rather than importing it as an isolated entry assumption.',['(= ((_ extract 15 0) TAG) #x1742)'])
 pp.append(solve('reject_erasing_inactive_variant_cache_store',prefix(*pack)+'(assert (= STAG #xd0ee))\n(assert (distinct RAW64 '+bv(0)+'))\n(assert '+neq(pack[-1].stores[5]['value'],bv(0))+')',decl,'Abstract source counterexample: even with active u32 tag,the checked prefix block copies raw64 cache. This is not a native initialization,exposure or information-leak claim.','sat'))
 return pp,tr,summ
def verify(s):return s==build()
def alterations(s):
 ops=[('missing_byte_reader',lambda t:t['fragments'].pop('0x100588cb0')),('wrong_flag_branch',lambda t:t['families'][1]['indices'].reverse()),('invent_decoded_u64',lambda t:t.__setitem__('complete_u64_transform_proved',True)),('wrong_header_writer',lambda t:t['preceding_word_writer_census']['candidates'][0].__setitem__('source_store','0x0')),('drop_special_output',lambda t:t['fragments'].pop('0x10058816c')),('promote_native_owner',lambda t:t.__setitem__('native_output_owner_proved',True))];aa=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=s;aa.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return aa
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert verify(s);pp,tr,summ=certificates(s);aa=alterations(s);sites={pc for q in tr.values()for pc in q['source_sites']};expected={i['ea']for f in[s['preparation']]+list(s['fragments'].values())+list(s['span_context'].values())for i in f['instructions'][:-1]};assert sites==expected,(len(sites),len(expected),expected-sites)
 counts={**s['verified_source_counts'],'queries_unsat':sum(q['result']=='unsat'for q in pp),'counterexamples_sat':sum(q['result']=='sat'for q in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(q['source_sites'])for q in tr.values()),'SSA_definitions':sum(q['SSA_definitions']for q in tr.values()),'rejected_alterations':len(aa)};c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_reader_extent_families.py':sha(ROOT/'validate_daemon_reader_extent_families.py'),'validate_daemon_reader_context_footprint.py':sha(ROOT/'validate_daemon_reader_context_footprint.py')},'source_recapture_match':True,'proofs':pp,'translations':tr,'family_summaries':summ,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'complete_u64_transform_proved':False,'native_output_owner_proved':False,'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
