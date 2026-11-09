#!/usr/bin/env python3
"""Source-linked paired shuffle abstractions and selector comparison."""
from validate_daemon_existing_scalar_reader import bv,z,neq,split,prefix
from validate_daemon_mode_one_scatter import ADDR,DIVS,SELECTORS,ADDRESS_GROUPS,SWAPS
def run_models(s,fresh,cert,part,solve,tr,second):
 sdiv,ssel,saddr,sswap=second;models={};ledgers=[];finite=[]
 frame=lambda n:f'(bvadd K {bv(n)})'
 def table(label,j):
  e=bv(ADDR[15],32)
  for k in range(14,j-1,-1):e=f'(ite (= {label}_S{j} {bv(k-j,32)}) {bv(ADDR[k],32)} {e})'
  return e
 def make(label):
  name='first_shuffle'if label=='first'else'second_shuffle';f=s['fragments'][name];ii=f['instructions'][:-1];div=DIVS if label=='first'else sdiv;selectors=dict(SELECTORS if label=='first'else ssel);addresses=ADDRESS_GROUPS if label=='first'else saddr;swaps=SWAPS if label=='first'else sswap
  if label=='first':selectors[0x100ca09a8]=(14,None)
  r={11:frame(0xd00),13:bv(0x8a66),**{j:z('A'+str(j))for j in range(4)}}if label=='first'else{11:frame(0xd00),4:bv(0x8d87),14:bv(757),16:bv(963)}
  ll={};dd=[]
  swap_ends={max(wp,vp):(j,rp,sp,wp,vp)for j,(rp,sp,wp,vp)in enumerate(swaps)}
  for q in ii:
   if q['mnemonic']in('ldr','ldrb'):
    w=8 if q['mnemonic']=='ldrb'else 32 if q['operands'].startswith('w')else 64;v=label+'_L'+str(len(dd));ll[q['ea']]=(v,w);dd.append(f'(declare-fun {v} () (_ BitVec {w}))')
  if label=='first':ll['0x100ca09c4']=('TABLE',64)
  else:ll.update({'0x100dbfc54':('A1',32),'0x100dbfc90':('A0',32),'0x100dbfcd0':('A2',32),'0x100dbfd00':('A3',32),'0x100dc0218':('TABLE',64)})
  g=fresh(label,r,ll);g.declarations='\n'.join(dd)+'\n';cc=[];raw_selectors={};snap={};starts={a:(b,num,den,j,out)for a,b,num,den,j,out in addresses};ends={b:(a,num,den,j,out)for a,b,num,den,j,out in addresses};before_div={a:(j,src,external)for j,(a,_,src,_,_,_,_,external)in div.items()}
  for q in ii:
   pc=int(q['ea'],16);snap[pc]=dict(g.r)
   if pc in before_div:
    j,src,external=before_div[pc];raw_selectors[j]={'kind':'unsigned_remainder','divisor':16-j,'source_input':g.get(src),'site':hex(pc)}
    if external:cert(label+'_live_division_constants_'+str(j),g,[neq(g.get('w'+str(k)),bv(v,32))for k,v in external.items()],cc)
   if pc in starts:
    _,num,den,j,_=starts[pc];ps=split(q['operands']);want=f'(bvadd #x00014b30 (bvmul (bvadd {label}_S{j} {bv(j,32)}) #x000002f5))';terms=[neq(g.get(num),want)]
    if q['mnemonic']=='udiv':terms.append(neq(g.get(ps[2]),bv(963,32)))
    else:
     assert q['mnemonic']=='umull'and ps[1]==num;sh=next(v for v in ii if int(v['ea'],16)==pc+4);shift=int(sh['operands'].split('#')[1],0);assert sh['mnemonic']=='lsr'and split(sh['operands'])[:2]==[ps[0],ps[0]];assert shift in(32,40);terms.append(neq(g.get(ps[2]),bv(0x440dd3 if shift==32 else 0x440dd2cf,32)))
    if not(label=='first'and pc==0x100ca049c):terms.append(neq(g.get(den),bv(963,32)))
    cert(label+'_address_numerator_'+hex(pc),g,terms,cc)
   g.run({'instructions':[q]},pc+4)
   if q['mnemonic']=='ldrb':
    v,w=ll[q['ea']];assert w==8;cc.extend([f'(bvuge {v} #xd0)',f'(bvult {v} #xe0)'])
   if pc in selectors:
    j,out=selectors[pc];symbol=f'{label}_S{j}';value=f'(bvand {g.get("w10")} #x00000001)'if out is None else g.get(out)
    if j in(0,8,12,14):
     if label=='second'and j==8:value=f'(bvsub {value} #x00000078)'
     cert(label+'_bit_selector_range_'+str(j),g,[f'(bvuge {value} {bv(16-j,32)})'],cc)
     raw_selectors[j]={'kind':'bit_selector','source_input':value,'site':hex(pc)};cc.append(f'(= {symbol} {value})')
    cc.append(f'(bvult {symbol} {bv(16-j,32)})')
    if out is None:g.flags={'eq':f'(= {symbol} #x00000000)','ne':f'(= {symbol} #x00000001)'}
    else:g.put(out,f'(bvadd #x00000078 {symbol})'if label=='second'and j==8 else symbol)
   if pc in ends:
    a,num,den,j,out=ends[pc];ps=split(q['operands']);assert q['mnemonic']=='msub'and ps[0]==out and ps[2]==den and ps[3]==num
    start=next(v for v in ii if int(v['ea'],16)==a);sp=split(start['operands']);assert ps[1]==sp[0].replace('x','w',1)
    if start['mnemonic']!='udiv':
     shift=int(next(v for v in ii if int(v['ea'],16)==a+4)['operands'].split('#')[1],0);multiplier=0x440dd3 if shift==32 else 0x440dd2cf
    if den!=out:cert(label+'_remainder_divisor_'+hex(pc),g,[neq(g.get(den),bv(963,32))],cc)
    for k in range(16-j):
     n=84784+757*(j+k);quotient=n//963 if start['mnemonic']=='udiv'else(n*multiplier)>>shift;assert quotient==n//963 and n%963==ADDR[j+k];finite.append({'fragment':label,'site':hex(pc),'selector':k,'numerator':n,'quotient':quotient,'residue':n%963})
    g.put(out,table(label,j))
   if pc in swap_ends:
    j,rp,sp,wp,vp=swap_ends[pc]
    old=next(v for v in g.reads if v['site']==hex(rp));selected=next(v for v in g.reads if v['site']==hex(sp));fixed_write=next(v for v in g.stores if v['site']==hex(wp));selected_write=next(v for v in g.stores if v['site']==hex(vp));fixed=frame(0xd00+ADDR[j])
    terms=[neq(old['address'],fixed),neq(fixed_write['address'],fixed),neq(fixed_write['value'],selected['input']),neq(selected_write['address'],selected['address']),neq(selected_write['value'],old['input'])]
    terms.append('(and '+' '.join(neq(selected['address'],frame(0xd00+k))for k in ADDR[j:])+')')
    cert(label+'_forward_swap_'+str(j),g,terms,cc)
  tr[label+'_full_source']=g.record();models[label]={'engine':g,'constraints':cc,'selectors':raw_selectors,'swaps':swaps,'snapshots':snap}
  return g
 first=make('first');second_model=make('second')
 for label,model in models.items():
  g=model['engine'];terms=[];cc=model['constraints']
  def rd(pc):return next(v for v in g.reads if v['site']==hex(pc))
  def st(pc):return next(v for v in g.stores if v['site']==hex(pc))
  for j,(rp,sp,wp,vp)in enumerate(model['swaps']):
   fixed=frame(0xd00+ADDR[j]);r,selected,w,v=rd(rp),rd(sp),st(wp),st(vp);terms.extend([neq(r['address'],fixed),neq(w['address'],fixed),neq(w['value'],selected['input']),neq(v['address'],selected['address']),neq(v['value'],r['input'])]);terms.append('(and '+' '.join(neq(selected['address'],frame(0xd00+k))for k in ADDR[j:])+')');assert max(rp,sp)<min(wp,vp)
   ledgers.append({'fragment':label,'stage':j,'read_fixed':hex(rp),'read_selected':hex(sp),'write_fixed':hex(wp),'write_selected':hex(vp),'fixed_frame_offset':hex(0xd00+ADDR[j]),'allowed_selected_positions':list(range(j,16)),'both_reads_before_both_writes':True})
  assert len(g.stores)==30
  # Each transposition was certified at its own completion above. The ledger
  # here does not add assumptions about later loads to those prefix proofs.
 # Compare source dividends/bit selectors,not an assumed equality of results.
 # Only earlier selector equalities enter each step. Integer division lemmas
 # then give equal remainder results for the equal dividends and divisors.
 combined=prefix(first)+prefix(second_model);same=[];coupling=[]
 constraints=models['first']['constraints']+models['second']['constraints']
 for j in range(15):
  a=models['first']['selectors'][j];b=models['second']['selectors'][j];assert a['kind']==b['kind']
  if a['kind']=='unsigned_remainder':assert a['divisor']==b['divisor']==16-j
  solve('paired_selector_'+str(j),combined+'(assert '+neq(a['source_input'],b['source_input'])+')',constraints+same)
  coupling.append({'stage':j,'kind':a['kind'],'divisor':a.get('divisor'),'first_site':a['site'],'second_site':b['site'],'first_source_input':a['source_input'],'second_source_input':b['source_input'],'equal_under_prior_selector_induction':True})
  same.append(f'(= first_S{j} second_S{j})')
 solve('paired_selector_domain_nonempty',combined,constraints+same,result='sat',note='Abstract source domain check,not a native-state reachability witness.')
 models['coupling_certificate']=coupling
 return models,ledgers,finite

def run_table(s,fresh,cert,tr,models,math):
 frame=lambda n:f'(bvadd K {bv(n)})'
 def lutfunc(name,values,bits=8):
  e=bv(values[-1],bits)
  for j in range(len(values)-2,-1,-1):e=f'(ite (= x {bv(j,8)}) {bv(values[j],bits)} {e})'
  return f'(define-fun {name} ((x (_ BitVec 8))) (_ BitVec {bits}) {e})\n'
 def indexed(values,arg):
  e=bv(values[-1],32)
  for j in range(len(values)-2,-1,-1):e=f'(ite (= {arg} {bv(j,32)}) {bv(values[j],32)} {e})'
  return e
 constants={1:0x8d87,2:0x4a74,3:0,6:0xd781bff7,7:0x53807,10:0x102f5,11:0x3245,12:0x2207,13:0x0a5cd4cf,14:757,15:0xa6,16:963,19:0x456c7a,20:944,22:0xd781bef7,24:0x6d,26:0xe8,27:0xac,28:0xbd5e7747,30:0x287e410a}
 second=models['second'];exitg=second['engine'];cert('second_shuffle_table_writer_seed',exitg,[neq(exitg.get('w'+str(j)),bv(v,32))for j,v in constants.items()]+[neq(exitg.get('x21'),frame(0xd00)),neq(exitg.get('x25'),bv(0xffffffff8e873ed9))],second['constraints'])
 r={k:bv(v)for k,v in constants.items()};r.update({21:frame(0xd00),25:bv(0xffffffff8e873ed9),3:z('IDX'),22:z('(bvadd #xd781bef7 IDX)')})
 f=s['fragments']['table'];ii=f['instructions'][:-1];ll={};dd=[]
 for q in ii:
  if q['mnemonic']in('ldr','ldrb'):
   bits=8 if q['mnemonic']=='ldrb'else 32 if q['operands'].startswith('w')else 64;v='table_L'+str(len(dd));ll[q['ea']]=(v,bits);dd.append(f'(declare-fun {v} () (_ BitVec {bits}))')
 ll.update({'0x100c0727c':('B0',8),'0x100c07290':('B1',8),'0x100c072ac':('CELL0',64),'0x100c072b0':('CWORD0',32),'0x100c072b4':('CELL1',64),'0x100c072b8':('CWORD1',32),'0x100c072cc':(bv(0x100e99a00),64),'0x100c072e0':(bv(0x100f4e390),64),'0x100c07300':(bv(s['data_roots'][2]['fixup']['target']),64),'0x100c07340':('B3',8),'0x100c07380':('TABLE',64)})
 funcs=lutfunc('LUT_LEFT',bytes.fromhex(s['data_roots'][0]['bytes']))+lutfunc('LUT_RIGHT',bytes.fromhex(s['data_roots'][1]['bytes']))+lutfunc('LUT_OP_BYTE',[q['encoded_byte']for q in math['source_lookup_cases']])+lutfunc('LUT_OP_OFFSET',[q['table_offset']for q in math['source_lookup_cases']],32)+lutfunc('LUT_FIXED',math['operation256'],32)
 g=fresh('table',r,ll);g.declarations='\n'.join(dd)+'\n'+funcs;cc=['(bvult IDX #x00000100)','(bvuge B0 #xd0)','(bvult B0 #xe0)','(bvuge B1 #xd0)','(bvult B1 #xe0)'];key=None;cuts=[]
 for q in ii:
  pc=int(q['ea'],16);ps=split(q['operands'])
  if pc==0x100c072a8:
   key=f'((_ extract 7 0) (bvxor {g.get("w17")} #x00000034))'
   want='(concat ((_ extract 3 0) (bvxor B1 #xd4)) ((_ extract 3 0) (bvxor B0 #xd4)))'
   cert('table_input_inverse_nibble_combination',g,[neq(key,want),f'(bvugt {g.get("w17")} #x000000ff)'],cc)
  if pc in(0x100c072d4,0x100c072e4):
   left=pc==0x100c072d4;base=0x100e99a00 if left else 0x100f4e390;address=g.address(ps[1]);index=f'(bvsub {address} {bv(base)})';cert('table_byte_bank_extent_'+hex(pc),g,[f'(bvugt {index} #x00000000000000ff)'],cc);g.loads[q['ea']]=(f'(LUT_{"LEFT"if left else"RIGHT"} ((_ extract 7 0) {index}))',8)
  if pc==0x100c07300:cert('table_operation_root_slot',g,[neq(g.address(ps[1]),bv(0x1010a8c28))],cc)
  if pc==0x100c07308:
   assert key;cert('table_fixed_operation_byte_address',g,[neq(g.address(ps[1]),f'(bvadd {bv(0x100f715a0)} {z("(LUT_OP_OFFSET "+key+")")})')],cc);g.loads[q['ea']]=(f'(LUT_OP_BYTE {key})',8)
  g.run({'instructions':[q]},pc+4)
  if pc==0x100c072ec:
   cert('table_bank_codec_is_constant208',g,[neq(g.get('w3'),'#x000000d0')],cc);cuts.append({'site':q['ea'],'source_value':g.get('w3'),'replacement':'#x000000d0','lemma':'table_bank_codec_is_constant208'});g.put('w3','#x000000d0')
  if pc==0x100c07318:
   cert('table_decodes_fixed_cyclic_nibble',g,[neq(g.get('w17'),f'(LUT_FIXED {key})')],cc);cuts.append({'site':q['ea'],'source_value':g.get('w17'),'replacement':'NIB','lemma':'table_decodes_fixed_cyclic_nibble','binding':f'(= NIB (LUT_FIXED {key}))'});g.put('w17','NIB');cc.extend(['(bvult NIB #x00000010)',f'(= NIB (LUT_FIXED {key}))'])
 tr['table_full_source']=g.record()
 return g,cc,cuts,key
