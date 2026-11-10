#!/usr/bin/env python3
"""Static capability gates,buffer effects and full selector21 provider ABI."""
import copy,hashlib,json,re,shutil,subprocess
from recover_versioned_request_abi import ROOT,P,SCOPE,FLAGS,DEPS,build,TABLE,POOL
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_kext_query_getter_values import GetterSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,neq
from validate_daemon_reader_container_origins import lut
from daemon_word_round_tools import lookup
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
COMMON_DECLARED=set(re.findall(r'\(declare-fun (\w+) ',DECL))
RAW='(bvxor CAP #xc49697f0)'
def bit(k):return '((_ extract '+str(k)+' '+str(k)+') CAP)'
def yes(k):return '(= '+bit(k)+' #b1)'
class SourceSSA(GetterSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.pair_lowerings=[];self.postindexes=[];self.auth_normalizations=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   p=split(i['operands']);m=i['mnemonic']
   if m in['ldp','stp']:
    w=32 if p[0].startswith('w')else 64;a=self.address(p[2]);match=re.fullmatch(r'\[(sp|x\d+)(?:, #(-?0x[0-9a-f]+|\d+))?\]',p[2]);assert match;i0=int(match[2],0)if match[2]else 0
    for j in range(2):
     off=i0+j*w//8;mem='['+match[1]+', #'+hex(off)+']';q={**i,'mnemonic':'ldr'if m=='ldp'else'str','operands':p[j]+', '+mem}
     if m=='ldp'and i['ea']in self.supplied_loads:
      pair=self.supplied_loads[i['ea']];assert len(pair)==2;self.supplied_loads[i['ea']]=pair[j]
      super().run({'instructions':[q]},pc+4);self.supplied_loads[i['ea']]=pair
     else:super().run({'instructions':[q]},pc+4)
    self.sites.pop();self.pair_lowerings.append({'site':i['ea'],'mnemonic':m,'first_address':a,'width_per_effect_bits':w})
   elif m=='csinc':
    w=32 if p[0].startswith('w')else 64;self.put(p[0],'(ite '+self.flags[p[3]]+' '+self.get(p[1],w)+' (bvadd '+self.get(p[2],w)+' '+bv(1,w)+'))');self.sites.append(i['ea'])
   elif m=='ands':
    w=32 if p[0].startswith('w')else 64;value='(bvand '+self.get(p[1],w)+' '+self.operand(p[2],w,p[3]if len(p)>3 else None)+')';self.put(p[0],value);self.flags.update(eq='(= '+value+' '+bv(0,w)+')',ne='(distinct '+value+' '+bv(0,w)+')');self.sites.append(i['ea'])
   elif m=='sxtw':self.put(p[0],'((_ sign_extend 32) '+self.get(p[1],32)+')');self.sites.append(i['ea'])
   elif m=='autda':
    self.auth_normalizations.append({'site':i['ea'],'signed_pointer':self.get(p[0]),'modifier':self.get(p[1]),'normal_value':'VT','premise':'Valid ordinary signed provider vptr;authentication outcome not modeled.'});self.put(p[0],'VT');self.decl['VT']=64;self.sites.append(i['ea'])
   elif m=='stur'and p[1]=='[x29, #-0x14]':
    before=self.address(p[1]);super().run({'instructions':[{**i,'mnemonic':'str','operands':p[0]+', [sp, #0x1c]'}]},pc+4);self.auth_normalizations.append({'site':i['ea'],'original_address':before,'normalized_frame_offset':0x1c})
   elif m=='ldrb'and len(p)==3:
    base=re.fullmatch(r'\[(x\d+)\]',p[1]);assert base;old=self.get(base[1]);super().run({'instructions':[{**i,'operands':p[0]+', '+p[1]}]},pc+4);increment=int(p[2][1:],0);increment=increment-(1<<64)if increment>=1<<63 else increment;self.put(base[1],'(bvadd '+old+' '+bv(increment)+')');self.postindexes.append({'site':i['ea'],'base':base[1],'original_base':old,'increment':increment})
   else:super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'original_pair_lowerings':self.pair_lowerings,'original_postindex_lowerings':self.postindexes,'conditional_auth_and_frame_normalizations':self.auth_normalizations}

def certificates(s):
 pp=[];models={};fs=s['fragments'];kf=s['kext_fragments'];rules={r['name']:r for r in s['bank_rules']};luts=''.join(lut('VR'+n,bytes.fromhex(b['bytes']))for n,b in s['banks'].items());bindings=[];cuts=[]
 def solve(name,body='',extra='',result='unsat',logic='QF_BV'):
  q='(set-option :timeout 45000)\n(set-logic '+logic+')\n'+DECL+extra+body+'\n'+('(check-sat)\n'if logic=='QF_AUFBV'else'(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n');r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.returncode,r.stdout[:1400],r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def cert(name,g,terms,cc=(),result='unsat'):
  solve(name,g.prefix()+''.join('(assert '+c+')\n'for c in cc)+'(assert (or '+' '.join(terms)+'))',luts+''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items()if n not in COMMON_DECLARED),result)
 def run(g,label,end=None):
  f=fs.get(label,kf.get(label));stop=int(f['instructions'][-1]['ea'],16)if end is None else end;g.run(f,stop);models[g.namespace]=g;return g
 def rd(g,site):return next(r for r in g.reads if r['site']==hex(site))
 def st(g,site):return next(r for r in g.stores if r['site']==hex(site))
 def supply_bank(g,i,name):
  address=g.address(split(i['operands'])[1]);base=int(s['banks'][name]['address'],16);index='((_ extract 7 0) (bvsub '+address+' '+bv(base)+'))';cert('bank_read_bound_'+i['ea'],g,[neq(address,'(bvadd '+bv(base)+' ((_ zero_extend 56) '+index+'))')]);g.supplied_loads[i['ea']]=('(LUT_VR'+name+' '+index+')',8);bindings.append({'site':i['ea'],'bank':name,'original_address':address,'index':index})
 root_spans={'CALL_L':(0x100634a78,0x100634a8c,12),'CALL_R':(0x100634a9c,0x100634ab0,13),'HEADER_L':(0x100634ae8,0x100634b00,11),'HEADER_R':(0x100634b10,0x100634b20,12),'LOOP_L':(0x100634b74,0x100634b88,11),'LOOP_R':(0x100634b98,0x100634bac,12)}
 for root in s['root_pointer_lineages']:
  a,zend,reg=root_spans[root['name']];f=fs['second_setup'];ii=[i for i in f['instructions']if a<=int(i['ea'],16)<zend];g=SourceSSA('root_'+root['name'],{15:bv(POOL)},loads={hex(a):(bv(root['fixup']['target']),64)});g.run({'instructions':ii},zend);models[g.namespace]=g;cert('original_pool_root_publication_'+root['name'],g,[neq(g.reads[0]['address'],bv(int(root['slot'],16))),neq(g.get('x'+str(reg)),bv(int(root['decoded_base'],16))),neq(g.stores[-1]['address'],frame(root['published_frame_offset'])),neq(g.stores[-1]['value'],bv(int(root['decoded_base'],16)))])
 g=SourceSSA('private_header_call',{26:'CA',23:bv(TABLE),11:bv(0xa6),12:bv(0xa5cd4cf),29:'FP'},presets={0x2b0:('CB',64),0x288:(bv(int(s['banks']['HEADERL']['address'],16)),64),0x280:(bv(int(s['banks']['HEADERR']['address'],16)),64)},loads={'0x100552ea4':('CAWORD',32),'0x100552eac':('CBWORD',32),'0x100552ee8':('FN',64)});g.decl.update(CA=64,CB=64,FP=64,CAWORD=32,CBWORD=32);ii=[i for i in fs['second_constructor']['instructions']if 0x100552ea4<=int(i['ea'],16)<0x100552ef8]
 for i in ii:
  if i['ea']in['0x100552ec4','0x100552ed4']:supply_bank(g,i,'HEADERL'if i['ea']=='0x100552ec4'else'HEADERR')
  g.run({'instructions':[i]},int(i['ea'],16)+4)
 models[g.namespace]=g;cert('private_header_adapter_original_slot_record_and_delta_cell_ABI',g,[neq(rd(g,0x100552ee8)['address'],bv(0x10109fe90)),neq(g.get('x0'),'(bvsub FP #x0000000000000098)'),neq(g.get('x1'),frame(0x5e0)),neq(g.get('x17'),bv(0x22a0))])
 g=SourceSSA('private_header_return',presets={0x5e0:('DELTA',64)});g.decl['DELTA']=64;ii=[i for i in fs['second_constructor']['instructions']if 0x100552efc<=int(i['ea'],16)<0x100552f0c];g.run({'instructions':ii},0x100552f0c);models[g.namespace]=g;cert('private_return_delta_changes_following_frame_base',g,[neq(g.get('sp'),'(bvadd K DELTA)'),neq(g.reads[0]['address'],frame(0x5e0))])
 solve('old_saved_state_pointer_cell_reused_iff_delta_zero','(assert '+neq('(= (bvadd (bvadd K DELTA) #x0000000000000080) (bvadd K #x0000000000000080))','(= DELTA #x0000000000000000)')+')',extra='(declare-fun DELTA () (_ BitVec 64))\n')
 solve('nonzero_delta_changes_state_pointer_read_address','(assert (= DELTA #x0000000000000010))\n(assert (distinct (bvadd (bvadd K DELTA) #x0000000000000080) (bvadd K #x0000000000000080)))',extra='(declare-fun DELTA () (_ BitVec 64))\n',result='sat')
 # Both state-pointer publications are rebuilt from source,with explicit domains.
 slot=0x1010a2d78;val=0x1020c48b3
 g=SourceSSA('pointer668',{7:z('SELECTOR'),1:bv(POOL)},loads={'0x100290400':(bv(val),64)});g.decl['SELECTOR']=32;run(g,'pointer668',int(fs['pointer668']['end'],16));cert('original_pointer668_publication',g,[neq(rd(g,0x100290400)['address'],bv(slot)),neq(g.stores[0]['address'],frame(0x668)),neq(g.stores[0]['value'],bv(0x1010b6380))],['(= ((_ extract 7 0) SELECTOR) #x43)'])
 g=SourceSSA('pointer80',{25:bv(int(s['banks']['STATEL']['address'],16)),16:bv(int(s['banks']['STATER']['address'],16)),13:'((_ zero_extend 56) ((_ extract 7 0) VALUE))',10:z('VALUE'),15:bv(POOL)});g.decl['VALUE']=32
 for i in fs['pointer80']['instructions']:
  pc=int(i['ea'],16)
  if pc in[0x100634b48,0x100634b50]:supply_bank(g,i,'STATEL'if pc==0x100634b48 else'STATER')
  if pc==0x100634b60:g.supplied_loads[i['ea']]=(bv(val),64)
  g.run({'instructions':[i]},pc+4)
 models['pointer80']=g;cert('original_pointer80_publication_all_selector_words',g,[neq(rd(g,0x100634b60)['address'],bv(slot)),neq(g.stores[0]['address'],frame(0x80)),neq(g.stores[0]['value'],bv(0x1010b6380))])
 # Capability tests share the numeric field but not an established live frame.
 for label,off,table_reg,target_reg,loadpc,indexexpr,div in[('first_gate',0x668,28,11,0x100376400,'(bvxor #x00008af5 (bvmul ((_ zero_extend 31) '+bit(3)+') #x000001f3))',0x2920),('second_gate',0x80,23,8,0x100552fb8,'(bvxor #x0000bc56 (bvmul ((_ zero_extend 31) '+bit(3)+') #x0000000c))',0x6207)]:
  g=SourceSSA(label,{table_reg:bv(TABLE),25:bv(0xbc56)},presets={off:(bv(0x1010b6380),64)},loads={hex(loadpc):('TARGET',64),hex(0x1003763d4 if label=='first_gate'else 0x100552fa4):(RAW,32)});g.decl.update(CAP=32,TARGET=64);run(g,label);cert(label+'_exact_capability_field_bit3_and_selected_slot',g,[neq(rd(g,0x1003763d4 if label=='first_gate'else 0x100552fa4)['address'],bv(0x1010b6394)),neq(rd(g,loadpc)['address'],'(bvadd '+bv(TABLE)+' (bvshl '+z(indexexpr)+' #x0000000000000003))'),neq(g.get('x17'),bv(div))])
  if label=='first_gate':cert('first_gate_saved_raw_capability_and_initial16_counter',g,[neq(g.loadframe(0x1df4,32),RAW),neq(g.loadframe(0xa90,32),'(bvand CAP #x00000008)'),neq(g.get('x12'),bv(16))])
 solve('raw_capability_bit3_same_bit5_and_bit6_inverted', '(assert (or '+neq('((_ extract 3 3) '+RAW+')',bit(3))+' '+neq('((_ extract 5 5) '+RAW+')','(bvnot '+bit(5)+')')+' '+neq('((_ extract 6 6) '+RAW+')','(bvnot '+bit(6)+')')+'))',extra='(declare-fun CAP () (_ BitVec 32))\n')
 g=SourceSSA('constructor_buffer',{21:bv(0x871a),20:'OFFSET'});g.decl['OFFSET']=64;run(g,'second_constructor',0x100552ddc);B='(bvadd '+frame(0x5f0)+' OFFSET)';cert('second_constructor552_buffer_views_and_bit3_gate_seed',g,[neq(g.get('x22'),B),neq(g.loadframe(0x3f8,64),B),neq(g.loadframe(0x480,64),'(bvadd '+B+' #x0000000000000010)'),neq(g.loadframe(0x488,64),'(bvadd '+B+' #x0000000000000020)'),neq(g.loadframe(0x3f0,64),bv(552)),neq(g.get('w25'),bv(0xbc56,32))])
 g=SourceSSA('entry_control',{20:z('PHASE'),19:z('PREKEY'),0:'R',23:bv(TABLE)},presets={0x698:('CONTEXT',64)},loads={'0x1006349b4':('ENTRYWORD',32),'0x100634a08':('FN',64)});g.decl.update(PHASE=32,PREKEY=32,R=64,CONTEXT=64,ENTRYWORD=32);run(g,'entry_gate',int(fs['entry_gate']['end'],16));phase_p='(bvor (bvsub PHASE #x000096dd) #x0000821a)';phase_n='(bvor (bvsub PHASE #x000089d8) #x00000150)';phase_i='(ite (= CONTEXT #x0000000000000000) (bvxor PHASE '+phase_p+' #x00009381 '+phase_n+') PHASE)';cert('original_constructor_entry_control_and_null_context_phase_formula',g,[neq(g.get('w21'),phase_p),neq(rd(g,0x100634a08)['address'],'(bvadd '+bv(TABLE)+' (bvshl ((_ sign_extend 32) '+phase_i+') #x0000000000000003))')])
 # The eight arithmetic preimages are a scope bound,not native entry evidence.
 q='PHASE';p='(bvor (bvsub PHASE #x000096dd) #x0000821a)';n='(bvor (bvsub PHASE #x000089d8) #x00000150)';ix='(bvxor PHASE '+p+' #x00009381 '+n+')';cases=[0x9bdd,0x9bdf,0x9ddd,0x9ddf,0x1bdd,0x1bdf,0x1ddd,0x1ddf]
 solve('null_context_entry_index9c13_has_exact_eight_phase_preimages','(assert (= '+ix+' #x00009c13))\n(assert (and '+' '.join(neq(q,bv(v,32))for v in cases)+'))',extra='(declare-fun PHASE () (_ BitVec 32))\n')
 # Working modes are source scalars;their identity with packet word0 is unproved.
 g=SourceSSA('clear_mode',{21:bv(0x871a),13:z(RAW),23:bv(TABLE)},loads={'0x1004d0ec4':('FN',64)});g.decl['CAP']=32;run(g,'second_clear');clear='(ite '+yes(1)+' (ite '+yes(6)+' #x00000006 #x00000002) #x00000001)';cert('clear_bit3_source_working_mode_from_decoded_bits1_and6',g,[neq(g.get('w8'),clear),neq(rd(g,0x1004d0ec4)['address'],bv(TABLE+8*0x1d24))])
 g=SourceSSA('post_prefix',{10:bv(0x4aa4),13:z(RAW),23:bv(TABLE)},presets={0x7c:(RAW,32)},loads={'0x10062ab84':('FN',64)});g.decl['CAP']=32;run(g,'second_post');idx5='(ite '+yes(5)+' #x00004aa4 #x00004ab7)';cert('post_prefix_decoded_bit5_selects_working5_or2_and_extended_or_fixed16_path',g,[neq(g.get('w12'),'(ite '+yes(5)+' #x00000005 #x00000002)'),neq(rd(g,0x10062ab84)['address'],'(bvadd '+bv(TABLE)+' (bvshl '+z(idx5)+' #x0000000000000003))')])
 g=SourceSSA('fixed16',{22:'B',24:'(bvadd B #x0000000000000010)',9:bv(0x3a30)});g.decl['B']=64;run(g,'fixed16');bytewrites=[r for r in g.stores if r['width_bits']==8];fixed=bytes.fromhex('4c7c354dbeb671d4a780ab38b965b8db');assert len(bytewrites)==16
 cert('fixed16_all_original_byte_values_and_B16_to31_addresses',g,[v for j,r in enumerate(reversed(bytewrites))for v in[neq(r['address'],'(bvadd B '+bv(16+j)+')'),neq(r['value'],bv(fixed[j],8))]])
 g=SourceSSA('fixed_mode',{10:bv(0x1d24),13:z(RAW),8:bv(6),12:bv(2),23:bv(TABLE)},loads={'0x100316c5c':('FN',64)});g.decl['CAP']=32;run(g,'fixed_join');cert('fixed16_path_selects_working6_or2_from_decoded_bit6',g,[neq(g.get('w8'),'(ite '+yes(6)+' #x00000006 #x00000002)')])
 g=SourceSSA('prefix_setup',{21:bv(0x871a),13:z(RAW),23:bv(TABLE),22:'B',28:'A'},presets={0xf0:('SB',64),0xf8:('SC',64),0x2b0:('CB',64),0x278:(bv(int(s['banks']['LOOPL']['address'],16)),64),0x298:(bv(int(s['banks']['LOOPR']['address'],16)),64)},loads={'0x10047a6c4':('FN',64)});g.decl.update(CAP=32,B=64,A=64,SB=64,SC=64,CB=64);run(g,'second_loop_setup');cert('original_prefix_setup_raw_capability_lifetime_and16_iteration_roots',g,[neq(g.loadframe(0x7c,32),RAW),neq(g.get('x11'),bv(15)),neq(g.get('x0'),bv(0)),neq(g.get('x8'),'(bvadd SC #x0000000000000010)'),neq(g.get('x9'),'(bvadd SB #x0000000000000012)'),neq(g.get('x12'),bv(0x4d44)),neq(g.get('x10'),bv(0x4aa4)),neq(g.get('x22'),'B'),neq(rd(g,0x10047a6c4)['address'],bv(TABLE+8*0x4d4a))])
 # Full source body of the decreasing16-byte loop,including two postindexes.
 ll=int(s['banks']['LOOPL']['address'],16);rr=int(s['banks']['LOOPR']['address'],16);data=int(s['loop_image_data']['address'],16);J='((_ zero_extend 32) IX)';domain=['(bvult IX #x00000010)']
 regs={0:bv(0),11:J,12:bv(0x4d44),13:bv(0xa6),14:bv(0xa5cd4cf),15:bv(0xe4),16:bv(0xfffffffff6fc90b5),6:bv(ll),27:bv(rr),21:bv(POOL),23:bv(TABLE),22:'B',28:'A',9:'(bvadd SB (bvadd '+J+' #x0000000000000003))',8:'(bvadd SC (bvadd '+J+' #x0000000000000001))',26:'CA',25:'CB'}
 g=SourceSSA('prefix_loop',regs,loads={'0x100636ad0':('CAV',32),'0x100636ad4':('CBV',32),'0x100636b18':('BA',8),'0x100636b1c':('BB',8),'0x100636b24':('BC',8)});g.decl.update(B=64,A=64,SB=64,SC=64,CA=64,CB=64,CAV=32,CBV=32,BA=8,BB=8,BC=8)
 for i in fs['second_loop']['instructions'][:-1]:
  pc=int(i['ea'],16)
  if pc in[0x100636ae8,0x100636af0]:supply_bank(g,i,'LOOPL'if pc==0x100636ae8 else'LOOPR')
  if pc==0x100636b00:g.supplied_loads[i['ea']]=(bv(int(rules['LOOP']['target'],16)),64)
  if pc==0x100636b0c:g.supplied_loads[i['ea']]=(lookup(list(bytes.fromhex(s['loop_image_data']['bytes'])),'((_ extract 7 0) IX)',8),8)
  if pc==0x100636b58:g.supplied_loads[i['ea']]=('FN',64);g.decl['FN']=64
  g.run({'instructions':[i]},pc+4)
  if pc==0x100636af8:
   cert('prefix_loop_original_bank_selector_constant5d',g,[neq(g.get('w17'),bv(0x5d,32))]);cuts.append({'site':i['ea'],'register':'w17','original_expression':g.get('w17'),'replacement_u32':0x5d,'fresh_source_proof':pp[-1]['name']});g.put('w17',bv(0x5d,32))
 models['prefix_loop']=g;img=lookup(list(bytes.fromhex(s['loop_image_data']['bytes'])),'((_ extract 7 0) IX)',8);byte='(bvxor (bvxor (bvxor (bvxor '+img+' BA) BB) BC) (bvxor ((_ extract 7 0) (bvmul IX #x0000001f)) #xdf))';wantix='(ite (= IX #x00000000) #x00004d44 #x00004d4a)'
 cert('prefix_loop_all_original_byte_addresses_value_and_control',g,[neq(rd(g,0x100636b00)['address'],bv(int(rules['LOOP']['slot'],16))),neq(rd(g,0x100636b0c)['address'],'(bvadd '+bv(data)+' '+J+')'),neq(rd(g,0x100636b18)['address'],'(bvadd A '+J+')'),neq(rd(g,0x100636b1c)['address'],'(bvadd SB (bvadd '+J+' #x0000000000000003))'),neq(rd(g,0x100636b24)['address'],'(bvadd SC (bvadd '+J+' #x0000000000000001))'),neq(g.stores[0]['address'],'(bvadd B '+J+')'),neq(g.stores[0]['value'],byte),neq(rd(g,0x100636b58)['address'],'(bvadd '+bv(TABLE)+' (bvshl '+z(wantix)+' #x0000000000000003))'),neq(g.get('x11'),'(bvsub '+J+' #x0000000000000001)'),neq(g.get('x9'),'(bvadd SB (bvadd '+J+' #x0000000000000002))'),neq(g.get('x8'),'(bvadd SC '+J+')')],domain)
 loop_ledger=[{'iteration':15-j,'j':j,'destination_offset':j,'image_offset':j,'A_offset':j,'SB_offset':j+3,'SC_offset':j+1,'repeat':j!=0}for j in reversed(range(16))];assert sorted(r['destination_offset']for r in loop_ledger)==list(range(16))
 # Original daemon API bind and complete six formal arguments.
 g=SourceSSA('daemon_API',{20:'CALLBASE',23:bv(TABLE),24:'APIPHASE64',25:bv(0xa6),26:bv(0xa5cd4cf)},presets={0x80:(bv(0x1010b6380),64),0x1c0:(bv(int(s['banks']['CALLL']['address'],16)),64),0x1b8:(bv(int(s['banks']['CALLR']['address'],16)),64),0x3f0:(bv(552),64)},loads={'0x1004789a0':('CV0',32),'0x1004789a8':('CV1',32),'0x1004789d8':('CONNECTION',32),'0x1004789e8':('METHOD',64)});g.decl.update(APIPHASE64=64,CALLBASE=64,CV0=32,CV1=32,CONNECTION=32,METHOD=64)
 for i in fs['api_call']['instructions']:
  pc=int(i['ea'],16)
  if pc>=0x100478a04:break
  if pc in[0x1004789c0,0x1004789d0]:supply_bank(g,i,'CALLL'if pc==0x1004789c0 else'CALLR')
  g.run({'instructions':[i]},pc+4)
 models['daemon_API']=g;cert('daemon_selector21_original_import_slot_connection_and_six_argument_ABI',g,[neq(rd(g,0x1004789e8)['address'],bv(0x1010a0640)),neq(rd(g,0x1004789d8)['address'],bv(0x1010b6384)),neq(g.get('x0'),z('CONNECTION')),neq(g.get('x1'),bv(21)),neq(g.get('x2'),'(bvadd CALLBASE #x0000000000000010)'),neq(g.get('x3'),bv(552)),neq(g.get('x4'),g.get('x2')),neq(g.get('x5'),frame(0x3f0)),neq(g.get('x17'),bv(0x7a6c)),neq(g.loadframe(0x3f0,64),bv(552))])
 # Source reply status codec,independent of protocol/provider embedded status.
 f=fs['api_call'];ii=[i for i in f['instructions']if 0x100478a0c<=int(i['ea'],16)<0x100478a28];g=SourceSSA('API_status',{0:z('STATUS')});g.decl['STATUS']=32;g.run({'instructions':ii},0x100478a28);models['API_status']=g;cert('daemon_transport_status_encoding_is_XOR8b3dc651',g,[neq(g.get('w28'),'(bvxor STATUS #x8b3dc651)')])
 g=SourceSSA('kernel_bad_argument',{0:'UC'});g.decl['UC']=64;ii=[i for i in kf['UserClient']['instructions']if 0xfffffe000a505010<=int(i['ea'],16)<0xfffffe000a50501c];g.run({'instructions':ii},0xfffffe000a50501c);models[g.namespace]=g;cert('kernel_guard_rejection_default_status_is_e00002c2',g,[neq(g.get('x0'),bv(0xe00002c2)),neq(g.get('x8'),'UC')])
 # Kernel admission and provider ABI. No inferred prototype supplies arguments.
 g=SourceSSA('kernel_admission',{1:'IN'},loads={'0xfffffe000a50503c':('COUNT',32)});g.decl.update(COUNT=32,IN=64);ii=[i for i in kf['UserClient']['instructions']if 0xfffffe000a50503c<=int(i['ea'],16)<0xfffffe000a505044];g.run({'instructions':ii},0xfffffe000a505044);models['kernel_admission']=g;cert('kernel_unsigned_input_count_guard',g,[neq(g.flags['hi'],'(bvugt COUNT #x00000200)'),neq(g.reads[0]['address'],'(bvadd IN #x0000000000000220)')])
 reads={'0xfffffe000a505050':(('PROVIDER',64),('TASK',64)),'0xfffffe000a505054':(('H0',32),('H4',32)),'0xfffffe000a505058':('H8',32),'0xfffffe000a505064':('SIGNEDVT',64),'0xfffffe000a50507c':('METHOD',64)}
 g=SourceSSA('kernel_provider_call',{8:'UC',1:'IN',19:'OUT',29:frame(0x30),7:z('COUNT')},loads=reads);g.decl.update(UC=64,IN=64,OUT=64,COUNT=32,PROVIDER=64,TASK=64,H0=32,H4=32,H8=32,SIGNEDVT=64,METHOD=64)
 ii=[i for i in kf['UserClient']['instructions']if 0xfffffe000a505048<=int(i['ea'],16)<0xfffffe000a50509c];g.run({'instructions':ii},0xfffffe000a50509c);models['kernel_provider_call']=g
 want={0:'PROVIDER',1:'TASK',2:z('H0'),3:z('H4'),4:z('H8'),5:'(bvadd IN #x000000000000000c)',6:'(bvadd IN #x0000000000000020)',7:z('COUNT')};cert('kernel_original_eleven_argument_provider_ABI_and_mutable512_capacity',g,[neq(g.get('x'+str(k)),v)for k,v in want.items()]+[neq(r['address'],'(bvadd UC '+bv(0xd8+j*8)+')')for j,r in enumerate(r for r in g.reads if r['site']=='0xfffffe000a505050')]+[neq(r['address'],'(bvadd IN '+bv(j*4)+')')for j,r in enumerate(r for r in g.reads if r['site']=='0xfffffe000a505054')]+[neq(r['original_address'],frame(0x1c))for r in g.auth_normalizations if 'original_address'in r]+[neq(g.loadframe(0,64),'(bvadd OUT #x000000000000000c)'),neq(g.loadframe(8,64),'(bvadd OUT #x0000000000000020)'),neq(g.loadframe(16,64),frame(0x1c)),neq(g.loadframe(0x1c,32),bv(512,32)),neq(rd(g,0xfffffe000a505058)['address'],'(bvadd IN #x0000000000000008)'),neq(rd(g,0xfffffe000a50507c)['address'],'(bvadd VT #x00000000000008b8)')])
 # Tail adapter removes this,shifts ten arguments and moves the final stack pair.
 regs={0:'PROVIDER',1:'TASK',2:z('H0'),3:z('H4'),4:z('H8'),5:'IA',6:'IB',7:z('COUNT')};g=SourceSSA('provider_tail',regs,presets={0:('OA',64),8:('OB',64),16:('LENPTR',64)});g.decl.update(PROVIDER=64,TASK=64,H0=32,H4=32,H8=32,IA=64,IB=64,COUNT=32,OA=64,OB=64,LENPTR=64);ii=[i for i in kf['provider_stub']['instructions']if i['mnemonic']not in['bti','b']];g.run({'instructions':ii},0xfffffe000a504ed0);models['provider_tail']=g
 core={0:'TASK',1:z('H0'),2:z('H4'),3:z('H8'),4:'IA',5:'IB',6:z('COUNT'),7:'OA'};cert('provider_tail_exact_ten_core_arguments_and_stack_pair',g,[neq(g.get('x'+str(k)),v)for k,v in core.items()]+[neq(g.loadframe(0,64),'OB'),neq(g.loadframe(8,64),'LENPTR')])
 # Abstract returning provider owns the mutable count;the wrapper copies it only
 # on provider status0 and then returns outer status0 on both admitted outcomes.
 g=SourceSSA('kernel_result',{0:z('PSTATUS'),19:'OUT'});g.decl.update(PSTATUS=32,OUT=64);ii=[i for i in kf['UserClient']['instructions']if 0xfffffe000a5050a0<=int(i['ea'],16)<0xfffffe000a5050a4];g.run({'instructions':ii},0xfffffe000a5050a4);models['kernel_result']=g;cert('kernel_always_embeds_provider_status_at_output548',g,[neq(g.stores[0]['address'],'(bvadd OUT #x0000000000000224)'),neq(g.stores[0]['value'],'PSTATUS')])
 for success in[False,True]:
  g=SourceSSA('kernel_success'if success else'kernel_error',{19:'OUT',29:frame(0x30),0:z('PSTATUS')},loads={'0xfffffe000a5050a8':('RETURNEDCOUNT',32)});g.decl.update(OUT=64,PSTATUS=32,RETURNEDCOUNT=32)
  ii=[i for i in kf['UserClient']['instructions']if (0xfffffe000a5050a8 if success else 0xfffffe000a5050b0)<=int(i['ea'],16)<=0xfffffe000a5050b0];g.run({'instructions':ii},0xfffffe000a5050b4);models[g.namespace]=g;terms=[neq(g.get('x0'),bv(0))]
  if success:terms+=[neq(g.stores[0]['address'],'(bvadd OUT #x0000000000000220)'),neq(g.stores[0]['value'],'RETURNEDCOUNT'),neq(g.reads[0]['address'],frame(0x1c))]
  else:assert not g.stores
  cert('kernel_'+('success_copies_mutable_count'if success else'provider_error_keeps_count')+'_and_returns_outer_zero',g,terms)
  if success:cert('fixed512_output_count_candidate_refuted',g,[neq(g.stores[0]['value'],bv(512,32))],['(= PSTATUS #x00000000)','(= RETURNEDCOUNT #x00000100)'],result='sat');cert('wrapper_postcall_count_bound_not_enforced_by_this_source',g,['(bvugt '+g.stores[0]['value']+' #x00000200)'],['(= PSTATUS #x00000000)','(= RETURNEDCOUNT #x00000201)'],result='sat')
 # Source pointer/count guard sites are explicit,with separate pre/post-call paths.
 ins={i['ea']:i for i in kf['UserClient']['instructions']}
 for pc,m,op in[(0xfffffe000a50501c,'cbz','x1, #0xfffffe000a5050c4'),(0xfffffe000a505038,'cbz','x2, #0xfffffe000a5050b4'),(0xfffffe000a505044,'b.hi','#0xfffffe000a5050b4'),(0xfffffe000a5050a4,'cbnz','w0, #0xfffffe000a5050b0')]:assert ins[hex(pc)]['mnemonic']==m and ins[hex(pc)]['operands']==op
 assert kf['provider_stub']['instructions'][-1]['operands']=='#0xfffffe000a5a2bac'
 sem={'source_models':{n:g.record_full()for n,g in models.items()},'source_nonbranch_instruction_instances_translated':sum(len(g.sites)for g in models.values()),'fresh_source_bank_cuts':cuts,'literal_bank_read_bindings':bindings,'decreasing_loop_ledger':loop_ledger,'loop_fixed_image_bytes':s['loop_image_data']['bytes'],'fixed16_bytes':fixed.hex(),'capability_bit3_direct_read_sites':['0x1003763d4','0x100552fa4'],'decoded_bit5_has_inverted_raw_test':True,'decoded_bit6_has_inverted_raw_test':True,'local_working_mode_formula':{'bit3_clear':'if C.bit1=0:1;else if C.bit6=1:6;else2','bit3_set':'if C.bit5=1:extended setup carries5;else fixed16 then C.bit6?6:2'},'working_mode_identity_with_wire_word0_proved':False,'daemon_call_PC':'0x100478a04','daemon_selector':21,'daemon_input_bytes':552,'daemon_output_capacity_bytes':552,'daemon_input_output_same_user_pointer':True,'kernel_scalar_input_offsets':[0,4,8],'kernel_input_span_starts':[12,32],'kernel_input_count_offset':544,'kernel_initial_output_capacity':512,'kernel_output_span_starts':[12,32],'kernel_output_count_offset':544,'kernel_embedded_provider_status_offset':548,'kernel_admission_predicate':'IN!=0 && OUT!=0 && u32[IN+544]<=512','kernel_outer_status_on_admitted_return':0,'kernel_outer_status_on_guard_rejection':'0xe00002c2','kernel_success_output_count':'source copies the provider-mutated u32 local;not a fixed512','kernel_error_output_count':'not written by wrapper after provider error','core_argument_count':10,'core_entry':'0xfffffe000a5a2bac','decompiler_fixed512_output_claim_corroborated':False,'same_frame_pointer_lifetime_and_private_call_delta_proved':False,'552_build_buffer_identity_with_API_buffer_proved':False,'complete_mode5_preparation_proved':False,'native_connection_provider_build_pairing_proved':False,'provider_obeys_output_capacity_or_count_bound_proved':False,'Mach_port_emissions':0,'new_IDA_access':True,'premises':['Original images,banks,dispatch words and base-provider vtable describe the pinned builds.','Pointer publications retain their stated pool,index/byte-root domains;same live frame/reaching pointer lifetime is separate.','Second-gate local control W21=871a and table base hold;first-gate table/field roots hold.','Source/API caller records,memory widths and buffer owners are valid and have stated alias/noninterference contracts.','Private helper returns,PAC/canary behavior,callee-saved state and delta/frame correspondence are ordinary-call premises.','The daemon 552-byte construction buffer is not equated with the API buffer without a separate producer/consumer join.','Kernel provider results/count mutations are abstract typed return channels,not native outputs or payloads.']}
 return pp,sem

def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('wrong_bit3',lambda t:next(i for i in t['fragments']['second_gate']['instructions']if i['ea']=='0x100552fa8').__setitem__('operands','w8, w13, #4, #1')),('wrong_count_guard',lambda t:next(i for i in t['kext_fragments']['UserClient']['instructions']if i['ea']=='0xfffffe000a505040').__setitem__('operands','w7, #0x201')),('wrong_count_load',lambda t:next(i for i in t['kext_fragments']['UserClient']['instructions']if i['ea']=='0xfffffe000a5050a8').__setitem__('operands','w8, #0x200')),('wrong_provider_stack',lambda t:next(i for i in t['kext_fragments']['provider_stub']['instructions']if i['ea']=='0xfffffe000a504eb4').__setitem__('operands','x10, x9, [sp]')),('wrong_import',lambda t:next(r for r in t['bank_rules']if r['name']=='CALL').__setitem__('target','0x0')),('wrong_fixed16',lambda t:t['fragments']['fixed16'].__setitem__('bytes','00'+t['fragments']['fixed16']['bytes'][2:])),('missing_census_site',lambda t:t['slot_load_census']['load_sites'].pop()),('invent_native',lambda t:t.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  t=copy.deepcopy(s);fn(t);assert t!=original;out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'source_nonbranch_instruction_instances_translated':sem['source_nonbranch_instruction_instances_translated'],'source_exact_bank_cuts':len(sem['fresh_source_bank_cuts']),'prefix_iterations':16,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json']+DEPS},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'capability_gates_and_selector21_provider_ABI_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
