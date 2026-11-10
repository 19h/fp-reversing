#!/usr/bin/env python3
"""Static source equations for UserClient task/context publication and teardown."""
import copy,json,re,shutil,subprocess
from recover_userclient_context_lifecycle import ROOT,P,SCOPE,FLAGS,DEPS,build,POOL,TABLE,qword
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_versioned_request_abi import SourceSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq
from validate_daemon_reader_container_origins import lut
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
NAMES={'UC':64,'TASK':64,'PROVIDER':64,'CELL':64,'CTX':64,'ALLOCATED':64,'MODE':32,'BASE_RESULT':32,'RETURN64':64,'HEAD':64,'VT':64,'METACLASS':64,'FN':64,'SECURITY':64,'TYPE64':64,'OLD':64}
DECLARED=set(re.findall(r'\(declare-fun (\w+) ',DECL))
class LifecycleSSA(SourceSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.preindexes=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   m=i['mnemonic'];p=split(i['operands'])
   if m in['ldr','str','strb','ldrb']and len(p)>1:
    decimal=re.fullmatch(r'\[sp, #(\d+)\]',p[1])
    if decimal:
     p[1]='[sp, #'+hex(int(decimal[1]))+']';i={**i,'operands':', '.join(p)}
   if m in['ldr','ldur','str','stur','strb']and p[1].endswith('!'):
    mem=p[1][:-1];base=split(mem.strip('[]'))[0];address=self.address(mem);self.put(base,address);q={**i,'operands':p[0]+', ['+base+']'};super().run({'instructions':[q]},pc+4);self.preindexes.append({'site':i['ea'],'base':base,'writeback_address':address})
   elif m=='cinc':
    w=32 if p[0].startswith('w')else 64;self.put(p[0],'(bvadd '+self.get(p[1],w)+' (ite '+self.flags[p[2]]+' '+bv(1,w)+' '+bv(0,w)+'))');self.sites.append(i['ea'])
   elif m=='tst':
    w=32 if p[0].startswith('w')else 64;value='(bvand '+self.get(p[0],w)+' '+self.get(p[1],w)+')';self.flags={'eq':'(= '+value+' '+bv(0,w)+')','ne':'(distinct '+value+' '+bv(0,w)+')'};self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'original_preindexed_lowerings':self.preindexes}
def certificates(s):
 pp=[];models={};bounds={};cuts=[];bindings=[];fs=s['fragments'];rules={r['name']:r for r in s['bank_rules']};luts=''.join(lut('UC'+n,bytes.fromhex(b['bytes']))for n,b in s['banks'].items())
 extra=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in NAMES.items()if n not in DECLARED);already=DECLARED|set(NAMES)
 def solve(name,body,more='',result='unsat',logic='QF_BV'):
  q='(set-option :timeout 45000)\n(set-logic '+logic+')\n'+DECL+extra+more+body+'\n'+('(check-sat)\n'if logic=='QF_AUFBV'else'(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n');r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-userclient-context-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.returncode,r.stdout[:1500],r.stderr);pp.append({'name':name,'query':q,'result':result,'static_scope':SCOPE});print(name,result,flush=True)
 def cert(name,g,terms,conditions=(),result='unsat'):
  more=luts+''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items()if n not in already);solve(name,g.prefix()+''.join('(assert '+c+')\n'for c in conditions)+'(assert (or '+' '.join(terms)+'))',more,result)
 def new(n,r=None):return LifecycleSSA(n,r)
 def span(label,g,data=None,bank_sites=None,cut_sites=None):
  data=data or{};bank_sites=bank_sites or{};cut_sites=cut_sites or{};bb=[]
  for i in fs[label]['instructions']:
   pc=int(i['ea'],16)
   if pc in data:
    address,value,w=data[pc];value=bv(value,w)if isinstance(value,int)else value;g.supplied_loads[i['ea']]=(value,w)
    if re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',value)and value not in already:g.decl[value]=w
   elif pc in bank_sites:
    name=bank_sites[pc];address=g.address(split(i['operands'])[1]);base=int(s['banks'][name]['address'],16);ix='((_ extract 7 0) (bvsub '+address+' '+bv(base)+'))';bb.append(neq(address,'(bvadd '+bv(base)+' ((_ zero_extend 56) '+ix+'))'));g.supplied_loads[i['ea']]=('(LUT_UC'+name+' '+ix+')',8)
   g.run({'instructions':[i]},pc+4)
   if pc in data:
    expected,value,w=data[pc];rd=g.reads[-1];expected=bv(expected)if isinstance(expected,int)else expected;bb.append(neq(rd['address'],expected));bindings.append({'phase':label,'site':i['ea'],'original_address':rd['address'],'expected_address':expected,'width_bits':w,'source_value':rd['input']})
   if pc in cut_sites:
    reg,rule=cut_sites[pc];value=int(rules[rule]['constant'],16);cert(label+'_'+rule+'_fresh_original_bank_and_address_equality',g,bb+[neq(g.get(reg),bv(value,32))]);cuts.append({'phase':label,'site':i['ea'],'register':reg,'before':g.get(reg),'constant_u32':value,'proof':pp[-1]['name']});g.put(reg,bv(value,32))
  models[label]=g;bounds[label]=bb;return g
 def pool(site,off):return(site,(POOL+off,qword(POOL+off),64))
 def rule(site,n):
  r=rules[n];return(site,(int(r['slot'],16),int(r['original_pointer']['target'],16),64))
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 def st(g,pc):return next(r for r in g.stores if r['site']==hex(pc))
 add=lambda a,o:'(bvadd '+a+' '+(bv(o)if isinstance(o,int)else o)+')'
 g=span('init_base_ABI',new('init_base',{19:'UC',20:'TASK',23:'SECURITY',22:'TYPE64'}),{0xfffffe000a5042a8:(0xfffffe000847c5e0,0xfffffe0007f55690,64),0xfffffe000a5042b0:(0xfffffe0007f55fb8,0xfffffe000c562a20,64)})
 cert('initializer_same_task_security_and_type_to_exact_base_initializer',g,bounds['init_base_ABI']+[neq(g.get('x0'),'UC'),neq(g.get('x1'),'TASK'),neq(g.get('x2'),'SECURITY'),neq(g.get('x3'),'TYPE64'),neq(g.get('x8'),bv(0xfffffe000c562a20))])
 g=span('init_success',new('init_success',{19:'UC',20:'TASK'}));cert('initializer_success_publishes_raw_task_zero_provider_and_live_byte',g,[neq(st(g,0xfffffe000a5042e0)['address'],add('UC',0xd8)),neq(g.stores[0]['value'],bv(0)),neq(g.stores[1]['address'],add('UC',0xe0)),neq(g.stores[1]['value'],'TASK'),neq(st(g,0xfffffe000a5042e8)['address'],add('UC',0xf4)),neq(st(g,0xfffffe000a5042e8)['value'],bv(0,8)),neq(g.get('w0'),bv(1,32))])
 g=span('start_zero',new('start_zero',{0:'UC',1:'PROVIDER'}),{0xfffffe000a504348:(add('UC',0xf0),'MODE',32)});cert('start_publishes_empty_context_cell_and_reads_mode32',g,bounds['start_zero']+[neq(g.stores[0]['address'],add('UC',0xe8)),neq(g.stores[0]['value'],bv(0)),neq(g.get('x19'),add('UC',0xe8))])
 g=span('start_mode_clear',new('start_mode_clear',{20:'UC'}));cert('nonone_mode_arm_stores_zero32',g,[neq(g.stores[0]['address'],add('UC',0xf0)),neq(g.stores[0]['value'],bv(0,32))])
 g=span('start_base',new('start_base',{20:'UC',21:'PROVIDER'}),{0xfffffe000a50435c:(0xfffffe000847c5e0,0xfffffe0007f55690,64),0xfffffe000a504364:(0xfffffe0007f55c90,0xfffffe000c4d82b0,64)});cert('start_exact_super_call_ABI',g,bounds['start_base']+[neq(g.get('x0'),'UC'),neq(g.get('x1'),'PROVIDER'),neq(g.get('x8'),bv(0xfffffe000c4d82b0))])
 g=span('start_cast',new('start_cast',{20:'UC',21:'PROVIDER'}),{0xfffffe000a504388:(0xfffffe000846b8b0,0xfffffe000ccc7878,64)});cert('start_exact_safeMetaCast_arguments',g,bounds['start_cast']+[neq(g.get('x0'),'PROVIDER'),neq(g.get('x1'),bv(0xfffffe000ccc7878))])
 # The call at 4390 is an external safeMetaCast. Its return in X0,not its input,
 # is the value stored at 4394. The preceding straight-line model is split here.
 g=LifecycleSSA('cast_return',{0:'PROVIDER',20:'UC'});g.run({'instructions':[i for i in s['functions']['start']['instructions']if i['ea']=='0xfffffe000a504394']},0xfffffe000a504398);models['cast_return']=g;cert('actual_cast_return_store_at_provider_field',g,[neq(g.stores[0]['address'],add('UC',0xd8)),neq(g.stores[0]['value'],'PROVIDER')])
 g=span('start_provider',new('start_provider',{0:'PROVIDER',19:add('UC',0xe8),20:'UC'}),{0xfffffe000a50439c:(add('UC',0xf0),'MODE',32),0xfffffe000a5043a0:(add('UC',0xe0),'TASK',64),0xfffffe000a5043a4:('PROVIDER','OLD',64),0xfffffe000a5043bc:(add('VT',0xa10),0xfffffe000a505184,64)});cert('start_exact_provider_cell_mode_and_task_ABI',g,bounds['start_provider']+[neq(g.get('x0'),'PROVIDER'),neq(g.get('x1'),add('UC',0xe8)),neq(g.get('x2'),z('MODE')),neq(g.get('x3'),'TASK'),neq(g.get('x8'),bv(0xfffffe000a505184))])
 g=span('start_return',new('start_return',{0:'RETURN64'}));cert('start_overwrites_helper_status_with_success_one',g,[neq(g.get('x0'),bv(1))])
 g=span('start_adapter',new('start_adapter',{1:'CELL',2:z('MODE'),3:'TASK'}));cert('start_adapter_removes_this_and_forwards_cell_mode_task',g,[neq(g.get('x0'),'CELL'),neq(g.get('x1'),z('MODE')),neq(g.get('x2'),'TASK')])
 g=span('stop_provider',new('stop_provider',{0:'UC',1:'PROVIDER'}),{0xfffffe000a5043fc:(add('UC',0xd8),'PROVIDER',64),0xfffffe000a504400:('PROVIDER','OLD',64),0xfffffe000a504418:(add('VT',0xa18),0xfffffe000a505178,64)});cert('stop_exact_provider_context_cell_ABI',g,bounds['stop_provider']+[neq(g.get('x0'),'PROVIDER'),neq(g.get('x1'),add('UC',0xe8)),neq(g.get('x8'),bv(0xfffffe000a505178))])
 g=span('stop_adapter',new('stop_adapter',{1:'CELL'}));cert('stop_adapter_removes_this_and_forwards_cell',g,[neq(g.get('x0'),'CELL')])
 g=span('stop_base',new('stop_base',{20:'UC',19:'PROVIDER',0:'RETURN64'}),{0xfffffe000a50442c:(0xfffffe000847c5e0,0xfffffe0007f55690,64),0xfffffe000a504434:(0xfffffe0007f55c98,0xfffffe000c4d8288,64)});cert('stop_ignores_helper_result_and_calls_exact_super',g,bounds['stop_base']+[neq(g.get('x0'),'UC'),neq(g.get('x1'),'PROVIDER'),neq(g.get('x8'),bv(0xfffffe000c4d8288))])
 g=span('stop_clear',new('stop_clear',{20:'UC',0:'RETURN64'}));cert('stop_clears_provider_and_task_after_base_return',g,[neq(g.stores[0]['address'],add('UC',0xd8)),neq(g.stores[1]['address'],add('UC',0xe0)),neq(g.stores[0]['value'],bv(0)),neq(g.stores[1]['value'],bv(0)),neq(g.get('x0'),'RETURN64')])
 g=span('died_tail',new('died_tail',{0:'UC'}),{0xfffffe000a5044b0:(0xfffffe000847c5e0,0xfffffe0007f55690,64),0xfffffe000a5044b8:(0xfffffe0007f55fc8,0xfffffe000c5629b8,64)});cert('clientDied_sets_byte_and_delegates_without_clearing_task',g,bounds['died_tail']+[neq(g.stores[0]['address'],add('UC',0xf4)),neq(g.stores[0]['value'],bv(1,8)),neq(g.get('x0'),'UC'),neq(g.get('x16'),bv(0xfffffe000c5629b8))])
 # Fresh exact bank reductions preserve independent controller snapshots per read.
 data={0xfffffe000a5b6320:(0xfffffe000ccc3388,'C_A',32),0xfffffe000a5b6328:(0xfffffe000ccc32f8,'C_B',32),0xfffffe000a5b6374:(0xfffffe000ccc3388,'Q_A',64),0xfffffe000a5b63b4:(0xfffffe000ccc32f8,'Q_B',64),0xfffffe000a5b63f4:(0xfffffe000ccc3388,'C_C',32),0xfffffe000a5b63f8:(0xfffffe000ccc32f8,'C_D',32),**dict([rule(0xfffffe000a5b6370,'CA'),pool(0xfffffe000a5b6384,0xf50),pool(0xfffffe000a5b6398,0xf20),rule(0xfffffe000a5b63b0,'CB'),rule(0xfffffe000a5b6438,'CT')]),0xfffffe000a5b6440:(add(bv(TABLE),'((_ zero_extend 32) (bvmul (bvxor #x000004cf (ite (distinct CELL #x0000000000000000) #x0000001b #x00000000)) #x00000008))'),'FN',64)}
 g=span('create_entry',new('create_entry',{0:'CELL',1:z('MODE'),2:'TASK'}),data,{0xfffffe000a5b6344:'AL',0xfffffe000a5b6358:'AR',0xfffffe000a5b638c:'BL',0xfffffe000a5b63a0:'BR',0xfffffe000a5b6414:'TL',0xfffffe000a5b6428:'TR'},{0xfffffe000a5b6360:('w11','CA'),0xfffffe000a5b63a8:('w15','CB'),0xfffffe000a5b6430:('w14','CT')});cert('context_create_entry_exact_controller_stores_table_and_null_cell_gate',g,bounds['create_entry']+[neq(g.get('x22'),bv(TABLE)),neq(g.get('w0'),bv(-0xa427,32)),neq(g.stores[0]['address'],bv(0xfffffe000ccc3388)),neq(g.stores[1]['address'],bv(0xfffffe000ccc32f8)),neq(g.get('x17'),bv(0x7e13))])
 gg=copy.deepcopy(g);data={0xfffffe000a5b6474:(0xfffffe000ccc3388,'C_E',32),0xfffffe000a5b6478:(0xfffffe000ccc32f8,'C_F',32),**dict([pool(0xfffffe000a5b6488,0x840),pool(0xfffffe000a5b6498,0xbb8),rule(0xfffffe000a5b64ac,'ALLOC'),pool(0xfffffe000a5b64bc,0xb70),pool(0xfffffe000a5b64cc,0xa10),rule(0xfffffe000a5b64e4,'ADESC')])};g=span('create_alloc',gg,data,{0xfffffe000a5b6490:'TL',0xfffffe000a5b649c:'TR',0xfffffe000a5b64c4:'AL',0xfffffe000a5b64d0:'AR'},{0xfffffe000a5b64a4:('w13','ALLOC'),0xfffffe000a5b64dc:('w8','ADESC')});cert('context_create_exact_typed_allocator_descriptor_and_saved_mode_task',g,bounds['create_alloc']+[neq(g.get('x13'),bv(0xfffffe000c4ba154)),neq(g.get('x0'),bv(0xfffffe000847b860)),neq(g.get('w21'),'MODE'),neq(g.get('x19'),'TASK'),neq(g.get('x20'),'CELL'),neq(g.get('x17'),bv(0xd0c8))])
 gg=copy.deepcopy(g);gg.put('x0','ALLOCATED');g=span('create_status',gg,{0xfffffe000a5b650c:(add(bv(TABLE),'((_ zero_extend 32) (bvmul (bvxor #x00000ca2 (ite (= ALLOCATED #x0000000000000000) #x00000008 #x00000000)) #x00000008))'),'FN',64)});cert('context_create_null_allocation_gate_and_raw_error',g,bounds['create_status']+[neq(g.get('w0'),bv(-0xa42c,32)),neq(g.get('x8'),'ALLOCATED'),neq(g.get('x17'),bv(0x35cc))])
 g=span('create_publish',new('create_publish',{8:'ALLOCATED',19:'TASK',20:'CELL',21:z('MODE'),22:bv(TABLE),23:bv(0x4cf)}),{0xfffffe000a5b6534:(TABLE+8*0x4cf,0xfffffe000a5b6540,64)});cert('context_success_exact24_byte_head_mode_task_and_cell_publication',g,bounds['create_publish']+[neq(g.stores[0]['address'],'ALLOCATED'),neq(g.stores[0]['value'],bv(0)),neq(g.stores[1]['address'],add('ALLOCATED',8)),neq(g.stores[1]['value'],'MODE'),neq(g.stores[2]['address'],add('ALLOCATED',16)),neq(g.stores[2]['value'],'TASK'),neq(g.stores[3]['address'],'CELL'),neq(g.stores[3]['value'],'ALLOCATED'),neq(g.get('w0'),bv(0,32))])
 data={0xfffffe000a626698:(0xfffffe000ccc3330,'D_A',32),0xfffffe000a6266a0:(0xfffffe000ccc32f8,'D_B',32),0xfffffe000a6266ec:(0xfffffe000ccc3330,'DQ_A',64),0xfffffe000a626720:(0xfffffe000ccc32f8,'DQ_B',64),0xfffffe000a626760:(0xfffffe000ccc3330,'D_C',32),0xfffffe000a626764:(0xfffffe000ccc32f8,'D_D',32),**dict([rule(0xfffffe000a6266e8,'DA'),rule(0xfffffe000a62671c,'DB'),rule(0xfffffe000a626790,'DT')]),0xfffffe000a626798:(add(bv(TABLE),'((_ zero_extend 32) (bvmul (bvxor #x00000aab (ite (distinct CELL #x0000000000000000) #x0000007e #x00000000)) #x00000008))'),'FN',64)}
 g=span('destroy_entry',new('destroy_entry',{0:'CELL'}),data,{0xfffffe000a6266bc:'TL',0xfffffe000a6266d0:'TR',0xfffffe000a626700:'TL',0xfffffe000a62670c:'TR',0xfffffe000a626778:'TL',0xfffffe000a626780:'TR'},{0xfffffe000a6266d8:('w9','DA'),0xfffffe000a626714:('w11','DB'),0xfffffe000a626788:('w8','DT')});cert('context_destroy_exact_roots_and_null_cell_gate',g,bounds['destroy_entry']+[neq(g.get('x27'),bv(TABLE)),neq(g.get('w8'),bv(-0xa427,32)),neq(g.get('x2'),bv(0xfffffe000ccc32f8)),neq(g.get('x3'),bv(0xfffffe000ccc3330))])
 g=span('destroy_cell',copy.deepcopy(g),{0xfffffe000a6267b0:('CELL','CTX',64),0xfffffe000a6267c0:(add(bv(TABLE),'((_ zero_extend 32) (bvmul (ite (distinct CTX #x0000000000000000) #x0000059f #x0000059e) #x00000008))'),'FN',64)});cert('context_destroy_reads_cell_and_returns_zero_for_empty_cell',g,bounds['destroy_cell']+[neq(g.get('w8'),bv(0,32)),neq(g.get('x11'),'CTX')])
 g=span('destroy_head',copy.deepcopy(g),{0xfffffe000a6267f0:('CTX','HEAD',64),**dict([pool(0xfffffe000a626818,0x458),pool(0xfffffe000a626820,0x638)]),0xfffffe000a62680c:(add(bv(TABLE),'((_ zero_extend 32) (bvmul (ite (= HEAD #x0000000000000000) #x00000980 #x000009a4) #x00000008))'),'FN',64)});cert('context_destroy_empty_head_selects_typed_free_and_saves_cell',g,bounds['destroy_head']+[neq(g.stores[-4]['address'],add('K',0x50)),neq(g.get('w21'),bv(0x58c,32))])
 data={0xfffffe000a62683c:(0xfffffe000ccc3330,'D_E',32),0xfffffe000a626840:(0xfffffe000ccc32f8,'D_F',32),**dict([rule(0xfffffe000a626878,'FREE'),pool(0xfffffe000a626888,0xf50),pool(0xfffffe000a62689c,0xf20),rule(0xfffffe000a6268b4,'FDESC')])};g=span('destroy_free',copy.deepcopy(g),data,{0xfffffe000a626858:'FL',0xfffffe000a626868:'FR',0xfffffe000a626890:'BL',0xfffffe000a6268a4:'BR'},{0xfffffe000a626870:('w10','FREE'),0xfffffe000a6268ac:('w8','FDESC')});cert('context_destroy_empty_head_exact_typed_free_ABI',g,bounds['destroy_free']+[neq(g.get('x0'),bv(0xfffffe000847c260)),neq(g.get('x1'),'CTX'),neq(g.get('x10'),bv(0xfffffe000c4ba368)),neq(g.get('x17'),bv(0x4d6a))])
 g.put('x0','RETURN64');g=span('destroy_clear',copy.deepcopy(g),{0xfffffe000a6268d4:(TABLE+8*0x58c,0xfffffe000a6268e0,64)});cert('context_destroy_after_free_clears_original_cell_and_returns_zero',g,bounds['destroy_clear']+[neq(st(g,0xfffffe000a6268d0)['address'],'CELL'),neq(st(g,0xfffffe000a6268d0)['value'],bv(0)),neq(g.get('w8'),bv(0,32))]);g=span('destroy_return',g);cert('context_destroy_normal_epilogue_uses_raw_status_in_w8',g,[neq(g.get('x0'),bv(0))])
 g=new('typed_allocator_adapter',{0:bv(0xfffffe000847b860)});g.supplied_loads['0xfffffe000c4ba158']=(bv(s['typed_descriptors'][0]['flags_u32'],32),32)
 g.run({'instructions':s['kernel_functions']['allocate_adapter']['instructions'][1:-1]},0xfffffe000c4ba16c);models['typed_allocator_adapter']=g
 cert('typed_allocator_descriptor_flags_select8004_without_task_argument',g,[neq(g.reads[0]['address'],bv(0xfffffe000847b888)),neq(g.get('x0'),bv(0xfffffe000847b860)),neq(g.get('w1'),bv(0x8004,32))])
 # Compose source-proved stores in byte memory. The cell must not overwrite
 # the allocated object. This is an explicit disjointness premise.
 index='((_ zero_extend 32) JBYTE)';address='(ite ROOT_CELL '+add('CELL',index)+' '+add('ALLOCATED',index)+')';body='(define-fun READ_ADDRESS () (_ BitVec 64) '+address+')\n';value='OLD_BYTE';serial=0
 for base,word,w in [('ALLOCATED',bv(0),64),(add('ALLOCATED',8),'MODE',32),(add('ALLOCATED',16),'TASK',64),('CELL','ALLOCATED',64)]:
  for j in range(w//8):
   name='BYTE'+str(serial);serial+=1;body+='(define-fun '+name+' () (_ BitVec 8) (ite (= READ_ADDRESS '+add(base,j)+') ((_ extract '+str(j*8+7)+' '+str(j*8)+') '+word+') '+value+'))\n';value=name
 def wordbyte(word,offset,w):
  ix='(bvsub JBYTE '+bv(offset,32)+')';ix=ix if w==32 else'((_ zero_extend 32) '+ix+')';return'((_ extract 7 0) (bvlshr '+word+' (bvmul '+ix+' '+bv(8,w)+')))'
 expected='(ite ROOT_CELL '+wordbyte('ALLOCATED',0,64)+' (ite (bvult JBYTE #x00000008) #x00 (ite (bvult JBYTE #x0000000c) '+wordbyte('MODE',8,32)+' (ite (bvult JBYTE #x00000010) OLD_BYTE '+wordbyte('TASK',16,64)+'))))'
 body+='(assert (bvult JBYTE (ite ROOT_CELL #x00000008 #x00000018)))\n(assert (bvuge (bvsub CELL ALLOCATED) #x0000000000000018))\n(assert (bvuge (bvsub ALLOCATED CELL) #x0000000000000008))\n(assert '+neq(value,expected)+')'
 solve('context_publication_byte_join_preserves_empty_head_mode_task_and_unwritten_padding',body,'(declare-fun JBYTE () (_ BitVec 32))\n(declare-fun ROOT_CELL () Bool)\n(declare-fun OLD_BYTE () (_ BitVec 8))\n')
 # Byte-store/load composition is independent of the old bytes. It requires
 # the separately stated object/lifetime/noninterference premises.
 body='';last='MEM'
 for j in range(8):
  n='M'+str(j);body+='(define-fun '+n+' () (Array (_ BitVec 64) (_ BitVec 8)) (store '+last+' '+add('UC',0xe0+j)+' ((_ extract '+str(j*8+7)+' '+str(j*8)+') TASK)))\n';last=n
 terms=['(select '+last+' '+add('UC',0xe0+j)+')'for j in reversed(range(8))];value=terms[0]
 for t in terms[1:]:value='(concat '+value+' '+t+')'
 solve('initializer_task_byte_store_to_selector21_task_load',body+'(assert '+neq(value,'TASK')+')','(declare-fun MEM () (Array (_ BitVec 64) (_ BitVec 8)))\n',logic='QF_AUFBV')
 solve('task64_does_not_reduce_to_user_mach_name32','(assert (distinct TASK ((_ zero_extend 32) ((_ extract 31 0) TASK))))',result='sat')
 solve('abstract_helper_allocation_failure_does_not_change_start_return_one',models['start_return'].prefix()+'(assert (= ALLOCATED #x0000000000000000))\n(assert (= BASE_RESULT #x00000001))\n(assert (distinct PROVIDER #x0000000000000000))\n(assert (= '+models['start_return'].get('x0')+' #x0000000000000001))',result='sat')
 # Replay the immediate downstream task forwarding,without claiming a live call.
 prior=json.loads(read(ROOT/'versioned_request_abi_checks.json'));replays=[]
 for n in ['kernel_original_eleven_argument_provider_ABI_and_mutable512_capacity','provider_tail_exact_ten_core_arguments_and_stack_pair']:
  row=next(p for p in prior['proofs']if p['name']==n);q=row['query'];r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({'name':'replayed_'+n,'query':q,'result':'unsat','replayed_query':True,'original_query_sha256':__import__('hashlib').sha256(q.encode()).hexdigest(),'static_scope':SCOPE});replays.append(n)
 sem={'source_models':{n:g.record_full()for n,g in models.items()},'source_instruction_instances_translated':sum(len(g.sites)for g in models.values()),'distinct_source_instruction_sites_translated':len({pc for g in models.values()for pc in g.sites}),'fresh_bank_cuts':cuts,'read_bindings':bindings,'context_size_bytes':24,'context_field_offsets':{'head_u64':0,'mode_u32':8,'unwritten_padding_start':12,'task_u64':16},'UserClient_field_offsets':{'provider_u64':216,'task_u64':224,'context_u64':232,'mode_u32':240,'died_u8':244},'allocation_descriptor':hex(0xfffffe000847b860),'free_descriptor':hex(0xfffffe000847c260),'descriptor_bytes_equal_in_source':True,'raw_status_null_cell_u32':hex((-0xa427)&0xffffffff),'raw_status_null_allocation_u32':hex((-0xa42c)&0xffffffff),'raw_success_u32':0,'typed_allocator_flags_for_descriptor':0x8004,'start_after_ordinary_helper_return':1,'empty_head_cleanup_proved':True,'populated_list_cleanup_proved':False,'native_allocation_failure_observed':False,'task_reference_balance_proved':False,'runtime_provider_identity_proved':False,'Mach_port_emissions':0,'predecessor_replays':replays,'source_only_no_CPU_execution':True}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('task_store_width',lambda t:next(i for i in t['functions']['initializer']['instructions']if i['ea']=='0xfffffe000a5042e0').__setitem__('operands','wzr, w20, [x19, #0xd8]')),('start_return',lambda t:t['fragments']['start_return']['instructions'][0].__setitem__('operands','w0, #0')),('task_field',lambda t:next(i for i in t['functions']['start']['instructions']if i['ea']=='0xfffffe000a5043a0').__setitem__('operands','x3, [x20, #0xe8]')),('bank_byte',lambda t:t['banks']['AL'].__setitem__('bytes','00'+t['banks']['AL']['bytes'][2:])),('context_size',lambda t:t['typed_descriptors'][0].__setitem__('size_u32',32)),('free_target',lambda t:next(r for r in t['bank_rules']if r['name']=='FREE').__setitem__('target','0x0')),('invent_native',lambda t:t.__setitem__('target_executed',True))];out=[]
 for n,fn in cases:
  t=copy.deepcopy(s);fn(t);assert t!=original;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);actual={pc for m in sem['source_models'].values()for pc in m['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']}|{'0xfffffe000a504394'}|{i['ea']for i in s['kernel_functions']['allocate_adapter']['instructions'][1:-1]};assert actual==expected,(actual-expected,expected-actual);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'source_instruction_instances_translated':sem['source_instruction_instances_translated'],'distinct_source_instruction_sites_translated':sem['distinct_source_instruction_sites_translated'],'fresh_bank_cuts':len(sem['fresh_bank_cuts']),'predecessor_queries_replayed':2,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json']+DEPS},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'userclient_task_context_lifecycle_proved':True,'complete_operation_proved':False,**{n:False for n in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
