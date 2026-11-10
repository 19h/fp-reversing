#!/usr/bin/env python3
"""Static source SSA for constant getter routes and conditional daemon cache values."""
import copy,hashlib,json,re,shutil,subprocess
from recover_kext_query_getter_values import ROOT,P,SCOPE,FLAGS,DEPS,OLD,build
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_word_round_tools import FrameSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,neq
from validate_daemon_reader_container_origins import lut
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
POOL=0xfffffe0008471f00;TABLE=0xfffffe0008472f20
CONFIG={
'version_getter':{'tag':'version','start':0xfffffe000a5a29ac,'call':0xfffffe000a5a2b7c,'FP':0x20,'target':0xfffffe000a66a5a8,'diversity':0x5c97,'pairs':[(0xfffffe000a5a29fc,'AL'),(0xfffffe000a5a2a10,'AR'),(0xfffffe000a5a2a44,'DL'),(0xfffffe000a5a2a58,'DR'),(0xfffffe000a5a2b04,'EL'),(0xfffffe000a5a2b18,'ER'),(0xfffffe000a5a2b48,'DL'),(0xfffffe000a5a2b58,'DR')],'cuts':[(0xfffffe000a5a2a18,'w12','version_A'),(0xfffffe000a5a2a60,'w16','version_B'),(0xfffffe000a5a2b20,'w14','version_call'),(0xfffffe000a5a2b60,'w8','version_TABLE')],'pool':[(0xfffffe000a5a2a28,0x880),(0xfffffe000a5a2a3c,0x458),(0xfffffe000a5a2a50,0x638),(0xfffffe000a5a2a68,0xe0),(0xfffffe000a5a2afc,0xc08),(0xfffffe000a5a2b10,0x158),(0xfffffe000a5a2b68,0x198),(0xfffffe000a5a2b70,'version_call')],'data':[(0xfffffe000a5a29b0,0xfffffe000847c5f8),(0xfffffe000a5a29b4,'GPTR'),(0xfffffe000a5a29c0,0xfffffe000ccc3368),(0xfffffe000a5a29c8,0xfffffe000ccc32f8),(0xfffffe000a5a2a2c,0xfffffe000ccc3368),(0xfffffe000a5a2a6c,0xfffffe000ccc32f8),(0xfffffe000a5a2ae8,0xfffffe000ccc3368),(0xfffffe000a5a2aec,0xfffffe000ccc32f8),(0xfffffe000a5a2b28,0xfffffe000ccc3368),(0xfffffe000a5a2b2c,0xfffffe000ccc32f8)]},
'capability_getter':{'tag':'capability','start':0xfffffe000a5a49e8,'call':0xfffffe000a5a4b90,'FP':0x20,'target':0xfffffe000a5c22a8,'diversity':0x7787,'pairs':[(0xfffffe000a5a4a38,'DL'),(0xfffffe000a5a4a4c,'DR'),(0xfffffe000a5a4a84,'AL'),(0xfffffe000a5a4a98,'AR'),(0xfffffe000a5a4b18,'AL'),(0xfffffe000a5a4b28,'AR'),(0xfffffe000a5a4b58,'BL'),(0xfffffe000a5a4b6c,'BR')],'cuts':[(0xfffffe000a5a4a54,'w12','capability_A'),(0xfffffe000a5a4aa0,'w13','capability_B'),(0xfffffe000a5a4b30,'w13','capability_call'),(0xfffffe000a5a4b74,'w8','capability_TABLE')],'pool':[(0xfffffe000a5a4a64,0x8e8),(0xfffffe000a5a4aa8,0xe0),(0xfffffe000a5a4b10,0x840),(0xfffffe000a5a4b24,0xbb8),(0xfffffe000a5a4b7c,0x198),(0xfffffe000a5a4b84,'capability_call')],'data':[(0xfffffe000a5a49ec,0xfffffe000847c5f8),(0xfffffe000a5a49f0,'GPTR'),(0xfffffe000a5a49fc,0xfffffe000ccc3670),(0xfffffe000a5a4a04,0xfffffe000ccc32f8),(0xfffffe000a5a4a68,0xfffffe000ccc3670),(0xfffffe000a5a4aac,0xfffffe000ccc32f8),(0xfffffe000a5a4afc,0xfffffe000ccc3670),(0xfffffe000a5a4b00,0xfffffe000ccc32f8),(0xfffffe000a5a4b38,0xfffffe000ccc3670),(0xfffffe000a5a4b3c,0xfffffe000ccc32f8)]},
'version_adapter':{'tag':'adapter','start':0xfffffe000a66a5bc,'call':0xfffffe000a66a7a8,'FP':0x30,'target':0xfffffe000a5aec10,'diversity':0x3936,'pairs':[(0xfffffe000a66a610,'AL'),(0xfffffe000a66a620,'AR'),(0xfffffe000a66a654,'BL'),(0xfffffe000a66a668,'BR'),(0xfffffe000a66a744,'AL'),(0xfffffe000a66a754,'AR'),(0xfffffe000a66a77c,'AL'),(0xfffffe000a66a784,'AR')],'cuts':[(0xfffffe000a66a628,'w14','adapter_A'),(0xfffffe000a66a670,'w16','adapter_B'),(0xfffffe000a66a75c,'w15','adapter_call'),(0xfffffe000a66a78c,'w8','adapter_TABLE')],'pool':[(0xfffffe000a66a638,0x7d8),(0xfffffe000a66a64c,0x4f0),(0xfffffe000a66a660,0x578),(0xfffffe000a66a678,0xe0),(0xfffffe000a66a73c,0x840),(0xfffffe000a66a750,0xbb8),(0xfffffe000a66a794,0x198),(0xfffffe000a66a79c,'adapter_call')],'data':[(0xfffffe000a66a5c4,0xfffffe000847c5f8),(0xfffffe000a66a5c8,'GPTR'),(0xfffffe000a66a5d4,0xfffffe000ccc7790),(0xfffffe000a66a5dc,0xfffffe000ccc32f8),(0xfffffe000a66a63c,0xfffffe000ccc7790),(0xfffffe000a66a67c,0xfffffe000ccc32f8),(0xfffffe000a66a6d4,'R'),(0xfffffe000a66a728,0xfffffe000ccc7790),(0xfffffe000a66a72c,0xfffffe000ccc32f8),(0xfffffe000a66a764,0xfffffe000ccc7790),(0xfffffe000a66a768,0xfffffe000ccc32f8)]}}

class GetterSSA(FrameSSA):
 def run(self,f,end):
  for original in f['instructions']:
   pc=int(original['ea'],16)
   if pc>=end:break
   m=original['mnemonic'];i={**original,'mnemonic':{'ldur':'ldr','ldurb':'ldrb','stur':'str'}.get(m,m)};p=split(i['operands']);w=32 if p[0].startswith('w')else 64
   if i['mnemonic']=='msub':self.put(p[0],'(bvsub '+self.get(p[3],w)+' (bvmul '+self.get(p[1],w)+' '+self.get(p[2],w)+'))');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self

def certificates(s):
 pp=[];models={};cuts=[];bindings=[];luts=''.join(lut('KG'+name,bytes.fromhex(b['bytes']))for name,b in s['banks'].items());rules={r['name']:r for r in s['bank_rules']};pool={int(r['slot'],16):int(r['value'],16)for r in s['literal_pool_records']}
 for row in s['bank_rules']:pool[int(row['slot'],16)]=int(row['original_pointer']['target'],16)
 def solve(name,body='',extra='',result='unsat',logic='QF_BV'):
  q='(set-option :timeout 45000)\n(set-logic '+logic+')\n'+DECL+extra+body+'\n'+('(check-sat)\n'if logic=='QF_AUFBV'else'(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n');r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.returncode,r.stdout[:1200],r.stderr)
  pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def cert(name,g,terms,result='unsat'):solve(name,g.prefix()+'(assert (or '+' '.join(terms)+'))',luts+''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items()),result=result)
 for label,config in CONFIG.items():
  g=GetterSSA(label,{29:frame(config['FP']),0:'R'});g.decl.update(R=64,GPTR=64);bound=[];data=dict(config['data']);pools=dict(config['pool']);pairs=dict(config['pairs']);cutmap={pc:(reg,rule)for pc,reg,rule in config['cuts']};fr=s['fragments'][label]
  for i in fr['instructions']:
   pc=int(i['ea'],16)
   if not config['start']<=pc<config['call']:continue
   m=i['mnemonic'];p=split(i['operands'])
   if m in['ldr','ldur','ldrb','ldurb']:
    addr=g.address(p[1]);w=8 if m in['ldrb','ldurb']else 32 if p[0].startswith('w')else 64
    if pc in pairs:
     bank=pairs[pc];base=int(s['banks'][bank]['address'],16);ix='((_ extract 7 0) (bvsub '+addr+' '+bv(base)+'))';value='(LUT_KG'+bank+' '+ix+')';bound.append(neq(addr,'(bvadd '+bv(base)+' ((_ zero_extend 56) '+ix+'))'))
    elif pc in pools:
     slot=POOL+pools[pc]if isinstance(pools[pc],int)else int(rules[pools[pc]]['slot'],16);value=bv(pool[slot]);bound.append(neq(addr,bv(slot)));bindings.append({'phase':label,'site':i['ea'],'kind':'original_pool_or_dispatch_pointer','source_address':addr,'expected_address':hex(slot),'normalized_original_value':hex(pool[slot])})
    else:
     expected=data[pc];expect=bv(expected)if isinstance(expected,int)else expected;bound.append(neq(addr,expect));value='GPTR'if expected==0xfffffe000847c5f8 else label+'_INPUT'+str(pc);g.decl[value]=w;bindings.append({'phase':label,'site':i['ea'],'kind':'typed_external_or_controller_snapshot','source_address':addr,'expected_address':hex(expected)if isinstance(expected,int)else expected,'width_bits':w,'input_symbol':value})
    g.supplied_loads[i['ea']]=(value,w)
   g.run({'instructions':[i]},pc+4)
   if pc in cutmap:
    reg,rule=cutmap[pc];constant=int(rules[rule]['constant'],16);original=g.get(reg);cert(label+'_'+rule+'_original_byte_bank_cancels_all_selector_inputs',g,[neq(original,bv(constant,32))]);cuts.append({'phase':label,'site':i['ea'],'register':reg,'original_expression':original,'replacement_u32':constant,'source_proof':pp[-1]['name'],'kind':'Fresh exact universal equality;not a sampled or assumed value.'});g.put(reg,bv(constant,32))
  dests=[frame(0x18),bv({'version_getter':0xfffffe000ccc3368,'capability_getter':0xfffffe000ccc3670,'version_adapter':0xfffffe000ccc7790}[label]),bv(0xfffffe000ccc32f8),frame(0x14 if label=='version_adapter'else 0x10)];assert len(g.stores)==4;bound.extend(neq(row['address'],want)for row,want in zip(g.stores,dests))
  cert(label+'_all_original_bank_pointer_and_data_addresses_and_call_ABI',g,bound+[neq(g.get('x8'),bv(config['target'])),neq(g.get('x0'),frame(0x10)),neq(g.get('x17'),bv(config['diversity']))])
  models[label]=g
 # Record word construction is recovered independently of the constant result.
 r=frame(0x10);key='((_ extract 31 0) '+r+')';g=models['version_getter'];st=next(r for r in g.stores if r['site']=='0xfffffe000a5a2ae4');cert('version_encoded_internal_record_word',g,[neq(st['address'],r),neq(st['value'],'(bvsub (bvmul (bvxor '+key+' #x841cb645) #x440e0fe1) #x007f03ff)')])
 g=models['capability_getter'];st=next(r for r in g.stores if r['site']=='0xfffffe000a5a4af8');cert('capability_encoded_internal_record_word',g,[neq(st['address'],r),neq(st['value'],'(bvsub #x3d7a7ab1 (bvmul (bvxor '+key+' #x6133a0c8) #x84d77373))')])
 # Prove both leaf store values and their untouched return-register channels.
 leafs={}
 for label,value,off in[('capability_leaf',0x1f8,4),('status_leaf',0x158d42ef,0)]:
  g=GetterSSA(label,{0:'R'});g.decl['R']=64;f=s['fragments'][label];ii=[i for i in f['instructions']if i['mnemonic']not in['bti','ret']];g.run({'instructions':ii},int(ii[-1]['ea'],16)+4);assert len(g.stores)==1;cert(label+'_exact_u32_store_and_pointer_return',g,[neq(g.stores[0]['address'],'(bvadd R '+bv(off)+')'),neq(g.stores[0]['value'],bv(value,32)),neq(g.get('x0'),'R')]);models[label]=g;
  if label=='capability_leaf':cert('zero_capability_candidate_refuted_by_original_leaf',g,[neq(g.stores[0]['value'],bv(0,32))],result='sat')
  leafs[label]={'value_u32':hex(value),'offset_bytes':off,'source_store':g.stores[0]['site'],'returned_X0':'unchanged incoming record pointer'}
 f=s['fragments']['version_adapter'];ii=[i for i in f['instructions']if 0xfffffe000a66a7ac<=int(i['ea'],16)<0xfffffe000a66a7b4];g=GetterSSA('version_publication',{19:'R',0:'NESTED'});g.decl.update(R=64,NESTED=64);g.run({'instructions':ii},0xfffffe000a66a7b4);cert('version_adapter_postcall_overwrites_caller_result_with4c0b0000',g,[neq(g.stores[0]['address'],'(bvadd R #x0000000000000004)'),neq(g.stores[0]['value'],'#x4c0b0000'),neq(g.get('x0'),'NESTED')]);models['version_publication']=g;cert('zero_version_candidate_refuted_by_original_postcall_store',g,[neq(g.stores[0]['value'],bv(0,32))],result='sat')
 for label,pc in[('version_getter',0xfffffe000a5a2b80),('capability_getter',0xfffffe000a5a4b94)]:
  i=next(i for i in s['fragments'][label]['instructions']if i['ea']==hex(pc));g=GetterSSA(label+'_returned_word',presets={0x14:('RESULT',32)});g.decl['RESULT']=32;g.run({'instructions':[i]},pc+4);cert(label+'_loads_record_result_as_zero_extended_u32',g,[neq(g.get('x0'),'((_ zero_extend 32) RESULT)'),neq(g.reads[0]['address'],frame(0x14))]);models[label+'_returned_word']=g
 # Exact four-byte little-endian store/load join,independent of the old word.
 body='(define-fun RADDR () (_ BitVec 64) (bvadd K #x0000000000000010))\n';last='MEM'
 for j in range(4):name='M'+str(j);body+='(define-fun '+name+' () (Array (_ BitVec 64) (_ BitVec 8)) (store '+last+' (bvadd RADDR '+bv(4+j)+') ((_ extract '+str(8*j+7)+' '+str(8*j)+') RESULT)))\n';last=name
 parts=['(select '+last+' (bvadd K '+bv(0x14+j)+'))'for j in reversed(range(4))];val=parts[0]
 for part in parts[1:]:val='(concat '+val+' '+part+')'
 solve('internal_result_four_byte_store_equals_enclosing_getter_load',body+'(assert '+neq(val,'RESULT')+')',extra='(declare-fun MEM () (Array (_ BitVec 64) (_ BitVec 8)))\n(declare-fun RESULT () (_ BitVec 32))\n',logic='QF_AUFBV')
 # Ordinary returning helper frames place the nested local48 B below F.
 solve('version_nested_record_does_not_alias_outer_result', '(assert (bvult NBYTE #x0000000000000008))\n(assert (bvult OBYTE #x0000000000000004))\n(assert (= (bvadd (bvsub K #x0000000000000030) NBYTE) (bvadd (bvadd K #x0000000000000014) OBYTE)))',extra='(declare-fun NBYTE () (_ BitVec 64))\n(declare-fun OBYTE () (_ BitVec 64))\n')
 replay=[]
 for parent,name in OLD:
  old=json.loads(read(ROOT/(parent+'_proofs.json')));row=next(r for r in old['proofs']if r['name']==name);original=read(ROOT/row['original_file']);assert hashlib.sha256(original.encode()).hexdigest()==row['original_sha256'];q=re.sub(r'\(set-option :timeout \d+\)','(set-option :timeout 45000)',original);proc=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not proc.returncode and not proc.stderr and proc.stdout.strip()=='unsat',(parent,name,proc.stdout[:800],proc.stderr);pp.append({'name':'replayed_'+parent+'_'+name,'query':q,'result':'unsat','original_query_sha256':row['original_sha256'],'replayed_query':True,'scope':'Retained universal source proposition;no native API result supplied.'});replay.append({'parent':parent,'proposition':name,'original_file':row['original_file']});print(pp[-1]['name'],'unsat',flush=True)
 version=0x4c0b0000;cap=0x1f8;cache={8:((version>>24)+0x0bfd3da4)&0xffffffff,12:(((version>>16)&255)+0x0e62359a)&0xffffffff,16:(((version>>8)&255)+0x0da54c41)&0xffffffff,20:cap^0xc49697f0}
 terms=[neq('(bvadd (bvlshr #x4c0b0000 #x00000018) #x0bfd3da4)',bv(cache[8],32)),neq('(bvadd (bvand (bvlshr #x4c0b0000 #x00000010) #x000000ff) #x0e62359a)',bv(cache[12],32)),neq('(bvadd (bvand (bvlshr #x4c0b0000 #x00000008) #x000000ff) #x0da54c41)',bv(cache[16],32)),neq('(bvxor #x000001f8 #xc49697f0)',bv(cache[20],32)),'(= #x000001f8 #x00000000)'];solve('matched_successful_query_values_specialize_daemon_cache_and_skip_zero_capability_fallback','(assert (or '+' '.join(terms)+'))')
 outcome_cases=[]
 for accept_v in[False,True]:
  for accept_c in[False,True]:
   v=version if accept_v else 0;c=cap if accept_c else 0;encoded=(c^0xc49697f0)if c else(0xc49697f8 if v>>16>=0x2e1e else 0xc49697f0);decoded=encoded^0xc49697f0
   formula='(ite (distinct '+bv(c,32)+' #x00000000) (bvxor '+bv(c,32)+' #xc49697f0) (ite (bvuge (bvlshr '+bv(v,32)+' #x00000010) #x00002e1e) #xc49697f8 #xc49697f0))'
   solve('query_outcomes_version'+str(int(accept_v))+'_capability'+str(int(accept_c)),'(assert '+neq(formula,bv(encoded,32))+')')
   outcome_cases.append({'version_status0_size4':accept_v,'capability_status0_size4':accept_c,'guarded_version_u32':hex(v),'guarded_capability_u32':hex(c),'fallback_entered':not accept_c,'final_encoded_capability_u32':hex(encoded),'decoded_capability_u32':hex(decoded),'native_outcome_observed':False})
 # Exact original prologue/normal-epilogue forms delimit ordinary-return claims.
 structures=[]
 for label,reserve,saves in[('version_getter',0x30,0x20),('capability_getter',0x30,0x20),('version_adapter',0x40,0x30)]:
  f=s['fragments'][label];ii=f['instructions'];assert ii[0]['mnemonic']=='pacibsp'and ii[1]['mnemonic']=='sub'and ii[1]['operands']=='sp, sp, #'+hex(reserve);assert any(i['mnemonic']=='add'and i['operands']=='sp, sp, #'+hex(reserve)for i in ii);assert len([i for i in ii if i['mnemonic']=='blraa'])==1 and len([i for i in ii if i['mnemonic']=='b.ne'])==1 and ii[-2]['mnemonic']=='retab'and ii[-1]['mnemonic']=='bl';structures.append({'phase':label,'stack_reservation_bytes':reserve,'saved_FP_offset':saves,'normal_return':'RETAB after one canary comparison','abnormal_call':ii[-1],'guard_path_observed_natively':False})
 for label,target in[('version_provider_stub',s['fragments']['version_getter']['start']),('capability_provider_stub',s['fragments']['capability_getter']['start'])]:
  ii=s['fragments'][label]['instructions'];assert ii[-1]['mnemonic']=='b'and ii[-1]['operands']=='#'+target
 actual=sum(len(g.sites)for g in models.values());sem={'source_models':{n:g.record_full()for n,g in models.items()},'source_nonbranch_instruction_instances_translated':actual,'bank_selector_cuts':cuts,'all12_bank_cuts_freshly_source_proved':True,'pointer_and_data_read_bindings':bindings,'independent_controller_snapshots_per_read':True,'stable_controller_value_premise_needed_for_selected_constant_targets':False,'original_table_and_pointer_epoch_stability_still_required':True,'version_u32':hex(version),'capability_u32':hex(cap),'leaf_contracts':leafs,'version_adapter_result_store':'0xfffffe000a66a7b0','getter_result_loads':['0xfffffe000a5a2b80','0xfffffe000a5a4b94'],'capability_set_bit_positions':[j for j in range(32)if cap>>j&1],'capability_bit_semantics':'unknown','four_guarded_query_outcomes':outcome_cases,'daemon_encoded_cache_u32':{hex(k):hex(v)for k,v in cache.items()},'daemon_state_marker_after_normal_cache_return':'0x0a','zero_capability_fallback_selected_for_successful_constant_response':False,'predecessor_replays':replay,'structural_return_contracts':structures,'premises':['Original immutable byte banks,decoded pool/dispatch pointers and base-provider vtable route retain their pinned epochs.','All declared memory roots,caller records and frames are valid with the stated disjointness and source-width semantics.','Internal callees return ordinarily,preserve ABI callee-saved registers/SP and do not mutate unrelated caller result/guard state.','Live canary/PAC/loader and native connection/provider identity are separate requirements.','Daemon specialization requires matching these static provider routes,normal IOKit success,size64=4 and the prior daemon entry/frame contracts.'],'whole_native_transaction_observed':False,'hardware_capability_meanings_proved':False,'live_daemon_kext_build_pairing_proved':False,'Mach_port_emissions':0,'new_IDA_access':True,'IDA_observation_repeated_on_validation':False,'IDA_memory_claims_used':0}
 return pp,sem

def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('wrong_version_store',lambda t:next(i for i in t['fragments']['version_adapter']['instructions']if i['ea']=='0xfffffe000a66a7ac').__setitem__('operands','w8, #0')),('wrong_capability',lambda t:t['fragments']['capability_leaf']['instructions'][1].__setitem__('operands','w8, #0')),('wrong_bank',lambda t:t['banks']['AL'].__setitem__('bytes','00'+t['banks']['AL']['bytes'][2:])),('wrong_dispatch_target',lambda t:next(r for r in t['bank_rules']if r['name']=='version_call').__setitem__('target','0x0')),('wrong_discriminator',lambda t:next(r for r in t['bank_rules']if r['name']=='capability_call')['original_pointer'].__setitem__('diversity','0x0')),('wrong_output_load',lambda t:next(i for i in t['fragments']['version_getter']['instructions']if i['ea']=='0xfffffe000a5a2b80').__setitem__('operands','w0, [sp, #0x10]')),('wrong_IDA_identity',lambda t:t['IDA_observation'].__setitem__('input_sha256','0'*64)),('invent_native',lambda t:t.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  t=copy.deepcopy(s);fn(t);assert t!=original;out.append({'name':name,'rejected_by_fresh_source_and_saved_observation_comparison':True})
 return out

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_instruction_instances_translated':sem['source_nonbranch_instruction_instances_translated'],'fresh_source_bank_cuts':12,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json']+DEPS},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'constant_query_getter_values_and_conditional_daemon_cache_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
