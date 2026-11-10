#!/usr/bin/env python3
"""Full static four-round prefix contracts and case-split address-mask identities."""
import copy,json,re,subprocess,shutil,functools
from recover_daemon_mode_one_record_long_prefix import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_join import JoinSSA
from validate_daemon_existing_scalar_reader import DECL,bv,frame,neq,at
from daemon_mode_one_handoff_tools import parse
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
EXTRA='(declare-fun PBUF () (_ BitVec 64))\n(declare-fun FN_EXIT () (_ BitVec 64))\n(declare-fun COUNT () (_ BitVec 32))\n'
DATA=[0x6cc,8,0x10,0x6c4,0x6c0,0xc,0x6bc,0x6c8]
class PrefixSSA(JoinSSA):
 def __init__(self,*args,**kw):super().__init__(*args,**kw);self.extra_lowerings=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   p=split(i['operands']);m=i['mnemonic']
   if m=='str'and p[1]=='[sp, #8]':
    self.extra_lowerings.append({'site':i['ea'],'kind':'decimal_SP_offset','original_address':self.address(p[1]),'frame_offset':8});super().run({'instructions':[{**i,'operands':p[0]+', [sp, #0x8]'}]},pc+4)
   elif m=='ldp':
    assert pc==0x100dad2c8 and p==['w10','w9','[sp, #0x14]'];self.extra_lowerings.append({'site':i['ea'],'kind':'pair_u32_load','frame_offsets':[0x14,0x18]})
    for j in range(2):super().run({'instructions':[{**i,'mnemonic':'ldr','operands':p[j]+', [sp, #'+hex(0x14+4*j)+']'}]},pc+4)
    self.sites.pop()
   elif m=='eon':
    w=32 if p[0].startswith('w')else 64;self.put(p[0],f'(bvxor {self.get(p[1],w)} (bvnot {self.operand(p[2],w,p[3]if len(p)>3 else None)}))');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'additional_source_lowerings':self.extra_lowerings}
def emit(a):return'('+' '.join(map(emit,a))+')'if isinstance(a,list)else a
def renamed(text,names,suffix,replace=None):
 replace=replace or{};return re.sub(r'\b\w+\b',lambda m:replace[m[0]]if m[0]in replace else m[0]+suffix if m[0]in names else m[0],text)
def dependency_census(source,declared,expressions):
 defs={a[1]:a[-1]for a in map(parse,source.splitlines())}
 @functools.lru_cache(None)
 def atom(a):return{a}if a in declared else walk(defs[a])if a in defs else set()
 def walk(a):return set().union(*(walk(v)for v in a))if isinstance(a,list)else atom(a)
 return[sorted(walk(parse(e)))for e in expressions]
def certificates(s):
 pp=[];models={};fs=s['fragments'];rounds=[]
 def solve(name,body,result='unsat',values=None,extra=''):
  query='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+extra+body+'\n(check-sat)\n'
  if values is not None:query+='(get-value ('+' '.join(values)+'))\n'
  r=subprocess.run([SOLVER,'-in'],input=query,text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr,(name,r.stdout,r.stderr);record={'name':name,'query':query,'result':result,'scope':SCOPE}
  if values is None:assert r.stdout.strip()==result,(name,r.stdout)
  else:
   assert result=='sat'and r.stdout.startswith('sat\n'),(name,r.stdout);v=parse(r.stdout[4:]);assert len(v)==len(values);record['model_value_hex']=[row[-1]for row in v];assert all(re.fullmatch('#x[0-9a-f]+',x)for x in record['model_value_hex'])
  pp.append(record);print(name,result,flush=True);return record
 def declarations(g):return''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())
 def cert(name,g,terms):return solve(name,g.prefix()+'(assert (or '+' '.join(terms)+'))',extra=declarations(g))
 def run(g,label):f=fs[label];g.run(f,int(f['instructions'][-1]['ea'],16));assert not g.initial;return g
 def chained(old,label,loads=None):
  g=PrefixSSA(label,old.r,loads=loads);g.defs=list(old.defs);g.decl=dict(old.decl);g.byte_cells=dict(old.byte_cells);g.loaded=old.loaded;return g
 from recover_daemon_mode_one_record_long_planes import build as previous_build
 from validate_daemon_mode_one_record_long_planes import certificates as previous_certificates
 old=previous_build();assert old==json.loads(read(ROOT/DEPS[0]));prior=json.loads(read(ROOT/DEPS[1]));bp,bs=previous_certificates(old);assert bp==prior['proofs']and json.loads(json.dumps(bs))==prior['semantics'];pp.extend({**v,'name':'replayed_long_planes_'+v['name'],'replayed_query':True}for v in bp)
 assert bs['F730']=='0x67f0'and bs['actual_long_entry_target']=='0x100c9148c'
 prior_written={r['frame_offset']+j for r in bs['source_model']['frame_writes']for j in range(r['width_bits']//8)};assert not prior_written&set(range(0x2cc,0x2d0))
 presets={0x730:(bv(0x67f0,32),32),0x740:('TABLE',64),0x748:('PBUF',64),0x750:(frame(0xd10),64),0x2cc:(bv(0x0c392ed3,32),32),0x18:(bv(0x53921748,32),32)}
 seed=run(PrefixSSA('prefix_seed',{6:bv(0x53921748)},presets=presets,loads={'0x100c9174c':('FN',64)}),'seed');models['seed']=seed;assert len(seed.stores)==len(seed.frame_writes)==47 and len(seed.frame_reads)==3 and len(seed.reads)==4
 const=[r for r in seed.frame_writes if r['frame_offset']not in DATA];assert len(const)==39
 fixed={12:0,1:0x0cb55635,14:0x7d269bca,13:0xb2054,11:0,10:0x4923,16:0xc09be,0:0xb1cf2,23:0xc065c,2:0xb1990,3:0xc02fa,5:0xb162e,6:0xbff98,7:0xb12cc,20:0xbfc36,25:0xb0f6a,15:0x453a3898,19:0x0be7880c,24:866,4:0x8864298f,26:0x324a764c67af2e0e,21:0xa7bebfcf1750d389,22:0xb6dc5654307e7f72,17:0x373d}
 values=solve('seed_saved_constant_candidates',seed.prefix(),result='sat',values=[r['value']for r in const])['model_value_hex'];cc=[int(v[2:],16)for v in values]
 cert('seed_all39_constants_full_counter_codec_ABI_and_target',seed,[neq(r['value'],bv(v,32))for r,v in zip(const,cc)]+[neq(seed.get('x'+str(k)),bv(v))for k,v in fixed.items()]+[neq(seed.get('x30'),'PBUF'),neq(next(r for r in seed.reads if r['site']=='0x100c9174c')['address'],at(0x67f0))])
 cert('seed_all47_original_store_and_three_frame_read_addresses',seed,[neq(r['address'],frame(fr['frame_offset']))for r,fr in zip(seed.stores,seed.frame_writes)]+[neq(next(r for r in seed.reads if r['site']==fr['site'])['address'],frame(fr['frame_offset']))for fr in seed.frame_reads])
 all_planes=set();records=[];g=seed
 for q in range(4):
  g=run(chained(g,'prefix_loop'+str(q)),'loop');models['round'+str(q)]=g;assert len(g.sites)==4720 and len(g.reads)==180 and len(g.frame_reads)==131 and len(g.stores)==96 and len(g.frame_writes)==64 and len(g.external)==49
  br=[r for r in g.reads if r['width_bits']==8];bt=[r for r in g.stores if r['width_bits']==8];assert len(br)==48 and len(bt)==32
  zeros=['(= K '+bv(0)+')','(= PBUF '+bv(0)+')']+['(= Z'+str(k)+' '+bv(0)+')'for k in range(31)]+[f'(= {n} {bv(0,w)})'for n,w in g.decl.items()]
  candidate=solve('round'+str(q)+'_address_candidates',g.prefix()+''.join('(assert '+c+')\n'for c in zeros),result='sat',values=[r['address']for r in br+bt],extra=declarations(g))['model_value_hex'];offsets=[int(v[2:],16)for v in candidate];addr=[]
  for j,(row,off)in enumerate(zip(br+bt,offsets)):
   root='PBUF'if off<64 else'K';assert off<64 or 0xd10<=off<0xd10+961;addr.append({'kind':'read'if j<48 else'store','site':row['site'],'root':root,'offset':off,'original_address':row['address']})
  cert('round'+str(q)+'_all80_original_byte_addresses',g,[neq(row['original_address'],f'(bvadd {row["root"]} {bv(row["offset"])})')for row in addr])
  live=[]
  for j in range(16):
   trip=addr[3*j:3*j+3];index=16*q+j;U=0xd10+(866*(896+index))%961;V=0xd10+(866*(827+index))%961
   assert sorted((r['root'],r['offset'])for r in trip)==sorted([('PBUF',index),('K',U),('K',V)])and trip[2]['offset']==V
   assert[addr[48+2*j]['offset'],addr[48+2*j+1]['offset']]==[U,V]and not{U,V}&all_planes;all_planes.update([U,V]);records.append(index)
   rd=next(r for r,a in zip(br[3*j:3*j+3],trip)if a['root']=='PBUF');ur=next(r for r,a in zip(br[3*j:3*j+3],trip)if a['offset']==U);vr=br[3*j+2]
   assert int(ur['site'],16)<int(bt[2*j]['site'],16)and int(vr['site'],16)<int(bt[2*j+1]['site'],16)
   live.append({'index':index,'record_read':rd,'U_read':ur,'V_read':vr,'U_store':bt[2*j],'V_store':bt[2*j+1],'U_offset':U,'V_offset':V})
  cert('round'+str(q)+'_all16_U_raw_XOR_updates',g,[neq(r['U_store']['value'],f'(bvxor {r["record_read"]["input"]} {r["U_read"]["input"]})')for r in live])
  # A data-dependent CSEL appears only in the first V byte's source cone.
  # Evaluate its two constant arms universally,then prove the common false
  # circuit's linear old-V update and address-only zero-input mask functions.
  defs=[parse(line)for line in g.prefix().splitlines()];names={d[1]for d in defs};guards=[d for d in defs if d[1].startswith('prefix_loop'+str(q)+'_')and isinstance(d[-1],list)and d[-1][0]=='ite'];assert len(guards)==6;guard=guards[0]
  def fixed_guard(value):return'\n'.join(emit([*d[:-1],['ite',value,*d[-1][2:]]])if d[1]==guard[1]else emit(d)for d in defs)+'\n'
  false=fixed_guard('false');true=renamed(fixed_guard('true'),names,'_true');first=bt[1]['value'];solve('round'+str(q)+'_CSEL_both_arms_same_first_V_byte',false+true+'(assert '+neq(first,renamed(first,names,'_true'))+')',extra=declarations(g))
  cut_symbol=guard[1];other_deps=dependency_census(g.prefix(),{cut_symbol},[r['value']for r in bt[3::2]]);assert all(not d for d in other_deps)
  zero={r['V_read']['input']:'#x00'for r in live};mask_source=renamed(false,names,'_mask',zero);mask_expr=[renamed(r['V_store']['value'],names,'_mask')for r in live]
  terms=[neq(r['V_store']['value'],f'(bvxor {r["V_read"]["input"]} {mask})')for r,mask in zip(live,mask_expr)];solve('round'+str(q)+'_false_arm_all16_V_XOR_address_functions',false+mask_source+'(assert (or '+' '.join(terms)+'))',extra=declarations(g))
  declared=set(re.findall(r'\(declare-fun (\w+) ',DECL+EXTRA))|set(g.decl);deps=dependency_census(mask_source,declared,mask_expr);assert deps==[['PBUF']for _ in range(16)]
  cert('round'+str(q)+'_all64_private_stores_and131_frame_reads',g,[neq(r['address'],frame(fr['frame_offset']))for r,fr in zip([r for r in g.stores if r['width_bits']!=8],g.frame_writes)]+[neq(next(r for r in g.reads if r['site']==fr['site'])['address'],frame(fr['frame_offset']))for fr in g.frame_reads])
  cert('round'+str(q)+'_exact_branch_counter_and_saved_phase',g,[neq(next(r for r in g.reads if r['site']=='0x100c168f4')['address'],at(0x84f9 if q<3 else 0x84ef)),neq(g.get('x19'),bv(0x0be7880c+16*(q+1))),neq(g.loadframe(0x730,32),bv(0x2b22871b-0x3620*(q+1),32)),neq(g.loadframe(0x534,32),bv(0x84ef,32)),neq(g.get('x17'),bv(0xadd2))])
  rounds.append({'round':q,'address_ledger':addr,'byte_updates':live,'first_CSEL_source_PC':'0x100c12160','first_CSEL_original_definition':emit(guard),'constant_arm_equality_certificate':'round'+str(q)+'_CSEL_both_arms_same_first_V_byte','other15_V_values_have_no_guard_dependency':True,'common_false_arm_source_SSA':false,'V_zero_input_mask_source_SSA':mask_source,'V_mask_expressions':mask_expr,'V_mask_declared_dependencies':deps,'raw_value_dependencies_are_not_proof_of_influence':True})
 assert records==list(range(64))and len(all_planes)==128
 tail=run(chained(g,'prefix_exit',loads={'0x100dad2e8':('FN_EXIT',64)}),'exit');models['exit']=tail;assert len(tail.sites)==12 and len(tail.stores)==len(tail.frame_writes)==2 and len(tail.reads)==6 and len(tail.frame_reads)==5
 cert('exit_pair_reloads_biased64_advances_state_reload_and_target',tail,[neq(tail.loadframe(0x18,32),bv(0x53921788,32)),neq(tail.loadframe(0x2cc,32),bv(0x0c392f13,32)),neq(tail.get('w10'),bv(0x4923,32)),neq(tail.get('w11'),seed.loadframe(0x6cc,32)),neq(next(r for r in tail.reads if r['site']=='0x100dad2e8')['address'],at(0x8d10)),neq(tail.get('x8'),'FN_EXIT'),neq(tail.get('x17'),bv(0x26e7))])
 cert('exit_both_stores_and_all_five_original_frame_reads',tail,[neq(r['address'],frame(fr['frame_offset']))for r,fr in zip(tail.stores,tail.frame_writes)]+[neq(r['address'],frame(fr['frame_offset']))for r,fr in zip([r for r in tail.reads if r['site']!='0x100dad2e8'],tail.frame_reads)])
 retained={0xd10+(base+866*j)%961 for base,n in[(0x77086,256),(0x368c4,256),(0,256),(0x73704,16),(0x6e272,16)]for j in range(n)};assert len(retained)==800 and not retained&all_planes
 protected={off+j for off,n in[(0x728,4),(0x740,8),(0x748,8),(0x750,8),(0x768,296),(0x1210,8)]for j in range(n)};written=set(all_planes)
 for name,m in models.items():
  words={r['frame_offset']+j for r in m.frame_writes for j in range(r['width_bits']//8)};assert not words&(protected|retained|all_planes);written|=words
  if name.startswith('round'):assert not words&{off+j for off in DATA for j in range(4)}
 # The memory theorem is local byte algebra;distinctness/preservation is
 # checked by the complete original address ledger and source ordering.
 solve('paired_XOR_update_composition','(assert (distinct (bvxor (bvxor B0 B1) (bvxor B2 B3)) (bvxor (bvxor B0 B2) (bvxor B1 B3))))')
 for label,c in [('first_long',64),('max_long',0xffffffff)]:solve(label+'_abstract_COUNT_domain','(assert (= COUNT '+bv(c,32)+'))',result='sat')
 actual={pc for m in models.values()for pc in m.sites};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==5034 and sum(len(m.sites)for m in models.values())==19194
 model_records={name:m.record_full()for name,m in models.items()};writes=[r for m in models.values()for r in m.stores];reads=[r for m in models.values()for r in m.reads]
 sem={'source_models':model_records,'rounds':rounds,'source_nonbranch_sites_translated':5034,'translated_instances':19194,'rounds_integer':4,'record_bytes_read':64,'plane_byte_reads':128,'plane_byte_stores':128,'records_read_offsets':records,'plane_cells_distinct':128,'original_planes_updated_exactly_once':True,'U_update':'Unew[i]=Uold[i] XOR raw_record_byte[i],0<=i<64','V_update':'Vnew[i]=Vold[i] XOR M[i](PBUF),0<=i<64;source-defined address-only mask functions','paired_update':'Unew[i] XOR Vnew[i] = Uold[i] XOR Vold[i] XOR raw[i] XOR M[i](PBUF)','first_CSEL_condition':'u8(raw_record_byte[16*q] XOR old_U[16*q])==0x74','first_CSEL_effect_on_first_V_byte':'Both constant arms universally equal;other15 V outputs have no source dependency on the guard','mask_candidate_construction':'Source CSEL fixed false and old V bytes set0;accepted linearity proof and two-arm equality justify actual source composition','canonical_mask_identity_proved':False,'eight_seed_state_word_stores':[r for r in seed.frame_writes if r['frame_offset']in DATA],'seed39_constant_word_stores':[{**r,'constant_u32':hex(v)}for r,v in zip(const,cc)],'seed_state_compact_form_proved':False,'eight_seed_words_preserved_through_all_four_rounds':True,'entry_F730':'0x67f0','loop_F730_seed':'0x2b22871b','loop_F730_step':'-0x3620','F18_after':'0x53921788','F2cc_after':'0x0c392f13','exit_target':'0x100b8ed9c','source_read_operations':len(reads),'source_store_effects':len(writes),'read_bytes':sum(r['width_bits']//8 for r in reads),'store_bytes':sum(r['width_bits']//8 for r in writes),'distinct_store_bytes':len(written),'retained_arithmetic_and_codebook_cells':800,'saved_roots_COUNT_workspace_and_budget_preserved':True,'source_frame_disjointness_is_a_premise':True,'native_record_buffer_extent_proved':False,'native_reachability_proved':False,'successful_output_publication_proved':False,'whole_algorithm_identified':False,'Mach_port_emissions':0,'excluded_exploratory_unknowns':'Four unsplit actual-CSEL/zero-input V-vector queries timed out;not accepted. The source case split,two-arm equality,false-arm linearity and dependency census are accepted separately. A requested model after an UNSAT exploratory zero-address contrast was unavailable;no counterexample is claimed.','native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['loop'].__setitem__('bytes','00'+q['fragments']['loop']['bytes'][2:])),('wrong_record_read',lambda q:next(i for i in q['fragments']['loop']['instructions']if i['ea']=='0x100c120e0').__setitem__('operands','w10, [x8]')),('wrong_exit',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('wrong_EON',lambda q:q['EON_decode_checks'][0].__setitem__('shift','ROR60')),('wrong_pair_offset',lambda q:q['pair_load_decode_checks'][0]['frame_offsets'].__setitem__(1,0x1c)),('wrong_prior_hash',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':5034,'translated_instances':19194,'iterations':4,'record_byte_reads':64,'plane_byte_reads':128,'plane_byte_stores':128,'all_byte_addresses_certified':320,'seed_state_words':8,'seed_constant_words':39,'CSEL_arm_equalities':4,'V_XOR_source_linearity_certificates':4,'arithmetic_and_codebook_cells_retained':800,'rejected_alterations':len(aa),'source_read_operations':sem['source_read_operations'],'source_store_effects':sem['source_store_effects'],'read_bytes':sem['read_bytes'],'store_bytes':sem['store_bytes'],'distinct_store_bytes':sem['distinct_store_bytes']}
 deps=[P+'_source.json','recover_daemon_mode_one_record_long_planes.py','validate_daemon_mode_one_record_long_planes.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'long64_prefix_absorption_and_exit_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
