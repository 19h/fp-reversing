#!/usr/bin/env python3
"""Source-pinned result words,dual-view encodings,phase transition and LOCAL stores."""
import copy,hashlib,json,shutil,subprocess
from recover_daemon_mode_one_result_publication import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_checkpoint import PostSSA
from validate_daemon_mode_one_secondary_word_extension import frame_value
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq,low
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
BIAS=0x2c238c16ca76f3a8
VIEW_OFFSETS={0x100c86a68:0x115c,0x100c86ac8:0x1100,0x100c86ba4:0x1109}
LOCAL_OFFSETS=[0,4,12,8,16,1,20,24,9,28,5,17,13,21,25,29,2,6,10,14,18,22,26,30,3,11,7,15,19,23,27,31]
WORD_PAIRS=[('IF_6f8_32','IF_710_32',0x11413f3d),('IF_6e8_32','IF_720_32',0x1490b20e),('IF_718_32','IF_730_32',0x2dc184b7),('IF_6cc_32','IF_6e0_32',0xbda713ff),('IF_6f0_32','IF_728_32',0xc4ba655f),('IF_6c0_32','IF_6c8_32',0xc7211506),('Z23','Z27',0x9af50c1f),('Z3','Z30',0x4136483d)]

class PublicationSSA(PostSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.eons=[];self.tests=[];self.divisions=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   p=split(i['operands']);m=i['mnemonic']
   if m=='udiv':self.divisions.append({'site':i['ea'],'denominator':self.get(p[2],32)})
   if m=='eon':
    width=32 if p[0].startswith('w')else 64;shift=p[3]if len(p)>3 else None;self.put(p[0],'(bvxor '+self.get(p[1],width)+' (bvnot '+self.operand(p[2],width,shift)+'))');self.sites.append(i['ea']);self.eons.append({'site':i['ea'],'width_bits':width,'shift':shift,'complement_after_shift':True})
   else:
    if m=='tst':self.tests.append({'site':i['ea'],'operands':i['operands'],'GPR_writes':[]})
    super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'EON_lowerings':self.eons,'TST_lowerings':self.tests,'UDIV_denominators':self.divisions}

class ViewsSSA(PublicationSSA):
 def __init__(self,*a,forward=False,**kw):super().__init__(*a,**kw);self.forward=forward;self.original=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc in VIEW_OFFSETS:
    p=split(i['operands']);off=VIEW_OFFSETS[pc];self.original.append({'site':i['ea'],'original_address':self.address(p[1]),'frame_offset':off})
    if self.forward:i={**i,'operands':p[0]+', [sp, #'+hex(off)+']'}
   super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'three_original_view_addresses':self.original,'additional_computed_store_normalizations':3 if self.forward else 0}

def chain(old,name,loads=None):
 g=PublicationSSA(name,old.r,loads=loads);g.defs=list(old.defs);g.decl=dict(old.decl);g.byte_cells=dict(old.byte_cells);g.loaded=old.loaded
 for v,w in(loads or{}).values():g.decl[v]=w
 return g

def certificates(s):
 pp=[];mm={};fs=s['fragments']
 def solve(name,g=None,terms=(),cc=(),result='unsat',extra='',body=''):
  q='(set-option :timeout 45000)\n(set-logic QF_BV)\n'+DECL+extra
  if g is not None:
   gs=g if isinstance(g,list)else[g];decl={};defs=[]
   for x in gs:
    for n,w in x.decl.items():assert n not in decl or decl[n]==w;decl[n]=w
    defs+=x.defs
   q+=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in decl.items())+'\n'.join(dict.fromkeys(defs))+'\n'
  q+=body+''.join('(assert '+v+')\n'for v in cc)
  if terms:q+='(assert (or '+' '.join(terms)+'))\n'
  q+='(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.returncode,r.stdout[:1600],r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def replay(prefix,names):
  c=json.loads(read(ROOT/(prefix+'_checks.json')));rows=[p for p in c['proofs']if p['name']in names];assert len(rows)==len(names)
  for p in rows:
   q=p['query'].replace('(set-option :timeout 15000)','(set-option :timeout 45000)');r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat',(prefix,p['name'],r.stdout[:1600],r.stderr);pp.append({**p,'query':q,'prior_query_sha256':hashlib.sha256(p['query'].encode()).hexdigest(),'timeout_budget_changed':q!=p['query'],'name':'replayed_'+prefix+'_'+p['name'],'replayed_query':True})
  print('replayed',prefix,len(rows),flush=True)
 replay('daemon_mode_one_secondary_rounds',['round_counter_progress_repeat_exit_and_update_W4','update_caller_bound_flag_partition_and_phase_words','gate_overflow_aware_rotated_unsigned_comparison'])
 replay('daemon_mode_one_parity_state_adapters',['odd_register_and_pointer_representation_contract','dispatcher_all_u32_parity_exact_targets_and_saved_word','generic_setup_flag_partition_and_saved_input_word','skip_register_copy_and_distinct_dispatch_interface'])
 replay('daemon_mode_one_record_checkpoint',['LOCAL_request18_NULL_partition_and_raw_marker','LOCAL_present_source_predicate_derived_views_and_entry_constants'])
 replay('daemon_mode_one_even_view_import',['initializer_F300_plus_bias_is_private_F1150_view','first_original_source_byte_address_value_and_reciprocal_destination_shape','second_source_byte_address_raw_value_UDIV962_and_destination_shape','even_context_encoded_suffix_input96_and_word_XOR_gate'])
 def run(g,label,fragment=None):
  f=fragment or fs[label];g.run(f,int(f['end'],16)if label=='status'else int(f['instructions'][-1]['ea'],16));mm[label]=g;return g
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 def frame_cert(name,g):
  rr={r['site']:r for r in g.reads};ss={r['site']:r for r in g.stores};solve(name+'_all_frame_effect_addresses',g,[neq(rr[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_reads]+[neq(ss[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_writes]+[neq(r['original_address'],frame(r['frame_offset']))for r in g.alias_records])
 base={0x740:('TABLE',64),0x758:(frame(0x8b0),64),0x750:(frame(0xc80),64),0x350:('(bvadd LOCAL '+bv(BIAS)+')',64),0x358:('(bvadd LOCAL '+bv(BIAS)+')',64),0x368:(frame(0x1150),64),0x370:(frame(0x1100),64),0x300:('(bvadd '+frame(0x1150)+' '+bv(0x0ff0ed06a1ef8a89)+')',64),0x388:('REQUEST',64)}
 m=PublicationSSA('materialize',{2:z('(bvand FLAG #x00000001)')},presets={**base,0x738:(bv(0xb55a,32),32),0x4f8:('FLAG',32)},loads={'0x100d21440':('MFN',64)});m.decl.update(FLAG=32,LOCAL=64,REQUEST=64,MFN=64);run(m,'materialize');frame_cert('materialize',m)
 assert(len(m.sites),len(m.reads),len(m.frame_reads),len(m.frame_writes),len(m.divisions),len(m.eons),len(m.tests))==(9240,718,165,149,14,1,1)
 solve('materialization_all14_UDIV_denominators962',m,[neq(r['denominator'],bv(962,32))for r in m.divisions])
 solve('materialization_constant_serializer_controls_and_exact_flag_partition',m,[neq(m.loadframe(0x434,32),bv(0x6012,32)),neq(m.loadframe(0x6d8,32),bv(0x40d0,32)),neq(m.loadframe(0x6d0,32),'(bvand FLAG #x00000001)'),neq(m.loadframe(0x4f8,32),'FLAG'),neq(m.loadframe(0x738,32),bv(0xb55a,32)),neq(rd(m,0x100d21440)['address'],'(ite (= (bvand FLAG #x00000001) #x00000000) '+at(0xb55a)+' '+at(0xb578)+')'),neq(m.get('x17'),bv(0xead))])
 presets={**base,0x434:(bv(0x6012,32),32),0x6d8:(bv(0x40d0,32),32)}
 def views(name,forward):
  q=ViewsSSA(name,presets=presets,loads={'0x100c87248':('VFN',64)},forward=forward);q.decl.update(LOCAL=64,REQUEST=64,VFN=64);return run(q,name,fs['views'])
 raw=views('raw_views',False);frame_cert('raw_views',raw)
 solve('all_three_original_register_rooted_view_addresses',raw,[neq(r['original_address'],frame(r['frame_offset']))for r in raw.original])
 v=views('views',True);frame_cert('views',v);solve('coherent_views_original_computed_addresses',v,[neq(r['original_address'],frame(r['frame_offset']))for r in v.original])
 byte_stores=[r for r in v.frame_writes if r['width_bits']==8];assert len(byte_stores)==64 and{r['frame_offset']for r in byte_stores}==set(range(0x1100,0x1120))|set(range(0x1150,0x1170))
 solve('views_flag1_parity0_selector_and_dispatch_handoff',v,[neq(v.loadframe(0x4f8,32),bv(1,32)),neq(v.loadframe(0x4b4,32),bv(0,32)),neq(v.loadframe(0x708,32),bv(0xc83d,32)),neq(v.get('x11'),bv(0)),neq(rd(v,0x100c87248)['address'],at(0x40d0)),neq(v.get('x17'),bv(0x465a))])
 solve('views_F748_zero_sample_is_not_universal_state',v,[neq(v.loadframe(0x748,32),bv(0,32))],result='sat')
 l=PublicationSSA('local',presets=presets,loads={'0x100bf7428':('LFN',64)});l.decl.update(LOCAL=64,REQUEST=64,LFN=64);run(l,'local');frame_cert('local',l)
 assert len(l.stores)==32 and not l.frame_writes and len(l.eons)==1 and sorted(LOCAL_OFFSETS)==list(range(32))
 solve('all32_original_LOCAL_output_byte_addresses',l,[neq(r['address'],'(bvadd LOCAL '+bv(off)+')')for r,off in zip(l.stores,LOCAL_OFFSETS)])
 by_offset={off:r for off,r in zip(LOCAL_OFFSETS,l.stores)}
 def packed(j):return'(concat '+by_offset[j]['value']+' (concat '+by_offset[j+1]['value']+' (concat '+by_offset[j+2]['value']+' '+by_offset[j+3]['value']+')))'
 word_rows=[]
 for j,(a,b,mask)in enumerate(WORD_PAIRS):
  aa=low(a)if a.startswith('Z')else a;bb=low(b)if b.startswith('Z')else b;want='(bvxor (bvxor '+aa+' '+bb+') '+bv(mask,32)+')';word_rows.append({'word_index':j,'LOCAL_byte_offsets':list(range(4*j,4*j+4)),'input_pair':[a,b],'XOR_mask':hex(mask),'original_packed_word':packed(4*j),'canonical_word':want})
 solve('all_eight_original_BIG_ENDIAN_LOCAL_word_pair_identities',l,[neq(r['original_packed_word'],r['canonical_word'])for r in word_rows])
 solve('LOCAL_serializer_result_code_and_status_target',l,[neq(l.get('w9'),bv(0x8b3dc651,32)),neq(rd(l,0x100bf7428)['address'],at(0x6012)),neq(l.get('x17'),bv(0x8041))])
 relation=[]
 for j in range(32):
  a=v.loadframe(0x1150+j,8);b=v.loadframe(0x1100+j,8);out=by_offset[j]['value'];relation.append({'byte_index':j,'view_1150_value':a,'view_1100_value':b,'LOCAL_value':out,'identity_mask':'0x2f'})
 solve('all32_same_input_state_dual_view_to_LOCAL_byte_identities',[v,l],[neq('(bvxor '+r['view_1150_value']+' '+r['view_1100_value']+')','(bvxor '+r['LOCAL_value']+' #x2f)')for r in relation])
 solve('imported_plane_pair_uses_D6_for_matched_serialized_byte',terms=[neq('(bvxor (bvxor (bvxor B0 #xf9) B1) #xd6)','(bvxor (bvxor B0 B1) #x2f)')])
 # The observed source handoff sets flag1 and dispatches even with arbitrary
 # reloaded state. Preserve the request/local/view roots while composing.
 d=chain(v,'dispatch',{'0x100b6fe3c':('DFN',64)});run(d,'dispatch');frame_cert('dispatch',d)
 solve('actual_view_handoff_selects_even_adapter',d,[neq(rd(d,0x100b6fe3c)['address'],at(0xc83d)),neq(d.loadframe(0x4b4,32),bv(0,32)),neq(d.get('x12'),bv(0x255c)),neq(d.get('x15'),bv(0x255c)),neq(d.loadframe(0x4f8,32),bv(1,32)),neq(d.get('x17'),bv(0xb0ef))])
 e=chain(d,'even',{'0x100be12d8':('EFN',64)});run(e,'even');frame_cert('even',e)
 u=chain(e,'setup',{'0x100d75154':('UFN',64)});run(u,'setup');frame_cert('setup',u)
 C=u.loadframe(0x4a4,32);A=u.loadframe(0x4ac,32)
 solve('actual_flag1_even_context_count32_roots_suffix_input_and_setup_target',u,[neq('(bvadd (bvsub '+C+' '+A+') #xdf8b76a4)',bv(32,32)),neq('(bvadd '+C+' #x8cca81ed)',bv(96,32)),neq(u.loadframe(0x4f8,32),bv(1,32)),neq(u.loadframe(0x380,64),frame(0x1100)),neq('(bvadd '+u.loadframe(0x360,64)+' '+bv(0xf00f12f95e107577)+')',frame(0x1150)),neq(u.loadframe(0x350,64),base[0x350][0]),neq(rd(u,0x100d75154)['address'],at(0x9654)),neq(u.loadframe(0x4a8,32),A)])
 k=chain(u,'skip',{'0x100dc42a8':('KFN',64)});run(k,'skip');frame_cert('skip',k)
 solve('actual_flag1_skip_returns_initial_even_view_import_ABI',k,[neq(rd(k,0x100dc42a8)['address'],at(0x34d0)),neq(k.get('x19'),bv(0x4a62f57c)),neq(k.get('x13'),bv(0x4923)),neq(k.get('x27'),bv(0x2dd9b66a)),neq(k.get('x7'),bv(0xb4)),neq(k.get('x20'),bv(0xd6)),neq(k.get('x0'),frame(0x1100)),neq(k.get('x21'),frame(0x8b0)),neq(k.get('x6'),'TABLE'),neq(k.loadframe(0x4f8,32),bv(1,32)),neq(k.loadframe(0x4b4,32),bv(0,32))])
 # This stronger standalone even/setup theorem leaves the dispatch-reloaded
 # W20 unrestricted rather than assigning its sampled zero value.
 g=PublicationSSA('broad_even',{12:bv(0x255c),15:bv(0x255c)},presets={**base,0x4f8:(bv(1,32),32)},loads={'0x100be12d8':('BEFN',64)});g.decl.update(LOCAL=64,REQUEST=64,BEFN=64);run(g,'broad_even',fs['even']);h=chain(g,'broad_setup',{'0x100d75154':('BUPFN',64)})
 # Distinct continuation input;the generic reloaded data word stays free.
 run(h,'broad_setup',fs['setup']);HA=h.loadframe(0x4ac,32);HC=h.loadframe(0x4a4,32)
 solve('generic_even_count32_and_suffix96_allow_arbitrary_reloaded_W20',h,[neq('(bvadd (bvsub '+HC+' '+HA+') #xdf8b76a4)',bv(32,32)),neq('(bvadd '+HC+' #x8cca81ed)',bv(96,32)),neq(h.loadframe(0x350,64),base[0x350][0])])
 status=chain(l,'status');run(status,'status');frame_cert('status',status)
 solve('status_prefix_stores_raw_result_code_to_REQUEST0',status,[neq(status.stores[0]['address'],'REQUEST'),neq(status.stores[0]['value'],bv(0x8b3dc651,32)),neq(status.reads[0]['address'],frame(0x388))]);assert len(status.sites)==2 and len(status.stores)==1
 # Original-address/caller proofs cover every normalized view write. LOCAL
 # is required to be disjoint from the private frame for stable frame reads.
 protected=set(range(0x300,0x308))|set(range(0x350,0x378))|set(range(0x388,0x390))|set(range(0x740,0x748))|set(range(0x750,0x760))|set(range(0x768,0x890))|set(range(0x8b0,0x8b0+962))|set(range(0xc80,0xc80+286*4))
 for name in['materialize','views','dispatch','even','setup','skip']:
  q=mm[name];written={r['frame_offset']+j for r in q.frame_writes for j in range(r['width_bits']//8)}
  allowed=set(range(0x360,0x368))if name=='even'else set()
  if name=='setup':allowed|=set(range(0x380,0x388))
  assert not written&(protected-allowed),(name,written&(protected-allowed))
 assert all(not set(range(r['frame_offset'],r['frame_offset']+r['width_bits']//8))&set(range(0x350,0x360))for name in['materialize','views','dispatch','even','setup','skip']for r in mm[name].frame_writes)
 for name in fs:assert set(mm[name].sites)=={i['ea']for i in fs[name]['instructions']if i['mnemonic']!='braa'}
 assert sum(len(mm[n].sites)for n in fs)==10704
 solve('abstract_flag0_materialization_domain_nonempty',m,cc=['(= (bvand FLAG #x00000001) #x00000000)'],result='sat');solve('abstract_flag1_materialization_domain_nonempty',m,cc=['(= (bvand FLAG #x00000001) #x00000001)'],result='sat')
 effects={n:{'nonbranch_sites':len(mm[n].sites),'loads':len(mm[n].reads),'stores':len(mm[n].stores),'read_bytes':sum(r['width_bits']//8 for r in mm[n].reads),'store_effect_bytes':sum(r['width_bits']//8 for r in mm[n].stores),'frame_stores':len(mm[n].frame_writes)}for n in fs}
 sem={'source_models':{n:g.record_full()for n,g in mm.items()},'source_nonbranch_sites_translated':10704,'materialize_computed_byte_reads':552,'materialize_literal_byte_reads':1,'materialize_lookup_byte_bounds_or_values_proved':False,'materialize_UDIV962_sites':14,'materialize_frame_u32_stores':149,'materialize_control_fields':{'F434':'0x6012','F6d8':'0x40d0','F6d0':'FLAG bit0','F738':'0xb55a unchanged'},'view_BYTE_store_ledger':byte_stores,'view_byte_ranges':[[0x1100,0x1120],[0x1150,0x1170]],'view_encoded_bytes':64,'view_additional_computed_address_normalizations':3,'view_existing_SP_alias_normalizations':len(v.alias_records),'LOCAL_store_ledger':[{'offset':off,**r}for off,r in zip(LOCAL_OFFSETS,l.stores)],'LOCAL_distinct_output_bytes':32,'LOCAL_word_identities':word_rows,'LOCAL_byte_order':'Eight big-endian u32 words;actual stores are interleaved.','same_input_state_dual_view_relation':relation,'same_input_relation_scope':'View1150[j] XOR View1100[j] = LOCAL-serializer-byte[j] XOR0x2f for matched serializer input fields/registers. Executed passes have different states;this is representation equivalence,not equality of their results.','import_pair_decoder_mask':'0xd6;the first imported view is additionally XOR0xf9','phase_bridge':'Views set FLAG1,PAR0,dispatch selector c83d and W11=0,then dispatch/even/setup/skip supplies PSTATE=4a62f57c,R32,view roots and flag1. F748 data remains unrestricted.','phase_saved_LOCAL_encoded_root_preserved':True,'status_word':'0x8b3dc651','status_destination':'REQUEST+0','LOCAL_origin':'u64[REQUEST+0x18],subject to retained checkpoint/caller/root-continuity contracts','native_LOCAL_owner_extent_and_alias_policy_proved':False,'LOCAL_frame_disjointness_premise':True,'REQUEST_LOCAL_overlap_policy_proved':False,'normal_return_census':s['frontier_census'],'stack_guard_reference':s['stack_guard_reference'],'whole_canary_return_execution_proved':False,'native_publication_observed':False,'native_arrival_proved':False,'whole_algorithm_identified':False,'whole_decoded_padding_proved':False,'daemon_kext_pairing_proved':False,'Mach_port_emissions':0,'new_IDA_access':False,'effect_counts':effects,'coherence_boundary':'Body computed byte reads are independentu8 inputs;their mapping/bounds and table validity are not newly proved. Literal/private-view forwarding is exact after original-address proofs. LOCAL32 is assumed disjoint from the private frame for stable serializer field reads. REQUEST/LOCAL ownership,extent and mutual alias policy remain unknown.','excluded_exploration':'The older EON helper rejected the actual LSL4 operand;the local EON lowering explicitly complements after shift and both encodings are checked. The guard is an unauthenticated bind,so the authenticated-pointer verifier rejected it;the new guard decoder checks original bind/import fields separately. Three view addresses initially remained unbound because saved F368/F370 roots were missing;accepted models bind the retained roots and prove all three original addresses. Sampled F748=0 was refuted and is not a control premise. The even count32 theorem is freshly proved with arbitrary reloaded W20. A sampled0x2f cross-serializer mask and eight word masks are accepted only after universal original-source proofs.'}
 return pp,sem

def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('source_byte',lambda q:q['fragments']['materialize'].__setitem__('bytes','00'+q['fragments']['materialize']['bytes'][2:])),('LOCAL_target',lambda q:q['branch_edges'][3].__setitem__('target','0x0')),('view_target',lambda q:q['branch_edges'][2].__setitem__('target','0x0')),('EON_shift',lambda q:next(r for r in q['ISA_decode_checks']if r['kind']=='eon'and r['shift_bits']==4).__setitem__('shift_bits',0)),('TST_mask',lambda q:next(r for r in q['ISA_decode_checks']if r['kind']=='tst_immediate').__setitem__('mask','0x0')),('guard_symbol',lambda q:q['stack_guard_reference'].__setitem__('import_name','wrong')),('lineage_hash',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert q!=original;out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':10704,'materialize_u32_stores':149,'materialize_computed_byte_reads':552,'materialize_proved_UDIV962_denominators':14,'view_bytes_written':64,'LOCAL_bytes_written':32,'LOCAL_word_identities':8,'matched_state_byte_representation_identities':32,'view_extra_computed_address_normalizations':3,'request_result_u32_stores':1,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_join.py','validate_daemon_existing_scalar_reader.py','validate_daemon_mode_one_secondary_word_extension.py','daemon_word_round_tools.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'result_materialization_dual_view_LOCAL_and_phase_bridge_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
