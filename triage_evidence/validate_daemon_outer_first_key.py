#!/usr/bin/env python3
"""Source-linked C0 first-key and normal-mode interfaces;no target execution."""
import copy,json,subprocess
from recover_daemon_outer_first_key import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import sha,read
from validate_daemon_reader_outer_lifecycle import Engine
from recover_daemon_reader_context_footprint import engine
from validate_daemon_reader_context_footprint import declarations
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix,WORD_BASE
SOLVER='/opt/homebrew/bin/z3';PH='(concat ((_ extract 63 32) Z30) #x00006cf4)';CBASE=0x7f76f633d66f61c6
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in [('OBJ',64),('COLL',64),('NODE',64),('LOCAL',64),('RESULT',32),('MODE',32),('T',16),('FLAG',8)])
def certificates(s):
 pp=[];tr={};fs=s['fragments'];pr,inp=engine(s['preparation'],ns='prep_');tr['preparation']=pr.record();nd=declarations(inp,'N');cells={q['offset_bytes']:a['value']for q,a in zip(s['preparation_write_ledger'],pr.stores)}
 frame=lambda off:f'(bvadd K {bv(off)})';at=lambda ix:f'(bvadd TABLE {bv(ix*8)})';enc='(bvxor PL #x8b3dc651)';secondary='(bvxor PL #x8ec35f08)';end=f'(bvadd {bv(CBASE)} {z("PL")} {bv(10)})';fit=f'(bvule (bvadd {z("PL")} {bv(10)}) {z("SIZE")})'
 def solve(n,body,result='unsat',note='',arrays=False):
  q='(set-option :timeout 15000)\n(set-logic '+('QF_AUFBV'if arrays else'QF_BV')+')\n'+DECL+EXTRA+nd+body+'\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr);pp.append({'name':n,'query':q,'result':result,'scope':SCOPE+' '+note,'reused_lemma':False});print(n,result,flush=True)
 def part(n,label=None,r=None,loads=None,chain=None):
  label=label or n;f=fs[n];ii=f['instructions'][:-1];ll={};dd=[]
  for i in ii:
   if i['mnemonic']in('ldr','ldrb','ldrh','ldrsh','ldur'):
    w=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']in('ldrh','ldrsh')else 32 if i['operands'].startswith('w')else 64;v='TABLE'if i['operands'].endswith('[sp, #0x9d8]')else PH if i['operands'].endswith('[sp, #0x9d0]')else None
    if v is None:v=label+'_L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {w}))')
    ll[i['ea']]=(v,w)
  ll.update(loads or{});rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K'
  if chain:rr.update({j:chain[-1].get('x'+str(j))for j in range(31)})
  rr.update(r or{});g=Engine(rr,ll,namespace=label+'_');g.run({'instructions':ii},int(f['instructions'][-1]['ea'],16));g.declarations='\n'.join(dd)+'\n';tr[label]=g.record();return(chain or[])+[g]
 def add(n,gs,tt,cc=(),note=''):solve(n,prefix(*gs)+''.join('(assert '+c+')\n'for c in cc)+'(assert (or '+' '.join(tt)+'))',note=note)
 def rd(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
 def store(g,pc,a,v):q=next(q for q in g.stores if q['site']==hex(pc));return[neq(q['address'],a),neq(q['value'],v)]
 pub=part('publish',r={8:bv(0x6cf4),6:bv(0x8b3dc651)},loads={'0x100758ae8':('COLL',64),'0x100758aec':('OBJ',64)});g=pub[-1]
 add('parser_publication_writes_first_child_and_selects_saved_return',pub,store(g,0x100758af0,'OBJ','COLL')+[neq(rd(g,0x100758b1c)['address'],at(0x188e))],note='Prior ingress contract supplies C/OUTcell and success phase;heap and frame ownership and omitted callee effects remain explicit premises.')
 ret=part('parser_return',chain=pub,loads={'0x1008c8b80':('CONT',64)});g=ret[-1];add('parser_saved_return_uses_outer_slot1649',ret,[neq(g.get('x8'),'CONT'),neq(g.get('x17'),bv(0xfc72)),neq(rd(g,0x1008c8b80)['address'],frame(0x5ff0))])
 outer=part('outer_return',chain=ret);g=outer[-1];add('actual_parser_success_produces_first_key_caller_phase',outer,[neq(g.get('w9'),'#x0000a80a'),neq(rd(g,0x1008b3abc)['address'],at(0xc6db))])
 head=part('head',chain=outer,loads={'0x10069a01c':('OBJ',64),'0x10069a020':('COLL',64)});g=head[-1]
 add('first_child_head_output_and_encoded_cursor_initialization',head,[neq(rd(g,0x10069a020)['address'],'OBJ'),neq(g.get('w22'),'#x00006cf4'),neq(rd(g,0x10069a058)['address'],f'(ite (= COLL {bv(0)}) {at(0xa80a)} {at(0xa80f)})')]+store(g,0x10069a024,frame(0x1de8),bv(0))+store(g,0x10069a038,frame(0x6468),bv(CBASE)))
 # Exact heap-pointer store/load identity across the captured no-write return prefix.
 mem='MEM0'
 for j in range(8):mem=f'(store {mem} (bvadd OBJ {bv(j)}) ((_ extract {8*j+7} {8*j}) COLL))'
 value='(concat '+' '.join(f'(select {mem} (bvadd OBJ {bv(j)}))'for j in range(7,-1,-1))+')'
 solve('published_first_child_reloads_same_eight_bytes','(declare-fun MEM0 () (Array (_ BitVec 64) (_ BitVec 8)))\n(assert '+neq(value,'COLL')+')',arrays=True,note='Original publication/head sites identify this store/load. Captured parser/outer returns contain no intervening store;stable OBJ/frame identity and nonaliasing of original heap/frame remain premises.')
 lc=part('lookup_call',chain=head);le=part('lookup_entry',chain=lc,loads={'0x1006fd1c0':('CONT',64)});g=le[-1]
 add('first_key_actual_identifier_output_and_saved_continuation',le,[neq(lc[-1].get('x8'),'COLL'),neq(lc[-1].get('w9'),'#xd719dce3'),neq(lc[-1].get('w10'),'#x000012d9'),neq(lc[-1].get('x11'),frame(0x1de8)),neq(rd(lc[-1],0x10066e5d0)['address'],at(0x18e2)),neq(rd(g,0x1006fd1c0)['address'],at(0x12d9))]+store(g,0x1006fd1c4,frame(0x7060),'CONT')+store(g,0x1006fd1cc,frame(0xaa5c),'#xd719dce3')+store(g,0x1006fd1d0,frame(0xaa60),frame(0x1de8)),[f'(distinct COLL {bv(0)})'],note='Replayed generic first-match lookup covers arbitrary key and output cell. Decoded wire key is5c241ab2;application meaning is unknown.')
 lr=part('lookup_return',r={6:z('RESULT')});g=lr[-1];add('saved_first_key_return_reaches_result_partition',lr,[neq(rd(g,0x1008949dc)['address'],at(0xc92d)),neq(g.get('x6'),z('RESULT'))])
 pt=part('partition',chain=lr);g=pt[-1];hi='(bvsgt RESULT #x74c29dec)'
 add('first_key_signed_result_partition_preserves_actual_phases',pt,[neq(g.get('w8'),'#x00000b9a'),neq(g.get('w10'),'#x0000445a'),neq(rd(g,0x100939f58)['address'],f'(ite {hi} {at(0x3613)} {at(0x3610)})')])
 ms=part('missing',chain=pt);g=ms[-1]
 add('only_exact_first_key_miss_enters_optional_discriminator',ms,[neq(g.get('w9'),'#x00007b40'),neq(g.get('w22'),'#x00006cf4'),neq(rd(g,0x100781048)['address'],f'(ite (= RESULT #x74c29ded) {at(0x43ec)} {at(0xb9a)})')],[hi])
 fl=part('option_flag',chain=ms,loads={'0x10086197c':('OBJ',64),'0x100861980':('FLAG',8)});g=fl[-1]
 add('first_key_miss_context_flag_routes_option_or_mode_gate',fl,[neq(g.get('w10'),'#x00000935'),neq(rd(g,0x1008619a4)['address'],f'(ite (= FLAG #x25) {at(0xbb19)} {at(0x7b40)})')],['(= RESULT #x74c29ded)'])
 md=part('option_mode',chain=fl,loads={'0x100864a70':('MODE',32)});g=md[-1]
 add('first_key_miss_flag25_requires_exact_mode_zero',md,[neq(rd(g,0x100864a70)['address'],f'(bvadd OBJ {bv(0x14)})'),neq(rd(g,0x100864a94)['address'],f'(ite (= MODE #x00000000) {at(0xa656)} {at(0x62f8)})'),neq(g.get('w6'),'#x74c29d72')],['(= RESULT #x74c29ded)','(= FLAG #x25)'])
 oc=part('option_call',chain=md,loads={'0x1008b35a8':('OBJ',64)});g=oc[-1]
 add('first_key_miss_reaches_actual_option_key_and_F_cell',oc,[neq(g.get('w9'),'#xf24be74b'),neq(g.get('w10'),'#x00000935'),neq(g.get('x8'),'OBJ'),neq(g.get('x11'),frame(0x53ac)),neq(rd(g,0x1008b35c0)['address'],at(0x3b01))],['(= RESULT #x74c29ded)','(= FLAG #x25)','(= MODE #x00000000)'],note='Actual flag25/mode0 route;prior option/default contracts continue from this exact ABI. No raw result is given a public error name.')
 direct=part('option_call','direct_option_call',chain=fl,loads={'0x1008b35a8':('OBJ',64)});g=direct[-1]
 add('first_key_miss_flag_not25_direct_option_ABI',direct,[neq(g.get('w9'),'#xf24be74b'),neq(g.get('w10'),'#x00000935'),neq(g.get('x8'),'OBJ'),neq(g.get('x11'),frame(0x53ac)),neq(rd(g,0x1008b35c0)['address'],at(0x3b01))],['(= RESULT #x74c29ded)','(distinct FLAG #x25)'])
 fg=part('found_gate',chain=pt);g=fg[-1]
 add('only_exact_first_key_found_marker_reads_matched_node',fg,[neq(g.get('w22'),'#x00006cf4'),neq(g.get('w9'),'#x0000796e'),neq(rd(g,0x1006fd644)['address'],f'(ite (= RESULT #x8b3dc651) {at(0x7228)} {at(0x445a)})')],['(not '+hi+')'])
 bf=part('buffer',chain=fg,loads={'0x1008b413c':('NODE',64),'0x1008b4140':('BUF',64),'0x1008b4144':('SIZE',32)});g=bf[-1]
 add('found_node_record_buffer_size_and_null_gate',bf,[neq(rd(g,0x1008b413c)['address'],frame(0x1de8)),neq(rd(g,0x1008b4140)['address'],f'(bvadd NODE {bv(24)})'),neq(rd(g,0x1008b4144)['address'],f'(bvadd NODE {bv(16)})'),neq(g.get('w8'),'#x00002167'),neq(rd(g,0x1008b416c)['address'],f'(ite (= BUF {bv(0)}) {at(0x7976)} {at(0x796e)})')]+store(g,0x1008b4148,frame(0x1b20),'BUF'),['(= RESULT #x8b3dc651)'])
 mn=part('minimum',chain=bf,loads={'0x100852358':(bv(CBASE),64)});g=mn[-1]
 add('first_record_requires_ten_bytes_and_snapshots_cursor',mn,store(g,0x100852354,frame(0xae08),z('SIZE'))+store(g,0x10085235c,frame(0xae10),bv(CBASE))+[neq(g.get('w16'),'#x000000f1'),neq(g.get('w22'),'#x00006cf4'),neq(rd(g,0x100852398)['address'],f'(ite (bvugt SIZE #x00000009) {at(0x5209)} {at(0x2167)})')],['(= RESULT #x8b3dc651)'])
 wp=part('word_prepare',chain=mn);g=wp[-1]
 add('first_record_offset_zero_word_and_actual_return_f1',wp,[neq(g.get('x1'),'BUF'),neq(g.get('x4'),bv(WORD_BASE)),neq(g.get('w16'),'#x000000f1'),neq(g.get('w8'),'#x00008c3f'),neq(rd(g,0x100898158)['address'],at(0x2520))],['(= RESULT #x8b3dc651)'])
 rr={j:'Z'+str(j)for j in range(31)};rr.update({'sp':'K',8:bv(0x8c3f),1:'BUF',4:'A',16:z('IX')});pa=Engine(rr,{q['site']:(q['input'],q['width_bits'])for q in inp},namespace='actual_prep_');pa.run(s['preparation'],int(s['preparation']['instructions'][-1]['ea'],16));tr['actual_preparation']=pa.record()
 add('shared_preparation_preserves_first_record_word_ABI',[pa],[neq(pa.get('x1'),'BUF'),neq(pa.get('x4'),'A'),neq(pa.get('w16'),'IX'),neq(pa.get('x6'),bv(0x324a764c67af2e0e)),neq(pa.get('x22'),'FN')])
 add('actual_first_record_length_key_from_AE10',[pr],[neq(cells[0x908],bv(WORD_BASE+6))],['(= N9 '+bv(CBASE)+')'],note='N9 is the original AE10 load at6f6ed0;the saved cursor is established by this minimum gate. Other eager preparation reads require valid stable frame storage.')
 wr=part('word_return');g=wr[-1]
 add('first_record_word_return_supplies_tag_offset_four',wr,[neq(g.get('w16'),'#x00000208'),neq(g.get('x4'),frame(0x1b20)),neq(g.get('x22'),frame(0xae10)),neq(rd(g,0x1006094bc)['address'],at(0x1f39)),neq(f'(bvadd {bv(CBASE)} {g.get("x1")} #x864f69af3c097da8)',bv(4))])
 tg=part('tag_return',r={24:z('T',16),28:bv(0x324a764c67af2e0e)},loads={'0x100538e34':(cells[0x908],64)});wc=part('word_call',chain=tg,loads={'0x100530d3c':('BUF',64)});g=wc[-1]
 add('first_tag_snapshot_then_length_word_at_offset_six',[pr]+wc,store(tg[-1],0x100538e18,frame(0x9bee),'T')+[neq(g.get('x1'),'BUF'),neq(g.get('x4'),bv(WORD_BASE+6)),neq(g.get('w16'),'#x000000f4'),neq(g.get('x6'),bv(0x324a764c67af2e0e)),neq(rd(g,0x100530d44)['address'],at(0x8c3f))],['(= N9 '+bv(CBASE)+')'])
 ex=part('extent',r={1:z(secondary),4:z(enc)},loads={'0x1005cf4d0':(bv(CBASE),64),'0x1005cf4f8':(z('SIZE'),64)});g=ex[-1]
 add('first_payload_fit_is_exact_u64_P_plus_ten_within_SIZE',ex,[neq(rd(g,0x1005cf54c)['address'],f'(ite {fit} {at(0x8ff0)} {at(0x9004)})'),neq(g.get('x8'),bv(CBASE)),neq(g.get('x10'),f'(bvadd {bv(CBASE)} {z("PL")})'),neq(g.get('w6'),'#x74c29d8f')],note='Full obfuscated comparison including its overflow/conditional-select logic;u32 PL/SIZE,not native pointer bounds.')
 fi=part('fit',chain=ex,loads={'0x1006117a0':('T',16)});g=fi[-1]
 add('first_record_fitted_end_payload_offset_and_unsigned_tag',fi,[neq(g.get('x8'),end),neq(g.get('x9'),bv(10)),neq(g.get('w10'),'((_ zero_extend 16) T)'),neq(rd(g,0x1006117a8)['address'],at(0x22ff))],[fit])
 ty=part('type',chain=fi);g=ty[-1];upper='(not (bvslt T #xd0ee))'
 add('first_type_signed_lower_partition',ty,[neq(g.get('w12'),'#x00006e96'),neq(rd(g,0x100797914)['address'],f'(ite {upper} {at(0x39ec)} {at(0x39bd)})')],[fit])
 lo=part('low',chain=ty);g=lo[-1]
 add('first_type_exact_u64_is_recognized_other_status',lo,[neq(g.get('w11'),'#x00008aed'),neq(g.get('w22'),'#x00006cf4'),neq(rd(g,0x1005a3f84)['address'],f'(ite (= T #xc31c) {at(0xc45e)} {at(0x9004)})')],[fit,'(not '+upper+')'])
 up=part('upper',chain=ty);g=up[-1];belowspan='(bvslt T #x1742)'
 add('first_type_signed_upper_partition',up,[neq(g.get('w11'),'#x00008aed'),neq(g.get('w13'),'#x0000419a'),neq(rd(g,0x10047e4c0)['address'],f'(ite {belowspan} {at(0x6e9f)} {at(0x6e96)})')],[fit,upper])
 u32=part('u32',chain=up);g=u32[-1]
 add('first_type_exact_u32_is_recognized_other_status',u32,[neq(g.get('w22'),'#x00006cf4'),neq(rd(g,0x10057418c)['address'],f'(ite (= T #xd0ee) {at(0xa9d3)} {at(0x8aed)})')],[fit,upper,belowspan])
 sp=part('span',chain=up);g=sp[-1]
 add('only_exact_span_continues_first_record_processing',sp,[neq(g.get('w11'),'#x00002356'),neq(g.get('w22'),'#x00006cf4'),neq(rd(g,0x1004d7754)['address'],f'(ite (= T #x1742) {at(0xb45d)} {at(0x419a)})')],[fit,upper,'(not '+belowspan+')'])
 for label,path,cond in [('u64',lo,'(= T #xc31c)'),('u32',u32,'(= T #xd0ee)')]:
  kn=part('known_other',label+'_known_other',chain=path);g=kn[-1]
  add(label+'_recognized_type_stages_extent_then_raw_status',kn,store(g,0x100552c7c,frame(0x6468),end)+store(g,0x100552c80,frame(0xf7c),enc)+[neq(g.get('w6'),'#x74c29cd6'),neq(g.get('w22'),'#x00006cf4'),neq(rd(g,0x100552c88)['address'],at(0x8aed))],[fit,cond],note='Recognized scalar tags do not decode a scalar or impose4/8 B payload-size equality at this accessor;they select a different raw status and error staging.')
 stage=part('stage',chain=sp,loads={'0x1005a55e0':('BUF',64),'0x1005a55f4':('OBJ',64),'0x1005a55f8':('MODE',32)});g=stage[-1]
 add('first_span_stages_borrowed_pointer_extent_end_and_mode',stage,store(g,0x1005a55e8,frame(0x6468),end)+store(g,0x1005a55ec,frame(0xf7c),enc)+store(g,0x1005a55f0,frame(0x58a0),f'(bvadd BUF {bv(10)})')+[neq(g.get('w10'),'#x00004449'),neq(g.get('x19'),'OBJ'),neq(rd(g,0x1005a55f8)['address'],f'(bvadd OBJ {bv(0x14)})'),neq(rd(g,0x1005a5600)['address'],at(0x2356))],[fit,'(= T #x1742)'])
 mp=part('mode_partition',chain=stage);g=mp[-1];positive='(bvsge MODE #x00000001)'
 add('first_span_mode_signed_partition_is_at_one',mp,[neq(g.get('w11'),'#x00002167'),neq(rd(g,0x1004dca18)['address'],f'(ite {positive} {at(0x448b)} {at(0x4449)})')],[fit,'(= T #x1742)'])
 ml=part('mode_low',chain=mp);g=ml[-1]
 add('nonpositive_mode_zero_or_error_flag_gate',ml,[neq(g.get('w22'),'#x00006cf4'),neq(g.get('w9'),'#x00009004'),neq(g.get('w8'),'#x74c29dee'),neq(rd(g,0x1007f712c)['address'],f'(ite (= MODE #x00000000) {at(0x722b)} {at(0x2167)})'),neq(g.get('w6'),'#x74c29dee')],[fit,'(= T #x1742)','(not '+positive+')'])
 mh=part('mode_high',chain=mp);g=mh[-1]
 add('positive_mode_only_exact_one_selects_helper',mh,[neq(g.get('w22'),'#x00006cf4'),neq(g.get('w9'),'#x0000419a'),neq(rd(g,0x1005b086c)['address'],f'(ite (= MODE #x00000001) {at(0x5fe6)} {at(0x419a)})'),neq(g.get('w6'),'#x74c29dee')],[fit,'(= T #x1742)',positive])
 mz=part('mode_zero',chain=ml,loads={'0x1005e74f0':('FLAG',8)});g=mz[-1]
 add('found_span_mode_zero_always_errors_with_flag_specific_marker',mz,[neq(g.get('w22'),'#x00006cf4'),neq(rd(g,0x1005e7510)['address'],at(0x9004)),neq(g.get('w6'),'(ite (= FLAG #x25) #x74c29d77 #x74c29dee)')],[fit,'(= T #x1742)','(= MODE #x00000000)'],note='Mode0 reaches a flag-sensitive error marker,not the missing-key optional-accessor path. A zero mode does not admit this found-span helper.')
 mo=part('mode_one',chain=mh,loads={'0x1005b04b4':('LOCAL',64)});g=mo[-1]
 add('mode_one_supplies_outer_object_local32_and_private_selector',mo,[neq(g.get('w24'),'#x000015db'),neq(g.get('w21'),'#x00002486'),neq(g.get('w9'),'#xd1a433c1'),neq(g.get('x8'),'OBJ'),neq(g.get('x20'),'LOCAL'),neq(rd(g,0x1005b04b4)['address'],frame(0x2290)),neq(rd(g,0x1005b04c8)['address'],at(0x24b2))],[fit,'(= T #x1742)','(= MODE #x00000001)'],note='LOCAL is the prior outer reserved32 B record. Stable saved local/object identity remains an owner/frame premise.')
 hs=part('helper_setup',chain=mo);g=hs[-1]
 add('helper_setup_object_field_addresses_and_next_entry',hs,[neq(g.get('x8'),'OBJ'),neq(g.get('w9'),'#xd1a433c1'),neq(g.get('x20'),'LOCAL'),neq(g.get('x11'),f'(bvadd OBJ {bv(0x18)})'),neq(g.get('x12'),f'(bvadd OBJ {bv(0x58)})'),neq(rd(g,0x100901530)['address'],at(0x2486)),neq(g.get('x17'),bv(0x844f))],[fit,'(= T #x1742)','(= MODE #x00000001)'],note='Original target729920 is a deeper private helper frontier. No cryptographic,policy or application operation name is assigned to it.')
 er=part('error',r={22:PH,6:z('RESULT')});g=er[-1]
 add('first_key_error_stages_raw_result_and_cleanup_frontier',er,store(g,0x100941a88,frame(0x5f60),'RESULT')+[neq(g.get('w9'),'#x00001fbb'),neq(rd(g,0x100941a90)['address'],at(0xc04f))])
 missok='(or (distinct FLAG #x25) (= MODE #x00000000))';optionroute='(and (= RESULT #x74c29ded) '+missok+')'
 add('missing_key_option_route_composition',[],[neq(optionroute,'(and (bvsgt RESULT #x74c29dec) (= RESULT #x74c29ded) (or (distinct FLAG #x25) (= MODE #x00000000)))')],note='This route is separate from the found-span route. The prior option/default report supplies F and selected N19 admission only after this exact caller.')
 add('span_type_forest_normal_continuation_exact_tag',[],[neq(f'(and {upper} (not {belowspan}) (= T #x1742))','(= T #x1742)')])
 add('first_span_extent_is_strict_subspan_of_record',[],['(bvuge PL SIZE)','(bvugt PL #xfffffff5)'],[fit])
 solve('reject_mode_zero_as_found_span_continuation',prefix(*mz)+'(assert '+fit+')\n(assert (= T #x1742))\n(assert (= MODE #x00000000))\n(assert (= FLAG #x00))\n(assert (= '+rd(mz[-1],0x1005e7510)['address']+' '+at(0x9004)+'))','sat',note='Source interpretation check:valid fitted span and mode0 can select error74c29dee. No target input,execution or external request is constructed.')
 # Replay only previously accepted universal lemmas,with fresh original byte recaptures.
 reused=[];old=json.loads(read(ROOT/'daemon_constructor_lookup_checks.json'));names={f'byte{i}_{p}'for i in range(4)for p in ['seed']+['round'+str(j)for j in range(1,8)]}|{'decoder_merge_and_four_addresses','lookup_entry_snapshot_partition','next_link_and_miss_state','candidate_decoder_interface','identifier_comparison_and_first_match','lookup_result_publication'};reused +=[(q,'daemon_constructor_lookup_checks.json')for q in old['proofs']if q['name']in names]
 old=json.loads(read(ROOT/'daemon_existing_scalar_reader_checks.json'));reused +=[(q,'daemon_existing_scalar_reader_checks.json')for q in old['proofs']if q['name'].startswith('tag_byte')or q['name']in('word_reader_dual_output_and_addresses','tag_reader_merge_and_addresses','shared_word_call_preserves_offset_selector')]
 old=json.loads(read(ROOT/'daemon_reader_u64_codec_checks.json'));reused +=[(q,'daemon_reader_u64_codec_checks.json')for q in old['proofs']if q['name']=='word_residual_and_preserved_key_values'];assert len(reused)==58
 for q,fn in reused:
  assert q['result']=='unsat';v=subprocess.run([SOLVER,'-in'],input=q['query'],text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()=='unsat';pp.append({**q,'name':'replay_'+fn.removesuffix('_checks.json')+'_'+q['name'],'reused_lemma':True,'source_certificate':fn})
 return pp,tr,[]
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_first_key',lambda t:t['fragments']['lookup_call']['instructions'][9].__setitem__('operands','w9, #0')),('wrong_mode_split',lambda t:t['fragments']['mode_partition']['instructions'][9].__setitem__('operands','w9, lt')),('omit_mode_zero_error',lambda t:t['fragments'].pop('mode_zero')),('wrong_cursor_base',lambda t:t['fragments']['head']['instructions'][8].__setitem__('operands','x10, #0')),('omit_helper_output_interface',lambda t:t['fragments'].pop('helper_setup')),('invent_native_identity',lambda t:t.__setitem__('native_target_executed',True))];out=[]
 for n,op in ops:t=copy.deepcopy(s);op(t);assert t!=s;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,_=certificates(s);sites={pc for q in tr.values()for pc in q['source_sites']};expected={i['ea']for f in list(s['fragments'].values())+[s['preparation']]for i in f['instructions']if i['mnemonic']!='braa'};assert sites==expected,(expected-sites,sites-expected)
 aa=alterations(s);counts={**s['verified_source_counts'],'new_queries_unsat':sum(q['result']=='unsat'and not q['reused_lemma']for q in pp),'reused_queries_unsat':sum(q['result']=='unsat'and q['reused_lemma']for q in pp),'counterexamples_sat':sum(q['result']=='sat'for q in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(q['source_sites'])for q in tr.values()),'SSA_definitions':sum(q['SSA_definitions']for q in tr.values()),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_reader_outer_lifecycle.py':sha(ROOT/'validate_daemon_reader_outer_lifecycle.py'),'recover_daemon_reader_context_footprint.py':sha(ROOT/'recover_daemon_reader_context_footprint.py')},'proofs':pp,'translations':tr,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'source_recapture_match':True,'all_checks_pass':True,'first_key_option_and_span_mode_interfaces_proved':True,'complete_parser_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
