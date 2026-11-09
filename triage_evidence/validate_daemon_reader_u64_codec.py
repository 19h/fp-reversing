#!/usr/bin/env python3
"""Source-derived eight-byte decoder seed/round/merge and N19 round-trip proofs."""
import copy,json,re,subprocess
from recover_daemon_reader_u64_codec import ROOT,P,SCOPE,FLAGS,KEYS,sha,read,build
from validate_daemon_reader_record_payloads import Engine
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix,split,WORD_BASE
from validate_daemon_constructor_lookup import CUTS as WORD_CUTS,written
ROUND_KEYS=[0x324a764c67af2e0e,0xe70987b7a1f527b0,0x9032dc5079388982,0x144db9b1af6b5721,0xeb8e58819a88bf30,0x7faaf81a732f68b4,0x4f99108510ad96e0]
SOLVER='/opt/homebrew/bin/z3';PH='(concat ((_ extract 63 32) Z30) #x00006cf4)';RAW_XOR=0xfa039b7ca50c772e
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in [('RAW64',64),('CTX',64),('NODE',64),('END',64),('HRAW',32),('STAG',16),('VAL32',32),('SPAN',64),('REC',64),('CONTAINER',64),('COMPARE_CTX',64)]+[('B'+str(j),8)for j in range(4,8)]+[('U'+str(j),64)for j in range(4,8)])
def certificates(s):
 fs=s['fragments'];pp=[];tr={};scope='Source component with the proved literal/residual keys,valid stable frame/buffer/node owners and source caller phase/selector premises. No native pointer validity,ownership,PAC,endpoint or transport proof.'
 def solve(n,body,result='unsat',note=''):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+body+'\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr);pp.append({'name':n,'query':q,'result':result,'scope':scope+' '+note,'reused_lemma':False});print(n,result,flush=True)
 def part(n,label=None,r=None,loads=None,chain=None,a=None,end=None,cuts=None):
  f=fs[n];label=label or n;a=a or int(f['start'],16);end=end or(int(f['instructions'][-1]['ea'],16)if f['instructions'][-1]['mnemonic']=='braa'else int(f['end'],16));ii=[i for i in f['instructions']if a<=int(i['ea'],16)<end];ll={};dd=[]
  for ins in ii:
   if ins['mnemonic']in('ldr','ldrb','ldrh','ldrsh','ldur'):
    w=8 if ins['mnemonic']=='ldrb'else 16 if ins['mnemonic']in('ldrh','ldrsh')else 32 if ins['operands'].startswith('w')else 64;v='TABLE'if ins['operands'].endswith('[sp, #0x9d8]')else PH if ins['operands'].endswith('[sp, #0x9d0]')else None
    if v is None:v=label+'_L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {w}))')
    ll[ins['ea']]=(v,w)
  ll.update(loads or{});rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K'
  if chain:rr.update({j:chain[-1].get('x'+str(j))for j in range(31)})
  rr.update(r or{});g=Engine(rr,ll,namespace=label+'_');g.cuts=cuts or{};g.run({'instructions':ii},end);g.declarations='\n'.join(dd)+'\n';tr[label]=g.record();return(chain or[])+[g]
 def initial(pc):return{int(j):bv(int(v,16))for j,v in s['constant_states_before_reader_sites'][hex(pc)].items()}
 def rd(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
 def add(n,gs,tt,cc=(),note=''):solve(n,prefix(*gs)+''.join('(assert '+c+')\n'for c in cc)+'(assert (or '+' '.join(tt)+'))',note=note)
 # The caller's real required key state is produced by the literal tail,word
 # reader residuals,and a caller MOV X3,X20; no runtime snapshot supplies it.
 lit=part('literal_tail');wcuts={pc:'U'+str(j)if j<3 else'(bvxor U3 #x5353535353535353)'for j,pc in enumerate(WORD_CUTS)}
 word=part('word','preceding_word_residuals',chain=lit,r={1:'BUF',4:f'(bvadd O {bv(WORD_BASE)})',16:z('IX')});g=word[-1]
 add('word_residual_and_preserved_key_values',word,[neq(g.get('x'+str(j)),bv(v))for j,v in KEYS.items()if j!=3]+[neq(g.get('x20'),bv(KEYS[3]))],note='The full preceding word decoder is translated without mask cuts. Key outputs are input-independent literal/residual values for arbitrary bytes and offsets.')
 gate=part('extent','u64_extent_gate',chain=word,r={8:bv(0x185d),1:z('(bvxor PL #x8ec35f08)')});g=gate[-1];at=lambda ix:f'(bvadd TABLE {bv(ix*8)})';frame=lambda off:f'(bvadd K {bv(off)})'
 add('N19_u64_eight_byte_extent_and_caller_phase',gate,[neq(g.get('w24'),'#x00006cf4'),neq(rd(g,0x100499070)['address'],f'(ite (= PL #x00000008) {at(0x851d)} {at(0x185d)})')])
 caller=part('caller','N19_u64_actual_call',chain=gate,loads={'0x1004a4e0c':('O',64)});g=caller[-1]
 add('N19_reader_arguments_and_all_ten_keys',caller,[neq(g.get('x'+str(j)),bv(v))for j,v in KEYS.items()]+[neq(g.get('x0'),'O'),neq(g.get('x10'),frame(0x4120)),neq(g.get('w8'),'#x000008c4'),neq(rd(g,0x1004a4e00)['address'],at(0xbe63))],['(= PL #x00000008)'],note='Other intervening source ranges preserve the nine inherited keys;X3 is restored from X20 by the caller.')
 # Bind the N19 cursor cache and literal state to the complete preparer.
 fp=part('prepare','actual_prepare',r={8:bv(0x8c3f),1:'BUF',4:f'(bvadd O {bv(WORD_BASE+6)})',16:z('IX')},loads={'0x1006f6c98':('O',64),'0x1006f70d0':(z('SIZE'),64)})
 cache=next(q for q in fp[-1].stores if q['site']=='0x1006f70c4')
 add('actual_N19_cursor_cache_and_literal_tail',lit+fp,[neq(cache['address'],frame(0x7e8)),neq(cache['value'],'O')]+[neq(fp[-1].get('x'+str(j)),lit[-1].get('x'+str(j)))for j in[19,9,6,12,27,21,2,25,8,23,26,14,15,20,30,5,7,11,0]],note='Other eager context loads remain arbitrary but valid. The N19 source cursor N0 at a610 is staged unchanged at7e8 before the u64 caller reloads it.')
 ii=fs['reader']['instructions'];seeds=s['reader_parts']['seed_indices'];eors=s['reader_parts']['round_markers'];sels=s['reader_parts']['selection_indices'];R='((_ rotate_right 8) (bvand A #xfffffffffffffff8))';S=f'(bvadd {R} #x622c5d3364e5d59f)';X=f'(bvxor {S} #xa7bebfcf1750d389)';Y=f'(bvxor {S} #xb6dc5654307e7f72)'
 for b,(a,sel)in enumerate(zip(seeds,sels)):
  ee=eors[6*b:6*b+6];yr=split(ii[ee[0]]['operands'])[0];mix=next(j for j in range(ee[0]-1,a,-1)if ii[j]['mnemonic']=='add'and split(ii[j]['operands'])[2]==yr);ops=split(ii[mix]['operands']);rr=initial(int(ii[a]['ea'],16));rr[int(split(ii[a]['operands'])[1][1:])]='A'
  gs=part('reader','byte'+str(b)+'_seed',r=rr,a=int(ii[a]['ea'],16),end=int(ii[mix]['ea'],16));g=gs[-1];add('byte'+str(b)+'_canonical_seed',gs,[neq(g.get(ops[1]),f'((_ rotate_right 8) {X})'),neq(g.get(yr),Y)],note='Universal u64 address;no address-domain guess. Only source-live literal values are supplied.')
  start=mix
  for j in range(7):
   stop=ee[j]+1 if j<6 else sel;rr=initial(int(ii[start]['ea'],16))
   if j==0:rr[int(ops[1][1:])]='((_ rotate_right 8) U)';rr[int(yr[1:])]='V'
   else:
    prev=split(ii[ee[j-1]]['operands']);xr,yr0=prev[1],prev[0];rr[int(xr[1:])]='U';rr[int(yr0[1:])]='V'
    for k in range(a,start):
     q=ii[k];p=split(q['operands'])
     if q['mnemonic']=='ror'and p[1]==xr and p[2]=='#8'and p[0]!=yr0 and all(xr[1:]not in written(v)and p[0][1:]not in written(v)for v in ii[k+1:start]):rr[int(p[0][1:])]='((_ rotate_right 8) U)'
   gs=part('reader','byte'+str(b)+'_round'+str(j+1),r=rr,a=int(ii[start]['ea'],16),end=int(ii[stop-1]['ea'],16)+4);g=gs[-1];key=ROUND_KEYS[j]^(0x9898989898989898 if b==7 and j==6 else 0);F=f'(bvxor (bvadd ((_ rotate_right 8) U) V) {bv(key)})'
   if j<6:p=split(ii[ee[j]]['operands']);tt=[neq(g.get(p[1]),F),neq(g.get(p[0]),f'(bvxor ((_ rotate_left 3) V) {F})')]
   else:tt=[neq(g.get(split(ii[sel+1]['operands'])[1]),F)]
   add('byte'+str(b)+'_round'+str(j+1),gs,tt,note='Arbitrary u64 state and source-carried precomputed rotates. Byte7 round7 has the explicit9898 word delta.');start=stop
 # Whole-reader merge with independently proved final mask-word cuts.
 byte_pcs=[int(q['ea'],16)for q in ii if q['mnemonic']=='ldrb'];assert len(byte_pcs)==8
 cuts={int(ii[sel-1]['ea'],16):'U'+str(j)if j<7 else'(bvxor U7 #x9898989898989898)'for j,sel in enumerate(sels)}
 full=part('reader','full_reader_merge',r={**{j:bv(v)for j,v in KEYS.items()},0:'O',10:'CELL',8:bv(0x8c4)},loads={'0x100588cb4':('FN',64),'0x100588cbc':('BUF',64),**{hex(pc):('B'+str(j),8)for j,pc in enumerate(byte_pcs)}},cuts=cuts);g=full[-1];decoded=[];tt=[]
 for j,pc in enumerate(byte_pcs):
  a=f'(bvadd BUF O {bv(10+j)})';mask=f'((_ extract 7 0) (bvlshr U{j} (bvshl (bvand {a} {bv(7)}) {bv(3)})))';decoded.append(f'(bvxor B{j} {mask})');tt.append(neq(rd(g,pc)['address'],a))
 wire='(concat '+' '.join(decoded)+')';raw=f'(bvxor {wire} {bv(RAW_XOR)})';tt.extend([neq(rd(g,0x100588cbc)['address'],'CELL'),neq(rd(g,0x100588cb4)['address'],at(0x8c4)),neq(g.get('x8'),'FN'),neq(g.get('x9'),raw)]);assert not g.stores
 add('whole_eight_byte_reader_merge_and_return',full,tt,note='Every instruction before BRAA is translated. Eight final-word cuts compose the64 new seed/round lemmas. X9 is an encoded u64 representation,not an unmodified wire value.')
 solve('raw_u64_is_not_unencoded_wire',prefix(*full)+'(assert '+neq(g.get('x9'),wire)+')','sat','Abstract representation counterexample only;no native request,input or fault fixture is generated.')
 returned=part('returned','N19_raw64_return_stage',chain=full);g=returned[-1];add('N19_complete_reader_return_stages_raw64',returned,[neq(g.stores[0]['address'],frame(0x12c8)),neq(g.stores[0]['value'],raw),neq(g.get('w9'),'#x00006cf4'),neq(rd(g,0x1004cdebc)['address'],at(0x746b))])
 joined=part('join','N19_u64_join',chain=returned,loads={'0x10047310c':('END',64),'0x100473114':('HRAW',32),'0x100473118':('STAG',16),'0x10047312c':('CTX',64)});g=joined[-1];add('N19_u64_returns_to_ordinary_record_path',joined,[neq(g.stores[0]['address'],frame(0xdb8)),neq(g.stores[0]['value'],'END'),neq(rd(g,0x100473150)['address'],at(0x70a6))],['(= STAG #xc31c)'])
 packed=part('pack','N19_raw64_pack',chain=joined,loads={'0x10056debc':('(bvxor #x00000008 #x8b3dc651)',32),'0x10056dee4':('VAL32',32),'0x10056deec':(raw,64),'0x10056def4':('SPAN',64)});g=packed[-1];st=g.stores[5];add('N19_raw64_staging_to_writer_operand_cell',packed,[neq(rd(g,0x10056deec)['address'],frame(0x12c8)),neq(st['address'],frame(0xa628)),neq(st['value'],raw)],['(= STAG #xc31c)'],note='Named reload is the just-proved returned raw64 under stable disjoint frame premises;inactive variant caches retain their existing separate obligations.')
 wc=part('writer_caller','N19_paired_writer_call',r={16:bv(0x6cf4)});g=wc[-1];add('paired_u64_writer_operand_cell_and_selector',wc,[neq(g.get('x1'),frame(0xa628)),neq(g.get('x14'),frame(0x5440)),neq(g.get('x16'),bv(0x80915f9a168f26e3)),neq(g.get('w0'),'#x00001351'),neq(rd(g,0x10053f034)['address'],at(0x7d2d))])
 we=part('writer_entry','paired_writer_raw_load',chain=wc,loads={'0x1005a2c2c':('NODE',64),'0x1005a2c30':('REC',64),'0x1005a2c54':(raw,64),'0x1005a2c60':('FN',64)});g=we[-1];add('paired_writer_loads_actual_decoded_operand',full+we,[neq(rd(g,0x1005a2c54)['address'],frame(0xa628)),neq(g.get('x16'),f'(bvxor {raw} #x80915f9a168f26e3)')],note='Existing complete N19 writer proof supplies wire=RAW64 XOR fa039b7ca50c772e and the destination-address mask.')
 terms=[neq(f'(bvxor {raw} {bv(RAW_XOR)})',wire)]
 for j,b in enumerate(decoded):
  a=f'(bvadd REC {bv(10+j)})';mask=f'((_ extract 7 0) (bvlshr U{j} (bvshl (bvand {a} {bv(7)}) {bv(3)})))';terms.append(neq(f'(bvxor (bvxor {b} {mask}) {mask})',b))
 add('u64_reader_writer_decoded_value_round_trip',[],terms,note='Reader RAW encoding cancels the established writer encoding. For arbitrary source/destination mask states,decoding the destination reproduces the eight decoded source bytes;encoded storage bytes need not match.')
 add('admitted_eight_payload_offsets_within_extent',[],[f'(bvuge (bvadd O {bv(10+j)}) {z("SIZE")})'for j in range(8)],[f'(bvult O {z("SIZE")})',f'(bvule (bvadd O {bv(18)}) {z("SIZE")})'],note='Logical offsets under the earlier u32 total-extent fit contract;physical BUF arithmetic and native ownership remain premises.')
 # Resolve the previously open16 B allocation/list-container relationship.
 ap=part('allocation_prefix','container_allocation_prefix',r={20:bv(0xc4dd)})
 aa=part('allocation_args','container_malloc16_arguments',chain=ap);g=aa[-1];add('source_requests_sixteen_byte_container',aa,[neq(g.get('x0'),bv(16)),neq(g.get('w22'),'#xc040eef7'),neq(g.get('w23'),'#x00006cf4'),neq(g.get('x24'),'TABLE')],note='The intervening gap preserves X20/X22/X23/X24. Prior source-certified bank/import evidence identifies malloc;the call is not executed.')
 ar=part('allocation_result','container_allocation_result',r={0:'CONTAINER',20:g.get('x20'),22:g.get('x22'),23:g.get('x23'),24:g.get('x24')});g=ar[-1]
 add('normal_allocation_result_staged_at6368',aa+ar,[neq(g.stores[0]['address'],frame(0x6368)),neq(g.stores[0]['value'],'CONTAINER'),neq(rd(g,0x1004958f8)['address'],f'(ite (= CONTAINER {bv(0)}) {at(0xc4dd)} {at(0xc4e0)})')],note='CONTAINER is the normal malloc-return input;SP/X19-X29 are preserved. No allocator ownership or native freshness is inferred.')
 zero=part('zero_container','container_initial_head_tail',chain=ar);g=zero[-1];add('allocated_container_two_word_initialization',aa+zero,[neq(g.stores[0]['address'],'CONTAINER'),neq(g.stores[0]['value'],bv(0)),neq(g.stores[1]['address'],f'(bvadd CONTAINER {bv(8)})'),neq(g.stores[1]['value'],bv(0)),neq(g.get('w12'),'#x0000b350'),neq(rd(g,0x1005b07b4)['address'],at(0x3599))],['(distinct CONTAINER '+bv(0)+')'])
 cj=part('join','allocated_container_ordinary_join',r={9:PH},loads={'0x10047310c':('END',64),'0x100473114':('HRAW',32),'0x100473118':('STAG',16),'0x10047312c':('CONTAINER',64)})
 cp=part('pack','allocated_container_pack',chain=cj,loads={'0x10056debc':('(bvxor #x00000008 #x8b3dc651)',32),'0x10056dee4':('VAL32',32),'0x10056deec':('RAW64',64),'0x10056def4':('SPAN',64)});g=cp[-1]
 add('allocation_result_is_the_ordinary_lookup_insertion_container',cp,[neq(rd(cj[-1],0x10047312c)['address'],frame(0x6368)),neq(g.stores[0]['address'],frame(0x8760)),neq(g.stores[0]['value'],'CONTAINER'),neq(rd(cj[-1],0x100473150)['address'],at(0x70a6))],['(not (and (= HRAW #x8b3dc651) (= STAG #x1742)))'],note='6368 is the previously proved allocation-result cell.8760 supplies the established lookup and append/replacement contracts. Stable reaching cells and disjoint owners remain premises.')
 comp=part('comparison_store','separate_comparison_context_origin',r={10:'COMPARE_CTX'});g=comp[-1];add('comparison_context_has_separate_saved_provenance',comp,[neq(g.stores[0]['address'],frame(0x5e50)),neq(g.stores[0]['value'],'COMPARE_CTX')],note='This is a separate producer/role,not a universal pointer-inequality theorem. Fresh/disjoint native allocation semantics are not proved here.')
 loop=part('loop','exhausted_container_loop',r={8:'O',19:z('(bvxor SIZE #x8b3dc651)'),12:bv(0xb350)})
 empty=part('empty','exhausted_container_reload',chain=loop,loads={'0x1005588bc':('CONTAINER',64)});success=part('success','exhausted_container_success',chain=empty)
 out=part('output','exhausted_container_output',chain=success,loads={'0x100588170':('OUT',64),'0x100588178':('CONT',64)});outer=part('outer_return','exhausted_container_return',chain=out);g=outer[-1]
 add('exhausted_input_publishes_the_allocated_container',outer,[neq(rd(empty[-1],0x1005588bc)['address'],frame(0x6368)),neq(out[-1].stores[0]['address'],'OUT'),neq(out[-1].stores[0]['value'],'CONTAINER'),neq(rd(out[-1],0x100588170)['address'],frame(0x8398)),neq(rd(out[-1],0x100588178)['address'],frame(0x7910)),neq(g.get('x6'),bv(0x8b3dc651)),neq(g.get('x21'),'CONT'),neq(g.get('x17'),bv(0xbcd2))],[f'(= O {z("SIZE")})'],note='The prior append/replacement progress contracts supply a fitting cursor. Equality selects exhaustion. The output is the allocated list-container pointer,not a flattened byte-buffer result;native/external transport remains unproved.')
 sj=part('join','special_container_join',r={9:PH},loads={'0x10047310c':('END',64),'0x100473114':('HRAW',32),'0x100473118':('STAG',16),'0x10047312c':('CONTAINER',64)})
 ss=part('success','special_container_success',chain=sj);so=part('output','special_container_output',chain=ss,loads={'0x100588170':('OUT',64),'0x100588178':('CONT',64)})
 add('zero_identifier_span_publishes_allocated_container_early',so,[neq(rd(sj[-1],0x100473150)['address'],at(0x7042)),neq(so[-1].stores[0]['address'],'OUT'),neq(so[-1].stores[0]['value'],'CONTAINER'),neq(so[-1].get('x6'),bv(0x8b3dc651))],['(= HRAW #x8b3dc651)','(= STAG #x1742)'],note='These encodings mean decoded identifier0 and wire span tag50db. Earlier fit/admission remains a premise. This publishes the container without allocating an ordinary node for this record;no padding-byte validation or native reachability is inferred.')
 # Revalidate generic writer components against the recaptured writer bytes.
 old=json.loads(read(ROOT/'daemon_typed_scalar_checks.json'));selected=[q for q in old['proofs']if re.fullmatch(r'byte[0-7]_(seed|round[1-7]|selection)',q['name'])];assert len(selected)==72
 selected=[('daemon_typed_scalar_checks.json',q)for q in selected]
 prior=json.loads(read(ROOT/'daemon_reader_record_payloads_checks.json'));specific=[q for q in prior['proofs']if q['name']=='N19_full_eight_byte_writer_cut_composition'];assert len(specific)==1;selected+= [('daemon_reader_record_payloads_checks.json',specific[0])]
 for fn,q0 in selected:
  v=subprocess.run([SOLVER,'-in'],input=q0['query'],text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()=='unsat';pp.append({**q0,'name':'reused_'+q0['name'],'reused_lemma':True,'prior_checks_sha256':sha(ROOT/fn)})
 return pp,tr,{'part':part,'add':add,'solve':solve,'caller':caller}
def verify(s):return s==build()
def alterations(s):
 ops=[('change_last_mask_delta',lambda t:t['reader_parts'].__setitem__('last_word_xor_delta','0x0')),('wrong_round3_input_key',lambda t:t['required_reader_key_values'].__setitem__('6','0x0')),('omit_caller_key_restore',lambda t:t['fragments'].pop('caller')),('truncate_raw64_store',lambda t:t['fragments']['returned']['instructions'][2].__setitem__('operands','w9, [sp, #0x12c8]')),('invent_native_roundtrip',lambda t:t.__setitem__('target_executed',True)),('conflate_comparison_and_list_origin',lambda t:t['fragments']['comparison_store']['instructions'][0].__setitem__('operands','x10, [sp, #0x6368]'))];out=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=s;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,ctx=certificates(s);aa=alterations(s);sites={pc for g in tr.values()for pc in g['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};assert expected<=sites,(len(expected),len(sites),expected-sites)
 counts={**s['verified_source_counts'],'new_queries_unsat':sum(q['result']=='unsat'and not q.get('reused_lemma')for q in pp),'reused_queries_unsat':sum(q.get('reused_lemma',False)for q in pp),'counterexamples_sat':sum(q['result']=='sat'for q in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(g['source_sites'])for g in tr.values()),'SSA_definitions':sum(g['SSA_definitions']for g in tr.values()),'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_reader_record_payloads.py','validate_daemon_constructor_lookup.py','daemon_typed_scalar_checks.json','daemon_reader_record_payloads_checks.json']
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'translations':tr,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'reader_raw_encoding':'wire_BE64 XOR fa039b7ca50c772e','decoded_u64_roundtrip_proved':True,'allocated_container_provenance_proved':True,'native_pointer_inequality_proved':False,'complete_parser_proved':False,'source_recapture_match':True,'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
