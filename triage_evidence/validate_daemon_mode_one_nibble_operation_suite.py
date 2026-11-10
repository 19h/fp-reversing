#!/usr/bin/env python3
"""Prove encoded carry/XOR and input/output numeric maps from the original image."""
import copy,json,re,subprocess,shutil
from recover_daemon_mode_one_nibble_operation_suite import ROOT,P,SCOPE,FLAGS,DEPS,ROM,E,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_encoded_addition import NamedByteSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq
from daemon_mode_one_handoff_tools import parse
SOLVER=shutil.which('z3');assert SOLVER
REGS={'carry':{8:bv(ROM),9:bv(0x7dba),10:z('IDX'),20:frame(0x8b0)},'xor':{0:bv(0x883fddf1),2:bv(653),3:bv(0x469ee6),4:bv(928),8:bv(ROM),11:bv(0x7dc2),12:bv(799),13:bv(0x73acf),14:bv(0x441fef),15:bv(962),16:z('IDX'),20:frame(0x8b0)},'decode':{1:z('IDX'),8:bv(ROM),9:bv(0x2d7e),20:frame(0x8b0)},'encode':{0:bv(928),8:bv(ROM),9:bv(0x2d7e),10:z('IDX'),11:bv(799),13:bv(0x883fddf1),14:bv(962),16:bv(653),20:frame(0x8b0)}}
LOADS={'carry':{0x100c1c8fc:('ILO',8),0x100c1c904:('IHI',8),0x100c1c938:('RB',8),0x100c1c980:('QV',8),0x100c1c9a8:('FN_C',64)},'xor':{0x100d3991c:('ILO',8),0x100d39930:('IHI',8),0x100d39954:('RB',8),0x100d399a0:('QV',8),0x100d399c8:('FN_X',64)},'decode':{0x100c62838:('IV',8),0x100c62888:('RB',8),0x100c628b4:('FN_D',64)},'encode':{0x100d3151c:('RB',8),0x100d31558:('QV',8),0x100d31584:('FN_E',64)}}
def carry_decode(b):return(((b+0x44)>>4)&15)^2
def xor_decode(b):
 n=(b-7)&0xffffffff;l=n&255;return(n^(l>>4)^(l>>3)^0xbbbbbbbb)&255
def lut(values,arg,iw,ow):
 out=bv(values[-1],ow)
 for j in reversed(range(len(values)-1)):out='(ite (= '+arg+' '+bv(j,iw)+') '+bv(values[j],ow)+' '+out+')'
 return out

def certificates(s):
 pp=[];models={};bridges=[];fs=s['fragments'];data=s['image_data'];EI=data['shared_E_inverse']
 def solve(name,body,result='unsat',extra='',cc=(),logic='QF_BV'):
  q='(set-option :timeout 15000)\n(set-logic '+logic+')\n'+DECL+extra+body+'\n'+''.join('(assert '+x+')\n'for x in cc)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def dec(g):return''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())
 def cert(name,g,terms,cc=()):solve(name,g.prefix()+'(assert (or '+' '.join(terms)+'))',extra=dec(g),cc=cc)
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 previous=json.loads(read(ROOT/'daemon_mode_one_encoded_addition_checks.json'));assert previous['all_checks_pass']and len(previous['proofs'])==686
 for p in previous['proofs']:
  r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()==p['result'];pp.append({**p,'name':'replayed_addition_'+p['name'],'replayed_query':True})
 # W9 was outside the abbreviated previous ABI. Recover its producer and
 # prove preservation instead of inferring it from an arbitrary live-in.
 old_source=json.loads(read(ROOT/'daemon_mode_one_encoded_addition_source.json'));assert not set(old_source['register_write_sets']['builder'])&{'x9','w9'}
 for label,terms in[('second_shuffle',[('9',bv(0x7dba))]),('builder',[('8',bv(ROM)),('10',bv(0)),('20',frame(0x8b0))])]:
  m=previous['semantics']['source_models'][label];ex=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in m['declarations'].items());solve('actual_incoming_'+label+'_register_contract',m['source_SSA']+'(assert (or '+' '.join(neq(m['final_registers'][r],v)for r,v in terms)+'))',extra=ex)
 assert s['image_data']['carry_compatible_generator']==11 and len(data['carry_compatible_encoding_candidates'])==1
 for g in data['sum_only_encodings']:
  e=g['encoding'];iv=[e.index(j)for j in range(16)];fits=all(r['decoded_symbol']==e[(iv[r['operand_byte']&15]+iv[r['operand_byte']>>4])//16]for r in data['carry256']);assert fits==(g['generator_symbol']==11)
 oldE=data['prior_sum_encoding'];assert all(oldE[j]==E[5*j%16]for j in range(16))
 # Independent universal4-bit checks bind the exact captured ROM slices
 # to the numeric operations under the carry-selected encoding.
 a=lut(EI,'A4',4,4);b=lut(EI,'B4',4,4);arg='(concat B4 A4)';extra='(declare-fun A4 () (_ BitVec 4))\n(declare-fun B4 () (_ BitVec 4))\n'
 total='(bvadd ((_ zero_extend 1) '+a+') ((_ zero_extend 1) '+b+'))';car='((_ zero_extend 3) ((_ extract 4 4) '+total+'))'
 for label,values,expected in[('sum',[r['decoded_u4']for r in data['prior_sum_selected_cells']],lut(E,'(bvadd '+a+' '+b+')',4,4)),('carry',[r['decoded_symbol']for r in data['carry256']],lut(E,car,4,4)),('xor',[r['decoded_symbol']for r in data['xor256']],lut(E,'(bvxor '+a+' '+b+')',4,4))]:solve('shared_encoding_ROM_'+label+'_all256', '(assert '+neq(lut(values,arg,8,4),expected)+')',extra=extra)
 sums=[]
 for x in range(16):
  for y in range(16):
   sym=E[x]+16*E[y];sr=data['prior_sum_selected_cells'][sym]['decoded_u4'];cr=data['carry256'][sym]['decoded_symbol'];xr=data['xor256'][sym]['decoded_symbol'];assert(sr,cr,xr)==(E[(x+y)%16],E[(x+y)//16],E[x^y]);sums.append({'a':x,'b':y,'sum':(x+y)%16,'carry':(x+y)//16,'xor':x^y,'encoded_sum':sr,'encoded_carry':cr,'encoded_xor':xr})
 assert sum(r['carry']==0 for r in sums)==136 and sum(r['carry']==1 for r in sums)==120
 assert len({(r['sum'],r['carry'])for r in sums})==31
 # Static E/EI are inverse maps. Private input/output maps additionally
 # compose with P and Q;they are not assumed mutual inverses.
 solve('static_numeric_encoding_and_decoding_are_inverse','(declare-fun N4 () (_ BitVec 4))\n(assert (or '+neq(lut(E,lut(EI,'N4',4,4),4,4),'N4')+' '+neq(lut(EI,lut(E,'N4',4,4),4,4),'N4')+'))')
 xor_alphabet=sorted({r['encoded_u8']for r in data['xor256']});assert len(xor_alphabet)==16 and set(xor_alphabet)=={v for v in range(256)if xor_decode(v)<16};assert{xor_decode(v)for v in xor_alphabet}==set(range(16))
 physical=lambda label:'(bvadd '+frame(0x8b0)+' ((_ zero_extend 32) (bvurem (bvmul '+label+' #x0000031f) #x000003c2)))'
 QREAD={'carry':0x100c1c980,'xor':0x100d399a0,'encode':0x100d31558};RREAD={'carry':0x100c1c938,'xor':0x100d39954,'decode':0x100c62888,'encode':0x100d3151c};IREAD={'carry':[0x100c1c8fc,0x100c1c904],'xor':[0x100d3991c,0x100d39930],'decode':[0x100c62838]}
 contracts=[];encoder_proposals=[]
 for label in['carry','xor','decode','encode']:
  g=NamedByteSSA(label,REGS[label],presets={0x740:('TABLE',64)},loads={hex(k):v for k,v in LOADS[label].items()});g.decl.update({'IDX':32,'ILO':8,'IHI':8,'IV':8,'RB':8,'QV':8,**{v[0]:v[1]for v in LOADS[label].values()}});limit=256 if label in['carry','xor']else 16;cc=['(bvult IDX '+bv(limit,32)+')','(bvult ILO #x10)','(bvult IHI #x10)','(bvult IV #x10)','(bvult QV #x10)']
  if label=='xor':cc.append('(or '+' '.join('(= RB '+bv(v,8)+')'for v in xor_alphabet)+')')
  if label=='decode':cc.extend(['(bvuge RB #x60)','(bvult RB #x70)'])
  for i in fs[label]['instructions'][:-1]:
   if i['ea']=='0x100d39914':cert('xor_actual_register_shift_count_is4',g,[neq(g.get('w17'),bv(4,32))],cc)
   if i['ea']=='0x100d399a4':cert('xor_hidden_UDIV_divisor_is962',g,[neq(g.get('w17'),bv(962,32))],cc)
   g.run({'instructions':[i]},int(i['ea'],16)+4)
  models[label]=g;assert len(g.stores)==1 and not g.frame_writes
  base={'carry':677,'xor':333,'decode':659,'encode':936}[label];counter={'carry':10,'xor':16,'decode':1,'encode':10}[label];yes,no={'carry':(0x7dc2,0x7dba),'xor':(0x8d55,0x7dc2),'decode':(0x2d7e,0x2d8f),'encode':(0x5d09,0x2d7e)}[label];targetpc=list(LOADS[label])[-1]
  cert(label+'_destination_progress_control_and_preserved_roots',g,[neq(g.stores[0]['address'],physical('(bvadd IDX '+bv(base,32)+')')),neq(g.get('w'+str(counter)),'(bvadd IDX #x00000001)'),neq(rd(g,targetpc)['address'],f'(ite (= IDX {bv(limit-1,32)}) {at(yes)} {at(no)})'),neq(g.get('x8'),bv(ROM)),neq(g.get('x20'),frame(0x8b0))],cc)
  if label in['carry','xor']:
   for j in range(16):
    cert(label+'_low_inverse_cell_'+str(j),g,[neq(rd(g,IREAD[label][0])['address'],frame(0x8b0+799*(593+j)%962))],cc+['(= (bvand IDX #x0000000f) '+bv(j,32)+')'])
    cert(label+'_high_inverse_cell_'+str(j),g,[neq(rd(g,IREAD[label][1])['address'],frame(0x8b0+799*(593+j)%962))],cc+['(= (bvlshr IDX #x00000004) '+bv(j,32)+')'])
   rows=data[label+'256']
   for row in rows:
    v=row['operand_byte'];cert(label+'_ROM_cell_'+str(v),g,[neq(rd(g,RREAD[label])['address'],bv(ROM+row['physical_offset']))],cc+['(= ILO '+bv(v&15,8)+')','(= IHI '+bv(v>>4,8)+')'])
   if label=='carry':
    for nib in range(16):
     vals=[b for b in range(256)if carry_decode(b)==nib];assert len(vals)==16;cert('carry_Q_cell_'+str(nib),g,[neq(rd(g,QREAD[label])['address'],frame(0x8b0+799*nib%962))],cc+['(or '+' '.join('(= RB '+bv(v,8)+')'for v in vals)+')'])
    cert('carry_stores_encoded_high_nibble',g,[neq(g.stores[0]['value'],'(bvshl QV #x04)')],cc)
   else:
    for raw in xor_alphabet:cert('xor_Q_encoded_byte_'+str(raw),g,[neq(rd(g,QREAD[label])['address'],frame(0x8b0+799*xor_decode(raw)%962))],cc+['(= RB '+bv(raw,8)+')'])
    cert('xor_stores_encoded_nibble',g,[neq(g.stores[0]['value'],'QV')],cc)
  elif label=='decode':
   for j in range(16):
    cert('decode_inverse_source_'+str(j),g,[neq(rd(g,IREAD[label][0])['address'],frame(0x8b0+799*(593+j)%962))],cc+['(= IDX '+bv(j,32)+')'])
    row=data['decoder16'][j];cert('decode_ROM_cell_'+str(j),g,[neq(rd(g,RREAD[label])['address'],bv(ROM+row['physical_offset']))],cc+['(= IV '+bv(j,8)+')'])
   cert('decode_plain_nibble_value',g,[neq(g.stores[0]['value'],'(bvxor RB #x68)')],cc)
  else:
   for row in data['encoder16_candidates']:
    j=row['numeric_nibble'];extra=['(= IDX '+bv(j,32)+')','(= RB '+bv(row['encoded_u8'],8)+')'];cert('encoder_original_ROM_candidate_'+str(j),g,[neq(rd(g,RREAD[label])['address'],bv(ROM+row['candidate_physical_offset']))],cc+extra);cert('encoder_Q_numeric_symbol_'+str(j),g,[neq(rd(g,QREAD[label])['address'],frame(0x8b0+799*E[j]%962))],cc+extra);encoder_proposals.append({**row,'original_source_address_and_decoded_symbol_proved':True})
   cert('encode_stores_Q_encoded_nibble',g,[neq(g.stores[0]['value'],'QV')],cc)
  abi={'carry':{0:0x883fddf1,2:653,3:0x469ee6,4:928,9:0x7dba,11:0x7dc2,12:799,13:0x73acf,14:0x441fef,15:962,16:0},'xor':{0:0x883fddf1,1:0,2:653,3:0x469ee6,4:928,9:0x2d7e,11:0x7dc2,12:799,13:0x73acf,14:0x441fef,15:962},'decode':{0:928,9:0x2d7e,10:0,11:799,13:0x883fddf1,14:962,16:653},'encode':{0:928,2:0x0a15c815,4:0x2a65c9df,9:0x2d7e,11:799,12:0xa77b2501,13:0x883fddf1,14:962,15:0x3489,16:653,22:0xf402e748,24:0xc5141de1}}[label]
  cert(label+'_full_outgoing_register_epoch',g,[neq(g.get('x'+str(k)),bv(v))for k,v in abi.items()],cc);contracts.append({'fragment':label,'counter_register':'w'+str(counter),'domain':[0,limit-1],'iterations':limit,'destination_label_base':base,'destination_label_end':base+limit-1,'byte_conditions':cc,'outgoing_fixed_u64':{str(k):hex(v)for k,v in abi.items()},'repeat_slot':hex(no),'exit_slot':hex(yes)})
 # Raw ROM decode functions are checked separately from their selected
 # byte alphabets. Only XOR/decoder require their actual image codomains.
 xraw='(declare-fun RAW8 () (_ BitVec 8))\n';v='((_ zero_extend 24) RAW8)';cdec='(bvxor (bvand (bvlshr (bvadd '+v+' #x00000044) #x00000004) #x0000000f) #x00000002)';solve('carry_byte_decode_is_always_a_nibble','(assert (bvuge '+cdec+' #x00000010))',extra=xraw)
 for j in range(16):assert E[EI[j]]==j and EI[E[j]]==j
 assert[data['decoder16'][j]['numeric_nibble']for j in range(16)]==EI and[data['encoder16_candidates'][j]['decoded_symbol']for j in range(16)]==E
 # Generic map-role negative control:input P=identity,output Q swaps0/1.
 # It is not a native reachable encoding claim.
 qsym=lambda x:'(ite (= '+x+' #x0) #x1 (ite (= '+x+' #x1) #x0 '+x+'))'
 roundtrip=lut(EI,qsym(lut(E,'#x5',4,4)),4,4);solve('different_input_output_maps_need_not_roundtrip','(assert '+neq(roundtrip,'#x5')+')',result='sat')
 low_old=previous['semantics']['static_encoding_E'];assert all(low_old[j]==E[5*j%16]for j in range(16))
 layout={'Q':list(range(16)),'sum':list(range(72,328)),'xor':list(range(333,589)),'inverse_P':list(range(593,609)),'decode_input':list(range(659,675)),'carry_high':list(range(677,933)),'encode_output':list(range(936,952))};cells={k:[0x8b0+799*j%962 for j in labels]for k,labels in layout.items()};allcells=[o for a in cells.values()for o in a];assert len(allcells)==len(set(allcells))==832 and all(0x8b0<=o<0xc72 for o in allcells)
 records={name:g.record_full()for name,g in models.items()};actual={pc for g in models.values()for pc in g.sites};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==245
 sem={'source_models':records,'source_nonbranch_sites_translated':245,'all686_predecessor_queries_replayed':True,'predecessor_checks':'daemon_mode_one_encoded_addition_checks.json','incoming_W9_producer':'Original second shuffle:W9=0x7dba;previous builder write census preserves X9/W9','incoming_ROM_pointer':'Preferred image0x100e755f0;original loader rebase and prior selector premises apply','phase_contracts':contracts,'source_overapproximations_inserted':0,'byte_loads_are_named_component_inputs':True,'numeric_E':E,'numeric_E_inverse':EI,'carry_fixes_generator_symbol':11,'carry_compatible_encodings':data['carry_compatible_encoding_candidates'],'prior_sum_E_relation':'Previous generator0 Eold(n)=E(5*n mod16);both represent the sum law','static_sum_carry_xor_cases':sums,'static_decoder_encoder_inverse':True,'ROM_carry_zero_pairs':136,'ROM_carry_one_pairs':120,'joint_sum_carry_numeric_results':31,'xor_raw_byte_alphabet':xor_alphabet,'xor_decoded_symbol_alphabet':list(range(16)),'carry_raw_byte_domain_needed':False,'input_encoding':'Ein=P composed with E','output_encoding':'Eout=Q composed with E','sum_contract':'SUM[Ein(a)+16*Ein(b)]=Eout((a+b)mod16)','carry_contract':'CARRY[Ein(a)+16*Ein(b)]=Eout(floor((a+b)/16))<<4','xor_contract':'XOR[Ein(a)+16*Ein(b)]=Eout(a XOR b)','decoder_contract':'DEC[s]=Ein_inverse(s)','encoder_contract':'ENC[n]=Eout(n)','private_decoder_encoder_mutual_inverse_proved':False,'map_role_counterexample_is_abstract':True,'map_role_counterexample_native_reachability_proved':False,'carry_byte_low4_zero':True,'carry_output_has_two_encoded_high_nibbles':True,'carry_is_not_plain_native_flag':True,'generated_xor_constant_diagonal':'Eout(0)','generic_operand_symbol_values_must_differ':False,'selected_ROM_encoder_candidates':encoder_proposals,'encoder_candidate_addresses_values_freshly_proved':True,'ROM_selected_union_size':800,'ROM_bytes_total':928,'all_ROM_bytes_assumed_selected':False,'logical_frame_layout':layout,'physical_frame_layout':cells,'known_frame_cells':832,'unclaimed_frame_cells':130,'current_phase_byte_writes':544,'private_maps_stable_by_disjointness':True,'workspace_and_saved_request_slots_preserved':True,'F750_root_consumed':False,'whole_word_carry_propagation_proved':False,'whole_cryptographic_algorithm_identified':False,'next_target':'0x100d845e0','next_target_semantics_proved':False,'native_ownership_proved':False,'successful_output_proved':False,'daemon_kext_pairing_proved':False,'LOCAL_pointer_dereferences':0,'Mach_port_emissions':0,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['carry'].__setitem__('bytes','00'+q['fragments']['carry']['bytes'][2:])),('wrong_shift_register',lambda q:next(i for i in q['fragments']['xor']['instructions']if i['ea']=='0x100d39914').__setitem__('operands','w17, w16, w18')),('wrong_carry_slice',lambda q:q['image_data']['carry256'][0].__setitem__('numeric_carry',1)),('wrong_numeric_encoding',lambda q:q['image_data']['shared_E'].__setitem__(0,0)),('wrong_encoder_candidate',lambda q:q['image_data']['encoder16_candidates'][0].__setitem__('candidate_physical_offset',0)),('wrong_next_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('wrong_lineage',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];original=build();out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert q!=original;out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':245,'incoming_register_contracts':2,'carry_iterations':256,'xor_iterations':256,'decoder_iterations':16,'encoder_iterations':16,'current_byte_writes':544,'carry_inverse_address_cases':32,'carry_ROM_address_cases':256,'carry_Q_address_cases':16,'xor_inverse_address_cases':32,'xor_ROM_address_cases':256,'xor_Q_alphabet_cases':16,'decoder_inverse_cases':16,'decoder_ROM_cases':16,'encoder_ROM_candidate_proofs':16,'encoder_Q_cases':16,'universal_ROM_operation_queries':3,'static_numeric_codec_inverse_query':1,'fresh_register_shift_and_divisor_proofs':2,'full_outgoing_ABI_contracts':4,'known_frame_cells':832,'unclaimed_frame_cells':130,'numeric_operation_cases':256,'carry_zero_pairs':136,'carry_one_pairs':120,'joint_sum_carry_numeric_results':31,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_encoded_addition.py','validate_daemon_mode_one_workspace_passes.py','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','daemon_word_lookup_algebra.py','validate_daemon_mode_one_word_schedule.py','validate_daemon_existing_scalar_reader.py','validate_daemon_constructor_inputs.py','validate_daemon_constructor_lookup.py','validate_daemon_list_output.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'carry_xor_input_decoder_output_encoder_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
