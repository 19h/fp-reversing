#!/usr/bin/env python3
"""Static LEN32 absorption,source-address and private continuation certificates."""
import copy,json,subprocess,shutil
from recover_daemon_mode_one_source_absorption import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_state_materialization import Engine as Parent
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix
from validate_daemon_mode_one_inverse_tables import frame,at
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
class Engine(Parent):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='udiv':
    p=split(i['operands']);w=32 if p[0].startswith('w')else 64;a,b=self.get(p[1],w),self.get(p[2],w)
    self.put(p[0],f'(ite (= {b} {bv(0,w)}) {bv(0,w)} (bvudiv {a} {b}))');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def fresh(label,r=None,loads=None):
 rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=Engine(rr,loads,namespace=label+'_');g.declarations='';return g
def lut(values,e,w=32):
 out=bv(values[-1],w)
 for j in reversed(range(len(values)-1)):out=f'(ite (= {e} {bv(j,32)}) {bv(values[j],w)} {out})'
 return out
def decode(y):
 mask=(1<<32)-1
 a=(((y^0x7a)-0x7a)^((y^2)-2)^((y^0x39)-0x39))&mask
 b=(a-0x57)&mask;c=((a+0x29)^0x60)&mask;v=b&0xffffffe0
 for _ in range(3):v=((c&((v<<1)&mask))^(b&0xffffffe0))&mask
 return(b^(v<<1)^0xeb)&255
def fixed_index(r):
 mask=(1<<32)-1;v=(r-(0x48&(r<<1))+0x24)&255;assert v==32+(r^4)
 a=((v^0x7959f8da)+0x042c3c9f)&mask;b=((v^0x6ef65769)+0x1383932e)&mask;c=((v^0x17afaf95)+0x6ada6bd2)&mask
 n=(((a^b^c)*527)+0xba9559f3)&mask;q=(n*0x22b63cbf)>>39
 result=(n-q*944)&mask;assert result==n%944
 return result,n,q
def certificates(s):
 pp=[];tr={};cuts=[];fs=s['fragments'];cc=['(bvult IX #x00000020)']
 def solve(n,body,conditions=(),result='unsat'):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+body+'\n'+''.join('(assert '+c+')\n'for c in conditions)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-absorption-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(n,r.stdout,r.stderr);pp.append({'name':n,'query':q,'result':result,'scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,conditions=()):solve(n,prefix(g)+'(assert (or '+' '.join(terms)+'))',conditions)
 def run(n,r=None,loads=None,a=None,end=None,label=None):
  f=fs[n];a=a or int(f['start'],16);end=end or int(f['instructions'][-1]['ea'],16);g=fresh(label or n,r,loads);g.run({'instructions':[i for i in f['instructions']if a<=int(i['ea'],16)<end]},end);tr[label or n]=g.record();return g
 constants={8:0xeb,9:0x77453be2,27:0x6ada6bd2,28:527,30:0xba9559f3,16:757,4:0x440dd2cf,20:963,0:0xd693a272}
 rr={k:bv(v)for k,v in constants.items()};rr.update({26:frame(0xd00),25:'BUF',23:bv(0x100f715a0),24:z('SIZE')})
 entry=run('entry',rr,{'0x100c21d7c':('#x00004923',32),'0x100c21d94':('#x0dc87a81',32),'0x100c21d9c':('TABLE',64),'0x100c21da0':('FN',64)})
 rd=lambda g,pc:next(v for v in g.reads if v['site']==hex(pc))
 cert('entry_binds_encoded_zero_counter_roots_and_constants',entry,[neq(entry.get('w13'),'#xc12face8'),neq(entry.get('w10'),'#x3ed05318'),neq(entry.get('w11'),'#x0000aace'),neq(entry.get('w15'),'#x6ef65769'),neq(rd(entry,0x100c21d7c)['address'],frame(0x730)),neq(rd(entry,0x100c21d94)['address'],frame(0x504)),neq(rd(entry,0x100c21da0)['address'],at(0x631f)),neq(entry.stores[0]['address'],frame(0x750)),neq(entry.stores[0]['value'],'#x00004923')]+[neq(entry.get('w'+str(k)),bv(v,32))for k,v in constants.items()if k!=8]+[neq(entry.get('x26'),frame(0xd00)),neq(entry.get('x25'),'BUF'),neq(entry.get('x23'),bv(0x100f715a0)),neq(entry.get('w24'),'SIZE')])
 # W8 is unchanged as well;it is the low-byte output XOR constant.
 cert('entry_preserves_byte_xor_constant',entry,[neq(entry.get('w8'),'#x000000eb')])
 loads={hex(pc):(v,w)for pc,v,w in[(0x100bd7994,'B0',8),(0x100bd79d4,'B1',8),(0x100bd7a68,'B2',8),(0x100bd7ac4,'B3',8),(0x100bd7b1c,'TABLE',64),(0x100bd7b20,'CONT',64)]}
 loop=fresh('loop',{**entry.r,13:z('(bvadd IX #xc12face8)')},loads);loop.defs=list(entry.defs)
 # This local proof includes the original arithmetic prefix,not a sampled divisor.
 loop.run(fs['loop'],0x100bd79cc)
 cert('LEN32_domain_obfuscated_unsigned_divisor_is16',loop,[neq(loop.get('w17'),'#x00000010'),neq(loop.get('w3'),'IX')],cc)
 cuts.append({'site':'0x100bd79c8','register':'w17','original_value':loop.get('w17'),'replacement':'#x00000010','universal_lemma':'LEN32_domain_obfuscated_unsigned_divisor_is16','domain':'0<=IX<32'})
 loop.put('w17','#x00000010');loop.run({'instructions':[i for i in fs['loop']['instructions']if int(i['ea'],16)>=0x100bd79cc]},int(fs['loop']['instructions'][-1]['ea'],16));tr['loop_full_source']=loop.record()
 first=f'(bvadd {frame(0xd00)} {z("(bvurem (bvmul (bvadd IX #x00000028) #x000002f5) #x000003c3)")})'
 second=f'(bvadd {frame(0xd00)} {z("(bvurem (bvmul (bvadd IX #x00000070) #x000002f5) #x000003c3)")})'
 cert('source_byte_and_two_state_addresses',loop,[neq(rd(loop,0x100bd7994)['address'],f'(bvadd BUF {z("IX")})'),neq(rd(loop,0x100bd79d4)['address'],first),neq(loop.stores[0]['address'],first),neq(rd(loop,0x100bd7ac4)['address'],second),neq(loop.stores[1]['address'],second),neq(loop.stores[0]['value'],'(bvxor B1 B0)')],cc)
 rows=[];raw=bytes.fromhex(s['operation_data']['bytes'])
 for j in range(16):
  offset,n,q=fixed_index(j);y=raw[offset];rows.append({'index_mod16':j,'numerator_u32':n,'quotient':q,'image_offset':offset,'image_byte':y,'state_xor_byte':decode(y)})
 offsets=[r['image_offset']for r in rows];keys=[r['state_xor_byte']for r in rows]
 cert('source_image_lookup_is_periodic16_in_selected_domain',loop,[neq(rd(loop,0x100bd7a68)['address'],f'(bvadd {bv(0x100f715a0)} {z(lut(offsets,"(bvand IX #x0000000f)"))})')],cc)
 # The late state load is independent of the image lookup input.
 # Supply its named byte to the isolated decoder and retain original addresses.
 # Rebuild with address-only roots;no decoder value assumes a valid target address.
 dec=run('loop',{14:z('B2',8),8:bv(0xeb),12:frame(0xd00),26:frame(0xd00)},loads={'0x100bd7ac4':('B3',8)},a=0x100bd7a70,end=0x100bd7ae8,label='image_byte_xor_decoder')
 mask_values=[decode(y)for y in range(256)]
 # A 256-case expression is a finite definition,then universally source-certified.
 cert('original_decoder_is_old_byte_xor_finite_image_mask',dec,[neq(dec.stores[0]['value'],f'(bvxor B3 {lut(mask_values,"((_ zero_extend 24) B2)",8)})')])
 cert('both_original_loop_values_are_local_XOR_updates',loop,[neq(loop.stores[0]['value'],'(bvxor B1 B0)'),neq(loop.stores[1]['value'],f'(bvxor B3 {lut(mask_values,"((_ zero_extend 24) B2)",8)})')],cc)
 cert('loop_control_roots_invariants_and_next_counter',loop,[neq(rd(loop,0x100bd7b20)['address'],f'(ite (bvult (bvadd IX #x00000001) (bvsub SIZE #x3874e8c9)) {at(0xaace)} {at(0xaad2)})'),neq(loop.get('w13'),'(bvadd IX #xc12face9)'),neq(loop.get('x17'),bv(0x9bc3)),neq(loop.get('x26'),frame(0xd00)),neq(loop.get('x25'),'BUF'),neq(loop.get('x23'),bv(0x100f715a0)),neq(loop.get('w24'),'SIZE')]+[neq(loop.get('w'+str(k)),bv(v,32))for k,v in constants.items()],cc)
 cert('LEN32_repeats31_times_then_joins',loop,[neq(rd(loop,0x100bd7b20)['address'],f'(ite (bvult IX #x0000001f) {at(0xaace)} {at(0xaad2)})')],cc+['(= SIZE #x3874e8e9)'])
 cert('loop_preserves_encoded_source_base_selector_and_decode_seed',loop,[neq(loop.get('w10'),'#x3ed05318'),neq(loop.get('w11'),'#x0000aace'),neq(loop.get('w15'),'#x6ef65769')],cc)
 # Zero-divisor handling is architecture-specific and does not use SMT's /0 value.
 div=run('loop',{3:z('VALUE'),17:bv(0)},a=0x100bd79cc,end=0x100bd79d0,label='unsigned_division_zero_semantics');cert('unsigned_division_zero_returns_zero',div,[neq(div.get('w1'),'#x00000000')])
 hand=run('handoff',loads={'0x100a763e0':('#x00004923',32),'0x100a763e8':('TABLE',64),'0x100a763f0':('CONT',64),'0x100a7650c':('VALUE',32),'0x100a76510':('PL',32),'0x100a76514':('TAG',32)})
 hstores=[(0x6d8,4,0),(0x610,4,0x803e),(0x618,4,0xb8d8),(0x608,4,0x03c3),(0x6e0,8,0x821c),(0x730,8,0x8df0),(0x728,8,0x90e5),(0x720,8,0x93da),(0x718,8,0x162d8),(0x710,8,0x165cd),(0x708,8,0x16bb7),(0x6b0,8,0x99c4),(0x6a8,8,0x9cb9),(0x700,8,0x9fae),(0x6f8,8,0xa2a3),(0x6a0,8,0x16eac),(0x698,8,0x171a1),(0x6f0,8,0x17496),(0x6e8,8,0x1778b)]
 assert len(hand.stores)==len(hstores)
 tt=[]
 for row,(off,w,value)in zip(hand.stores,hstores):assert row['width_bits']==8*w;tt.extend([neq(row['address'],frame(off)),neq(row['value'],bv(value,8*w))])
 hconst={3:0x3f0,20:0x33,23:0x7648,24:0x793d,22:0x14b30,6:0x1511a,30:0x14e25,4:0x1540f,19:0x8511,27:0x8806,21:0x8afb,10:0x15704,16:0x159f9,2:0x15cee,15:0x15fe3}
 tt +=[neq(hand.get('w'+str(k)),bv(v,32))for k,v in hconst.items()]+[neq(hand.get('x7'),bv(0)),neq(hand.get('x28'),bv(0x881ba59da4055115)),neq(hand.get('w26'),'VALUE'),neq(hand.get('w0'),'PL'),neq(hand.get('w25'),'TAG'),neq(hand.get('x17'),bv(0x505b)),neq(rd(hand,0x100a763f0)['address'],at(0x803e))]
 for pc,off in[(0x100a763e0,0x750),(0x100a763e8,0x740),(0x100a7650c,0x6cc),(0x100a76510,0x6d0),(0x100a76514,0x690)]:tt.append(neq(rd(hand,pc)['address'],frame(off)))
 cert('post_loop_frame_schedule_and_three_materialized_word_reloads',hand,tt)
 prior=json.loads(read(ROOT/'daemon_mode_one_state_materialization_checks.json'));assert prior['all_checks_pass']and prior['local_state_materialization_proved']
 from recover_daemon_mode_one_state_materialization import build as previous_build
 assert previous_build()==json.loads(read(ROOT/'daemon_mode_one_state_materialization_source.json'))
 replay={'LEN32_context_and_initial_byte_encoding','spilled_word_addresses_and_control_seed','compact_spilled_word_0x504','phase_cell_epochs_and_conditional_continuation','next_stage_restores_pointer_roots_and_stride_constants'};done=set()
 for p in prior['proofs']:
  if p['name']not in replay:continue
  r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**p,'name':'replayed_'+p['name'],'replayed_query':True});done.add(p['name']);print('replayed_'+p['name'],'unsat',flush=True)
 assert done==replay
 solve('selected_loop_domain_nonempty','',cc+['(= SIZE #x3874e8e9)'],result='sat')
 byoff={r['frame_offset']:r for r in prior['semantics']['source_store_ledger']if r['width_bytes']==4}
 reloads=[{'site':hex(pc),'frame_offset':off,'producer_site':byoff[off]['site'],'producer_value_SMT':byoff[off]['value_SMT']}for pc,off in[(0x100a7650c,0x6cc),(0x100a76510,0x6d0),(0x100a76514,0x690)]]
 cells=[{'input_index':j,'source_offset':j,'plane0_logical':40+j,'plane0_physical_offset':757*(40+j)%963,'plane1_logical':112+j,'plane1_physical_offset':757*(112+j)%963,'image_key_index':j%16,'plane1_xor':keys[j%16],'repeat':j<31}for j in range(32)]
 state={r[k]for r in cells for k in['plane0_physical_offset','plane1_physical_offset']};assert len(state)==64
 live=json.loads(read(ROOT/'daemon_mode_one_digit_maps_checks.json'))['semantics']['region_offsets'];assert not state&{x for n,v in live.items()if n!='A'for x in v}
 assert state<=set(prior['semantics']['physical_byte_offsets'])
 hs=[off+j for off,w,_ in hstores for j in range(w)];assert len(hs)==len(set(hs))and not{0xd00+x for x in state}&set(hs)
 preserved=set(range(0x438,0x440))|set(range(0x450,0x460))|set(range(0x568,0x588))|set(range(0x738,0x748))|set(range(0x750,0x754))|set(range(0x1210,0x1218));assert not set(hs)&preserved
 sem={'selected_input_bytes':32,'encoded_counter':'W13=c12face8+IX mod2^32','entry_zero_counter':'0xc12face8','counter_domain':'0<=IX<32','SIZE_context':'0x3874e8e9','source_extent_relative':'SRC[0..31] read once each','plane0_update':'S0[i] := S0[i] XOR SRC[i],0<=i<32','plane1_update':'S1[i] := S1[i] XOR K[i mod16],0<=i<32','plane1_key16':keys,'image_lookup_cases':rows,'all_image_byte_decode_masks':mask_values,'per_iteration_layout':cells,'computed_divisor_cut':cuts,'loop_source_SSA':loop.prefix(),'decoder_source_SSA':dec.prefix(),'loop_store_ledger':loop.stores,'loop_reads':loop.reads,'repeat_iterations':31,'loop_body_iterations':32,'read_bytes_total':640,'data_read_byte_operations':128,'control_read_bytes':512,'source_bytes_read':32,'state_bytes_read':64,'image_bytes_read':32,'state_store_operations':64,'unique_state_bytes_written':64,'untouched_plane_bytes':64,'live_arithmetic_cells_preserved':800,'state_750_value':'0x4923','handoff_source_SSA':hand.prefix(),'handoff_store_ledger':[{'site':row['site'],'frame_offset':off,'width_bytes':w,'value':hex(value)}for row,(off,w,value)in zip(hand.stores,hstores)],'handoff_store_bytes':len(hs),'handoff_register_constants':{str(k):hex(v)for k,v in hconst.items()},'materialized_word_reloads':reloads,'post_loop_target':s['branch_edges'][-1]['target'],'pointer_epochs':{'X23':'image root replaced by0x7648','X24':'size context replaced by0x793d','X25':'source root replaced by materialized u32 F+0x690','X26':'scratch root replaced by materialized u32 F+0x6cc','X28':'0x881ba59da4055115'},'preserved_frame_byte_offsets':sorted(preserved),'other_lengths_proved':False,'source_frame_alias_excluded_by_assumption':True,'new_calls_or_traps':0,'Mach_port_emissions':0,'native_claim':False}
 return pp,tr,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('wrong_source_byte',lambda q:q['fragments']['loop'].__setitem__('bytes','00'+q['fragments']['loop']['bytes'][2:])),('wrong_source_load',lambda q:q['fragments']['loop']['instructions'][211].__setitem__('operands','w4, [x25, #1]')),('wrong_image_byte',lambda q:q['operation_data'].__setitem__('bytes','00'+q['operation_data']['bytes'][2:])),('wrong_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for n,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':n,'rejected_by_fresh_original_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,sem=certificates(s);aa=alterations(s)
 actual={pc for t in tr.values()for pc in t['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 counts={**s['verified_source_counts'],'distinct_nonbranch_sites_translated':len(actual),'untranslated_source_sites':len(expected-actual),'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'replayed_queries_unsat':sum(p.get('replayed_query',False)for p in pp),'selected_loop_iterations':32,'image_lookup_cases':16,'image_decode_cases':256,'source_bytes_read':32,'state_bytes_written':64,'live_arithmetic_cells_preserved':800,'materialized_word_reloads':3,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_state_materialization.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','daemon_mode_one_state_materialization_checks.json','daemon_mode_one_digit_maps_checks.json']
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'translations':tr,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'local_LEN32_source_absorption_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
