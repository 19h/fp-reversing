#!/usr/bin/env python3
"""Prove the address-keyed word,request predicate,list edge and field gates."""
import copy,json,shutil,subprocess
from recover_daemon_mode_one_record_scan import ROOT,P,SCOPE,FLAGS,BLOCKS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_mode_one_handoff_tools import FrameSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,at,frame
from validate_daemon_constructor_lookup import KEYS,written,split
SOLVER=shutil.which('z3');assert SOLVER
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec 64))\n'for n in ['NODE','NEXT','PBUF','R','COOKIE','LOCAL'])+''.join(f'(declare-fun {n} () (_ BitVec 32))\n'for n in ['D','Q','COUNT'])
CUTS=[0x100bda654,0x100bda820,0x100bdaa04,0x100bdac0c]
LOADS={hex(a):('B'+str(j),8)for j,a in enumerate([0x100bda498,0x100bda670,0x100bda840,0x100bdac18])}
LOADS.update({'0x100bda490':('PBUF',64),'0x100bdaca4':('Q',32),'0x100bdacd4':('FN',64),'0x100a7653c':('FN',64)})
class WordCuts(FrameSSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc in CUTS:
    j=CUTS.index(pc);value='U'+str(j)if j<3 else'(bvxor U3 #x5353535353535353)';self.put(split(i['operands'])[0],value);self.sites.append(i['ea']);self.cuts.append({'site':i['ea'],'replacement':value,'justification':'byte'+str(j)+'_seed_and_seven_rounds'})
   else:super().run({'instructions':[i]},pc+4)
  return self
def certificates(s):
 pp=[];models={};fs=s['fragments'];common={0x740:('TABLE',64),0x388:('R',64),0x2c0:('COOKIE',64)}
 def solve(name,body,result='unsat',conditions=()):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+body+'\n'+''.join('(assert '+c+')\n'for c in conditions)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-record-scan-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def pre(g):return ''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
 def cert(name,g,terms,conditions=()):solve(name,pre(g)+'(assert (or '+' '.join(terms)+'))',conditions=conditions)
 def rd(g,pc):return next(v for v in g.reads if v['site']==hex(pc))
 def run(g,name):
  f=fs[name];g.run(f,int(f['instructions'][-1]['ea'],16)if name in BLOCKS else int(f['end'],16));return g
 wanted={DEPS[1]:{'workspace_request_C0_chain_and_null_dispatch','present_C0_value_preserves_pointee_and_rebases_workspace','core_saves_private_request_R_at_F388'},DEPS[3]:{'private48_record_fields_and_address_cookie','aligned_request_decodes_mode4923_and_length_operand','ordinary_stack_alignment_supplies_request_cookie_premise'}}
 for file,names in wanted.items():
  found=set()
  for p in json.loads(read(ROOT/file))['proofs']:
   if p['name']not in names:continue
   r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**p,'name':'replayed_'+p['name'],'replayed_query':True});found.add(p['name'])
  assert found==names,(file,found,names)
 c=FrameSSA('seed',{0:'NODE',9:bv(0xf518)},presets=common,loads=LOADS);run(c,'seed');models['seed']=c
 constants={2:0x471b,3:0x5605,4:0x18df,5:0x4719,7:0x622c5d3364e575a7,19:0x6d44f77ef42a3bc3,20:0x1dd3a2cc9b1a2a60,21:0x92bb08810bd51832,22:0xfffffffffffffffe,23:0x3505b74e1c8517b5,24:0x24675ed53babbb4e,27:KEYS[0],28:0xda740029fd112266,30:0x92c5ffeb01776ecd}
 cert('seed_live_constants_and_workspace',c,[neq(c.get('x'+str(r)),bv(v))for r,v in constants.items()]+[neq(c.get('x0'),'NODE'),neq(c.loadframe(0x750,64),frame(0xd10)),neq(rd(c,0x100a7653c)['address'],at(0xac4c))])
 ii=fs['decode']['instructions'];seeds=[j for j,i in enumerate(ii)if i['mnemonic']=='and'and'#0xfffffffffffffff8'in i['operands']];eors=[j for j,i in enumerate(ii)if i['mnemonic']=='eor'and'ror #61'in i['operands']];ends=[next(j for j,i in enumerate(ii)if int(i['ea'],16)==pc)for pc in CUTS];assert len(seeds)==4 and len(eors)==24
 def part(name,r,rows,end):
  start=int(rows[0]['ea'],16);base=WordCuts(name+'_prefix',dict(c.r),presets=common,loads=LOADS);base.defs=list(c.defs);base.decl=dict(c.decl);base.loaded=c.loaded;base.run(fs['decode'],start)
  overrides={reg:value for reg,value in r.items()if value in ['A','U','V','((_ rotate_right 8) U)']};regs={**base.r,**overrides}
  g=FrameSSA(name,regs,presets=common,loads=LOADS);g.defs=list(base.defs);g.decl=dict(base.decl);g.loaded=base.loaded;g.cuts=list(base.cuts);g.run({'instructions':rows},end);models[name]=g;return g
 R='((_ rotate_right 8) (bvand A #xfffffffffffffff8))';B=f'(bvadd {R} #x622c5d3364e5d59f)';X=f'(bvxor {B} #xa7bebfcf1750d389)';Y=f'(bvxor {B} #xb6dc5654307e7f72)'
 for b,(a,end)in enumerate(zip(seeds,ends)):
  ee=eors[6*b:6*b+6];yr=split(ii[ee[0]]['operands'])[0];mix=next(j for j in range(ee[0]-1,a,-1)if ii[j]['mnemonic']=='add'and split(ii[j]['operands'])[2]==yr);ops=split(ii[mix]['operands']);r=dict(c.r);r[int(split(ii[a]['operands'])[1][1:])]='A';g=part('byte'+str(b)+'_seed',r,ii[a:mix],int(ii[mix]['ea'],16));cert('byte'+str(b)+'_seed',g,[neq(g.get(ops[1]),f'((_ rotate_right 8) {X})'),neq(g.get(yr),Y)]);start=mix
  for j in range(7):
   stop=ee[j]+1 if j<6 else end+1;r=dict(c.r)
   if j==0:r[int(ops[1][1:])]='((_ rotate_right 8) U)';r[int(yr[1:])]='V'
   else:
    old=split(ii[ee[j-1]]['operands']);xr,yr0=old[1],old[0];r[int(xr[1:])]='U';r[int(yr0[1:])]='V'
    for k in range(start):
     q=ii[k];p=split(q['operands'])
     if q['mnemonic']=='ror'and p[1]==xr and p[2]=='#8'and p[0]!=yr0 and all(xr[1:]not in written(v)and p[0][1:]not in written(v)for v in ii[k+1:start]):r[int(p[0][1:])]='((_ rotate_right 8) U)'
   g=part('byte'+str(b)+'_round'+str(j+1),r,ii[start:stop],int(ii[stop-1]['ea'],16)+4);key=KEYS[j]^(0x5353535353535353 if b==3 and j==6 else 0);F=f'(bvxor (bvadd ((_ rotate_right 8) U) V) {bv(key)})'
   if j<6:
    op=split(ii[ee[j]]['operands']);terms=[neq(g.get(op[1]),F),neq(g.get(op[0]),f'(bvxor ((_ rotate_left 3) V) {F})')]
   else:terms=[neq(g.get(split(ii[end]['operands'])[0]),F)]
   cert('byte'+str(b)+'_round'+str(j+1),g,terms);start=stop
 bs=[]
 for j in range(4):
  a=f'(bvadd PBUF {bv(j)})';m=f'((_ extract 7 0) (bvlshr U{j} (bvshl (bvand {a} #x0000000000000007) #x0000000000000003)))';bs.append(f'(bvxor B{j} {m})')
 wire='(concat '+' '.join(bs)+')';g=WordCuts('merge',dict(c.r),presets=common,loads=LOADS);g.defs=list(c.defs);g.decl=dict(c.decl);g.loaded=c.loaded;g.run(fs['decode'],0x100bdac50);models['merge']=g
 cert('BE32_merge_and_exact_byte_addresses',g,[neq(g.get('w10'),f'(bvxor {wire} #x8ec35f08)'),neq(rd(g,0x100bda490)['address'],f'(bvadd NODE {bv(0x18)})')]+[neq(rd(g,pc)['address'],f'(bvadd PBUF {bv(j)})')for j,pc in enumerate([0x100bda498,0x100bda670,0x100bda840,0x100bdac18])])
 norm=FrameSSA('normalize',{10:z('VALUE')});norm.run({'instructions':[i for i in ii if 0x100bdac50<=int(i['ea'],16)<0x100bdaca0]},0x100bdaca0);models['normalize']=norm;cert('three_term_obfuscation_is_xor_plus_bias',norm,[neq(norm.get('w10'),'(bvadd (bvxor VALUE #x8ec35f08) #x74c239af)')])
 # The full raw decoder supplies control constants even when mask outputs are cut.
 full=WordCuts('full',dict(c.r),presets=common,loads=LOADS);full.defs=list(c.defs);full.decl=dict(c.decl);full.loaded=c.loaded;run(full,'decode');models['full']=full
 predicate=f'(= {wire} (bvadd Q (bvneg ((_ extract 31 0) COOKIE)) #x8a7fe6f1))'
 cert('decoded_header_controls_original_edges',full,[neq(rd(full,0x100bdaca4)['address'],f'(bvadd R {bv(0x20)})'),neq(rd(full,0x100bdacd4)['address'],f'(ite {predicate} {at(0x4719)} {at(0x4724)})'),neq(full.get('w9'),bv(0xac0a,32)),neq(full.get('w8'),bv(0x5ff8,32)),neq(full.get('x0'),'NODE')])
 solve('aligned_wrapper_decoded_sentinel','(assert '+neq('(bvadd Q (bvneg ((_ extract 31 0) COOKIE)) #x8a7fe6f1)','#x5c241ab2')+')',conditions=['(= Q (bvadd ((_ extract 31 0) COOKIE) #xd1a433c1))'])
 nxt=FrameSSA('next',{0:'NODE',9:bv(0xac0a)},presets=common,loads={'0x100d07434':('NEXT',64)});run(nxt,'next');models['next']=nxt
 cert('equal_header_advances_or_joins_LOCAL',nxt,[neq(rd(nxt,0x100d07434)['address'],'NODE'),neq(nxt.get('x0'),'NEXT'),neq(nxt.get('w5'),bv(0x4719,32)),neq(nxt.get('w8'),bv(0x4923,32)),neq(rd(nxt,0x100d0745c)['address'],f'(ite (= NEXT {bv(0)}) {at(0xac0a)} {at(0xac4c)})')])
 preserved=[]
 for reg in constants:
  if reg==5:continue
  for name in ['decode','next']:
   assert not {prefix+str(reg)for prefix in ['x','w']}&set(s['register_write_sets'][name]),(reg,name)
  preserved.append(reg)
 # Compose the original decoder/advance sources on a second abstract node.
 repeat=WordCuts('repeat',{**c.r,0:'NEXT',5:nxt.get('x5')},presets=common,loads=LOADS);repeat.defs=list(c.defs)+list(nxt.defs);repeat.decl={**c.decl,**nxt.decl};repeat.loaded=max(c.loaded,nxt.loaded);run(repeat,'decode');models['repeat']=repeat
 cert('repeat_entry_preserves_header_predicate',repeat,[neq(rd(repeat,0x100bda490)['address'],f'(bvadd NEXT {bv(0x18)})'),neq(rd(repeat,0x100bdacd4)['address'],f'(ite {predicate} {at(0x4719)} {at(0x4724)})')])
 pg=FrameSSA('payload_gate',{0:'NODE',8:bv(0x5ff8)},presets=common,loads={'0x100c4da90':('PBUF',64)});run(pg,'payload_gate');models['payload_gate']=pg
 # Bind the reloaded buffer to its actual read site rather than assuming its PC.
 pr=rd(pg,0x100c4da90)
 cert('different_header_reloads_buffer_and_sets_payload_ABI',pg,[neq(pr['address'],f'(bvadd NODE {bv(0x18)})'),neq(pg.get('x12'),pr['input']),neq(rd(pg,0x100c4dabc)['address'],f'(ite (= {pr["input"]} {bv(0)}) {at(0x6012)} {at(0x5ff8)})'),neq(pg.get('w10'),bv(0x4cc6,32)),neq(pg.get('w11'),bv(0x4f,32)),neq(pg.get('w9'),bv(0x74c29dee,32))])
 lg=FrameSSA('length_gate',{0:'NODE',12:'PBUF',10:bv(0x4cc6),11:bv(0x4f)},presets=common,loads={'0x100bf2d2c':('COUNT',32)});run(lg,'length_gate');models['length_gate']=lg
 cert('selected_record_saved_fields_and_zero_count_partition',lg,[neq(rd(lg,0x100bf2d2c)['address'],f'(bvadd NODE {bv(0x10)})'),neq(lg.loadframe(0x748,64),'PBUF'),neq(lg.loadframe(0x2b8,64),'NODE'),neq(lg.loadframe(0x728,32),'COUNT'),neq(lg.loadframe(0x738,32),bv(0,32)),neq(lg.get('w1'),bv(0x4923,32)),neq(lg.get('w2'),bv(0x4923,32)),neq(rd(lg,0x100bf2d74)['address'],f'(ite (= COUNT #x00000000) {at(0x4cd6)} {at(0x4cc6)})')])
 local=FrameSSA('local',{8:bv(0x4923)},presets=common,loads={'0x100cbddd4':('LOCAL',64)});run(local,'local');models['local']=local
 cert('empty_scan_LOCAL_fallback',local,[neq(rd(local,0x100cbddd4)['address'],f'(bvadd R {bv(0x18)})'),neq(rd(local,0x100cbddf0)['address'],f'(ite (= LOCAL {bv(0)}) {at(0x4923)} {at(0x4928)})'),neq(local.get('w9'),bv(0x74c29dee,32))])
 reject=FrameSSA('reject',{9:bv(0x74c29dee)},presets=common);run(reject,'reject');models['reject']=reject;cert('empty_scan_or_buffer_gate_raw_result_before_guard',reject,[neq(reject.stores[0]['address'],'R'),neq(reject.stores[0]['value'],bv(0x74c29dee,32))])
 cookie=FrameSSA('cookie_save',{12:'COOKIE'});run(cookie,'cookie_save');models['cookie_save']=cookie;cert('core_saves_cookie_in_F2c0',cookie,[neq(cookie.stores[0]['address'],frame(0x2c0)),neq(cookie.loadframe(0x2c0,64),'COOKIE')])
 for name in ['seed','length_gate','cookie_save']:
  g=models[name];assert len(g.stores)==len(g.frame_writes);cert(name+'_private_frame_store_addresses',g,[neq(row['address'],frame(fr['frame_offset']))for row,fr in zip(g.stores,g.frame_writes)])
 solve('equal_header_domain_nonempty','(assert (= D #x5c241ab2))',result='sat');solve('selected_header_domain_nonempty','(assert (distinct D #x5c241ab2))',result='sat')
 solve('wrong_advance_on_inequality_counterexample',pre(full)+'(assert (distinct '+wire+' #x5c241ab2))\n(assert (= Q (bvadd ((_ extract 31 0) COOKIE) #xd1a433c1)))\n(assert '+neq(rd(full,0x100bdacd4)['address'],at(0x4719))+')',result='sat')
 solve('zero_count_domain_nonempty','(assert (= COUNT #x00000000))',result='sat')
 records={n:g.record_full()for n,g in models.items()};actual={pc for m in records.values()for pc in m['source_sites']};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 sem={'source_models':records,'source_nonbranch_sites_translated':len(actual),'word_cut_sites':[hex(a)for a in CUTS],'codec_round_keys_u64':[hex(k)for k in KEYS],'fourth_mask_word_xor_delta':'0x5353535353535353','BE32_merge_xor':'0x8ec35f08','normalization_bias':'0x74c239af','general_equal_word':'u32(Q-low32(COOKIE)+0x8a7fe6f1)','aligned_wrapper_equal_word':'0x5c241ab2','equal_word_action':'follow u64[NODE+0]','different_word_action':'reload u64[NODE+0x18],then read u32[NODE+0x10]','loop_invariant_preserved_registers':preserved,'W5_restored_each_advance':'0x4719','nil_next_LOCAL_gate':'0x100cbddd0','selected_nonzero_count_frontier':'0x100d863f4','selected_zero_count_frontier':'0x100bf2aa0','decode_has_no_stores':not full.stores,'decode_external_byte_reads':4,'word_codec_seed_lemmas':4,'word_codec_round_lemmas':28,'Mach_port_emissions':0,'termination_requires_finite_stable_acyclic_chain':True,'successful_output_publication_proved':False,'native_reachability_proved':False,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['decode'].__setitem__('bytes','00'+q['fragments']['decode']['bytes'][2:])),('header_byte_offset',lambda q:q['fragments']['decode']['instructions'][4].__setitem__('operands','w11, [x10, #1]')),('next_link_target',lambda q:q['branch_edges'][3].__setitem__('target','0x0')),('zero_count_target',lambda q:q['branch_edges'][8].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':sem['source_nonbranch_sites_translated'],'codec_seed_lemmas':4,'codec_round_lemmas':28,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','daemon_word_round_tools.py','daemon_mode_one_handoff_tools.py','daemon_word_lookup_algebra.py','validate_daemon_constructor_lookup.py','validate_daemon_existing_scalar_reader.py']+DEPS;c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'local_record_scan_and_field_gates_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
