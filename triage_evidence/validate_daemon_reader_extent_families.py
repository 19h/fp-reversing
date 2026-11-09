#!/usr/bin/env python3
"""Composed preparation/extent/bridge/tag-prefix proofs,source-only."""
import copy,json,re,subprocess
from recover_daemon_reader_extent_families import ROOT,P,SCOPE,FLAGS,sha,build
from recover_daemon_reader_context_footprint import engine
from validate_daemon_existing_scalar_reader import SSA as ParentSSA,DECL,bv,z,neq,prefix,WORD_BASE,split
from validate_daemon_reader_context_footprint import declarations
SOLVER='/opt/homebrew/bin/z3'
class SSA(ParentSSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='sxth':
    ps=split(i['operands']);w=32 if ps[0].startswith('w')else 64;self.put(ps[0],self.operand(ps[1],w,'sxth'));self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def make(f,n,r=None,loads=None):
 end=int(f['instructions'][-1]['ea'],16);ll=dict(loads or{});dd=[]
 for i in f['instructions']:
  if int(i['ea'],16)>=end:break
  if i['mnemonic']in('ldr','ldur','ldrh')and i['ea']not in ll:
   bits=16 if i['mnemonic']=='ldrh'else 32 if i['operands'].startswith('w')else 64;v=n+'_L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {bits}))');ll[i['ea']]=(v,bits)
 rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=SSA(rr,ll,namespace=n+'_');g.run(f,end);g.declarations='\n'.join(dd)+'\n';return g
def solve(n,body,decl,scope,result='unsat'):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+decl+body+'\n(check-sat)\n';p=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert p.returncode==0 and not p.stderr and p.stdout.strip()==result,(n,p.stdout,p.stderr);return {'name':n,'query':q,'result':result,'scope':scope}
def certificates(s):
 pp=[];tr={};summ=[];pr,inp=engine(s['preparation'],ns='prep_');decl=declarations(inp,'N');tr['preparation']=pr.record();cells={q['offset_bytes']:a['value']for q,a in zip(s['preparation_write_ledger'],pr.stores)}
 def add(n,gs,tt,scope):
  pp.append(solve(n,prefix(*gs)+'(assert (or '+' '.join(tt)+'))',decl,scope))
 def frame(off):return f'(bvadd K {bv(off)})'
 def at(ix):return f'(bvadd TABLE {bv(int(ix,16)*8)})'
 def loads(f,tagoff=None):
  out={}
  for i in f['instructions']:
   if i['mnemonic']!='ldr':continue
   m=re.fullmatch(r'[xw]\d+, \[sp, #(0x[0-9a-f]+)\]',i['operands'])
   if not m:continue
   off=int(m[1],16);bits=32 if i['operands'].startswith('w')else 64
   if off==0x9d0:v='(concat ((_ extract 63 32) Z30) #x00006cf4)'
   elif off==0x9d8:v='TABLE'
   elif off==tagoff:v='TAG'
   elif off in cells:v=cells[off]
   else:continue
   out[i['ea']]=(v,bits)
  return out
 keyterms=[]
 for row in s['families']:
  kb=int(row['length_key_bias'],16);keyterms.append(neq(cells[int(row['length_key_cache_offset'],16)],f'(bvadd {row["cursor_input"]} {bv(kb)})'))
 add('all_five_source_preparation_length_key_bindings',[pr],keyterms,'All abstract preparation nuisance inputs; source-derived key cells equal the listed cursor plus bias. Valid frame loads remain premises.')
 for row in s['families']:
  n=row['name'];cur=row['cursor_input'];lim=row['limit_input'];kb=int(row['length_key_bias'],16);off=f'(bvsub (bvadd {cur} {bv(kb)}) {bv(WORD_BASE)})';end=f'(bvadd {off} {bv(4)} {z("PL")})';fit=f'(bvule {end} {lim})';g=make(s['fragments'][row['gate']],n+'_gate',r={1:z('(bvxor PL #x8ec35f08)'),4:z('(bvxor PL #x8b3dc651)')},loads=loads(s['fragments'][row['gate']]));tr[n+'_gate']=g.record();endstore=next(q for q in g.stores if q['width_bits']==64);tt=[neq(endstore['address'],frame(int(row['saved_end_offset'],16))),neq(endstore['value'],f'(bvadd {cur} {bv(10)} {z("PL")})'),neq(g.reads[-1]['address'],f'(ite {fit} {at(row["fit_index"])} {at(row["reject_index"])})'),neq(g.get('sp'),'K')]
  if n=='N19':
   first=g.stores[0];assert first['width_bits']==32;tt.extend([neq(first['address'],frame(0x958c)),neq(first['value'],'(bvxor PL #x8b3dc651)')])
  for actual in g.reads[:-1]:
   i=next(i for i in s['fragments'][row['gate']]['instructions']if i['ea']==actual['site']);m=re.fullmatch(r'x\d+, \[sp, #(0x[0-9a-f]+)\]',i['operands']);assert m;tt.append(neq(actual['address'],frame(int(m[1],16))))
  add(n+'_normalized_extent_and_saved_end',[pr,g],tt,'Source-composed preparation and gate,low32(phase)=6cf4 with arbitrary upper32,arbitrary u64 cursor/limit and u32 decoded extent. Fit is modular64(length-word-offset+4+PL)<=limit. This is not a no-wrap/native admission or initialization proof.')
  b=make(s['fragments'][row['fit_bridge']],n+'_bridge',r={j:g.get('x'+str(j))for j in range(31)},loads=loads(s['fragments'][row['fit_bridge']]));tr[n+'_bridge']=b.record();add(n+'_fixed_fit_bridge',[pr,g,b],[neq(b.reads[-1]['address'],at(row['type_index'])),neq(b.get('sp'),'K')],'Entered bridge with exact gate terminal registers; fixed phase composition,not an isolated compiler function.')
  t=make(s['fragments'][row['type_prefix']],n+'_type',r={j:b.get('x'+str(j))for j in range(31)},loads=loads(s['fragments'][row['type_prefix']],int(row['working_tag_offset'],16)));tr[n+'_type']=t.record();tagread=next(q for q in t.reads if q['width_bits']==32);signed='((_ sign_extend 16) ((_ extract 15 0) TAG))';low=f'(bvslt {signed} #xffffd0ee)';add(n+'_signed_low16_type_partition',[pr,g,b,t],[neq(tagread['address'],frame(int(row['working_tag_offset'],16))),neq(t.reads[-1]['address'],f'(ite {low} {at(row["tag_low_index"])} {at(row["tag_high_index"])})'),neq(t.get('sp'),'K')],'Arbitrary raw32 working tag from the prior tag-return stage,overriding its preparation value. Only signed low16 affects this first split. Complete accepted types and native accessor reachability remain unproved.')
  bf=s['fragments'][row['reject_first']];ll=loads(bf)
  if n in('N21','N23'):
   first2=[i for i in bf['instructions']if i['mnemonic']=='ldr'][:2];ll[first2[0]['ea']]=('U',64);ll[first2[1]['ea']]=('V',64)
  e=make(bf,n+'_reject',r={j:g.get('x'+str(j))for j in range(31)},loads=ll);tr[n+'_reject']=e.record();tt=[neq(e.get('sp'),'K')]
  if n=='N19':
   a,c=e.stores;tt.extend([neq(a['address'],frame(0x2b1c)),neq(a['value'],'#x74c29d8f'),neq(c['address'],frame(0x4ed8)),neq(c['value'],e.reads[0]['input']),neq(e.reads[0]['address'],frame(0x6368)),neq(e.get('x19'),frame(0x4ed8)),neq(e.reads[-1]['address'],at(row['reject_next_indices'][0]))])
  elif n in('N20','N22'):tt.extend([neq(e.get('w6'),'#x74c29d8f'),neq(e.reads[-1]['address'],at(row['reject_next_indices'][0]))]);assert not e.stores
  else:
   offsets=(0x8318,0x26c4,0x6f18)if n=='N21'else(0x1bf0,0x1744,0x8d98);values=[bv(0),'#x8b3dc651',bv(0x510df273a0723664 if n=='N21'else 0x799f55970eba2bcd)]
   for q,oo,v in zip(e.stores,offsets,values):tt.extend([neq(q['address'],frame(oo)),neq(q['value'],v)])
   tt.extend([neq(e.reads[0]['address'],frame(0x21b0 if n=='N21'else 0x19f0)),neq(e.reads[1]['address'],'U'),neq(e.get('w6'),'#x74c29d88'),neq(e.reads[-1]['address'],f'(ite (= V {bv(0)}) {at(row["reject_next_indices"][0])} {at(row["reject_next_indices"][1])})')])
  add(n+'_first_reject_effects',[pr,g,e],tt,'First source rejection continuation only; no full return/cleanup contract. Borrowed frame cells and the N21/N23 context-head dereference require valid memory; status markers differ across families.')
  summ.append({**row,'logical_length_word_offset':off,'normalized_end':end,'fit_condition':fit,'saved_end':f'(bvadd {cur} {bv(10)} {z("PL")})','native_read_validity_proved':False})
 # A generic circular-translation identity makes the four comparison networks readable.
 lo='(bvult O U)';hi='(bvugt V (bvnot U))';gt='(bvugt O (bvadd V U))';c=f'(ite (xor {hi} {lo}) {lo} {gt})'
 pp.append(solve('generic_unsigned_bias_compare_identity',f'(assert (distinct {c} (bvugt (bvsub O U) V)))',decl,'Every u64 biased coordinate O,translation U and limit V; source-specific circuits are separately checked in all five composed gate queries.'))
 wide=f'(bvadd ((_ zero_extend 64) O) {bv(4,128)} ((_ zero_extend 96) PL))';narrow=f'(bvadd O {bv(4)} {z("PL")})'
 pp.append(solve('no_wrap_premise_joins_widened_extent',f'(assert (bvule {wide} {bv((1<<64)-1,128)}))\n(assert (distinct (bvule {narrow} V) (bvule {wide} ((_ zero_extend 64) V))))',decl,'The separate no-wrap premise relates modular source bounds to a widened128-bit sum,which cannot overflow for u64 offset plus u32 extent plus4. No preceding native path proves this premise here.'))
 n20=next(q for q in summ if q['name']=='N20');pp.append(solve('reject_treating_encoded_cursor_as_logical_offset',f'(assert (distinct {n20["fit_condition"]} (bvule (bvadd N1 {bv(10)} {z("PL")}) N2)))',decl,'Abstract cut counterexample only: the saved encoded cursor is not interchangeable with a logical byte offset. No target input or native execution is constructed.','sat'))
 return pp,tr,summ
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_key_bias',lambda t:t['families'][1].__setitem__('length_key_bias','0x0')),('swapped_fit_reject',lambda t:t['families'][0].__setitem__('fit_index',t['families'][0]['reject_index'])),('wrong_saved_end_width',lambda t:t['fragments'][t['families'][0]['gate']]['instructions'][17].__setitem__('operands','w16, [x17, #0x1590]')),('wrong_tag_cell',lambda t:t['families'][2].__setitem__('working_tag_offset','0x980')),('invent_native_initialization',lambda t:t['families'][0].__setitem__('same_active_frame_initialization_proved',True)),('missing_reject_fragment',lambda t:t['fragments'].pop(t['families'][0]['reject_first']))];aa=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=s;aa.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return aa
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert verify(s);pp,tr,summ=certificates(s);aa=alterations(s);sites={pc for q in tr.values()for pc in q['source_sites']};expected={i['ea']for f in [s['preparation']]+list(s['fragments'].values())for i in f['instructions'][:-1]};assert sites==expected
 counts={**s['verified_source_counts'],'queries_unsat':sum(q['result']=='unsat'for q in pp),'counterexamples_sat':sum(q['result']=='sat'for q in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(q['source_sites'])for q in tr.values()),'SSA_definitions':sum(q['SSA_definitions']for q in tr.values()),'rejected_alterations':len(aa)};assert counts['queries_unsat']==23 and counts['counterexamples_sat']==1
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_existing_scalar_reader.py':sha(ROOT/'validate_daemon_existing_scalar_reader.py'),'validate_daemon_reader_context_footprint.py':sha(ROOT/'validate_daemon_reader_context_footprint.py')},'source_recapture_match':True,'proofs':pp,'translations':tr,'family_summaries':summ,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'no_wrap_native_premise_proved':False,'complete_accessor_semantics_proved':False,'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
