#!/usr/bin/env python3
"""Source-linked address/projection certificates; no target/model execution."""
import copy,json,re,subprocess
from recover_daemon_reader_context_footprint import ROOT,P,SCOPE,FLAGS,sha,build,engine,CRITICAL,OBSREGS
from validate_daemon_existing_scalar_reader import bv,DECL,neq,prefix
SOLVER='/opt/homebrew/bin/z3'
def declarations(inputs,side):
 return ''.join(f'(declare-fun {side+q["input"][1:]} () (_ BitVec {q["width_bits"]}))\n'for q in inputs if q['role']=='nuisance_cut')
def certificates(s):
 g,inputs=engine(s['preparation'],ns='a_',side='N');other,_=engine(s['preparation'],ns='b_',side='M');decl=DECL+declarations(inputs,'N')+declarations(inputs,'M')+'(declare-fun RBYTE () (_ BitVec 64))\n(declare-fun WBYTE () (_ BitVec 64))\n';pp=[]
 def add(name,body,scope,expected='unsat'):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+decl+body+'\n(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert r.returncode==0 and not r.stderr and r.stdout.strip()==expected,(name,r.stdout,r.stderr);pp.append({'name':name,'query':q,'expected':expected,'result':expected,'scope':scope})
 terms=[]
 for actual,row in zip(g.reads,s['read_ledger']):
  base=row['address_base'];want=f'(bvadd {base} {bv(row["offset_bytes"])})';terms.append(neq(actual['address'],want))
 add('all29_load_addresses',prefix(g)+'(assert (or '+' '.join(terms)+'))','All arbitrary input bytes/GPR values;28 fixed frame cells and one selected table slot. No native mapping or initialization claim.')
 terms=[neq(actual['address'],f'(bvadd K {bv(row["offset_bytes"])})')for actual,row in zip(g.stores,s['write_ledger'])]
 add('all50_store_addresses',prefix(g)+'(assert (or '+' '.join(terms)+'))','All50 store addresses are fixed SP-relative offsets independent of loaded context values.')
 body=f'(assert (bvuge RBYTE {bv(0x9d8)}))\n(assert (bvult RBYTE {bv(0xae48)}))\n(assert (bvuge WBYTE {bv(0x7e8)}))\n(assert (bvult WBYTE {bv(0x9bc)}))\n(assert (= (bvadd K RBYTE) (bvadd K WBYTE)))'
 add('frame_byte_read_write_disjoint',body,'Bounding envelopes imply nonoverlap for all actual frame read/write bytes. Table/frame owner separation remains a distinct premise.')
 terms=[]
 for a,b,row in zip(g.stores,other.stores,s['write_ledger']):
  terms.append(neq(a['address'],b['address']))
  if row['selected_critical_field']:terms.append(neq(a['value'],b['value']))
 terms.extend(neq(g.get('x'+str(j)),other.get('x'+str(j)))for j in OBSREGS)
 add('selected_projection_two_run_noninterference',prefix(g,other)+'(assert (or '+' '.join(terms)+'))','Two independent sets of25 nuisance load values; shared selected cursor0,SIZE,BUF,TABLE,FN and caller phase/selector. Only six critical store values,24 terminal registers and all store addresses are compared; other cache values are excluded.')
 affine=s['affine_recovery']['candidates'];widths={q['input']:q['width_bits']for q in inputs if q['role']=='nuisance_cut'};widths['SIZE']=32;inverse=[];seen=set()
 for actual,row in zip(g.stores,affine):
  bits=row['width_bits'];name=row['input'];bias=row['candidate_bias'];term=bias
  if name:
   iw=widths[name];base=name if iw==bits else f'((_ zero_extend {bits-iw}) {name})'if iw<bits else f'((_ extract {bits-1} 0) {name})';term=f'(bvadd {base} {bias})'
  add('affine_cache_'+row['site'],prefix(g)+'(assert '+neq(actual['value'],term)+')','Universal source-linked cache expression under selected cursor0 and phase. The two candidate assignments are not proof; this query covers every raw abstract input value.')
  if name and name.startswith('N')and name not in seen:
   seen.add(name);iw=widths[name];recovered=f'(bvsub {actual["value"]} {bias})';recovered=f'((_ extract {iw-1} 0) {recovered})'if iw<bits else recovered;inverse.append(neq(recovered,name))
 assert len(inverse)==25
 add('all25_nuisance_inputs_recoverable_from_cache',prefix(g)+'(assert (or '+' '.join(inverse)+'))','One chosen cache cell per input recovers all19 u64/six u16 abstract nuisance values by modular subtraction and optional low16 extraction. No native observability or input reachability claim.')
 # Negative control: frame+a610 feeds a cached encoded offset and a raw saved value.
 j=next(j for j,row in enumerate(s['write_ledger'])if row['offset_bytes']==0x810);assert s['write_ledger'][j]['syntactic_transitive_inputs']==['N0']
 equal=[f'(assert (= N{k} M{k}))'for k in range(1,25)]
 body=prefix(g,other)+'\n'.join(equal)+'\n(assert (= N0 '+bv(0)+'))\n(assert (= M0 '+bv(1)+'))\n(assert '+neq(g.stores[j]['value'],other.stores[j]['value'])+')'
 add('reject_whole_cache_noninterference',body,'Explicit abstract cut witness: changing only the+a610 input from0 to1 changes cache+810. This is not a native reachability witness.','sat')
 # Six-instruction prefix projection; no frame ownership is inferred from metadata containment.
 ii=s['compiler_container']['entry_prefix']['instructions'];sp='K';fp=None;ledger=[]
 for i in ii:
  m=i['mnemonic'];op=i['operands']
  if m=='pacibsp':assert op==''
  elif m=='stp':
   if op.endswith('!'):
    mat=re.search(r'\[sp, #(-0x[0-9a-f]+)\]!',op);assert mat;sp=f'(bvadd {sp} {bv(int(mat[1],0))})'
   else:assert '[sp,'in op
  elif m=='add':assert op=='x29, sp, #0x20';fp=f'(bvadd {sp} {bv(0x20)})'
  elif m=='sub':assert op=='sp, sp, #0x10';sp=f'(bvsub {sp} {bv(0x10)})'
  else:raise AssertionError(i)
  ledger.append(i['ea'])
 add('compiler_entry_prefix_delta_only','(assert (or '+neq(sp,f'(bvsub K {bv(64)})')+' '+neq(fp,f'(bvsub K {bv(16)})')+'))','Source prefix reserves48 B+16 B=64 B and sets FP=entrySP-16 B. Later stack epochs/calls/internal branch entries are not joined to preparation.')
 assert len(g.sites)==len(set(g.sites))==385
 return pp,{'preparation':g.record(),'second_run':other.record(),'prefix_projection_source_sites':ledger}
def verify(s):return s==build()
def alterations(s):
 baseline=build();ops=[('wrong_read_offset',lambda t:t['read_ledger'][0].__setitem__('offset_bytes',0)),('missing_LDUR',lambda t:t['read_ledger'].pop(3)),('wrong_write_width',lambda t:t['write_ledger'][0].__setitem__('extent_bytes',4)),('promote_projection_to_full_effect',lambda t:t['selected_projection'].__setitem__('scope','all cache values independent')),('invent_native_frame_owner',lambda t:t['compiler_container'].__setitem__('scope','native stack owner established'))];out=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=baseline;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert verify(s);pp,tr=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':56,'counterexamples_sat':1,'affine_cache_relations_proved':50,'nuisance_values_inverted':25,'distinct_preparation_sites_translated':385,'two_run_instruction_instances':770,'SSA_definitions_per_run':len(tr['preparation']['source_sites'])-50,'rejected_alterations':len(aa)}
 assert counts['SSA_definitions_per_run']==tr['preparation']['SSA_definitions']
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_existing_scalar_reader.py':sha(ROOT/'validate_daemon_existing_scalar_reader.py')},'proofs':pp,'translations':tr,'alterations':aa,'verified_counts':counts,'source_recapture_match':True,'full_cache_noninterference':False,'native_frame_owner_proved':False,'dependency_graph_scope':'Syntactic transitive overapproximation, not an exact semantic influence graph. The self-composition proves only the selected projection.','solver':{'path':SOLVER,'sha256':sha(SOLVER)},'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
