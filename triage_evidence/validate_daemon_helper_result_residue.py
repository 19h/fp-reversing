#!/usr/bin/env python3
"""Scalar bit-vector certificate and source/retained-evidence controls only."""
import copy,json,subprocess
from recover_daemon_helper_result_residue import ROOT,P,SCOPE,FLAGS,sha,build
SOLVER='/opt/homebrew/bin/z3'
def bv(v):return '#x'+format(v&((1<<64)-1),'016x')
def xor(a,b):return '(bvxor '+a+' '+b+')'
def low(n,x):return '((_ extract '+str(n-1)+' 0) '+x+')'
def lift(s):
 r={'x5':'R','x17':'T'};rows=[]
 for i in s['scalar_projection']:
  p=i['operands'].split(', ');dst=p[0];m=i['mnemonic']
  if m=='mov':v=bv(int(p[1][1:],0))
  elif m=='movk':
   shift=int(p[2].split('#')[1]);mask=0xffff<<shift;v='(bvor (bvand '+r[dst]+' '+bv(~mask)+') '+bv(int(p[1][1:],0)<<shift)+')'
  elif m=='eor':
   rhs=r[p[2]]
   if len(p)==4:rhs='(bvshl '+rhs+' '+bv(int(p[3].split('#')[1]))+')'
   v=xor(r[p[1]],rhs)
  else:raise AssertionError(m)
  name='V'+str(len(rows));rows.append({'site':i['ea'],'name':name,'expression':v});r[dst]=name
 assert len(rows)==6
 return rows,r['x8']
def certificates(s):
 rows,result=lift(s);decl='(declare-fun R () (_ BitVec 64))\n(declare-fun T () (_ BitVec 64))\n(declare-fun U () (_ BitVec 64))\n'
 body=''.join('(define-fun '+r['name']+' () (_ BitVec 64) '+r['expression']+')\n'for r in rows)
 c=bv(0xc0eaaa2272eb67c0);shift='(bvshl T '+bv(36)+')';formula=xor(xor('R',shift),c);u=xor(xor('R','(bvshl U '+bv(36)+')'),c);base=xor('R',c)
 cases=[
 ('exact_source_output','unsat','(distinct '+result+' '+formula+')','Six original scalar instructions only; memory/output-pointer effects reuse the pinned prior contract.'),
 ('low36_result_from_live_residue','unsat','(distinct '+low(36,result)+' '+low(36,base)+')','Every u64 R,T; source shift contributes zero to bits0..35.'),
 ('wire_low32_composition','unsat','(distinct '+low(32,xor(result,bv(0x55919137)))+' '+low(32,xor(base,bv(0x55919137)))+')','Existing caller/constructor/serializer codec is a separate pinned premise.'),
 ('upper28_is_shifted_intermediate','unsat','(distinct ((_ extract 63 36) '+xor(result,base)+') '+low(28,'T')+')','Relative to R xor constant, the unresolved upper28 bits equal low28(T).'),
 ('same_low28_intermediate_same_result','unsat','(and (= '+low(28,'T')+' '+low(28,'U')+') (distinct '+result+' '+u+'))','Shows that higher36 bits of cut T do not affect the result expression.'),
 ('different_low28_intermediate_different_result','unsat','(and (distinct '+low(28,'T')+' '+low(28,'U')+') (= '+result+' '+u+'))','Algebraic bijection only; arbitrary cut values are not asserted reachable in the real helper.'),
 ('reject_full64_residue_xor_only','sat','(and (= R '+bv(0x968f340323885d42)+') (= T '+bv(1)+') (distinct '+result+' '+base+'))','Explicit scalar counterexample rejects omission of the shift; not a native witness.'),
 ('bit36_not_determined_by_this_cut','sat','(and (= R '+bv(0x968f340323885d42)+') (= T '+bv(0)+') (= U '+bv(1)+') (= '+low(36,result)+' '+low(36,u)+') (distinct '+result+' '+u+'))','Two abstract cut assignments have equal low36 and different bit36; helper-internal reaching constraints are not solved.')]
 out=[]
 for name,expected,predicate,scope in cases:
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+decl+body+'(assert '+predicate+')\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==expected,(name,v.stdout,v.stderr)
  out.append({'name':name,'expected':expected,'result':expected,'query':q,'scope':scope})
 return out,rows
def verify(s):
 assert s==build()
 assert s['verified_source_counts']['recovered_result_bits']==36 and all(s[k]is False for k in FLAGS)
 assert len(s['profiles'])==12 and all(p['derived_helper_output_low36']=='0x151633a82'and p['X5_residue_u64']=='0x968f340323885d42'for p in s['profiles'])
 return True
def alterations(s):
 controls=[]
 for label,field,value in [('wrong_shift','shift',35),('wrong_output_constant','constant',0xc0eaaa2272eb67c1)]:
  t=copy.deepcopy(s)
  if field=='shift':t['scalar_projection'][0]['operands']='x11, x5, x17, lsl #35'
  else:t['scalar_projection'][1]['operands']='x8, #0x67c1'
  rows,result=lift(t);q='(set-logic QF_BV)\n(declare-fun R () (_ BitVec 64))\n(declare-fun T () (_ BitVec 64))\n'+''.join('(define-fun '+r['name']+' () (_ BitVec 64) '+r['expression']+')\n'for r in rows)+'(assert (distinct '+low(36,result)+' '+low(36,xor('R',bv(0xc0eaaa2272eb67c0)))+'))\n(check-sat)\n'
  v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and v.stdout.strip()=='sat'and not v.stderr;controls.append({'name':label,'query':q,'result':'sat','altered_claim_rejected':True})
 return controls
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert verify(s);pp,rows=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':6,'interpretation_counterexamples_sat':2,'rejected_alterations':len(aa),'scalar_instructions_translated':len(rows)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'source_sha256':sha(ROOT/(P+'_source.json')),'source_recapture_match':True,'proofs':pp,'scalar_translation':rows,'alterations':aa,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'verified_counts':counts,'all_checks_pass':True,'full_helper_value_semantics_proved':False,'native_snapshot':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
