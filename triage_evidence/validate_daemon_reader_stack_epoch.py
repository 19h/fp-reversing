#!/usr/bin/env python3
"""Universal SP arithmetic and source-interval preservation certificate."""
import copy,json,subprocess
from recover_daemon_reader_stack_epoch import ROOT,P,SCOPE,FLAGS,sha,build
from validate_daemon_existing_scalar_reader import bv
SOLVER='/opt/homebrew/bin/z3'
DECL=''.join(f'(declare-fun {n} () (_ BitVec 64))\n'for n in ['E','OFF','BYTE','PARENT','CALLDELTA'])
def run(name,body,scope,expected='unsat'):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+body+'\n(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert r.returncode==0 and not r.stderr and r.stdout.strip()==expected,(name,r.stdout,r.stderr)
 return {'name':name,'query':q,'result':expected,'scope':scope}
def certificates(s):
 pp=[];F=f'(bvsub E {bv(0x10dd0)})';localtop=f'(bvsub E {bv(128)})';fps=f'(bvsub E {bv(16)})'
 # MOV/MOVK and ADRP/ADD are the source-producing instructions, not guessed native values.
 ii=s['prefix']['instructions'];by={i['ea']:i for i in ii}
 assert by['0x10061a2f8']['operands']=='w9, #0xd50'and by['0x10061a2fc']['operands']=='w9, #1, lsl #16'
 assert by['0x10061a300']['operands']=='x17, #0x1010b1000'and by['0x10061a304']['operands']=='x17, x17, #0xe28'and by['0x10061a308']['operands']=='x16, [x17]'and by['0x10061a30c']['operands']=='x16, x17'
 request='(bvor #x00000d50 #x00010000)';slot='(bvadd #x00000001010b1000 #x0000000000000e28)'
 pp.append(run('stack_probe_register_and_modifier_interface','(assert (or (distinct '+request+' #x00010d50) (distinct '+slot+' #x00000001010b1e28)))','Source W9 requests68944 B; X17 is the authenticated slot address used as modifier. Original pointer record identifies ___chkstk_darwin; actual callee/PAC behavior remains a premise.'))
 expr='E'
 for r in s['prefix']['SP_writes']:expr=f'(bvadd {expr} {bv(r["delta_bytes"])})'
 pp.append(run('core_frame_geometry','(assert (or (distinct '+expr+' '+F+') (distinct (bvadd '+F+' '+bv(68944)+') '+localtop+') (distinct '+fps+' (bvadd '+F+' '+bv(0x10dc0)+'))))','Full source SP effect under normal probe return:128 B saved plus68944 B local scratch; FP=E-16 B. Modular geometry is separate from native mapped ownership.'))
 pp.append(run('helper_SP_and_PAC_modifier_restoration','(assert (distinct (bvadd (bvsub PARENT '+bv(192)+') '+bv(192)+') PARENT))','Full source helper census has only SUBSP,c0 and ADDSP,c0. Entry/exit SP agree, making the PACIBSP/RETAB SP-modifier convention source-compatible; hardware authentication remains untested.'))
 summaries=[]
 for k,p in enumerate(s['profiles']):
  expr=f'(bvsub E {bv(128)})';defs=[];terms=[];count=0
  for row in p['intervals']:
   f=s['path_intervals'][row['interval']]
   for r in f['SP_writes']:
    name=f'p{k}_{count}';defs.append(f'(define-fun {name} () (_ BitVec 64) (bvadd {expr} {bv(r["delta_bytes"])}))');expr=name;count+=1
   if row['event_index']==p['reader_entry_event']:terms.append(f'(distinct {expr} {F})')
   if row['event']['instruction']=='retab':terms.append(f'(distinct {expr} {F})')
  terms.append(f'(distinct {expr} {F})');assert count==20 and len(terms)==11
  pp.append(run('source_epoch_'+p['label'],'\n'.join(defs)+'\n(assert (or '+' '.join(terms)+'))','Frozen chosen control edges; each original daemon instruction is inspected for SP writes, source helper returns are paired, and imported calls preserve SP on the declared normal-return premise. No data-dependent routing or native replay proof.'))
  summaries.append({'label':p['label'],'SP_updates':count,'milestone_equalities':len(terms),'reader_entry_delta':p['reader_entry_SP_delta'],'builder_finish_delta':p['final_SP_delta'],'source_interval_instances':len(p['intervals']),'source_instruction_instances':p['instruction_instances']})
 # A nonwrapping entry is required for ordinary unsigned memory-range containment.
 pre=f'(assert (bvuge E {bv(0x10dd0)}))\n'
 for name,a,z in [('preparation_writes',0x7e8,0x9bc),('preparation_reads',0x9d8,0xae48),('borrowed_u32_output',0x601c,0x6020),('helper_argument_record',0x10cb8,0x10cc8)]:
  body=pre+f'(assert (or (bvult (bvadd {F} {bv(a)}) {F}) (bvugt (bvadd {F} {bv(z)}) {localtop})))'
  pp.append(run(name+'_within_source_locals',body,'Conditional K=F and source-reserved local area only. Actual mapping,initialization,BUF/OUT aliasing and access success remain unproved.'))
 pp.append(run('reader_envelope_headroom',pre+f'(assert (distinct (bvsub {localtop} (bvadd {F} {bv(0xae48)})) {bv(24328)}))','Reader frame-read upper bound leaves24328 B=0x5f08 before the source local-area end. Sparse accesses do not initialize that envelope.'))
 pp.append(run('reader_envelopes_below_saved_guard',pre+f'(assert (or (bvugt (bvadd {F} {bv(0xae48)}) (bvadd {F} {bv(0x10d38)})) (distinct (bvsub {localtop} {bv(0x18)}) (bvadd {F} {bv(0x10d38)}))))','Saved guard location reuses the pinned shared-root source contract. Preparation accesses end below it; guard correctness/native authentication is not proved.'))
 pp.append(run('import_SP_preservation_is_required',f'(assert (= CALLDELTA {bv(16)}))\n(assert (distinct (bvadd {F} CALLDELTA) {F}))','Abstract counterexample to omitting imported-callee SP preservation. It is not evidence that a native callee violates its calling convention.','sat'))
 return pp,summaries
def verify(s):return s==build()
def alterations(s):
 baseline=build();ops=[('wrong_core_delta',lambda t:t['prefix']['SP_writes'][0].__setitem__('delta_bytes',-64)),('missed_helper_SP_write',lambda t:next(f for f in t['path_intervals'].values()if len(f['SP_writes'])==2 and f['SP_writes'][0]['delta_bytes']==-192)['SP_writes'].pop()),('invent_native_path',lambda t:t['profiles'][0].__setitem__('native_evidence',True)),('wrong_reader_epoch',lambda t:t['profiles'][0].__setitem__('reader_entry_SP_delta',0)),('wrong_probe_binding',lambda t:t['stack_probe_binding']['fixup'].__setitem__('target','unknown'))];out=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=baseline;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert verify(s);pp,summary=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'counterexamples_sat':sum(p['result']=='sat'for p in pp),'source_SP_updates_per_profile':20,'milestone_equalities_per_profile':11,'rejected_alterations':len(aa)}
 assert counts['queries_unsat']==21 and counts['counterexamples_sat']==1
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'source_recapture_match':True,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json'))},'proofs':pp,'profile_SP_summaries':summary,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'all_checks_pass':True,'native_mapping_proved':False,'fresh_runtime_replay':False,'import_callee_SP_preservation_is_premise':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
