#!/usr/bin/env python3
"""Source caller contracts with a named, rechecked core-result theorem.
O(I+C*W+query DAG) construction/space; 60 s per SMT query.
"""
import copy,json
import z3
from z3.z3util import get_vars
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_transfer_boundary as T
import audit_userclient_zero_tag_return as C
import recover_userclient_zero_tag_provider as R
pc=R.pc;bv=T.bv;RESULT=C.RESULT
class Model(T.Model):
 def __init__(self,*args,**kw):
  super().__init__(*args,**kw);self.boundaries=[];self.external_reads=[]
 def load(self,a,n,part=0):
  self.external_reads.append((self.pc,a,n));out=super().load(a,n,part)
  if self.pc==pc(0xa504080):return bv(pc(0xa505198))
  return out
 def call(self):
  role=T.R.CALLS[self.pc][0];i=self.ins[self.pc];target=self.op(i,i.operands[0],64);modifier=self.op(i,i.operands[1],64)if i.mnemonic=='blraa'else None
  # BL sets LR before the callee sees the entry state. Authentication stays opaque.
  regs={r:self.regread(r)for r in ['sp',*('x'+str(j)for j in range(31))]};regs['x30']=bv(self.pc+4)
  self.boundaries.append({'role':role,'PC':self.pc,'target':target,'modifier':modifier,'registers':regs});super().call()
 def premises(self):
  # These two pointer assumptions are unnecessary for a value only forwarded.
  removed=[self.state!=0,z3.ULE(self.state,bv(T.MASK-0x1000))];old=super().premises();drop=[q for q in old if any(z3.eq(q,x)for x in removed)];assert len(drop)==2
  out=[q for q in old if not any(z3.eq(q,x)for x in removed)]+[z3.UGE(self.sp,0x2000)]
  if self.kind=='handler':out.append(self.vprovider==bv(pc(0x846b8d0)))
  return out
def selected(e,kind,alias=False):
 v=Model(e['caller'],kind,'normal'if kind=='provider'else'nonzero',alias)
 if kind=='provider':v.core_return=bv(RESULT)
 else:v.provider_return=bv(RESULT)
 return v.run()
def predicates(v):return v.premises()+v.checks
def audit(e=None):
 e=e or json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];admissions=[];controls=[];covered=set();traces={};footprints=[]
 def prove(name,v,bad,extra=()):
  ps=v.premises()+list(extra);s=z3.Solver();s.set(timeout=60000);s.add(*ps);assert s.check()==z3.sat,('vacuous',name);s.add(z3.Or(*[z3.Not(q)for q in v.checks],bad));assert s.check()==z3.unsat,name;qs.append({'name':name,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2()});covered.update(v.visited);print(name,flush=True)
 for kind in ['provider','handler']:
  for alias in ([False,True]if kind=='handler'else[False]):
   v=selected(e,kind,alias);prefix=kind+('_alias'if alias else'_separate');d={r:a for r,a,p in v.events};traces[prefix]=[{'role':r,'PC':hex(p)}for r,a,p in v.events]
   prove(prefix+'_nullable_state_exact_status_and_frame',v,z3.Or(v.regread('x0')!=bv(RESULT),v.regread('sp')!=v.sp,*[v.regread('x'+str(j))!=v.initial['x'+str(j)]for j in range(19,30)]))
   state=str(v.state);assert all(state not in {str(x)for x in get_vars(a)}for p,a,n in v.external_reads);assert all(state not in {str(x)for x in get_vars(q)}for q in v.guards+v.checks)
   footprints.append({'component':prefix,'source_read_instances':len(v.external_reads),'state_dependent_load_addresses':0,'state_dependent_control_or_address_checks':0,'state_only_forwarded_as_value':True})
   for statevalue in [0,T.MASK]:
    s=z3.Solver();s.set(timeout=60000);s.add(*predicates(v),v.state==bv(statevalue),v.extent_parameter==14);assert s.check()==z3.sat;admissions.append({'name':prefix+'_state_'+hex(statevalue),'result':'sat','query':s.to_smt2(),'native_reachability_established':False})
   if kind=='provider':
    prove('provider_source_core_argument_and_direct_target_binding',v,z3.Or(T.same(d['core'][:3],[v.staging,v.extent_parameter,v.state]),next(b['target']for b in v.boundaries if b['role']=='core')!=pc(0xa635208)))
    prove('provider_copy_requests_have_same_staging_and_low32_extent',v,z3.Or(T.same(d['copy_in'][:4],[v.descriptor,bv(0),v.staging,bv(v.extent)]),T.same(d['copy_out'][:4],[v.descriptor,bv(0),v.staging,bv(v.extent)])))
    prove('provider_arbitrary_short_counts_leave_selected_nonzero_status',v,v.regread('x0')!=bv(RESULT),[v.extent_parameter==14,z3.ULT(v.count_in,14),z3.ULT(v.count_out,14),v.state==0])
    core=next(b for b in v.boundaries if b['role']=='core');ce=json.loads(read(ROOT/'userclient_zero_tag_return_checks.json'));f=C.prologue(ce);bindings=[(f.initial['x'+str(j)],core['registers']['x'+str(j)])for j in range(31)]+[(f.F,core['registers']['sp']-0x10f0)];sub=lambda q:z3.simplify(z3.substitute(q,*bindings))
    for role,reg,off,writer in R.ARGS:
     prove('actual_provider_call_to_core_prologue_'+role,v,z3.Or(sub(C.frame_cell(f,off))!=d['core'][reg],*[z3.Not(sub(q))for q in f.address_checks]),[sub(q)for q in f.owned()])
    prove('provider_to_core_frame_and_nominal_link',v,z3.Or(sub(f.read('sp'))!=v.sp-0x50-0x10f0,sub(f.read('x29'))!=v.sp-0x60,sub(f.initial['x29'])!=v.sp-0x10,sub(f.initial['x30'])!=pc(0xa505300)),[sub(q)for q in f.owned()])
    prove('zero_state_reaches_core_argument_lane',v,d['core'][2]!=bv(0),[v.state==0])
    assert [r for r,a,p in v.events][7:]==['copy_out','buffer_complete','buffer_release','task_complete','task_release']
    prove('selected_lifecycle_receivers_and_direction',v,z3.Or(T.same(d['buffer_complete'][:2],[v.buffer,bv(0)]),d['buffer_release'][0]!=v.buffer,T.same(d['task_complete'][:2],[v.descriptor,bv(0)]),d['task_release'][0]!=v.descriptor))
   else:
    prove(prefix+'_provider_arguments_zero_extend_packet_extent',v,T.same(d['provider'],[v.provider,v.address,bv(v.extent),v.state,v.task]))
    boundary=next(b for b in v.boundaries if b['role']=='provider');mod=(v.vprovider+0xa20)&bv((1<<48)-1)|bv(0x3499<<48)
    prove(prefix+'_nominal_provider_slot_and_modifier',v,z3.Or(boundary['target']!=pc(0xa505198),boundary['modifier']!=mod))
    assert [r for r,a,p in v.events]==['provider','error_log'];assert not [p for p,a,n,x in v.stores if p in [pc(0xa5040b0),pc(0xa5040b8)]]
    prove(prefix+'_source_error_log_stack_status',v,v.private[v.key(v.sp-0x40,8)]!=bv(RESULT))
 # Instantiate the provider entry with the actual handler call registers.
 p=selected(e,'provider');h=selected(e,'handler');hb=next(b for b in h.boundaries if b['role']=='provider');pb=next(b for b in p.boundaries if b['role']=='core');args=next(a for r,a,at in h.events if r=='provider')
 pairs=[(p.sp,hb['registers']['sp'])]+[(getattr(p,n),args[j])for j,n in enumerate(['provider','address','extent_parameter','state','task'])];sub=lambda q:z3.simplify(z3.substitute(q,*pairs))
 prove('actual_handler_provider_core_argument_and_frame_interface',h,z3.Or(sub(pb['registers']['x1'])!=bv(h.extent),sub(pb['registers']['x2'])!=h.state,sub(pb['registers']['sp'])!=h.sp-0x90,sub(pb['registers']['x29'])!=h.sp-0x50,sub(pb['registers']['x30'])!=pc(0xa505300),h.regread('x0')!=sub(p.regread('x0'))))
 prove('nested_source_frames_are_adjacent_without_wrap',h,z3.Or(z3.ULT(h.sp-0x1180,1),z3.UGE(h.sp-0x1180,h.sp-0x90),z3.UGE(h.sp-0x90,h.sp-0x40),z3.UGE(h.sp-0x40,h.sp)))
 # Admission of the former model at state=0 must fail for the identified premise.
 old=T.Model(e['caller'],'provider').run();s=z3.Solver();s.add(*old.premises(),old.state==0);assert s.check()==z3.unsat
 omission={'name':'former_nonnull_forwarded_state_excludes_zero','result':'unsat','query':s.to_smt2(),'native_fault_established':False}
 # The caller composition consumes the exact retained theorem, not a native run.
 prior=[]
 for name,count in [('userclient_zero_tag_return_audit.json',44),('userclient_transfer_boundary_audit.json',23)]:
  a=json.loads(read(ROOT/name));assert len(a['source_proofs'])==count
  for q in a['source_proofs']:
   s=z3.Solver();s.set(timeout=120000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat;prior.append({'artifact':name,'name':q.get('name',q.get('label')),'result':'unsat'})
 # Source mutations alter defined operands without running the target.
 for label,kind,at,oldword,newword in [('state_argument','provider',0xa5052f8,'e20315aa','020080d2'),('copyout_extent','provider',0xa505338,'e30314aa','030080d2')]:
  changed=copy.deepcopy(e);f=changed['caller']['functions'][kind];raw=bytearray.fromhex(f['bytes_hex']);off=pc(at)-int(f['start'],16);assert raw[off:off+4].hex()==oldword;raw[off:off+4]=bytes.fromhex(newword);f['bytes_hex']=raw.hex();v=selected(changed,kind);d={r:a for r,a,p in v.events};bad=d['core'][2]!=v.state if label=='state_argument'else d['copy_out'][3]!=bv(v.extent);s=z3.Solver();s.set(timeout=60000);s.add(*predicates(v),v.extent_parameter==14,v.state==1,bad);assert s.check()==z3.sat;controls.append({'name':label,'mutated_PC':hex(pc(at)),'result':'sat','satisfiable_violation_query':s.to_smt2(),'native_target_executed':False})
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'verified_counts':e['verified_counts'],'source_proofs':qs,'rechecked_prior_proofs':prior,'nullable_state_admissions':admissions,'former_model_exclusion':omission,'negative_source_controls':controls,'state_use_footprints':footprints,'caller_traces':traces,'proved_caller_PCs':[hex(p)for p in sorted(covered)],'core_contract_consumed':{'artifact':'userclient_zero_tag_return_audit.json','sha256':sha(ROOT/'userclient_zero_tag_return_audit.json'),'source_proof':'normal_return_exact_u32_result_and_restored_frame','local_X0':'0x00000000ffff5bbc','selected_path_premise_retained':True,'ordinary_authenticated_return_to_nominal_caller_assumed':True,'native_return_established':False},'independent_totals':{'new_source_queries_unsat':len(qs),'prior_queries_unsat':len(prior),'nullable_state_admissions_sat':len(admissions),'former_model_zero_exclusion_unsat':1,'negative_source_controls':len(controls),'proved_caller_source_words':len(covered),'prefix_argument_cells':90,'prefix_argument_bytes':720,'native_target_calls':0},'all_checks_pass':True,'conditional_zero_tag_provider_established':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
