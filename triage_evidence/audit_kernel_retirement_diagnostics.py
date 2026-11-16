#!/usr/bin/env python3
"""Instruction-derived diagnostic routing, variadic operands and global stores.
O(I+query DAG) construction/space; separate SMT search, 30 s/query.
Static _panic call boundaries only; no native panic or termination proof.
"""
import copy
import json
import z3
from kext_port_tools import ROOT
from lskd_values_symbolic import resize
from audit_kernel_retirement_dispatch import Model as DispatchModel
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_retirement_diagnostics as R

class Model(DispatchModel):
 def __init__(self,e):
  e=copy.deepcopy(e);e['spans']+=e['reused_caller_spans'];super().__init__(e)

def setup(e,zone=None):
 v=Model(e)
 if zone is not None:v.zone=resize(zone,64);v.seed('x3',v.zone)
 v.seed('x19',v.zone);v.seed('x20',v.pointer)
 return v

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(c) for c in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));r=s.check();assert r==z3.sat,('vacuous',label,str(r),s.reason_unknown())
  s.add(*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV','query':s.to_smt2()})
  if hasattr(v,'environment_intervention'):qs[-1]['environment_intervention']=v.environment_intervention
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores),
   'linked_edge_obligations':len(v.edge_checks),'authentication_envelopes':v.authentication_envelopes})
  visited.update(v.visited);print(label,flush=True)
 def panic(v,frame,fmt,args):
  return z3.Or(v.next!=R.PANIC,v.read('sp')!=v.sp0-frame,v.read('x0')!=R.LITERALS[fmt][0],
   *[v.load(v.sp0-frame+8*j,8)!=resize(value,64) for j,value in enumerate(args)])
 v=setup(e).run('class_entry');admit=z3.And(z3.UGE(v.zone,R.BASE),z3.ULT(v.zone,R.BASE+132480))
 prove('all_zone64_class_diagnostic_rechecks_exact_zone_interval_and_frame64',v,z3.Or(
  v.next!=z3.If(admit,resize(0xfffffe000c62d460,64),resize(0xfffffe000c62d458,64)),
  v.read('x8')!=v.zone-R.BASE,v.read('sp')!=v.sp0-64,v.read('x3')!=v.zone))
 v.run('class_bad_zone')
 prove('invalid_class_zone_calls_original_zone_diagnostic_with_zone_in_x0',v,z3.Or(
  v.next!=0xfffffe000c6336f8,v.read('x0')!=v.zone),[z3.Not(admit)])
 v.run('zone_diagnostic')
 prove('nested_invalid_class_zone_reaches_panic_with_zone_file_line732',v,panic(v,112,'zone',
  [v.zone,R.LITERALS['source_zalloc'][0],732]),[z3.Not(admit)])
 v=setup(e);v.seed('x0',v.zone);v.enter('zone_diagnostic')
 prove('all_zone64_direct_diagnostic_requests_panic_with_three_stack_words',v,panic(v,48,'zone',
  [v.zone,R.LITERALS['source_zalloc'][0],732]))
 v=setup(e).run('geometry_error').run('zone_diagnostic')
 prove('dispatch_geometry_error_joins_complete_zone_panic_argument_producer',v,panic(v,48,'zone',
  [v.zone,R.LITERALS['source_zalloc'][0],732]))
 idx=z3.BitVec('KE_query_zone_id10',10);zone=resize(R.BASE,64)+192*z3.ZeroExt(54,idx)
 def prefix(capture=e,joined=False):
  v=setup(capture,zone);v.regions=[(v.heap,32),(zone,32),(R.FLAGS,690*4),(R.NAMES,256*8),(R.DIAG_FLAG,1),(R.DIAG_ZONE,8)]
  v.flag=v.load(resize(R.FLAGS,64)+4*z3.ZeroExt(54,idx),4);v.heap_class=v.load(v.heap+16,1)
  v.heap_name=v.load(resize(R.NAMES,64)+8*z3.ZeroExt(56,v.heap_class),8);v.zone_name=v.load(zone+16,8)
  v.cls=z3.Extract(10,8,v.flag);v.class_mask=v.flag&0x700
  v.old_diag_flag=v.load(resize(R.DIAG_FLAG,64),1);v.old_diag_zone=v.load(resize(R.DIAG_ZONE,64),8)
  if joined:v.run('mismatch')
  return v.run('class_entry').run('class_index')
 v=prefix();prem=[z3.ULT(idx,690)]
 prove('query_id10_diagnostic_reciprocal_flag_heap_name_and_type_bit_branch',v,z3.Or(
  v.read('x11')!=z3.ZeroExt(54,idx),v.read('w10')!=v.flag,v.read('x8')!=v.heap_name,
  v.read('x9')!=R.NAMES,v.read('x12')!=R.FLAGS,v.read('x0')!=v.heap,v.read('x1')!=v.pointer,
  v.read('x2')!=v.request,v.read('x3')!=zone,
  v.next!=z3.If((v.flag&0x800)!=0,resize(0xfffffe000c62d4d4,64),resize(0xfffffe000c62d490,64))),prem)
 v.run('class_regular_gate');prem=[z3.ULT(idx,690),(v.flag&0x800)==0]
 prove('coherent_flag_reload_class_mask_and_known_name_gate_are_exact',v,z3.Or(
  v.read('w10')!=v.class_mask,v.read('w11')!=z3.ZeroExt(29,v.cls),v.read('x8')!=v.heap_name,
  v.next!=z3.If(z3.UGT(v.cls,4),resize(0xfffffe000c62d510,64),resize(0xfffffe000c62d4a4,64))),prem)
 v=prefix().run('class_regular_gate');named=v.load(resize(R.NAMES,64)+8*z3.ZeroExt(61,v.cls),8)
 v.run('class_named_gate')
 prove('known_class_name_load_and_regular_vs_heap_format_gate',v,z3.Or(v.read('x9')!=named,
  v.next!=z3.If(v.cls==0,resize(0xfffffe000c62d4ac,64),resize(0xfffffe000c62d51c,64))),
  [z3.ULT(idx,690),(v.flag&0x800)==0,z3.ULE(v.cls,4)])
 v=prefix().run('class_regular_gate').run('class_invalid_name')
 prove('coherent_class_above_four_uses_invalid_literal_and_heap_format',v,z3.Or(
  v.read('x9')!=R.LITERALS['invalid_name'][0],v.next!=0xfffffe000c62d51c),
  [z3.ULT(idx,690),(v.flag&0x800)==0,z3.UGT(v.cls,4)])
 # Explicit environmental cuts distinguish a coherent snapshot from a
 # changed word between the two loads. These writes are hypotheses, not
 # source stores or observed concurrent/native operations.
 def changed_epoch():
  v=prefix();second=z3.BitVec('KE_second_epoch_flag32',32)
  v.setmem(resize(R.FLAGS,64)+4*z3.ZeroExt(54,idx),4,second)
  v.environment_intervention={'after_source_pc':'0xfffffe000c62d48c','before_source_pc':'0xfffffe000c62d490',
   'effect':'replace selected zone-flag u32 with an independent symbolic second-epoch word',
   'source_store':False,'native_interleaving_observed':False}
  return v,second
 v,second=changed_epoch();v.run('class_regular_gate');second_class=z3.Extract(10,8,second)
 prove('explicit_second_epoch_changes_reloaded_class_but_not_first_class_mask',v,z3.Or(
  v.read('w10')!=v.class_mask,v.read('w11')!=z3.ZeroExt(29,second_class),v.read('x8')!=v.heap_name,
  v.next!=z3.If(z3.UGT(second_class,4),resize(0xfffffe000c62d510,64),resize(0xfffffe000c62d4a4,64))),
  [z3.ULT(idx,690),(v.flag&0x800)==0])
 v,second=changed_epoch();v.run('class_regular_gate').run('class_invalid_name').run('class_regular')
 prove('explicit_two_epoch_zero_first_mask_and_invalid_second_class_select_regular_format',v,
  panic(v,64,'regular',[v.pointer,v.request,R.LITERALS['invalid_name'][0],v.zone_name,R.LITERALS['source_kalloc'][0],2769]),
  [z3.ULT(idx,690),(v.flag&0x800)==0,v.class_mask==0,z3.UGT(z3.Extract(10,8,second),4)])
 # All four valid-zone diagnostic routes start at the dispatch's actual
 # three-word mismatch-call producer and remain linked through _panic.
 for mode in ['typed','regular','heap_named','heap_invalid']:
  v=prefix(joined=True);prem=[z3.ULT(idx,690)]
  if mode=='typed':
   prem.append((v.flag&0x800)!=0);v.run('class_typed')
   args=[v.pointer,v.zone_name,v.heap_name,R.LITERALS['source_kalloc'][0],2764];fmt='typed'
   extra=z3.Or(v.load(resize(R.DIAG_FLAG,64),1)!=1,v.load(resize(R.DIAG_ZONE,64),8)!=zone)
  else:
   prem.append((v.flag&0x800)==0);v.run('class_regular_gate')
   if mode=='heap_invalid':
    prem.append(z3.UGT(v.cls,4));v.run('class_invalid_name');name=resize(R.LITERALS['invalid_name'][0],64)
   else:
    prem.append(v.cls==0 if mode=='regular' else z3.And(z3.UGT(v.cls,0),z3.ULE(v.cls,4)))
    name=v.load(resize(R.NAMES,64)+8*z3.ZeroExt(61,v.cls),8);v.run('class_named_gate')
   if mode=='regular':
    v.run('class_regular');fmt='regular';args=[v.pointer,v.request,name,v.zone_name,R.LITERALS['source_kalloc'][0],2769]
   else:
    v.run('class_heap');fmt='heap';args=[v.pointer,v.request,name,v.heap_name,R.LITERALS['source_kalloc'][0],2772]
   extra=z3.Or(v.load(resize(R.DIAG_FLAG,64),1)!=v.old_diag_flag,v.load(resize(R.DIAG_ZONE,64),8)!=v.old_diag_zone)
  prove('dispatch_class_error_'+mode+'_route_exact_panic_format_varargs_and_diagnostics',v,z3.Or(panic(v,64,fmt,args),extra),prem)
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']}
 reused={int(i['ea'],16) for s in e['reused_caller_spans'] for i in s['instructions']}
 assert visited==selected|reused,sorted(map(hex,(selected|reused)-visited))
 changed=copy.deepcopy(e);row=next(s for s in changed['spans'] if s['label']=='class_typed');raw=bytearray.fromhex(row['bytes_hex'])
 assert row['instructions'][2]['ea']=='0xfffffe000c62d4dc' and row['instructions'][2]['mnemonic']=='strb'
 raw[8:12]=bytes.fromhex('1f2003d5');row['bytes_hex']=raw.hex()
 v=prefix(changed,True).run('class_typed')
 common=[*v.owned(),*v.edge_checks,z3.ULT(idx,690),(v.flag&0x800)!=0,v.old_diag_flag==0]
 bad=v.load(resize(R.DIAG_FLAG,64),1)!=1
 s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for([*common,bad]),bad);assert s.check()==z3.sat
 negative={'altered_typed_diagnostic_store_counterexample':True,'result':'sat','query':s.to_smt2()}
 prior=[];old=json.loads(read(ROOT/'kernel_retirement_dispatch_audit.json'))
 for label in ['rejected_zone64_calls_geometry_error_with_original_zone',
  'data_class_rejection_calls_error_with_heap_base_request_zone',
  'second_special_class_rejection_calls_error_with_heap_base_request_zone',
  'ordinary_class_rejection_calls_error_with_heap_base_request_zone',
  'all_query_zone_id10_guard_admits_exact_ids_below_690']:
  q=next(q for q in old['source_proofs'] if q['label']==label);s=z3.SolverFor(q['logic']);s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
  prior.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/'kernel_retirement_dispatch_audit.json')})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,
  'proved_source_PCs':sorted(map(hex,visited)),'rechecked_prior_source_proofs':prior,'negative_control':negative,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(prior),
   'distinct_new_proved_instructions':len(selected),'distinct_reused_proved_instructions':len(reused),
   'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'linked_valid_zone_panic_routes':4,
   'explicit_metadata_intervention_queries':2,
   'altered_typed_diagnostic_store_counterexample':True},
  'conditional_kernel_retirement_diagnostics_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
