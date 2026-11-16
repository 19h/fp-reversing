#!/usr/bin/env python3
"""Source/CFG ordering certificates and continuous whole-state components.
O(source + records + visits + RAM + query DAG) construction/space; solver
search separate with 30 s/query. No native callback or allocator executes.
"""
import json
from collections import Counter,deque
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import resize
from audit_kernel_magazine_bootstrap import Model,DEC
from replay_kernel_zone_boot_order import Replay
import recover_kernel_zone_boot_order as R
import recover_kernel_magazine_bootstrap as M
import probe_kernel_zone_boot_order as CPU

def caller_cfg(e,nop=None):
 f=e['functions'][0];raw=bytearray.fromhex(f['bytes'])
 if nop is not None:raw[nop-R.CALLER:nop-R.CALLER+4]=bytes.fromhex('1f2003d5')
 code={i.address:i for i in DEC.disasm(raw,R.CALLER)}
 events={0xfffffe000c634f1c:(M.POLICY,'policy'),0xfffffe000c634fd0:(R.DISPATCH,'dispatch6'),0xfffffe000c635054:(R.DISPATCH,'dispatch7')}
 initial=(R.CALLER,());queue=deque([initial]);seen={initial};returns=[];outside=[];edges=0
 while queue:
  pc,order=queue.popleft();i=code[pc]
  if i.mnemonic=='bl' and pc in events:
   target,label=events[pc];assert i.operands[0].imm&((1<<64)-1)==target;order=(*order,label)
  if i.mnemonic=='retab':returns.append({'pc':hex(pc),'call_order':list(order)});continue
  if i.mnemonic=='b':nexts=[i.operands[0].imm&((1<<64)-1)]
  elif i.mnemonic.startswith('b.'):nexts=[pc+4,i.operands[0].imm&((1<<64)-1)]
  else:nexts=[pc+4]
  for nxt in nexts:
   edges+=1
   if nxt not in code:outside.append({'from':hex(pc),'to':hex(nxt),'reason':'diagnostic_callee_return_falls_outside_captured_interval'});continue
   state=(nxt,order)
   if state not in seen:seen.add(state);queue.append(state)
 return {'source_nodes':len(code),'reachable_states':len(seen),'edges':edges,'normal_returns':returns,'external_interval_edges':outside,
  'every_normal_return_visits_policy_dispatch6_dispatch7':bool(returns) and all(r['call_order']==['policy','dispatch6','dispatch7'] for r in returns),
  'scope':'May-branch intraprocedural CFG with ordinary returning calls. It establishes source visit order on normal return, not callee termination or RAM noninterference.'}

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs=[];coverage=[]
 def local():v=Model({**e,'reused_caller_spans':[]});v.regions=[];return v
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks),
   'checked_read_store_rewrites':list(v.separation_rewrites.values())});print(label,flush=True)
 v=local();ident,left=z3.BitVecs('BO_metadata_index64 BO_metadata_remaining64',64);rng=z3.BitVec('BO_metadata_random32',32)
 at=resize(R.SECURITY,64)+4*ident;v.regions=[(at,2)];old=v.load(at,2)
 for name,value in [('x22',R.SECURITY),('x19',ident),('x20',left),('w21',0xdf00),('w0',rng)]:v.seed(name,value)
 v.enter('metadata_iteration');expected=(old&0xdf00)|z3.ZeroExt(15,z3.Extract(0,0,rng))<<13|((old+z3.ZeroExt(14,z3.Extract(2,1,rng)))&0xff)
 domain=[z3.UGE(ident,1),z3.ULE(ident,689),z3.UGE(left,1),z3.ULE(left,689)]
 prove('one_metadata_iteration_exact_low16_entropy_update',v,v.load(at,2)!=expected,domain)
 prove('one_metadata_iteration_advances_index_and_decrements_count',v,z3.Or(v.read('x19')!=ident+1,v.read('x20')!=left-1,
  v.next!=z3.If(left==1,resize(0xfffffe000c632040,64),resize(0xfffffe000c632010,64))),domain)
 v=local();base,index=z3.BitVecs('BO_descriptor_base64 BO_descriptor_index64',64);v.seed('x22',base);v.seed('x21',index);v.enter('descriptor_address')
 prove('descriptor_address_is_base_plus48_times_index_modulo_u64',v,v.read('x19')!=base+48*index)
 v=local();base=z3.BitVec('BO_descriptor64',64);v.regions=[(base,48)];v.seed('x19',base);v.seed('x24',17);v.enter('descriptor_fields')
 prove('descriptor_fields_are_u32_zero_u64_zero_u64_seventeen',v,z3.Or(v.load(base+16,4)!=0,v.load(base+24,8)!=0,v.load(base+32,8)!=17))
 v=local();base=z3.BitVec('BO_direct_descriptor64',64);v.seed('x19',base);v.enter('direct_descriptor_request')
 prove('direct_descriptor_helper_receives_descriptor_and16',v,z3.Or(v.read('x0')!=base,v.read('w1')!=16,v.next!=0xfffffe000be57bec))
 for phase in [6,7]:
  v=local();v.enter('request_phase'+str(phase));prove('caller_requests_original_dispatch_phase'+str(phase),v,z3.Or(v.read('w0')!=phase,v.next!=R.DISPATCH))
 v=local();v.regions=[(CPU.MEMORY,8)];word=v.load(CPU.MEMORY,8);v.enter('feature_high_word')
 prove('feature_load_is_high_u32_of_same_sane_size_word',v,z3.Or(v.read('w9')!=z3.Extract(63,32,word),
  v.next!=z3.If(z3.ULT(word,resize(1<<32,64)),resize(0xfffffe000c631ff8,64),resize(0xfffffe000c632198,64))))
 v.enter('caller_memory_read');prove('later_caller_load_uses_full_same_u64_in_unchanged_memory_epoch',v,v.read('x8')!=word)
 # Reconstruct and re-solve the retained instruction-derived comparator and
 # dispatcher certificates. This does not assume sort stability for ties.
 from recover_startup_dispatch import prove as prior_prove
 from verify_daemon_second_mix_publication import canonical_expression
 retained=json.loads(read(ROOT/'startup_dispatch_checks.json'));fresh,_=prior_prove({'spans':retained['spans']});prior=[]
 for label,p in retained['proofs'].items():
  a,b=z3.parse_smt2_string(p['query']),z3.parse_smt2_string(fresh[label]['query']);assert len(a)==len(b)>0
  assert all(canonical_expression(x)==canonical_expression(y) for x,y in zip(a,b))
  s=z3.Solver();s.set(timeout=30000);s.add(*a);assert s.check()==z3.unsat
  prior.append({'label':label,**p,'source_artifact_sha256':sha(ROOT/'startup_dispatch_checks.json')})
 separations=[]
 for p in json.loads(read(ROOT/'kernel_zone_bitmap_release_audit.json'))['rechecked_separation_lemmas']:
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
  separations.append({'label':p['label'],'query':p['query'],'result':'unsat','source_artifact_sha256':sha(ROOT/'kernel_zone_bitmap_release_audit.json')})
 graph=caller_cfg(e);assert graph['every_normal_return_visits_policy_dispatch6_dispatch7'];mutant=caller_cfg(e,0xfffffe000c634f1c)
 assert not mutant['every_normal_return_visits_policy_dispatch6_dispatch7']
 table,order,sort=CPU.sorted_table();image=Image();components=[];replays=[];totals=Counter()
 for c in CPU.cases():
  row=CPU.Probe(image,c,table,order).run();row['independent_oracle_checks']=CPU.oracle(row,order);components.append(row)
  r=Replay(image,row).run();replays.append(r);totals.update(r)
 negative=[]
 for case,pc in [(0,0xfffffe000c632030),(1,0xfffffe000c632160),(0,0xfffffe000c632084),(0,0xfffffe000c635050)]:
  row=CPU.Probe(image,CPU.cases()[case],table,order,pc).run()
  try:CPU.oracle(row,order)
  except AssertionError as err:negative.append({'component':row,'oracle_rejection':err.args[0][0]})
  else:raise AssertionError('changed source accepted')
 source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={i['pc'] for c in components for i in c['source_visits']}
 proved={pc for row in coverage for pc in row['PCs']};assert proved=={i['ea'] for row in e['spans'] for i in row['instructions']}
 independent={'source_queries_unsat':len(proofs),'prior_source_queries_reconstructed_and_rechecked':len(prior),'rechecked_separation_lemmas_unsat':len(separations),
  'proved_source_PCs':len(proved),'proof_instruction_instances':sum(r['instruction_instances'] for r in coverage),
  'linked_edge_obligations':sum(r['linked_edge_obligations'] for r in coverage),'checked_read_store_rewrites':sum(len(r['checked_read_store_rewrites']) for r in coverage),
  'components':len(components),'component_source_visits':sum(len(r['source_visits']) for r in components),'executed_source_PCs':len(visited&source),
  'independent_oracle_checks':sum(len(r['independent_oracle_checks']) for r in components),'changed_source_controls':len(negative),'changed_CFG_controls':1,
  'registered_callback_return_models':sum(sum(e['kind']=='registered_callback' for e in r['sequence_events']) for r in components)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_zone_boot_order.py'),
  'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':R.SCOPE,
  'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'rechecked_separation_lemmas':separations,'coverage':coverage,'caller_CFG':graph,
  'changed_CFG_control':{'policy_call_replaced_with_NOP':'0xfffffe000c634f1c','certificate':mutant},
  'original_source_sort':sort,'sorted_record_order':order,'components':components,'independent_replays':replays,'independent_replay_totals':dict(totals),
  'negative_controls':negative,'unexecuted_source_PCs':sorted(source-visited),'independent_totals':independent,
  'conditional_kernel_zone_boot_order_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
