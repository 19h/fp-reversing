#!/usr/bin/env python3
"""Paired observer ABI, flag, geometry, hash and caller-custody obligations.
O(instruction instances + formula DAG + component RAM/journals) construction
and space; SMT search separate, 30 s/query. No native target/IDB effects.
"""
import json
import z3
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import resize
from audit_kernel_zone_bitmap_release import Model as Parent,DEC
import recover_kernel_zone_observer_event as R
import probe_kernel_zone_observer_event as CPU

class Model(Parent):
 def __init__(self,e):
  super().__init__(e);self.branch_auth=z3.Function('OE_uninterpreted_BLRAA',z3.BitVecSort(64),z3.BitVecSort(64),z3.BitVecSort(64))
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic!='blraa':
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.pc=i.address;self.visited.add(i.address);self.count+=1;self.seed('x30',i.address+4);self.call_return=i.address+4
   self.next=self.branch_auth(self.read('x8'),self.read('x17'))
   self.authentication_envelopes.append({'pc':hex(i.address),'instruction':'blraa','uninterpreted_target':True})
  return self

def hash_expression(event,count,base):
 a=(event^z3.LShR(event,31))*0x7fb5d329728ea185;b=(a^z3.LShR(a,27))*0x81dadef4bc2dd44d
 index=z3.Extract(31,0,b^z3.LShR(b,33))&(count-1);offset=z3.ZeroExt(32,index)*24
 ordinary=offset==z3.SignExt(32,z3.Extract(31,0,offset));address=base+offset
 return z3.If(ordinary,address,(address&0xffffffffffff)|0x2bad000000000000),index,offset

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs=[];coverage=[]
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(c) for c in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));r=s.check();assert r==z3.sat,('vacuous',label,r)
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,r,s.reason_unknown())
  proofs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV','query':s.to_smt2()})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks),
   'checked_read_store_rewrites':list(v.separation_rewrites.values()),'authentication_envelopes':v.authentication_envelopes})
  print(label,flush=True)
 def local():
  v=Model(e);v.regions.append((v.zone,192));v.seed('x0',v.zone);v.seed('x19',v.zone);return v
 v=local();flag=v.load(v.zone+0x3c,1);v.enter('arm_flag')
 prove('arm_existing_flag_bypasses_observers_but_not_wait_request',v,v.next!=z3.If((flag&16)!=0,resize(0xfffffe000bd73408,64),resize(0xfffffe000bd73388,64)))
 for name in ['arm_set','follow_clear']:
  v=local();flag=v.load(v.zone+0x3c,4);v.enter(name);expected=flag|16 if name=='arm_set' else flag&0xffffffef
  prove(name+'_changes_only_bit4_in_full_u32_word',v,v.load(v.zone+0x3c,4)!=expected)
 for name in ['arm','follow']:
  v=local();v.enter(name+'_geometry');delta=v.zone-R.BASE
  success=0xfffffe000bd733d8 if name=='arm' else 0xfffffe000bd75b9c
  failure=0xfffffe000bd73450 if name=='arm' else 0xfffffe000bd75c5c
  admit=z3.ULT(delta,132480)
  prove(name+'_observer_geometry_guard_is_exact_unsigned_132480_byte_interval',v,z3.Or(v.read('x8')!=delta,v.next!=z3.If(admit,resize(success,64),resize(failure,64))))
  v.run(name+'_id');quotient=z3.LShR(delta*0x1555556,32)
  prove(name+'_all_delta64_exact_reciprocal_callback_index',v,v.read('x21')!=quotient,[admit])
 for name in ['arm','follow']:
  v=local();node=z3.BitVec('OE_'+name+'_observer_node64',64);index=z3.BitVec('OE_'+name+'_zone_index64',64)
  v.regions.append((node,16));v.seed('x20',node);v.seed('x21',index);pointer=v.load(node+8,8);v.enter(name+'_callback')
  callpc=0xfffffe000bd733fc if name=='arm' else 0xfffffe000bd75bc0
  prove(name+'_authenticated_observer_raw_pointer_modifier_arguments_and_LR',v,z3.Or(
   v.read('x8')!=pointer,v.read('x0')!=(index&0xffff),v.read('x1')!=v.zone,v.read('x2')!=int(name=='arm'),
   v.read('x17')!=0xeed9,v.read('x30')!=callpc+4,v.next!=v.branch_auth(pointer,resize(0xeed9,64))))
  v=local();node=z3.BitVec('OE_'+name+'_postcallback_node64',64);v.regions.append((node,16));v.seed('x20',node)
  successor=v.load(node,8);v.enter(name+'_next')
  again=0xfffffe000bd733e8 if name=='arm' else 0xfffffe000bd75bac
  exitpc=0xfffffe000bd73408 if name=='arm' else 0xfffffe000bd75bcc
  prove(name+'_postcallback_memory_supplies_next_pointer_and_loop_gate',v,z3.Or(v.read('x20')!=successor,
   v.next!=z3.If(successor!=0,resize(again,64),resize(exitpc,64))))
 v=local();v.enter('arm_wait');prove('arm_requests_assert_wait_on_zone_plus32_with_raw_control8',v,z3.Or(
  v.read('x0')!=v.zone+32,v.read('x1')!=8,v.next!=0xfffffe000bd28394))
 v=local();v.enter('arm_block');prove('ordinary_registration_return_is_followed_by_zero_argument_block_request',v,z3.Or(
  v.read('x0')!=0,v.read('x1')!=0,v.read('x2')!=0,v.next!=0xfffffe000bd28f6c))
 v=local();v.regions.append((R.OBSERVER,8));root=v.load(resize(R.OBSERVER,64),8);v.enter('follow_root')
 prove('follow_reads_file_root_slot_once_and_zero_bypasses_geometry_callbacks',v,z3.Or(v.read('x20')!=root,
  v.next!=z3.If(root==0,resize(0xfffffe000bd75bcc,64),resize(0xfffffe000bd75b84,64))))
 hashes=[]
 for name in ['follow','wait']:
  v=local();base=z3.BitVec('OE_shared_table_base64',64);count=z3.BitVec('OE_shared_table_count32',32);event=v.zone+32
  v.regions.extend([(0xfffffe0007e66df8,8),(0xfffffe0007e66e00,4)])
  v.setmem(0xfffffe0007e66df8,8,base);v.setmem(0xfffffe0007e66e00,4,count)
  if name=='wait':v.seed('x20',event);v.seed('x19',8)
  v.enter(name+'_hash');expected,index,offset=hash_expression(event,count,base)
  prove(name+'_all_table_count32_exact_shared_hash_event_and_tagged_address',v,z3.Or(
   v.read('x0')!=expected,v.read('x1')!=event,v.read('x9')!=offset))
  hashes.append((v,expected))
 v=local();queue,event=z3.BitVecs('OE_tail_queue64 OE_tail_event64',64);v.seed('sp',v.sp0-48)
 for offset,j in [(0,22),(8,21),(16,20),(24,19),(32,29),(40,30)]:v.setmem(v.sp0-48+offset,8,v.initial[j])
 v.seed('x0',queue);v.seed('x1',event);v.enter('follow_tail')
 prove('follow_tail_restores_frame_and_GP_then_requests_wake_all_raw_zero',v,z3.Or(v.read('x0')!=queue,v.read('x1')!=event,
  v.read('x2')!=0,v.read('x3')!=0,v.read('w4')!=0xffffffff,v.read('sp')!=v.sp0,
  *[v.read('x'+str(j))!=v.initial[j] for j in [19,20,21,22,29,30]],v.next!=0xfffffe000bd6e22c))
 return finish(e,proofs,coverage,hashes)

def finish(e,proofs,coverage,hashes):
 compositions=[]
 delta=z3.Int('OE_admitted_zone_displacement_bytes');s=z3.Solver();s.set(timeout=30000)
 s.add(delta>=0,delta<132480,z3.Or(delta*0x1555556>=2**64,(delta*0x1555556)/(2**32)!=delta/192))
 assert s.check()==z3.unsat
 compositions.append({'label':'admitted_integer_displacement_reciprocal_equals_floor_by192_without_u64_overflow',
  'result':'unsat','logic':'QF_LIA','query':s.to_smt2()})
 s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000)
 s.add(hashes[0][1]!=hashes[1][1]);assert s.check()==z3.unsat
 compositions.append({'label':'paired_hash_contracts_join_under_identical_event_root_count_epoch','result':'unsat','logic':'QF_AUFBV','query':s.to_smt2()})
 prior=[]
 selection={
  'aes_event_registration_checks.json':['hash_queue_join','masked_index_bound','scaled_index_sign_fit','scaled_index_table_extent','zero_interruptibility_cannot_abort'],
  'aes_event_wake_selection_checks.json':['full_identity_comparison','full_event_comparison','full_match_conjunction','request_fields','selected_plus_more_return']}
 for path,names in selection.items():
  a=json.loads(read(ROOT/path))
  for name in names:
   p=a['proofs'][name];s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
   prior.append({'label':name,'source_artifact':path,'source_sha256':sha(ROOT/path),'result':'unsat'})
 separations=[]
 for p in json.loads(read(ROOT/'kernel_zone_bitmap_release_audit.json'))['rechecked_separation_lemmas']:
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
  separations.append({'label':p['label'],'result':'unsat','query':p['query'],'source_artifact_sha256':sha(ROOT/'kernel_zone_bitmap_release_audit.json')})
 from kernel_vm_mig_tools import Image
 image=Image();parent=json.loads(read(ROOT/'kernel_zone_startup_profiles.json'))['cases'][7];components=[]
 for c in CPU.configurations():
  row=CPU.Probe(image,parent,c).run();row['independent_oracle_checks']=CPU.oracle(row);components.append(row)
 negative=[]
 for mode,pc,flags in [('follow',0xfffffe000bd75b74,16),('arm',0xfffffe000bd73398,0)]:
  row=CPU.Probe(image,parent,{'mode':mode,'flags':flags},pc).run()
  try:CPU.oracle(row)
  except AssertionError as failure:
   assert failure.args[0][0]=='source_flag_update_and_declared_interference';negative.append({'component':row,'oracle_rejection':failure.args[0][0]})
  else:raise AssertionError('altered flag store accepted')
 proved={p for c in coverage for p in c['PCs']};selected={i['ea'] for s in e['spans'] for i in s['instructions']};assert proved==selected
 new_source={i['ea'] for f in e['functions'][:2] for i in f['instructions']};visits={v['pc'] for c in components for v in c['source_visits']}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':R.SCOPE,
  'source_proofs':proofs,'composition_proofs':compositions,'coverage':coverage,'rechecked_prior_proofs':prior,
  'rechecked_separation_lemmas':separations,'components':components,'negative_controls':negative,
  'unexecuted_new_source_PCs':sorted(new_source-visits),
  'independent_totals':{'source_queries_unsat':len(proofs),'composition_queries_unsat':len(compositions),
   'prior_queries_unsat':len(prior),'rechecked_separation_lemmas_unsat':len(separations),'proved_source_PCs':len(proved),
   'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),
   'checked_read_store_rewrites':sum(len(c['checked_read_store_rewrites']) for c in coverage),
   'components':len(components),'component_source_visits':sum(len(c['source_visits']) for c in components),
   'new_component_PCs':len(new_source&visits),'unexecuted_new_source_PCs':len(new_source-visits),
   'observer_requests':sum(len(c['observer_requests']) for c in components),
   'independent_oracle_checks':sum(len(c['independent_oracle_checks']) for c in components),'changed_store_controls':len(negative)},
  'conditional_kernel_zone_observer_event_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
