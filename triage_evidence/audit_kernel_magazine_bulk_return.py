#!/usr/bin/env python3
"""Bulk instruction certificates, full-state oracle and fill roundtrips.
O(source instances + formula DAG + component journals/RAM) construction
and space; SMT search separate, 30 s/query. No target/IDB effects.
"""
import copy,json
import z3
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import resize
from audit_kernel_zone_bitmap_release import Model as Parent,DEC
import recover_kernel_magazine_bulk_return as R
import probe_kernel_magazine_bulk_return as CPU

class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.op_str!='w13, [x12, #4]!':
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
   at=self.address(i,i.operands[1]);self.write('w13',self.load(at,4));self.write('x12',at)
  return self

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs=[];coverage=[]
 def local():
  v=Model(e);v.metadata=z3.BitVec('BK_metadata64',64);v.regions=[(v.zone,192),(v.metadata,16)]
  v.seed('x0',v.zone);v.seed('x8',v.metadata);return v
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(c) for c in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));r=s.check();assert r==z3.sat,('vacuous',label,r)
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,r,s.reason_unknown())
  proofs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV','query':s.to_smt2()})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,
   'linked_edge_obligations':len(v.edge_checks),'checked_read_store_rewrites':list(v.separation_rewrites.values())})
  print(label,flush=True)
 v=local();array,index=z3.BitVecs('BK_array64 BK_slot_index64',64);slot=array+(index<<3);v.regions.append((slot,8));old=v.load(slot,8)
 v.seed('x2',array);v.seed('x20',index);v.enter('slot')
 prove('slot_pointer_is_read_then_cleared_before_validation',v,z3.Or(v.read('x9')!=old,v.load(slot,8)!=0))
 v=local();lo,hi,pointer=z3.BitVecs('BK_lower64 BK_upper64 BK_pointer64',64);v.regions.append((0xfffffe0007e66e50,16))
 v.setmem(0xfffffe0007e66e50,8,lo);v.setmem(0xfffffe0007e66e58,8,hi);v.seed('x26',0xfffffe0007e66e50);v.seed('x9',pointer);v.enter('range')
 prove('unsigned_half_open_pointer_range',v,v.next!=z3.If(z3.And(z3.UGE(pointer,lo),z3.ULT(pointer,hi)),resize(0xfffffe000bd74c74,64),resize(0xfffffe000bd74fa4,64)))
 v=local();root,pointer=z3.BitVecs('BK_root64 BK_owner_pointer64',64);meta=root+(z3.LShR(pointer,10)&0xffffffff0)
 v.regions[-1]=(meta,16);v.regions.append((0xfffffe0007e66f00,8));v.setmem(0xfffffe0007e66f00,8,root)
 header=v.load(meta,2);v.seed('x26',0xfffffe0007e66e50);v.seed('x28',0xfffffe000caeb480);v.seed('x9',pointer);v.enter('owner')
 owner=resize(0xfffffe000caeb480,64)+192*z3.ZeroExt(48,header&0x3ff)
 prove('metadata_low10_zone_identity_before_displacement',v,z3.Or(v.read('x8')!=meta,v.next!=z3.If(owner==v.zone,resize(0xfffffe000bd74c9c,64),resize(0xfffffe000bd74fa4,64))))
 v=local();disp=z3.BitVec('BK_before_extended_displacement64',64);extra=v.load(v.metadata+2,1);v.seed('x11',disp);v.enter('extended');lead=v.metadata-(z3.ZeroExt(56,extra)<<4)
 tagged=((v.metadata^lead)&0xffc0000000000000)!=0
 prove('extended_displacement_and_leading_metadata_tag_gate',v,z3.Or(v.read('x11')!=disp+(z3.ZeroExt(56,extra)<<14),v.read('x13')!=lead,
  v.next!=z3.If(tagged,resize(0xfffffe000bd74cd4,64),resize(0xfffffe000bd74cd8,64))))
 for tag in [False,True]:
  w=copy.deepcopy(v)
  if tag:w.run('extended_tag')
  w.run('extended_join');expected=(lead&0xffffffffffff)|0xc8a2000000000000 if tag else lead
  prove(('changed' if tag else 'preserved')+'_extended_leading_metadata_address',w,w.read('x8')!=expected,[tagged if tag else z3.Not(tagged)])
 v=local();disp=z3.BitVec('BK_displacement64',64);extent=z3.BitVec('BK_extent16',16);v.seed('x11',disp);v.seed('w10',extent);multiplier=v.load(v.zone+0x28,8);v.enter('quotient')
 product=multiplier*disp;index=z3.Extract(63,32,product);matches=z3.ZeroExt(32,index)*z3.ZeroExt(48,extent)==disp
 prove('full_displacement_reciprocal_extent_gate',v,z3.Or(v.read('x12')!=product,v.read('w13')!=index,v.next!=z3.If(matches,resize(0xfffffe000bd74cf4,64),resize(0xfffffe000bd74fa4,64))))
 v=local();header=v.load(v.metadata,2);v.enter('layout')
 prove('metadata_bit11_selects_inline_layout',v,v.next!=z3.If((header&0x800)!=0,resize(0xfffffe000bd74d2c,64),resize(0xfffffe000bd74cfc,64)))
 for inline in [False,True]:
  v=local();product=z3.BitVec('BK_'+str(inline)+'_product64',64);index=z3.Extract(63,32,product)
  v.seed('x12',product);v.seed('w13',index);v.seed('x19',1)
  if inline:
   v.regions[-1]=(v.metadata,0x80000000);at=v.metadata+(z3.LShR(product,37)<<4)+4;mask=resize(1,32)<<(index&31);width=4
  else:
   base=z3.BitVec('BK_external_bitmap64',64);v.regions.append((0xfffffe0007e66e70,8));v.setmem(0xfffffe0007e66e70,8,base)
   v.seed('x17',0xfffffe0007e66000);offset=v.load(v.metadata+4,4)&0xfffffff
   at=base+(z3.ZeroExt(32,offset)<<3)+(z3.LShR(product,38)<<3);mask=resize(1,64)<<(z3.ZeroExt(32,index)&63);width=8;v.regions.append((at,8))
  word=v.load(at,width);v.enter(('inline' if inline else 'external')+'_gate');setbit=(word&mask)!=0
  success=0xfffffe000bd74d44 if inline else 0xfffffe000bd74d20
  prove(('inline32' if inline else 'external64')+'_exact_word_bit_and_already_free_gate',v,v.next!=z3.If(setbit,resize(0xfffffe000bd74fb4,64),resize(success,64)))
  v.run(('inline' if inline else 'external')+'_set')
  prove(('inline32' if inline else 'external64')+'_clear_bit_becomes_set',v,v.load(at,width)!=(word^mask),[z3.Not(setbit)])
 v=local();old=v.load(v.metadata+2,2);v.enter('count')
 prove('u16_count_decrement_precedes_underflow_diagnostic',v,z3.Or(v.load(v.metadata+2,2)!=old-1,v.next!=z3.If(old==0,resize(0xfffffe000bd74fbc,64),resize(0xfffffe000bd74d60,64))))
 v=local();count=z3.BitVec('BK_decremented_count32',32);v.seed('w11',count);v.enter('zero')
 prove('empty_metadata_branch_uses_low16_decremented_count',v,v.next!=z3.If((count&0xffff)==0,resize(0xfffffe000bd74de8,64),resize(0xfffffe000bd74d68,64)))
 v=local();old=z3.BitVec('BK_threshold_old_count32',32);extent=z3.BitVec('BK_threshold_extent32',32);header=v.load(v.metadata,2);v.seed('w9',old);v.seed('w10',extent);v.enter('threshold')
 amount=z3.ZeroExt(32,extent)*(z3.ZeroExt(32,old&0x7fff)+1);span=(z3.ZeroExt(48,header)<<2)&0x3c000
 prove('partial_queue_transition_uses_masked_old_count_plus_one_extent',v,v.next!=z3.If(z3.ULE(amount,span),resize(0xfffffe000bd74ec8,64),resize(0xfffffe000bd74d84,64)))
 v=local();flags=v.load(v.zone+0x3c,1);v.enter('follow_gate')
 prove('each_processed_object_reloads_followup_bit4',v,v.next!=z3.If((flags&16)!=0,resize(0xfffffe000bd74f54,64),resize(0xfffffe000bd74ed0,64)))
 v=local();index=z3.BitVec('BK_loop_index64',64);remaining=z3.BitVec('BK_loop_remaining32',32);v.seed('x20',index);v.seed('w27',remaining);v.enter('loop')
 prove('loop_increments_slot_index_and_decrements_remaining_count',v,z3.Or(v.read('x20')!=index+1,v.read('w27')!=remaining-1,
  v.next!=z3.If(remaining!=1,resize(0xfffffe000bd74c5c,64),resize(0xfffffe000bd74edc,64))))
 v=local();v.enter('loop_exit');prove('last_slot_joins_completion_accounting',v,v.next!=0xfffffe000bd74f78)
 v=local();count=z3.BitVec('BK_saved_original_count32',32);array,head=z3.BitVecs('BK_saved_array64 BK_saved_empty_head64',64);v.seed('w1',count);v.seed('x2',array);v.seed('x15',head);v.enter('follow_save')
 prove('followup_saves_zone_original_count_array_and_empty_head',v,z3.Or(v.load(v.sp0+0x18,8)!=v.zone,v.load(v.sp0+0x14,4)!=count,
  v.load(v.sp0,8)!=head,v.load(v.sp0+8,8)!=array,v.next!=R.FOLLOW,v.read('x30')!=0xfffffe000bd74f64))
 v=local();count=z3.BitVec('BK_restored_original_count32',32);array,head=z3.BitVecs('BK_restored_array64 BK_restored_empty_head64',64)
 v.setmem(v.sp0+0x18,8,v.zone);v.setmem(v.sp0+0x14,4,count);v.setmem(v.sp0,8,head);v.setmem(v.sp0+8,8,array);v.enter('follow_restore')
 prove('ordinary_followup_return_restores_volatile_bulk_inputs',v,z3.Or(v.read('x0')!=v.zone,v.read('x1')!=z3.ZeroExt(32,count),v.read('x2')!=array,v.read('x15')!=head,v.next!=0xfffffe000bd74ed0))
 v=local();old=v.load(v.zone+0xa8,4);count=z3.BitVec('BK_completion_original_count32',32);v.seed('w1',count);v.enter('available')
 prove('completion_adds_original_count_modulo_u32',v,v.load(v.zone+0xa8,4)!=old+count)
 return finish(e,proofs,coverage)

def finish(e,proofs,coverage):
 from kernel_vm_mig_tools import Image
 from replay_kernel_zone_refill import Replay
 separations=[]
 for p in json.loads(read(ROOT/'kernel_zone_bitmap_release_audit.json'))['rechecked_separation_lemmas']:
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
  separations.append({'label':p['label'],'query':p['query'],'result':'unsat','source_artifact_sha256':sha(ROOT/'kernel_zone_bitmap_release_audit.json')})
 image=Image();parent=json.loads(read(ROOT/'kernel_zone_startup_profiles.json'))['cases'][7]
 producers={used:CPU.produce(image,parent,used) for used in [16,63]};producer_replays=[];components=[]
 for used,p in producers.items():producer_replays.append({'before_fill_used':used,'checks':Replay(image,p).run()})
 for c in CPU.configurations():
  row=CPU.Probe(image,parent,c,producers.get(c.get('producer_used'))).run();row['independent_oracle_checks']=CPU.oracle(row);components.append(row)
 negative=[]
 for pc in [0xfffffe000bd74c60,0xfffffe000bd74f80]:
  row=CPU.Probe(image,parent,{'n':1,'count':2},mutate=pc).run()
  try:CPU.oracle(row)
  except AssertionError as failure:negative.append({'component':row,'oracle_rejection':failure.args[0][0]})
  else:raise AssertionError('altered bulk store accepted')
 source={i['ea'] for i in e['functions'][0]['instructions']};visits={v['pc'] for c in components for v in c['source_visits']};proved={p for c in coverage for p in c['PCs']}
 assert proved=={i['ea'] for s in e['spans'] for i in s['instructions']}
 totals={'source_queries_unsat':len(proofs),'rechecked_separation_lemmas_unsat':len(separations),'proved_source_PCs':len(proved),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),
  'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'checked_read_store_rewrites':sum(len(c['checked_read_store_rewrites']) for c in coverage),
  'components':len(components),'component_source_visits':sum(len(c['source_visits']) for c in components),'bulk_component_PCs':len(source&visits),
  'unexecuted_bulk_PCs':len(source-visits),'source_fill_producers':len(producers),'source_produced_roundtrip_components':sum(c['source_producer'] is not None for c in components),
  'independent_oracle_checks':sum(len(c['independent_oracle_checks']) for c in components),'changed_source_controls':len(negative)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':R.SCOPE,
  'source_proofs':proofs,'rechecked_separation_lemmas':separations,'producer_independent_replays':producer_replays,
  'coverage':coverage,'components':components,'negative_controls':negative,
  'unexecuted_bulk_PCs':sorted(source-visits),'independent_totals':totals,
  'conditional_kernel_magazine_bulk_return_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
