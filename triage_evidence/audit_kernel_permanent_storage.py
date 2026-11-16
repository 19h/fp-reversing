#!/usr/bin/env python3
"""Source-bitvector obligations, semantic oracles and fresh CPU replay.
O(source + formula DAG + visits + journals + mapped state) construction/space;
SMT search separate,30 s/query. Native backing/refill/ownership unproved.
"""
import json
from collections import Counter
import z3
from capstone.arm64 import ARM64_EXT_UXTH
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_zone_boot_inputs import Model as Parent,DEC
from lskd_values_symbolic import resize
from probe_kernel_vm_mig import P
import recover_kernel_permanent_storage as R
import recover_kernel_magazine_bootstrap as M
import probe_kernel_permanent_storage as CPU
from replay_kernel_permanent_storage import Replay

class Model(Parent):
 def operand(self,i,o,n):
  if o.ext==ARM64_EXT_UXTH:return resize(self.read(i.reg_name(o.reg))&0xffff,n)
  return super().operand(i,o,n)
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic not in ['sbfiz','mrs']:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1;o=i.operands
   if i.mnemonic=='mrs':assert i.op_str=='x9, tpidr_el1';self.write('x9',self.thread)
   else:
    n=self.width(i.reg_name(o[0].reg));width=o[3].imm;value=z3.Extract(width-1,0,self.read(i.reg_name(o[1].reg)))
    self.write(i.reg_name(o[0].reg),z3.SignExt(n-width,value)<<o[2].imm)
  return self

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,label,a,b):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16)
  v.e=v.c={'spans':[{'label':label,'start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.enter(label)
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks),'checked_read_store_rewrites':list(v.separation_rewrites.values())});print(label,flush=True)
 v=local();request,mask=z3.BitVecs('PS_request64 PS_alignment_mask64',64);zone=z3.BitVec('PS_round_zone64',64);v.seed('x0',zone);v.seed('x1',request);v.seed('x2',mask);v.enter('round_request')
 prove('request_rounding_is_modular_size_plus_mask_and_not_mask',v,z3.Or(v.read('x23')!=((request+mask)&~mask),v.read('x24')!=~mask,v.read('x19')!=zone))
 v=local();v.regions=[(R.ZONE,192)];index=v.load(R.ZONE+0x9c,4);v.seed('x19',R.ZONE);cut(v,'head_gate',0xfffffe000bd71a68,0xfffffe000bd71a70)
 prove('zero_ready_head_requests_original_refill',v,z3.Or(v.read('x21')!=z3.ZeroExt(32,index),v.next!=z3.If(index==0,resize(0xfffffe000bd71a5c,64),resize(0xfffffe000bd71a70,64))))
 v=local();base=z3.BitVec('PS_metadata64',64);index=z3.BitVec('PS_index32',32);q=z3.BitVec('PS_rounded64',64);record=base+16*z3.ZeroExt(32,index)
 v.regions=[(R.METABASE,8),(record,16)];v.setmem(R.METABASE,8,base);off=v.load(record+4,4);v.seed('x22',0xfffffe0007e66000);v.seed('w21',index);v.seed('x23',q)
 cut(v,'candidate_fit',0xfffffe000bd71a70,0xfffffe000bd71a88);total=q+z3.ZeroExt(32,off)
 prove('candidate_fit_uses_unsigned_mod64_sum_and_16384_inclusive_limit',v,z3.Or(v.read('x1')!=record,v.read('x9')!=z3.ZeroExt(32,off),v.next!=z3.If(z3.ULE(total,16384),resize(0xfffffe000bd71a94,64),resize(0xfffffe000bd71a88,64))))
 v=local();record=z3.BitVec('PS_next_record64',64);v.regions=[(record,16)];nxt=v.load(record+8,4);v.seed('x1',record);cut(v,'next_candidate',0xfffffe000bd71a88,0xfffffe000bd71a90)
 prove('nonfitting_candidate_advances_by_stored_next_or_falls_to_refill',v,z3.Or(v.read('x21')!=z3.ZeroExt(32,nxt),v.next!=z3.If(nxt!=0,resize(0xfffffe000bd71a74,64),resize(0xfffffe000bd71a90,64))))
 v=local();record=CPU.META;thread=P+0x10000+0x1000;statistics=P+0x50000;payload=CPU.PAGE;byte=z3.BitVec('PS_payload_offset64',64)
 v.regions=[(R.ZONE,192),(record,16),(thread,512),(statistics,16),(payload,16384)]
 v.thread=resize(thread,64);v.setmem(R.ZONE+8,8,statistics);v.setmem(thread+0x1b8,2,0)
 old_used=v.load(record+2,2);free=v.load(R.ZONE+0xa8,4);old_stats=v.load(statistics,8);old_payload=v.load(payload+byte,1)
 q,mask,off=z3.BitVecs('PS_debit_size64 PS_debit_mask64 PS_debit_offset64',64);aligned=(off+mask)&~mask
 v.seed('x1',record);v.seed('x19',R.ZONE);v.seed('x20',mask);v.seed('x24',~mask);v.seed('x23',q);v.seed('x9',off);v.enter('debit_page')
 prove('debit_updates_metadata_free_statistics_and_preserves_every_disjoint_payload_byte',v,z3.Or(v.read('x20')!=aligned,
  v.load(record+4,4)!=z3.ZeroExt(16,z3.Extract(15,0,aligned+q)),v.load(record+2,2)!=old_used+z3.Extract(15,0,q),
  v.load(R.ZONE+0xa8,4)!=free-z3.Extract(31,0,q),v.load(statistics,8)!=old_stats+q,v.load(payload+byte,1)!=old_payload),[z3.ULT(byte,16384)])
 v=local();record=z3.BitVec('PS_full_record64',64);v.regions=[(record,16)];used=v.load(record+2,2);v.seed('x1',record);v.enter('full_gate')
 prove('full_queue_transition_threshold_is_unsigned_used_at_least16376',v,v.next!=z3.If(z3.ULT(used,16376),resize(0xfffffe000bd71bd8,64),resize(0xfffffe000bd71aec,64)))
 v=local();index=z3.BitVec('PS_return_index32',32);offset=z3.BitVec('PS_return_aligned64',64);v.seed('w21',index);v.seed('x20',offset);v.enter('return_pointer')
 prove('return_is_signed32_page_index_shift14_plus_low16_aligned_offset',v,v.read('x0')!=((z3.SignExt(32,index)<<14)+z3.ZeroExt(48,z3.Extract(15,0,offset))))
 for j,label in enumerate(['setup1','setup2']):
  v=local();zone=z3.BitVec('PS_'+label+'_zone64',64);v.regions=[(zone,192)];flags=v.load(zone+0x3c,4);ret=v.read('x30');v.seed('x1',zone);v.enter(label)
  prove(label+'_exact_flag100_extent1_and_original_return',v,z3.Or(v.load(zone+0x3c,4)!=(flags|0x100),v.load(zone+0x34,2)!=1,v.next!=ret))
 for label,n,mask in [('creator_statistics_request',32,7),('cache_storage_request',64,63)]:
  v=local();v.enter(label);prove(label+'_exact_slot2_size_alignment_mask_ABI',v,z3.Or(v.read('x0')!=R.ZONE,v.read('x1')!=n,v.read('x2')!=mask,v.next!=R.ALLOC))
 for j,label in enumerate(['fixed1_request','fixed2_request']):
  v=local();v.enter(label);prove(label+'_exact_name_extent_flags_ID_setup_record',v,z3.Or(v.read('x0')!=[0xfffffe000705352d,0xfffffe000705353a][j],v.read('x1')!=1,
   v.read('x2')!=[0xe000000044000020,0xe000000045000020][j],v.read('x3')!=j+1,v.read('x4')!=R.RECORDS[j],v.next!=M.CREATE))
 v=local();cache=z3.BitVec('PS_cache64',64);v.regions=[(cache,64)];counts=v.load(cache+4,4);v.seed('x24',cache);v.enter('cache_control_stores')
 prove('cache_vector_list_and_lock_stores_preserve_both_u16_magazine_counts',v,v.load(cache+4,4)!=counts)
 separations=[]
 for p in json.loads(read(ROOT/'kernel_zone_bitmap_release_audit.json'))['rechecked_separation_lemmas']:
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
  separations.append({'label':p['label'],'query':p['query'],'result':'unsat','source_artifact_sha256':sha(ROOT/'kernel_zone_bitmap_release_audit.json')})
 image=Image();components=[];replays=[];totals=Counter()
 def component(mode,c,parent=None):
  row=CPU.Probe(image,mode,c,parent).run();row['independent_oracle_checks']=CPU.oracle(row,parent);components.append(row);r=Replay(image,row,parent).run();replays.append(r);totals.update(r);return row
 for c in CPU.cases():component('direct',c)
 for j in range(2):component('setup',{'setup':j})
 for capacity,count in [(8,1),(10,2),(14,3)]:
  parent_index=len(components);row=component('publish',{'capacity':capacity,'count':count,'cpu':count-1});component('cache',{'cpu':count-1,'publication_component':parent_index},row)
 negative=[]
 for mode,c,parent,pc in [('direct',CPU.cases()[0],None,0xfffffe000bd71aa4),('setup',{'setup':0},None,0xfffffe000bd77cf8),
  ('cache',{'cpu':0},components[15],0xfffffe000bd77cb4)]:
  row=CPU.Probe(image,mode,c,parent,pc).run()
  try:CPU.oracle(row,parent)
  except AssertionError as error:negative.append({'component':row,'oracle_rejection':error.args[0][0]})
  else:raise AssertionError('changed source accepted')
 source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={i['pc'] for c in components for i in c['source_visits']}
 stats={'source_queries_unsat':len(proofs),'rechecked_separation_lemmas_unsat':len(separations),'components':len(components),
  'component_source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(source&visited),
  'proved_source_PCs':len({p for c in coverage for p in c['PCs']}),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),
  'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'checked_read_store_rewrites':sum(len(c['checked_read_store_rewrites']) for c in coverage),
  'independent_oracle_checks':sum(len(c['independent_oracle_checks']) for c in components),'changed_source_controls':len(negative),
  'original_permanent_entries':sum(sum(e['kind']=='permanent_entry' for e in c['permanent_events']) for c in components)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_permanent_storage.py'),
  'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],
  'source_proofs':proofs,'rechecked_separation_lemmas':separations,'coverage':coverage,'components':components,'independent_replays':replays,
  'independent_replay_totals':dict(totals),'negative_controls':negative,'unexecuted_source_PCs':sorted(source-visited),'independent_totals':stats,
  'conditional_kernel_permanent_storage_contract_established':True,**{k:False for k in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
