#!/usr/bin/env python3
"""Original-source bitvector obligations, private byte oracles and replay.
O(source + query DAG + visits + journals + RAM) construction/space; SMT
search separate,30 s/query. Hardware/cache/physical ownership unproved.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_permanent_storage import Model as Parent,DEC
from lskd_values_symbolic import resize
import recover_kernel_physical_zero as R
import probe_kernel_physical_zero as CPU
from replay_kernel_physical_zero import Replay

class Model(Parent):
 def __init__(self,e):super().__init__(e);self.dcs=[]
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic not in ['cset','dc']:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
   if i.mnemonic=='cset':
    pred=self.condition(i.op_str.split(',')[-1].strip());assert pred is not None
    self.write(i.reg_name(i.operands[0].reg),z3.If(pred,resize(1,32),resize(0,32)))
   else:
    assert i.op_str.startswith('zva, x');self.dcs.append({'pc':hex(i.address),'address':self.read(i.op_str[5:])&resize(~63,64)})
  return self

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,label,a,b,enter=True):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16)
  v.e=v.c={'spans':[{'label':label,'start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]}
  return v.enter(label) if enter else v.run(label)
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks),
   'checked_read_store_rewrites':list(v.separation_rewrites.values())});print(label,flush=True)
 v=local();obj,lower=z3.BitVecs('PZ_page_object64 PZ_object_lower64',64);base=z3.BitVec('PZ_base_PFN32',32)
 v.regions=[(0xfffffe0007ef8000,4)];v.setmem(0xfffffe0007ef8000,4,base);v.seed('x28',obj);v.seed('x8',lower)
 v.enter('refill_zero_request');pfn=z3.Extract(31,0,z3.LShR(obj-lower,6))+base
 prove('refill_in_interval_object_maps_to_low32_PFN_then_exact_16384_byte_zero_request',v,z3.Or(v.read('x0')!=(z3.ZeroExt(32,pfn)<<14),v.read('x1')!=16384,v.next!=R.ZERO))
 v=local();physical=z3.BitVec('PZ_physical64',64);lo,hi=z3.BitVecs('PZ_interval_lower64 PZ_interval_upper64',64)
 v.regions=[(R.LOWER,16)];v.setmem(R.LOWER,8,lo);v.setmem(R.UPPER,8,hi);v.seed('x20',physical);v.seed('x23',0xfffffe0007ef8000);v.seed('x24',0xfffffe0007ef8000)
 v.enter('range_gate');outside=z3.Or(z3.ULT(physical,lo),z3.UGE(physical,hi))
 prove('unsigned_half_open_direct_interval_and_PFN_cache_attribute_request',v,z3.Or(v.read('w25')!=z3.If(outside,resize(1,32),resize(0,32)),v.read('x0')!=z3.LShR(physical,14),v.next!=R.ATTR))
 v=local();index,cpu=z3.BitVecs('PZ_window_index32 PZ_CPU16',32);offset=z3.BitVec('PZ_page_offset64',64)
 v.seed('w21',index);v.seed('w27',cpu);v.seed('x26',offset);v.enter('window_alias')
 expected=resize(R.WINDOW_BASE,64)+offset+z3.ZeroExt(32,((index<<14)|(cpu<<16)))
 prove('window_alias_exact_base_and_disjoint_CPU_index_bit_fields',v,v.read('x0')!=expected,[z3.ULT(index,4),z3.ULT(cpu,65536),z3.ULT(offset,16384)])
 v=local();available,remaining=z3.BitVecs('PZ_available64 PZ_remaining64',64);v.setmem(v.sp0+0x28,8,available);v.seed('x19',remaining);v.enter('chunk_minimum')
 minimum=z3.If(z3.ULT(available,remaining),available,remaining)
 prove('chunk_is_unsigned_minimum_and_is_saved_for_range_progress',v,z3.Or(v.read('x2')!=minimum,v.load(v.sp0+0x28,8)!=minimum))
 v=local();attr=z3.BitVec('PZ_attributes32',32);v.seed('w22',attr);v.enter('attribute_limit')
 prove('attribute_dispatch_uses_low8_and_upper_limit22',v,z3.Or(v.read('w8')!=(attr&255),v.next!=z3.If(z3.UGT(attr&255,22),resize(0xfffffe000be7b958,64),resize(0xfffffe000be7b6cc,64))))
 v=local();value=z3.BitVec('PZ_attribute_low8_32',32);v.seed('w8',value);v.seed('w28',0x00440844);v.enter('attribute_mask');admit=z3.Or(*[value==j for j in [2,6,11,18,22]])
 prove('only_attributes2_6_11_18_22_admit_bzero_or_inline_DC',v,v.next!=z3.If(admit,resize(0xfffffe000be7b6dc,64),resize(0xfffffe000be7b958,64)),[z3.ULE(value,22)])
 v=local();chunk=z3.BitVec('PZ_chunk64',64);v.seed('x2',chunk);v.enter('full_page_gate')
 prove('inline_DC_path_requires_exact_16384_byte_chunk',v,v.next!=z3.If(chunk==16384,resize(0xfffffe000be7b6e4,64),resize(0xfffffe000be7b918,64)))
 for label,target in [('partial_bzero',R.BZERO),('fallback_memset',R.MEMSET)]:
  v=local();alias,chunk=z3.BitVecs('PZ_'+label+'_alias64 PZ_'+label+'_chunk64',64);v.seed('x0',alias);v.seed('x2',chunk);v.enter(label)
  prove(label+'_exact_original_clear_ABI',v,z3.Or(v.next!=target,v.read('x0')!=alias,v.read('x1')!=(chunk if target==R.BZERO else 0),v.read('x2')!=chunk))
 v=local();alias=z3.BitVec('PZ_inline_page_alias64',64);v.seed('x0',alias)
 cut(v,'inline_init',0xfffffe000be7b6e4,0xfffffe000be7b6f4)
 for j in range(4):cut(v,'inline_iteration',0xfffffe000be7b6f4,0xfffffe000be7b914,False)
 assert len(v.dcs)==256
 prove('inline_four_iterations_cover_each_64_byte_block_of_one_aligned_16384_byte_alias',v,
  z3.Or(v.next!=0xfffffe000be7b914,*[r['address']!=alias+64*j for j,r in enumerate(v.dcs)]),[(alias&16383)==0])
 separations=[]
 for p in json.loads(read(ROOT/'kernel_zone_bitmap_release_audit.json'))['rechecked_separation_lemmas']:
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
  separations.append({'label':p['label'],'query':p['query'],'result':'unsat','source_artifact_sha256':sha(ROOT/'kernel_zone_bitmap_release_audit.json')})
 image=Image();components=[];replays=[];totals=Counter()
 for c in CPU.cases():
  row=CPU.Probe(image,c).run();row['independent_oracle_checks']=CPU.oracle(row);components.append(row)
  r=Replay(image,row).run();replays.append(r);totals.update(r)
 negative=[]
 for j,pc in [(10,0xfffffe000be7b708),(45,0xfffffe000c64814c),(63,0xfffffe000c648200)]:
  row=CPU.Probe(image,CPU.cases()[j],pc).run()
  try:CPU.oracle(row)
  except AssertionError as error:negative.append({'component':row,'oracle_rejection':error.args[0][0]})
  else:raise AssertionError('changed source accepted')
 source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={i['pc'] for c in components for i in c['source_visits']}
 stats={'source_queries_unsat':len(proofs),'rechecked_separation_lemmas_unsat':len(separations),'components':len(components),
  'component_source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(source&visited),
  'proved_source_PCs':len({p for c in coverage for p in c['PCs']}),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),
  'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'checked_read_store_rewrites':sum(len(c['checked_read_store_rewrites']) for c in coverage),
  'independent_oracle_checks':sum(len(c['independent_oracle_checks']) for c in components),'changed_source_controls':len(negative),
  'logical_DC_ZVA_effects':sum(len(c['logical_DC_ZVA_effects']) for c in components)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_physical_zero.py'),
  'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],
  'source_proofs':proofs,'rechecked_separation_lemmas':separations,'coverage':coverage,'components':components,'independent_replays':replays,
  'independent_replay_totals':dict(totals),'negative_controls':negative,'unexecuted_source_PCs':sorted(source-visited),'independent_totals':stats,
  'logical_DC_model':{'granule_bytes':64,'effect':'Zero the operand-containing aligned64 B block in declared private RAM; no hardware DC or native physical translation.'},
  'conditional_kernel_physical_zero_contract_established':True,**{k:False for k in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
