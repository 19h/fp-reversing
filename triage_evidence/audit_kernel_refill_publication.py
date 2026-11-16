#!/usr/bin/env python3
"""Source block proofs, continuous refill witnesses and consumer epoch joins.
O(source + query DAG + visits + journals + RAM) construction/space; solver
search separate,30 s/query. Native mappings/ownership and full refill unknown.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_physical_zero import Model as Parent,DEC
from lskd_values_symbolic import resize
import recover_kernel_refill_publication as R
import recover_kernel_physical_zero as Z
import recover_kernel_permanent_storage as PS
import probe_kernel_refill_publication as CPU
import probe_kernel_permanent_storage as Consumers
from replay_kernel_refill_publication import Replay
from replay_kernel_permanent_storage import Replay as ConsumerReplay

class Model(Parent):
 def __init__(self,e):super().__init__(e);self.vectors={}
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   m=i.mnemonic;o=i.operands
   custom=m in ['ldadd','csinc'] or m=='ldr' and i.writeback or i.address in range(0xfffffe000bd744e4,0xfffffe000bd744f4,4)
   if not custom:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
   if m=='csinc':
    pred=self.condition(i.op_str.rsplit(',',1)[1].strip());assert pred is not None
    self.write(i.reg_name(o[0].reg),z3.If(pred,self.read(i.reg_name(o[1].reg)),self.read(i.reg_name(o[2].reg))+1))
   elif m=='ldadd':
    at=self.address(i,o[2]);n=self.width(i.reg_name(o[0].reg))//8;old=self.load(at,n);delta=self.read(i.reg_name(o[0].reg))
    self.store(at,n,old+delta,i.address);self.write(i.reg_name(o[1].reg),old)
   elif m=='ldr' and i.writeback:
    at=self.address(i,o[1]);self.write(i.reg_name(o[0].reg),self.load(at,self.width(i.reg_name(o[0].reg))//8));self.write(i.reg_name(o[1].mem.base),at)
   elif m=='ldr':assert i.op_str=='d0, [x19, #0xa8]';self.vectors['v0']=self.load(self.read('x19')+0xa8,8)
   elif m=='dup':assert i.op_str=='v1.2s, w8';self.vectors['v1']=z3.Concat(self.read('w8'),self.read('w8'))
   elif m=='add':
    assert i.op_str=='v0.2s, v0.2s, v1.2s';a,b=self.vectors['v0'],self.vectors['v1']
    self.vectors['v0']=z3.Concat(z3.Extract(63,32,a)+z3.Extract(63,32,b),z3.Extract(31,0,a)+z3.Extract(31,0,b))
   else:assert m=='str' and i.op_str=='d0, [x19, #0xa8]';self.store(self.read('x19')+0xa8,8,self.vectors['v0'],i.address)
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
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks),
   'checked_read_store_rewrites':list(v.separation_rewrites.values())});print(label,flush=True)
 v=local();base,offset,head=z3.BitVecs('RP_refill_base64 RP_old_bytes64 RP_list_head64',64);length=z3.BitVec('RP_new_bytes64',64);flags=z3.BitVec('RP_refill_flags32',32);tag=z3.BitVec('RP_tag32',32)
 v.seed('x25',base);v.seed('x8',offset);v.seed('x28',head);v.seed('x3',length);v.seed('w9',flags);v.seed('w10',tag)
 mode,extra=z3.BitVecs('RP_mapping_mode32 RP_mapping_extra32',32);v.setmem(v.sp0+0x9c,4,mode);v.setmem(v.sp0+0xa0,4,extra);v.enter('refill_mapping_request')
 prove('refill_requests_page_list_at_virtual_base_plus_old_byte_extent',v,z3.Or(v.next!=R.CONSUME,v.read('x0')!=CPU.MAPOBJ,v.read('x1')!=base+offset,v.read('x2')!=base+offset,v.read('x3')!=length,
  v.read('x4')!=head,v.read('w5')!=(flags|extra),v.read('w6')!=12,v.read('w7')!=mode,v.load(v.sp0,1)!=z3.Extract(7,0,tag)))
 v=local();zone,base,old,new=z3.BitVecs('RP_insert_zone64 RP_insert_base64 RP_old_pages64 RP_new_pages64',64)
 v.seed('x19',zone);v.seed('x25',base);v.seed('x24',old);v.seed('x23',new);v.enter('refill_insert_request')
 prove('refill_inserter_uses_old_count_total_low32_and_zero_initial_used',v,z3.Or(v.next!=R.INSERT,v.read('x0')!=zone,v.read('x1')!=base,v.read('x2')!=0,v.read('x3')!=old,
  v.read('x4')!=z3.ZeroExt(32,z3.Extract(31,0,old+new)),v.read('x5')!=0))
 v=local();obj=z3.BitVec('RP_list_object64',64);v.regions=[(obj,64)];nxt=v.load(obj,8);v.seed('x24',obj);v.enter('list_pop')
 prove('nonzero_list_object_is_consumed_by_saved_next_then_link_clear',v,z3.Or(v.read('x19')!=nxt,v.load(obj,8)!=0),[obj!=0])
 v=local();obj,lower=z3.BitVecs('RP_object64 RP_lower64',64);pfn=z3.BitVec('RP_PFN_base32',32);v.regions=[(0xfffffe0007ef8000,4)];v.setmem(0xfffffe0007ef8000,4,pfn)
 v.seed('x19',obj);v.seed('x8',lower);v.enter('map_PFN_in_interval')
 prove('mapper_reconstructs_same_low32_object_stride_PFN_expression_as_zero_request',v,v.read('w8')!=pfn+z3.Extract(31,0,z3.LShR(obj-lower,6)))
 v=local();v.regions=[(0xfffffe000cb0bf88,1)];bit=v.load(0xfffffe000cb0bf88,1);pfn=z3.BitVec('RP_map_PFN32',32)
 protection,options,offset,base,mode,tag=z3.BitVecs('RP_protection64 RP_options64 RP_offset64 RP_base64 RP_mode64 RP_tag64',64)
 for reg,value in [('w8',pfn),('x25',protection),('x21',options),('x23',offset),('x24',base),('x26',mode),('x22',tag)]:v.seed(reg,value)
 v.enter('map_lower_request');prot=z3.Extract(31,0,protection)
 prove('lower_pmap_receives_exact_virtual_physical_fields_register_arguments_and_stack_byte',v,z3.Or(v.next!=R.PMAP,v.read('x0')!=0xfffffe000cb0bf18,v.read('x1')!=base+offset,
  v.read('x2')!=(z3.ZeroExt(32,pfn)<<14),v.read('w3')!=z3.If((bit&1)!=0,prot&0xfffffffb,prot),v.read('x4')!=0,v.read('x5')!=options,v.read('x6')!=1,v.read('x7')!=mode,v.load(v.sp0,1)!=z3.Extract(7,0,tag)))
 v=local();v.regions=[(PS.ZONE,192)];flags=v.load(PS.ZONE+0x3c,4);v.seed('x19',PS.ZONE);v.enter('permanent_no_bitmap')
 prove('permanent_flag100_skips_generic_bitmap_construction',v,v.next!=z3.If((flags&0x100)!=0,resize(0xfffffe000bd74308,64),resize(0xfffffe000bd73d48,64)))
 v=local();v.regions=[(CPU.META,16),(CPU.PAGE,49152)];index=z3.BitVec('RP_payload_byte64',64);before=v.load(CPU.PAGE+index,1)
 header,span,used=z3.BitVecs('RP_header32 RP_span32 RP_initial_used32',32);v.seed('w6',header);v.seed('w11',span);v.seed('w5',used);v.seed('x23',CPU.META)
 cut(v,'header',0xfffffe000bd73d28,0xfffffe000bd73d3c)
 prove('fresh_metadata_header_used_zero_cursor_links_preserve_every_disjoint_payload_byte',v,z3.Or(v.load(CPU.META,2)!=z3.Extract(15,0,header|(span<<12)),v.load(CPU.META+2,2)!=z3.Extract(15,0,used),
  v.load(CPU.META+4,4)!=0,v.load(CPU.META+8,8)!=0,v.load(CPU.PAGE+index,1)!=before),[z3.ULT(index,49152)])
 v=local();v.regions=[(PS.ZONE,192)];flag=v.load(PS.ZONE+0x3d,1);v.seed('x19',PS.ZONE);cut(v,'ready_flag',0xfffffe000bd74410,0xfffffe000bd74418)
 prove('permanent_bit_routes_to_ready_queue_even_when_used_zero',v,v.next!=z3.If((flag&1)!=0,resize(0xfffffe000bd74420,64),resize(0xfffffe000bd74418,64)))
 v=local();v.regions=[(CPU.META,16)];used=v.load(CPU.META+2,2);v.seed('x23',CPU.META);cut(v,'used_queue',0xfffffe000bd74418,0xfffffe000bd74420)
 prove('nonpermanent_used_zero_selects_empty_queue',v,v.next!=z3.If(used==0,resize(0xfffffe000bd74564,64),resize(0xfffffe000bd74420,64)))
 v=local();v.regions=[(PS.ZONE,192),(CPU.META,16)];old=v.load(PS.ZONE+0x9c,4);v.seed('x19',PS.ZONE);v.seed('x23',CPU.META);v.seed('x26',PS.HEADBASE);v.enter('queue_head_code')
 prove('ready_queue_push_preserves_old_head_and_encodes_positive_head_address',v,z3.Or(v.read('x8')!=PS.ZONE+0x9c,v.load(CPU.META+8,4)!=old,v.read('w9')!=CPU.head_code(0x9c)))
 v=local();v.regions=[(PS.ZONE,192),(CPU.META,16),(PS.METABASE,8)];v.setmem(PS.METABASE,8,CPU.METABASE)
 v.seed('x23',CPU.META);v.seed('w9',CPU.head_code(0x9c));v.seed('x25',0xfffffe0007e66000);v.seed('x8',PS.ZONE+0x9c);v.enter('queue_publish')
 prove('ready_queue_publication_has_same_page_index_consumed_by_permanent_allocator',v,z3.Or(v.load(CPU.META+12,4)!=CPU.head_code(0x9c),v.load(PS.ZONE+0x9c,4)!=CPU.INDEX))
 v=local();v.regions=[(PS.ZONE,192)];a,b=v.load(PS.ZONE+0xa8,4),v.load(PS.ZONE+0xac,4);capacity,old=z3.BitVecs('RP_capacity32 RP_old_capacity32',32)
 v.seed('x19',PS.ZONE);v.seed('w27',capacity);v.seed('w20',old);v.enter('ready_accounting')
 prove('both_free_and_available_u32_lanes_add_same_modular_capacity_delta',v,z3.Or(v.load(PS.ZONE+0xa8,4)!=a+capacity-old,v.load(PS.ZONE+0xac,4)!=b+capacity-old))
 v=local();v.regions=[(CPU.LEDGER,65560)];flags=z3.BitVec('RP_ledger_flags32',32);delta=z3.BitVec('RP_ledger_delta64',64);at=resize(CPU.LEDGER,64)+z3.ZeroExt(48,z3.Extract(15,0,flags))+8;old=v.load(at,8)
 v.seed('x0',CPU.LEDGER);v.seed('w1',flags);v.seed('x2',delta);v.enter('ledger_direct')
 prove('accounting_helper_direct_path_atomically_adds_at_low16_offset_plus8',v,z3.Or(v.load(at,8)!=old+delta,v.read('x2')!=old+delta))
 v=local();v.regions=[(PS.ZONE,192)];flags=v.load(PS.ZONE+0x3c,4);request=z3.BitVec('RP_creator_request_flags64',64)
 v.seed('x22',PS.ZONE);v.seed('x20',request);v.enter('creator_percpu_flag')
 prove('constructor_request_bit24_publishes_zone_percpu_bit40',v,v.load(PS.ZONE+0x3c,4)!=(flags|0x40),[(request&(1<<24))!=0])
 v=local();v.regions=[(0xfffffe0007e66f38,4)];count=v.load(0xfffffe0007e66f38,4);v.enter('creator_percpu_span')
 prove('constructor_percpu_geometry_uses_low32_CPU_count_times16384_bytes',v,z3.Or(v.read('w9')!=(count<<14),v.next!=0xfffffe000bd77590))
 v=local();v.regions=[(PS.ZONE,192)];flags=v.load(PS.ZONE+0x3c,4);pages=z3.BitVec('RP_insert_physical_pages32',32);v.seed('x19',PS.ZONE);v.seed('w21',pages);v.enter('insert_logical_span')
 logical=z3.If((flags&0x40)==0,pages,resize(1,32));header=z3.If((flags&0x40)==0,resize(-0x2000,32),resize(-0x1000,32))
 prove('permanent_inserter_uses_one_logical_page_for_percpu_and_distinct_child_header_class',v,z3.Or(v.read('w11')!=logical,v.read('w4')!=header,v.next!=0xfffffe000bd73c8c),[(flags&0x100)!=0])
 v=local();logical,tail=z3.BitVecs('RP_logical_pages32 RP_tail_bytes32',32);v.seed('w11',logical);v.seed('w12',tail);v.enter('insert_logical_bytes')
 prove('logical_byte_capacity_uses_low16_pages_shift14_minus_tail_mod32',v,z3.Or(v.read('w12')!=((logical&0xffff)<<14)-tail,v.read('w3')!=0,v.next!=0xfffffe000bd73d10))
 v=local();length,extent=z3.BitVecs('RP_logical_bytes32 RP_element_bytes32',32);v.seed('w12',length);v.seed('w8',extent);v.enter('insert_capacity')
 prove('capacity_is_unsigned_byte_extent_division_with_A64_zero_divisor_result',v,v.read('w27')!=z3.If(extent==0,resize(0,32),z3.UDiv(length,extent)))
 prior=[]
 for p in json.loads(read(ROOT/(Z.P+'_audit.json')))['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
  prior.append({'label':p['label'],'query':p['query'],'result':'unsat','source_artifact_sha256':sha(ROOT/(Z.P+'_audit.json'))})
 separations=[]
 for p in json.loads(read(ROOT/'kernel_zone_bitmap_release_audit.json'))['rechecked_separation_lemmas']:
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
  separations.append({'label':p['label'],'query':p['query'],'result':'unsat','source_artifact_sha256':sha(ROOT/'kernel_zone_bitmap_release_audit.json')})
 image=Image();components=[];replays=[];totals=Counter();links=[];epoch_links=[]
 for c in CPU.cases():
  row=CPU.Probe(image,c).run();row['independent_oracle_checks']=CPU.oracle(row);components.append(row);links.append(CPU.correspondence(row))
  r=Replay(image,row).run();replays.append(r);totals.update(r)
 for parent_index in [0,2,4]:
  parent=components[parent_index];c=parent['configuration'];settings={k:c[k] for k in ['capacity','cpu']};settings['count']=c['pages']
  row=Consumers.Probe(image,'publish',settings,parent).run();row['independent_oracle_checks']=[x.replace('nonzero','source_produced_zero') for x in Consumers.oracle(row,parent)]
  publish_index=len(components);components.append(row);r=ConsumerReplay(image,row,parent).run();replays.append(r);totals.update(r)
  cache=Consumers.Probe(image,'cache',{'cpu':c['cpu']},row).run();cache['independent_oracle_checks']=CPU.cache_oracle(cache,row)
  cache_index=len(components);components.append(cache);r=ConsumerReplay(image,cache,row).run();replays.append(r);totals.update(r)
  epoch_links.append({'refill_component':parent_index,'publication_component':publish_index,'cache_component':cache_index,
   'kind':'Exact predecessor RAM/recorded-region transfer under declared new-call epochs; no native continuity inferred',
   'source_statistics_return':hex(CPU.PAGE),'source_cache_return':hex(CPU.PAGE+64),'both_counts_zero_for_all_CPUs':True})
 negative=[]
 for pc in [0xfffffe000bdc1670,0xfffffe000bd7446c,0xfffffe000bd01488]:
  row=CPU.Probe(image,CPU.cases()[0],pc).run()
  try:CPU.oracle(row)
  except AssertionError as error:negative.append({'component':row,'oracle_rejection':error.args[0][0]})
  else:raise AssertionError('changed source accepted')
 source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={i['pc'] for c in components for i in c['source_visits']}
 stats={'source_queries_unsat':len(proofs),'prior_source_queries_rechecked':len(prior),'rechecked_separation_lemmas_unsat':len(separations),'components':len(components),
  'continuous_refill_components':len(CPU.cases()),'consumer_epoch_pairs':3,'component_source_visits':sum(len(c['source_visits']) for c in components),
  'executed_captured_source_PCs':len(source&visited),'all_executed_source_PCs':len(visited),
  'proved_source_PCs':len({p for c in coverage for p in c['PCs']}),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),
  'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'checked_read_store_rewrites':sum(len(c['checked_read_store_rewrites']) for c in coverage),
  'independent_oracle_checks':sum(len(c['independent_oracle_checks']) for c in components),'changed_source_controls':len(negative),
  'zero_to_mapping_request_links':sum(map(len,links))}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_refill_publication.py'),
  'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],
  'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'rechecked_separation_lemmas':separations,'coverage':coverage,
  'components':components,'independent_replays':replays,'independent_replay_totals':dict(totals),'zero_to_mapping_correspondence':links,'consumer_epoch_links':epoch_links,
  'negative_controls':negative,'unexecuted_captured_source_PCs':sorted(source-visited),'independent_totals':stats,
  'original_refill_source_cut_executed':True,'conditional_kernel_refill_publication_contract_established':True,**{k:False for k in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
