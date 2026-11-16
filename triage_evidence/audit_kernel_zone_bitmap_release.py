#!/usr/bin/env python3
"""Exact local instruction obligations and independent whole-source components.
O(instruction instances + query DAG + component journals/RAM) construction,
time and space; solver search separate, 30 s/query. Native effects unexecuted.
"""
import copy,json
import z3
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import resize
from audit_kernel_retirement_magazines import Model as Parent,DEC
import recover_kernel_zone_bitmap_release as R
import probe_kernel_zone_bitmap_release as CPU

class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   m=i.mnemonic;o=i.operands
   special=m=='umull' or m=='mrs' or m=='ldr' and i.writeback and i.op_str!='x16, [x17, #0x40]!'
   if not special:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
   if m=='umull':self.write(i.reg_name(o[0].reg),z3.ZeroExt(32,self.read(i.reg_name(o[1].reg)))*z3.ZeroExt(32,self.read(i.reg_name(o[2].reg))))
   elif m=='mrs':
    assert i.op_str=='x8, tpidr_el1';self.seed('x8',self.thread)
   else:
    assert i.op_str=='w11, [x10, #4]!';at=self.address(i,o[1]);self.write('w11',self.load(at,4));self.write('x10',at)
  return self

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs=[];coverage=[]
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(c) for c in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));r=s.check();assert r==z3.sat,('vacuous',label,r)
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,r,s.reason_unknown())
  proofs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV','query':s.to_smt2()})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,
   'linked_edge_obligations':len(v.edge_checks),'checked_read_store_rewrites':list(v.separation_rewrites.values())})
  print(label,flush=True)
 def local():
  v=Model(e);v.metadata=z3.BitVec('BR_metadata64',64);v.regions.extend([(v.zone,192),(v.metadata,16)])
  v.seed('x0',v.zone);v.seed('x1',v.metadata);return v
 v=local();d=z3.BitVec('BR_before_extended_displacement64',64);extra=v.load(v.metadata+2,1)
 v.seed('x9',d);v.enter('extended_lead');lead=v.metadata-(z3.ZeroExt(56,extra)<<4)
 tagged=((v.metadata^lead)&0xffc0000000000000)!=0
 prove('extended_lead_displacement_backstep_and_high_bit_tag_gate',v,z3.Or(v.read('x9')!=d+(z3.ZeroExt(56,extra)<<14),
  v.read('x11')!=lead,v.next!=z3.If(tagged,resize(0xfffffe000bd757b8,64),resize(0xfffffe000bd757bc,64))))
 for tag in [False,True]:
  w=copy.deepcopy(v)
  if tag:w.run('extended_tag')
  w.run('extended_join');expected=((lead&0xffffffffffff)|0xc8a2000000000000) if tag else lead
  prove(('changed' if tag else 'preserved')+'_extended_lead_join_exact_high16',w,w.read('x1')!=expected,[tagged if tag else z3.Not(tagged)])
 v=local();d=z3.BitVec('BR_displacement64',64);extent=z3.BitVec('BR_extent16',16);v.seed('x9',d);v.seed('w8',extent)
 multiplier=v.load(v.zone+0x28,8);product=multiplier*d;quotient=z3.Extract(63,32,product);v.enter('quotient')
 prove('quotient64_product_and_high32_extent_equality_gate',v,z3.Or(v.read('x10')!=product,v.read('w11')!=quotient,
  v.next!=z3.If(z3.ZeroExt(32,quotient)*z3.ZeroExt(48,extent)==d,resize(0xfffffe000bd757d8,64),resize(0xfffffe000bd75b34,64))))
 v=local();header=v.load(v.metadata,2);v.enter('layout')
 prove('leading_metadata_bit11_selects_inline_bitmap',v,v.next!=z3.If((header&0x800)!=0,resize(0xfffffe000bd75818,64),resize(0xfffffe000bd757e0,64)))
 for inline in [False,True]:
  v=local();product=z3.BitVec('BR_'+str(inline)+'_product64',64);index=z3.Extract(63,32,product)
  v.seed('x10',product);v.seed('w11',index)
  if inline:
   at=v.metadata+(z3.LShR(product,37)<<4)+4;mask=resize(1,32)<<(index&31);width=4
  else:
   base=z3.BitVec('BR_external_bitmap_base64',64);v.setmem(0xfffffe0007e66e70,8,base);v.regions.append((0xfffffe0007e66e70,8))
   offset=v.load(v.metadata+4,4)&0xfffffff;at=base+(z3.ZeroExt(32,offset)<<3)+(z3.LShR(product,38)<<3)
   mask=resize(1,64)<<(z3.ZeroExt(32,index)&63);width=8
  # Only the selected word must be valid at this local cut. It can alias
  # the metadata arena in inline layout; no separation is assumed there.
  if not inline:v.regions.append((at,8))
  else:
   # One nonwrapping arena covers both the leading header and every
   # selected inline word for an arbitrary product64. This 2 GiB proof
   # domain is not an assertion about a native metadata allocation.
   v.regions[-1]=(v.metadata,0x80000000)
  old=v.load(at,width);v.enter(('inline' if inline else 'external')+'_gate')
  nonzero=(old&mask)!=0;success=0xfffffe000bd75834 if inline else 0xfffffe000bd7580c
  prove(('inline32' if inline else 'external64')+'_exact_word_address_bit_and_existing_free_bit_rejection',v,z3.Or(
   v.next!=z3.If(nonzero,resize(0xfffffe000bd75b40,64),resize(success,64)),
   v.read('x10')!=at if inline else v.read('x9')!=at-(z3.LShR(product,38)<<3)))
  v.run(('inline' if inline else 'external')+'_set')
  prove(('inline32' if inline else 'external64')+'_clear_bit_becomes_set_and_preserves_other_word_bits',v,z3.Or(
   v.load(at,width)!=(old^mask),v.next!=0xfffffe000bd7583c),[z3.Not(nonzero)])
 v=local();old=v.load(v.metadata+2,2);v.enter('count')
 prove('count_u16_store_precedes_zero_old_count_underflow_request',v,z3.Or(v.load(v.metadata+2,2)!=old-1,
  v.read('w9')!=z3.ZeroExt(16,old),v.read('w10')!=z3.ZeroExt(16,old)-1,
  v.next!=z3.If(old==0,resize(0xfffffe000bd75b48,64),resize(0xfffffe000bd75850,64))))
 v.run('count_zero');prove('nonunderflow_zero_new_count_selects_empty_span_queue',v,
  v.next!=z3.If(old==1,resize(0xfffffe000bd758a8,64),resize(0xfffffe000bd75858,64)),[old!=0])
 v=local();old=z3.BitVec('BR_oldcount16',16);extent=z3.BitVec('BR_threshold_extent16',16);header=v.load(v.metadata,2)
 v.seed('w9',old);v.seed('w8',extent);v.enter('threshold');bytes_used=z3.ZeroExt(48,extent)*(z3.ZeroExt(48,old&0x7fff)+1)
 span_bytes=(z3.ZeroExt(48,header)<<2)&0x3c000
 prove('nonempty_threshold_uses_old_low15_plus_one_times_extent_and_span_nibble',v,z3.Or(v.read('x8')!=bytes_used,
  v.read('x9')!=span_bytes,v.next!=z3.If(z3.ULE(bytes_used,span_bytes),resize(0xfffffe000bd759b0,64),resize(0xfffffe000bd75874,64))))
 v=local();v.seed('x0',v.zone+0x80);old=v.load(v.zone+0x80,4);v.enter('unlock_byte')
 expected=z3.Concat(z3.Extract(31,24,old),z3.Extract(23,16,old)+resize(1,8),z3.Extract(15,0,old))
 prove('unlock_changes_only_owner_byte_mod256',v,v.load(v.zone+0x80,4)!=expected)
 v=local();v.regions.append((v.thread,512));old=v.load(v.thread+0x1c8,4);v.enter('nest_gate')
 prove('unlock_reads_thread_nesting_and_rejects_zero_before_decrement',v,z3.Or(v.read('x8')!=v.thread,
  v.next!=z3.If(old==0,resize(0xfffffe000bd0ab70,64),resize(0xfffffe000bd0ab48,64))))
 v.run('nest_decrement');prove('unlock_nonzero_thread_nesting_decrements_and_tests_result',v,z3.Or(v.load(v.thread+0x1c8,4)!=old-1,
  v.next!=z3.If(old!=1,resize(0xfffffe000bd0ab60,64),resize(0xfffffe000bd0ab54,64))),[old!=0])
 v=local();obj=z3.BitVec('BR_pending_object64',64);v.regions.extend([(v.thread,512),(obj,80)])
 v.setmem(v.thread+0x1c0,8,obj);flags=v.load(obj+0x4c,1);v.seed('x8',v.thread);v.enter('pending_gate')
 prove('nesting_zero_pending_bit2_selects_original_tail',v,v.next!=z3.If((flags&4)!=0,resize(0xfffffe000bd0ab74,64),resize(0xfffffe000bd0ab60,64)))
 compositions=[]
 for extent in [128,256]:
  d=z3.BitVec('BR_bounded_displacement_'+str(extent),64);p=d*((0xffffffff//extent)+1)
  q=z3.LShR(p,32);accept=q*extent==d
  s=z3.SolverFor('QF_BV');s.set(timeout=30000);s.add(z3.ULT(d,32768),z3.Or(accept!=(z3.URem(d,extent)==0),q!=z3.UDiv(d,extent)))
  assert s.check()==z3.unsat
  compositions.append({'label':'extent'+str(extent)+'_bounded_two_page_quotient_and_alignment','result':'unsat','logic':'QF_BV','query':s.to_smt2()})
 prior=[];old_a=json.loads(read(ROOT/'kernel_retirement_magazines_audit.json'))
 for p in old_a['separation_lemmas']:
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
  prior.append({'label':p['label'],'result':'unsat','source_audit_sha256':sha(ROOT/'kernel_retirement_magazines_audit.json'),'query':p['query']})
 from kernel_vm_mig_tools import Image
 image=Image();parent=json.loads(read(ROOT/'kernel_zone_startup_profiles.json'))['cases'][7];components=[]
 for c in CPU.configurations():
  row=CPU.Probe(image,parent,c).run();row['independent_oracle_checks']=CPU.oracle(row);components.append(row)
 negative=[]
 for inline,pc in [(False,0xfffffe000bd75810),(True,0xfffffe000bd75838)]:
  row=CPU.Probe(image,parent,{'inline':inline},pc).run()
  try:CPU.oracle(row)
  except AssertionError as failure:
   assert failure.args[0][0]=='bitmap_exact_word';negative.append({'component':row,'oracle_rejection':failure.args[0][0]})
  else:raise AssertionError('altered bitmap store accepted')
 proved={p for c in coverage for p in c['PCs']};selected={i['ea'] for s in e['spans'] for i in s['instructions']};assert proved==selected
 all_source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={v['pc'] for c in components for v in c['source_visits']}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':R.SCOPE,
  'source_proofs':proofs,'composition_proofs':compositions,'coverage':coverage,'rechecked_separation_lemmas':prior,'components':components,'negative_controls':negative,
  'unexecuted_captured_PCs':sorted(all_source-visited),
  'independent_totals':{'source_queries_unsat':len(proofs),'composition_queries_unsat':len(compositions),'rechecked_separation_lemmas_unsat':len(prior),
   'proved_source_PCs':len(proved),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),
   'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),
   'checked_read_store_rewrites':sum(len(c['checked_read_store_rewrites']) for c in coverage),
   'components':len(components),'component_source_visits':sum(len(c['source_visits']) for c in components),
   'captured_component_PCs':len(all_source&visited),'unexecuted_captured_PCs':len(all_source-visited),
   'independent_oracle_checks':sum(len(c['independent_oracle_checks']) for c in components),'changed_store_controls':len(negative)},
  'conditional_kernel_zone_bitmap_release_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
