#!/usr/bin/env python3
"""All-value constructor codecs, borrowed-field transfer/epoch changes,
first-interface arguments and exact NULL partition under retained setup roots.
O(source projection + BV DAGs + solver resources) time/space. No native effects.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE,FIXUPS
from daemon_arena_lifetime_symbolic import LifetimeFlags
from capture_daemon_record720 import sha
from validate_daemon_record720_spill import parse_value
from daemon_operation_heads_symbolic import B
from daemon_import_bindings import binding
def variables(c):return {n:z3.Bool(n)if bits=='Bool'else z3.BitVec(n,bits)for n,bits in c['variable_widths'].items()}
def predicate(text,v):return z3.parse_smt2_string('(assert '+text+')',decls=v)[0]
def obligations():
 source=json.loads((ROOT/'daemon_operation_heads_source.json').read_text());symbolic=json.loads((ROOT/'daemon_operation_heads_symbolic.json').read_text());qs=[];constructors=[];interfaces=[];counts={};full_domains=[]
 FP=z3.BitVec('operation_head_constructor_FP64',64);phase=z3.BitVec('operation_head_constructor_phase32',32)
 for head in source['handlers']:
  op=int(head['operation32'],16)
  for candidate in head['literal_candidates']:
   if 'record_constructor'not in candidate:continue
   c=candidate['record_constructor'];m=LifetimeFlags({'spans':[]});cut=LifetimeFlags({'spans':[]});KEY=z3.BitVec('head_constructor_computed_key32',32)
   for machine in [m,cut]:machine.seed('x29',FP);machine.seed('w19',phase)
   multiplier=None
   from daemon_output_base_dispatch import CS
   for j,row in enumerate(c['projection']):
    ins=next(CS.disasm(bytes.fromhex(row['bytes_hex']),int(row['pc'],16)))
    if ins.mnemonic=='mul':
     assert multiplier is None;prekey=m.operand(ins,ins.operands[1],32);factor=z3.simplify(m.operand(ins,ins.operands[2],32));assert z3.is_bv_value(factor)and factor.as_long()==0x7398180b;multiplier={'PC':row['pc'],'destination':ins.reg_name(ins.operands[0].reg),'factor32':'0x7398180b'}
    for machine in [m,cut]:machine.c={'spans':[{'label':'one','start':row['pc'],'bytes_hex':row['bytes_hex']}]};machine.run('one')
    if ins.mnemonic=='mul':cut.seed(multiplier['destination'],KEY)
   assert multiplier is not None
   P=FP+c['record_relative_to_FP_bytes'];canonical_prekey=z3.Extract(31,0,P)^0xeaae0ac9;K=canonical_prekey*0x7398180b;tag=phase+0x1d7b if op==0xa70e6eb4 else z3.BitVecVal(0x6cf4,32);q=z3.Or(m.read(c['tag_register'])!=(tag^K),m.read(c['operation_register'])!=(op^K));name='constructor_'+candidate['pc'][2:];full_domains.append({'name':name,'counterexample_formula':q.sexpr()});qs.append((name+'_aligned_prekey',z3.And(FP&15==0,prekey!=canonical_prekey)));qs.append((name+'_all_key32_codec',z3.Or(cut.read(c['tag_register'])!=(tag^KEY),cut.read(c['operation_register'])!=(op^KEY))));counts[name]=len(c['projection']);constructors.append({'operation32':hex(op),'literal_PC':candidate['pc'],'store_PC':c['store_PC'],'record_FP_offset_bytes':c['record_relative_to_FP_bytes'],'MIG_request_IDs':[r['request_ID']for r in candidate['MIG_links']],'decoded_tag':c['decoded_tag_contract'],'proved_domain':'all u64 FP with FP mod16=0; incoming phase arbitrary u32','composition':{'aligned_prekey_lemma':name+'_aligned_prekey','source_multiply':multiplier,'universal_key_codec_lemma':name+'_all_key32_codec','formal_key_cut_is_not_a_runtime_assignment':True}})
 for c in symbolic['cases']:
  op=int(c['operation32'],16);v=variables(c);path=predicate(c['path_condition'],v);regs=c['end_GPR_expressions'];writes=[e for e in c['effects']if e['kind']=='write'];F=0x680004f230
  def parsed(s,n=64):return parse_value(s,n,v)
  def word(off,n):
   e=next(r for r in c['input_reads']if int(r['address'],16)==B+off and r['size_bytes']==n);return parsed(e['expression'],8*n)
  def field(off,n):
   cells={int(r['address'],16):parsed(r['expression'],8)for r in c['initial_bytes']}
   for e in writes:
    a=int(e['address'],16);x=parsed(e['expression'],8*e['size_bytes'])
    for j in range(e['size_bytes']):cells[a+j]=z3.Extract(8*j+7,8*j,x)
   return z3.Concat(*[cells[F+off+j]for j in reversed(range(n))])if n>1 else cells[F+off]
  prefix='head_%08x_%s'%(op,c['path_class']);b=c['boundary'];assert b['kind']in ['before_braa','before_blraa'];last=next(e for e in reversed(c['effects'])if e['kind']=='read'and e['size_bytes']==8 and int(e['address'],16)in FIXUPS);slot=int(last['address'],16);fix=FIXUPS[slot];wordraw=int.from_bytes(IMAGE.read(slot,8),'little');modifier=parsed(b['modifier_expression']);assert wordraw>>63==1 and(wordraw>>48)&7==0;assert z3.is_true(z3.simplify(modifier==((wordraw>>32)&65535)))
  interface={'operation32':hex(op),'path_class':c['path_class'],'PC':b['pc'],'kind':b['kind'],'slot':hex(slot),'original_word':hex(wordraw),'fixup':fix,'input_minimum_endpoint_bytes':c['minimum_head_input_endpoint_bytes']}
  if isinstance(fix['target'],str):
   r=next(r for r in c['new_export_variables']if r['symbol']==fix['target']);expected=v[r['variable']]+r['binding']['total_addend'];interface['binding']=binding(slot)
  else:expected=z3.BitVecVal(fix['target'],64)
  qs.append((prefix+'_target',z3.And(path,parsed(b['target_expression'])!=expected)));bad=[]
  if op==0x8799a4f1:
   bad=[field(0x9a0,4)!=word(4,4),field(0x8dfc,4)!=word(4,4),field(0x998,4)!=(word(12,4)^0x8b3dc651),field(0x4834,4)!=(word(12,4)^0x8b3dc651),field(0x990,4)!=(word(8,4)^0x8b3dc651),field(0x6264,4)!=(word(8,4)^0x8b3dc651),field(0x4280,8)!=word(16,8),field(0x988,8)!=word(24,8),field(0x5fa0,8)!=word(24,8),field(0x1554,4)!=(word(32,4)^0x8b3dc651),field(0x5a08,8)!=word(40,8),field(0x13a0,8)!=B+48,field(0x39e8,8)!=B+56,field(0x47a8,8)!=B+60];glob={int(r['address'],16):v[r['variable']]for r in c['unavailable_global_byte_variables']};cf=z3.Concat(*[glob[0x1010c4d00+j]for j in reversed(range(8))]);bad.append(parsed(regs['x0'])!=cf);interface['CF_object_cell']='0x1010c4d00'
  elif op==0x8f7506ee:
   bad=[field(0x9b8,4)!=word(0,4),field(0x23c8,8)!=v[c['pointer_variable']],parsed(regs['x6'])!=0x8b3dc655];expected_target=0x100528dd8 if c['path_class']=='null'else 0x1005554b4;qs.append((prefix+'_null_route',z3.And(path,parsed(b['target_expression'])!=expected_target)))
  elif op==0xa70e6eb4:
   bad=[field(0x82d8,8)!=word(0,8),field(0x1a30,8)!=word(56,8),field(0x7098,8)!=word(64,8),parsed(regs['x0'])!=B+24,parsed(regs['x1'])!=F+0x5d68,parsed(regs['x2'])!=32]
  else:
   assert op==0xad952088;bad=[field(0x9d0,8)!=z3.ZeroExt(32,word(0,4)),field(0x9a0,8)!=word(48,8),field(0x9b8,8)!=word(64,8),parsed(regs['x0'])!=B+8,parsed(regs['x1'])!=F+0xbc0,parsed(regs['x2'])!=32]
  qs.append((prefix+'_fields_and_arguments',z3.And(path,z3.Or(*bad))));interfaces.append(interface)
 ptr=z3.BitVec('head_null_partition_pointer64',64);qs.append(('all_u64_null_partition_complete_disjoint',z3.Or(z3.Not(z3.Or(ptr==0,ptr!=0)),z3.And(ptr==0,ptr!=0))))
 q=z3.BitVec('head_nested_phase32',32);qs.append(('nested_tag6cf4_iff_phase4f79',z3.Xor(q+0x1d7b==0x6cf4,q==0x4f79)))
 return qs,{'constructors':constructors,'interfaces':interfaces,'projection_instruction_counts':counts,'full_FP_domain_probe_formulas':full_domains,'native_wrapper_admission_proved':False,'same_epoch_later_auxiliary_join_proved':False}
def main():
 qs,meta=obligations();rows=[];probes=[]
 for row in meta['full_FP_domain_probe_formulas']:
  decls={'operation_head_constructor_FP64':z3.BitVec('operation_head_constructor_FP64',64),'operation_head_constructor_phase32':z3.BitVec('operation_head_constructor_phase32',32)};q=predicate(row['counterexample_formula'],decls);s=z3.Solver();s.set(timeout=30000);s.add(q);answer=s.check();assert answer!=z3.unknown;smt=ROOT/('daemon_operation_heads_'+row['name']+'_full_FP_domain.smt2');smt.write_text(s.to_smt2());probe={'name':row['name'],'file':smt.name,'sha256':sha(smt),'result':str(answer)}
  if answer==z3.sat:probe['FP_counterexample']=hex(s.model().eval(decls['operation_head_constructor_FP64'],model_completion=True).as_long());probe['phase_counterexample']=hex(s.model().eval(decls['operation_head_constructor_phase32'],model_completion=True).as_long())
  probes.append(probe);print('full_FP',probe,flush=True)
 for name,q in qs:
  s=z3.Solver();s.set(timeout=30000);s.add(q);answer=s.check();assert answer==z3.unsat,(name,str(answer),str(s.model())if answer==z3.sat else s.reason_unknown());a=ROOT/('daemon_operation_heads_'+name+'_original.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());b=ROOT/('daemon_operation_heads_'+name+'.smt2');s=z3.Solver();s.add(z3.simplify(q));assert s.check()==z3.unsat;b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':'unsat'});print(name,'unsat',flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_operation_heads_source.json','daemon_operation_heads_symbolic.json','daemon_operation_heads_symbolic.py','daemon_arena_lifetime_symbolic.py']},'proofs':rows,'full_FP_domain_probes':probes,'metadata':meta,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_operation_heads_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
