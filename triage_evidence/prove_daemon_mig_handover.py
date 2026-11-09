#!/usr/bin/env python3
"""Source-local key/record/consumer identities and continuous copy/handover
obligations. Arbitrary bytes/words remain quantified; source validity, retained
setup roots and native admission are separate premises. O(BV/solver resources)
time/space; no native target, API, PAC or IPC execution.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE,FIXUPS,TABLE
from daemon_arena_lifetime_symbolic import LifetimeFlags
from daemon_output_base_dispatch import CS
from lskd_values_symbolic import mem,cell
from capture_daemon_record720 import sha
from prove_daemon_operation_heads import variables,predicate
from validate_daemon_record720_spill import parse_value
from daemon_mig_handover_symbolic import F,E,B
R=F+0x10cb8
BIAS={0x10:0x3caa1ef2f6106d5e,0x28:0x3f9273076ee1a810,0x40:0x4fb6a6dfc639c7cb,0x50:0x4a83435b1f0a2d7f,0x60:0x0c1825a49380c80d,0x68:0x247f7cf79b589f68,0x70:0x3481cf9de847370c,0x78:0x78e117d710db84c2}
def local_obligations():
 qs=[];counts={}
 def run(name,a,z,seeds=(),memory=(),overrides=None):
  m=LifetimeFlags({'spans':[{'label':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
  for n,x in seeds:m.seed(n,x)
  for addr,width,x in memory:mem(m,addr,width,x)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('handover_local_'+name+'_'+n)for n in ['N','Z','C','V']]
  if overrides:
   for ins in CS.disasm(IMAGE.read(a,z-a),a):
    m.c={'spans':[{'label':'one','start':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex()}]};m.run('one')
    for (pc,reg),value in overrides.items():
     if pc==ins.address:m.seed(reg,value)
  else:m.run(name)
  counts[name]=m.count;return m
 S=z3.BitVec('handover_builder_SP64',64);P=S+0x10cb8;Q=z3.BitVec('handover_borrowed_base64',64);KEY=z3.BitVec('handover_computed_key32',32);phase27,phase20,d0,d4,d56=z3.BitVecs('handover_phase27_32 handover_phase20_32 handover_input0_32 handover_input4_32 handover_input56_32',32);q48,q64=z3.BitVecs('handover_input48_64 handover_input64_64',64)
 pre=run('AD_key_input',0x10046685c,0x100466894,[('sp',S)]);canonical=z3.Extract(31,0,P)^0x7a9247f6;qs.append(('all_SP64_AD_key_input',pre.read('w11')!=canonical));mul=next(CS.disasm(IMAGE.read(0x100466894,4),0x100466894));assert(mul.mnemonic,mul.op_str)==('mul','w11, w11, w12')
 memory=[(S+0x990,8,Q+BIAS[0x10]),(S+0x978,8,Q+BIAS[0x70]),(S+0x980,8,Q+BIAS[0x28]),(S+0x9a0,8,q48),(S+0x998,8,Q+BIAS[0x68]),(S+0x988,8,Q+BIAS[0x50]),(S+0x9b8,8,q64),(S+0x9d0,4,d0)]
 m=run('AD_record_builder',0x100466838,0x100466948,[('sp',S),('w27',phase27),('w20',phase20),('w28',d4),('w25',d56),('x26',Q+BIAS[0x78]),('x24',Q+BIAS[0x60]),('x19',Q+BIAS[0x40])],memory,{(0x100466894,'w11'):KEY})
 expected={0:(8,S+0xbc0),8:(4,KEY+d4+0x72d85fd7),0x10:(8,Q+BIAS[0x10]),0x18:(4,(d56^0x8b3dc651)-KEY),0x20:(8,q48),0x28:(8,Q+BIAS[0x28]),0x30:(4,phase20-KEY-0x179),0x38:(8,q64),0x40:(8,Q+BIAS[0x40]),0x50:(8,Q+BIAS[0x50]),0x58:(4,d0*0x121d0b99+KEY+(phase27^0x0ade8461)),0x60:(8,Q+BIAS[0x60]),0x68:(8,Q+BIAS[0x68]),0x70:(8,Q+BIAS[0x70]),0x78:(8,Q+BIAS[0x78])};qs.append(('all_key32_AD_record_fields',z3.Or(*[cell(m,P+o,n)!=x for o,(n,x)in expected.items()])))
 phase=z3.BitVec('handover_40_phase32',32);token=z3.BitVec('handover_40_token_pointer64',64);m40=run('A70_record40',0x1004c45b8,0x1004c4600,[('sp',S),('w21',phase),('x19',token)]);k40=(z3.Extract(31,0,P)^0xc6d66014)*0x6b86592f;qs.append(('all_SP_phase_token_record40',z3.Or(cell(m40,P,8)!=S+0xbfc0,cell(m40,P+16,8)!=S+0x2cff,cell(m40,P+24,4)!=phase-k40-0xa5d,cell(m40,P+32,8)!=token)))
 delta=z3.BitVec('handover_return_delta64',64);status=z3.BitVec('handover_return_status32',32);ret=run('AD_caller_consumer',0x100466a0c,0x100466a20,[('sp',F),('x19',F+0xb000),('x27',F+0x10000)],[(F+0xba68,8,delta),(R+0x48,4,status)]);qs.append(('all_return_delta_status_consumer',z3.Or(ret.read('sp')!=F+delta,ret.read('w6')!=status)))
 flag,result=z3.BitVecs('handover_return_flag8 handover_return_byte8',8);base=z3.BitVec('handover_gate_phase32',32);gate=run('A70_caller_gate',0x1004c464c,0x1004c4674,[('sp',F),('x28',F+0x10000),('w21',base)],[(R+8,1,result),(F+0x2cff,1,flag)]);cond=z3.Or(flag==0,result==0x5b);qs.append(('all_flag_result_bytes_caller_gate',gate.read('w8')!=(base^z3.If(cond,z3.BitVecVal(0x12,32),z3.BitVecVal(0,32)))))
 inv=pow(0x121d0b99,-1,2**32);assert(0x121d0b99*inv)&0xffffffff==1;qs.append(('all_u32_phase_field_affine_inverse',(d0*0x121d0b99+KEY-KEY)*inv!=d0))
 slots=[]
 for ix in [0x960f,0x960f^0x12]:
  slot=TABLE+8*ix;fix=FIXUPS[slot];raw=int.from_bytes(IMAGE.read(slot,8),'little');assert raw>>63==1 and(raw>>32)&65535==0x6deb and(raw>>48)&7==0;slots.append({'index':hex(ix),'slot':hex(slot),'target':hex(fix['target']),'original_word':hex(raw)})
 return qs,counts,{'record128_key':'u32((low32(R) XOR 0x7A9247F6)*0x31B6B333)','record128_codec_is_composed_from_key_input_and_universal_key_field_lemmas':True,'source_key_multiply_PC':'0x100466894','record128_fields':[{'offset_bytes':o,'width_bytes':n,'expression':x.sexpr()}for o,(n,x)in expected.items()],'record40_key':'u32((low32(R) XOR 0xC6D66014)*0x6B86592F)','record40_raw_control':'u32(phase21 - K40(R) - 0xA5D)','phase_field_multiplier':'0x121d0b99','phase_field_inverse':hex(inv),'post_call_gate':'flag8==0 OR result_byte8==0x5B','post_call_gate_slots':slots,'caller_consumer_instructions_are_separate_from_native_callee_effects':True}

def obligations():
 qs,counts,meta=local_obligations();data=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());copybad=[];preserved=[];targets=[];ledgers=[]
 for c in data['cases']:
  v=variables(c);path=predicate(c['path_condition'],v);parse=lambda text,n=64:parse_value(text,n,v);cells={int(r['address'],16):parse(r['expression'],8)for r in c['final_defined_bytes']};entrycells={int(r['address'],16):parse(r['expression'],8)for r in c['initial_bytes']}
  def read(a,n):return z3.Concat(*[cells[a+j]for j in reversed(range(n))])if n>1 else cells[a]
  for call in c['copy_calls']:
   ent,ret=call['entry'],call['return'];dest=z3.simplify(parse(ent['destination'])).as_long();origin=B+24 if c['operation32']=='0xa70e6eb4'else B+8
   copybad.extend(z3.And(path,cells[dest+j]!=v['head_%s_input_%02x'%(c['operation32'][2:],origin-B+j)])for j in range(32));preserved.append(z3.And(path,parse(ent['SP'])!=parse(ret['SP'])));preserved.extend(z3.And(path,parse(text)!=parse(ret['preserved_GPRs'][name]))for name,text in ent['saved_preserved_GPRs'].items())
  record_extent=128 if c['operation32']=='0xad952088'else 40;writes=[e for e in c['effects']if e['kind']=='write'and R<=int(e['address'],16)<R+record_extent];defined=[j for j in range(record_extent)if R+j in cells];ledger={'operation32':c['operation32'],'class':c['path_class'],'record_address':hex(R),'record_extent_bytes':record_extent,'record_writes':writes,'defined_record_offsets':defined,'undefined_record_offsets':[j for j in range(record_extent)if R+j not in cells],'copy_calls':len(c['copy_calls'])};ledgers.append(ledger)
  if c['boundary']['kind']=='before_retab':
   qs.append(('A70_anynull_raw_result_and_entry_SP',z3.And(path,z3.Or(read(0x6800064018,4)!=0x74c29d88,parse(c['end_GPR_expressions']['sp'])!=E))))
  else:
   target=0x1004d4268 if c['operation32']=='0xad952088'else 0x10046ef4c;mod=0xbdfe if c['operation32']=='0xad952088'else 0xba8c;last=next(e for e in reversed(c['effects'])if e['kind']=='read'and e['size_bytes']==8 and int(e['address'],16)in FIXUPS and FIXUPS[int(e['address'],16)]['target']==target);slot=int(last['address'],16);raw=int.from_bytes(IMAGE.read(slot,8),'little');assert raw>>63==1 and(raw>>32)&65535==mod and(raw>>48)&7==0;targets.append({'operation32':c['operation32'],'PC':c['boundary']['pc'],'slot':hex(slot),'target':hex(target),'modifier':hex(mod),'original_word':hex(raw)});qs.append((c['operation32'][2:]+'_callee_and_record_argument',z3.And(path,z3.Or(parse(c['boundary']['target_expression'])!=target,parse(c['boundary']['modifier_expression'])!=mod,parse(c['end_GPR_expressions']['x0'])!=R))))
   if c['operation32']=='0xad952088':
    cursor=z3.Concat(*[v['head_global_%x'%(0x1010b8d10+j)]for j in reversed(range(8))]);qs.append(('AD_cached_runtime_word_argument',z3.And(path,z3.Or(read(F+0xba68,8)!=cursor,parse(c['end_GPR_expressions']['x1'])!=F+0xba68))))
   else:qs.append(('A70_record40_live_fields',z3.And(path,z3.Or(read(R,8)!=F+0xbfc0,read(R+16,8)!=F+0x2cff,read(R+24,4)!=0x60f8bf6e,read(R+32,8)!=F+0xc0a0))))
 qs.append(('all_copy_bytes_preserved',z3.Or(*copybad)));qs.append(('all_copy_callee_saved_GPRs_and_SP',z3.Or(*preserved)))
 a=next(c for c in data['cases']if c['path_class']=='allnonnull');b=next(c for c in data['cases']if c['path_class']=='anynull');v=variables(a);pa=predicate(a['path_condition'],v);pb=predicate(b['path_condition'],v);env=z3.And(*[x!=0 for n,x in v.items()if n.startswith('core_export_address_')]);qs.append(('A70_pointer_class_coverage_disjoint',z3.And(env,z3.Or(z3.Not(z3.Or(pa,pb)),z3.And(pa,pb)))))
 meta.update({'record_ledgers':ledgers,'next_call_targets':targets,'total_source_copy_calls':sum(len(c['copy_calls'])for c in data['cases']),'native_callee_effects_executed':False,'cached_runtime_word_value_known':False});return qs,counts,meta
def main():
 qs,counts,meta=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('daemon_mig_handover_'+name+'_original.smt2');b=ROOT/('daemon_mig_handover_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer);b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_mig_handover_source.json','daemon_mig_handover_symbolic.json','daemon_mig_handover_symbolic.py','daemon_arena_lifetime_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'metadata':meta,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_mig_handover_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
