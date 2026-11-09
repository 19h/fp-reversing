#!/usr/bin/env python3
"""Original-instruction local BV proofs for second-query/type predicates,
conversion ABI/marker, frame bit8, borrowed pointer identities, isolated zero
stores and the next private-record codec/copy paths. Explicit readable/writable
cell and retained phase premises; no native owner or admission proof.
O(source/BV DAGs + solver resources) time/space; no native target/IPC.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE
from daemon_output_base_dispatch import CS
from daemon_arena_lifetime_symbolic import LifetimeFlags
from lskd_values_symbolic import mem,cell,resize
from capture_daemon_record720 import sha
from prove_daemon_operation_heads import variables
from validate_daemon_record720_spill import parse_value
class Local(LifetimeFlags):
 def run(self,label):
  span=next(s for s in self.c['spans']if s['label']==label)
  for ins in CS.disasm(bytes.fromhex(span['bytes_hex']),int(span['start'],16)):
   if ins.mnemonic=='cinc':
    assert ins.op_str=='w24, w8, ne';value=self.read('w8');self.write('w24',z3.If(self.condition('ne'),value+1,value));self.count+=1
   else:
    self.c={'spans':[{'label':'one','start':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex()}]};super().run('one')
def obligations():
 c=json.loads((ROOT/'daemon_secondary_result_contracts.json').read_text());qs=[];counts={}
 def run(name,a,z,seeds=(),memory=()):
  m=Local({'spans':[{'label':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
  for r,v in seeds:m.seed(r,v)
  for at,n,v in memory:mem(m,at,n,v)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('secondary_'+name+'_'+f)for f in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 S,V,E=z3.BitVecs('secondary_SP64 secondary_value_ref64 secondary_error_ref64',64);m=run('query_gate',0x1002382ec,0x100238314,[('sp',S),('x0',V),('w20',0xbb08),('w19',0x1f11),('w25',0x5949)],[(S+0x98,8,E)]);qs.append(('all_query_value_error_words',z3.Or(m.read('x21')!=V,m.read('w8')!=z3.If(z3.And(V!=0,E==0),z3.BitVecVal(0x594b,32),z3.BitVecVal(0x5949,32)))))
 A,B=z3.BitVecs('secondary_expected_type64 secondary_actual_type64',64);m=run('number_type',0x10003b38c,0x10003b3ac,[('x24',A),('x0',B),('w25',0xa9a3),('w19',0x5946),('w20',0xbb08)]);qs.append(('all_number_type_ID_pairs',m.read('w8')!=z3.If(A==B,z3.BitVecVal(0xbb08,32),z3.BitVecVal(0xbb3a,32))))
 m=run('string_type',0x1000134a4,0x1000134b8,[('x24',A),('x0',B),('w26',0x38f8),('w19',0x5946)]);qs.append(('all_string_type_ID_pairs',m.read('w8')!=z3.If(A==B,z3.BitVecVal(0x644e,32),z3.BitVecVal(0x5946,32))))
 OUT=z3.BitVec('secondary_number_out64',64);m=run('number_arguments',0x10000b724,0x10000b734,[('x21',V),('sp',S)],[(S+0x18,8,OUT)]);qs.append(('all_number_argument_pointers',z3.Or(m.read('x0')!=V,m.read('x1')!=3,m.read('x2')!=OUT,m.read('x17')!=0x8642)))
 RET=z3.BitVec('secondary_number_return32',32);m=run('number_marker',0x10000b738,0x10000b748,[('w26',0x38f8),('w0',RET)]);qs.append(('all_number_return_words_marker',m.read('w24')!=z3.If(RET==0,z3.BitVecVal(0x31,32),z3.BitVecVal(0x32,32))))
 FP=z3.BitVec('secondary_string_FP64',64);m=run('string_arguments',0x10014c644,0x10014c658,[('x29',FP),('x21',V)]);qs.append(('all_string_argument_addresses',z3.Or(m.read('x0')!=V,m.read('x1')!=FP-0x80,m.read('x2')!=32,m.read('x3')!=0x600,m.read('x17')!=0x7208)))
 FLAGS=z3.BitVec('secondary_old_flags32',32);m=run('bit8',0x1007f7970,0x1007f7980,[('sp',S)],[(S+0x6adc,4,FLAGS)]);qs.append(('all_old_state_words_bit8',cell(m,S+0x6adc,4)!=(FLAGS|8)))
 parent=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in parent['cases']if c['path_class']=='allnonnull');v=variables(stage);ram={int(e['address'],16):e['expression']for e in stage['final_defined_bytes']};bad=[]
 for offset,input_at in [(0x1a30,0x38),(0x7098,0x40)]:
  actual=z3.Concat(*[parse_value(ram[0x680004f230+offset+j],8,v)for j in reversed(range(8))]);expected=z3.Concat(*[v['head_a70e6eb4_input_'+format(input_at+j,'x')]for j in reversed(range(8))]);bad.append(actual!=expected)
 qs.append(('all_borrowed_output_pointer_bytes',z3.Or(*bad)))
 PTR=z3.BitVec('secondary_borrowed_output_pointer64',64)
 for j,a,z,offset in [(0,0x10057a770,0x10057a778,0x1a30),(1,0x10057a778,0x10057a780,0x7098)]:
  m=run('output_zero_'+str(j),a,z,[('sp',S)],[(S+offset,8,PTR)]);qs.append(('isolated_all_output_pointer_words_'+str(j),cell(m,PTR,8)!=0))
 PHASE,TOKEN=z3.BitVec('secondary_bridge_phase32',32),z3.BitVec('secondary_bridge_token64',64);R=S+0x10cb8;KEY=(z3.Extract(31,0,R)^0x7cf28be0)*0x83918153;m=run('bridge_record',0x1007f79f4,0x1007f7a3c,[('sp',S),('w24',PHASE),('x20',TOKEN)]);qs.append(('all_bridge_phase_and_token_words',z3.Or(cell(m,R,8)!=TOKEN,cell(m,R+0xc,4)!=((PHASE+0xd64d96e8)^KEY),cell(m,R+0x10,8)!=S+0x6adc)))
 for j,path in enumerate(c['copy_paths']):
  call=path['call'];SRC,DST=[int(x,16)for x in call['arguments8'][:2]];payload=z3.BitVec('secondary_token'+str(j)+'_256',256);data={SRC+k:z3.Extract(8*k+7,8*k,payload)for k in range(32)};bad=[]
  class Copy(LifetimeFlags):
   def load(self,a,n):
    a=z3.simplify(a);assert z3.is_bv_value(a);at=a.as_long();return z3.Concat(*[data[at+k]for k in reversed(range(n))])if n>1 else data[at]
   def store(self,a,n,x,pc):
    a=z3.simplify(a);assert z3.is_bv_value(a);at=a.as_long();x=resize(x,8*n)
    for k in range(n):data[at+k]=z3.Extract(8*k+7,8*k,x)
  m=Copy({'spans':[]});m.seed('x0',SRC);m.seed('x1',DST);m.seed('x2',32);m.seed('x30',int(call['pc'],16)+4);m.seed('sp',int(call['SP'],16));m.negative,m.equal,m.carry,m.overflow=[z3.Bool('secondary_copy'+str(j)+'_'+f)for f in ['N','Z','C','V']];body=path['body']
  for k,row in enumerate(body):
   pc=int(row['pc'],16);ins=next(CS.disasm(bytes.fromhex(row['bytes_hex']),pc))
   if ins.mnemonic=='ret':continue
   if ins.mnemonic=='b'or ins.mnemonic.startswith('b.')or ins.mnemonic in ['cbz','cbnz']:
    if ins.mnemonic=='b':condition=z3.BoolVal(True);target=ins.operands[0].imm
    elif ins.mnemonic.startswith('b.'):condition=m.condition(ins.mnemonic[2:]);target=ins.operands[0].imm
    else:condition=m.read(ins.reg_name(ins.operands[0].reg))==0;target=ins.operands[1].imm;condition=z3.Not(condition)if ins.mnemonic=='cbnz'else condition
    bad.append(z3.If(condition,z3.BitVecVal(target,64),z3.BitVecVal(pc+4,64))!=int(body[k+1]['pc'],16));continue
   m.c={'spans':[{'label':'one','start':hex(pc),'bytes_hex':row['bytes_hex']}]};m.run('one')
  qs.append(('all_256_next_token_bits_'+str(j),z3.Or(*bad,*[data[DST+k]!=z3.Extract(8*k+7,8*k,payload)for k in range(32)])));counts['copy_'+str(j)]=len(body)
 return qs,counts
if __name__=='__main__':
 qs,counts=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('daemon_secondary_result_'+name+'_original.smt2');b=ROOT/('daemon_secondary_result_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer);b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_secondary_result_contracts.json','daemon_mig_handover_symbolic.json','daemon_arena_lifetime_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_secondary_result_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
