#!/usr/bin/env python3
"""Source-lifted local equations for state/rejoin context, three token-copy
paths, PID ABI, second string/record codec and marker channel. Readable cell
and retained phase premises are explicit. O(source/BV DAGs + solver resources)
time/space; no native target, framework, PAC or IPC execution.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE
from daemon_output_base_dispatch import CS
from daemon_arena_lifetime_symbolic import LifetimeFlags
from lskd_values_symbolic import mem,cell,resize
from capture_daemon_record720 import sha
def obligations():
 contract=json.loads((ROOT/'daemon_entitlement_flow_contracts.json').read_text());qs=[];counts={}
 def run(name,a,z,seeds=(),memory=()):
  m=LifetimeFlags({'spans':[{'label':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
  for r,v in seeds:m.seed(r,v)
  for at,n,v in memory:mem(m,at,n,v)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('ent_flow_'+name+'_'+f)for f in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 S=z3.BitVec('ent_flow_frame64',64);I,C=z3.BitVecs('ent_flow_saved_index32 ent_flow_old_flags32',32);m=run('state_update',0x1004b3e6c,0x1004b3ea4,[('sp',S)],[(S+0x998,4,I),(S+0x6adc,4,C)]);T=(I+0x1d89966)&0xfe276bef;qs.append(('all_saved_indices_and_flags',z3.Or(cell(m,S+0x9b8,4)!=T,cell(m,S+0x6adc,4)!=(C|(T-0x405f)),z3.And(I==0x3b0b,cell(m,S+0x6adc,4)!=(C|2)))))
 Q=z3.BitVec('ent_flow_phase32',32);m=run('literal_phase',0x1004b4f2c,0x1004b4f48,[('sp',S)],[(S+0x9b8,4,Q)]);qs.append(('all_phases_literal_phase',z3.Or(m.read('w25')!=((Q+0x29d31a4a)&0xd62cf57e),z3.And(Q==0x4061,m.read('w25')!=0x502a))))
 for j,path in enumerate(contract['copy_paths']):
  call=path['call'];SRC,DST=[int(x,16)for x in call['arguments8'][:2]];payload=z3.BitVec('ent_flow_token'+str(j)+'_256',256);data={SRC+k:z3.Extract(8*k+7,8*k,payload)for k in range(32)};bad=[]
  class Copy(LifetimeFlags):
   def load(self,a,n):
    at=z3.simplify(a);assert z3.is_bv_value(at);addr=at.as_long();return z3.Concat(*[data[addr+k]for k in reversed(range(n))])if n>1 else data[addr]
   def store(self,a,n,value,pc):
    at=z3.simplify(a);assert z3.is_bv_value(at);addr=at.as_long();value=resize(value,8*n)
    for k in range(n):data[addr+k]=z3.Extract(8*k+7,8*k,value)
  m=Copy({'spans':[]});m.seed('x0',SRC);m.seed('x1',DST);m.seed('x2',32);m.seed('x30',int(call['pc'],16)+4);m.seed('sp',int(call['SP'],16));m.negative,m.equal,m.carry,m.overflow=[z3.Bool('ent_flow_copy'+str(j)+'_'+f)for f in ['N','Z','C','V']];body=path['body']
  for k,row in enumerate(body):
   pc=int(row['pc'],16);ins=next(CS.disasm(bytes.fromhex(row['bytes_hex']),pc))
   if ins.mnemonic=='ret':continue
   if ins.mnemonic=='b'or ins.mnemonic.startswith('b.')or ins.mnemonic in ['cbz','cbnz']:
    if ins.mnemonic=='b':condition=z3.BoolVal(True);target=ins.operands[0].imm
    elif ins.mnemonic.startswith('b.'):condition=m.condition(ins.mnemonic[2:]);target=ins.operands[0].imm
    else:condition=m.read(ins.reg_name(ins.operands[0].reg))==0;target=ins.operands[1].imm;condition=z3.Not(condition)if ins.mnemonic=='cbnz'else condition
    bad.append(z3.If(condition,z3.BitVecVal(target,64),z3.BitVecVal(pc+4,64))!=int(body[k+1]['pc'],16));continue
   m.c={'spans':[{'label':'one','start':hex(pc),'bytes_hex':row['bytes_hex']}]};m.run('one')
  qs.append(('all_256_token_bits_copy_'+str(j),z3.Or(*bad,*[data[DST+k]!=z3.Extract(8*k+7,8*k,payload)for k in range(32)])));counts['copy_'+str(j)]=len(body)
 A=z3.BitVec('ent_flow_audit_argument64',64);m=run('PID_arguments',0x1004b5010,0x1004b503c,[('sp',S),('x21',A)]);qs.append(('all_PID_call_addresses',z3.Or(m.read('x0')!=A,m.read('x6')!=S+0x5d5c,m.read('x17')!=0xdc55,cell(m,S,8)!=0,*[m.read('x'+str(j))!=0 for j in [1,2,3,4,5,7]])))
 encoded=bytes.fromhex(contract['literal']['encoded_hex']);at=int(contract['literal']['source_address'],16);m=run('literal',0x1004b50a8,0x1004b51b0,[('sp',S),('x8',at),('w25',0x502a)],[(at+j,1,b)for j,b in enumerate(encoded)]);literal=bytes.fromhex(contract['literal']['decoded_hex']);qs.append(('all_frame_addresses_literal16',z3.Or(*[cell(m,S+0x1033e+j,1)!=b for j,b in enumerate(literal)])))
 PTR=z3.BitVec('ent_flow_second_token_pointer64',64);R=S+0x10cb8;K=(z3.Extract(31,0,R)^0x7a9247f6)*0x31b6b333;m=run('second_record',0x1004b5218,0x1004b526c,[('sp',S),('x20',PTR)],[(S+0x998,8,PTR),(S+0x9b8,4,Q)]);qs.append(('all_phase_words_secondary_record',z3.Or(cell(m,R,8)!=PTR,cell(m,R+8,4)!=((Q+0x6b30)^K),cell(m,R+0x10,8)!=S+0x1280,cell(m,R+0x20,8)!=S+0x1033e)))
 P=z3.BitVec('ent_flow_record_address64',64);RAW=z3.BitVec('ent_flow_raw_control32',32);m=run('second_key_input',0x100014048,0x100014074,[('x25',P)]);qs.append(('all_record_addresses_secondary_key_input',m.read('w12')!=(z3.Extract(31,0,P)^0x7a9247f6)));INPUT=z3.BitVec('ent_flow_key_input32',32);m=run('second_decode',0x100014074,0x100014088,[('x25',P),('w12',INPUT)],[(P+8,4,RAW)]);qs.append(('all_key_inputs_secondary_decode',m.read('w20')!=(RAW^(INPUT*0x31b6b333))));KEY0=z3.BitVec('ent_flow_composed_key32',32);qs.append(('all_phase_keys_secondary_codec_composition',(((Q+0x6b30)^KEY0)^KEY0)!=(Q+0x6b30)))
 REF=z3.BitVec('ent_flow_second_string_ref64',64);m=run('second_string_gate',0x1000141c8,0x1000141e8,[('x0',REF),('w20',0xab91)]);qs.append(('all_secondary_string_refs',m.read('w8')!=z3.If(REF==0,z3.BitVecVal(0xab91^((0xab91-0x223d)^0x891e),32),z3.BitVecVal(0xab91,32))))
 m=run('second_NULL_marker',0x100067240,0x100067244,[('x25',P),('w21',0x31)]);qs.append(('all_second_record_addresses_NULL_marker',cell(m,P+0x18,1)!=0x31))
 ALLOC,TASK,NAME=z3.BitVecs('ent_flow_allocator64 ent_flow_task64 ent_flow_key_object64',64);m=run('secondary_task_arguments',0x1000622dc,0x1000622e8,[('sp',S),('x19',ALLOC)]);qs.append(('all_secondary_task_argument_addresses',z3.Or(m.read('x0')!=ALLOC,m.read('x1')!=S+0x78,m.read('x17')!=0x2a84)))
 m=run('secondary_query_arguments',0x1002382d8,0x1002382e8,[('sp',S),('x0',TASK)],[(S+0x50,8,NAME)]);qs.append(('all_secondary_query_argument_addresses',z3.Or(m.read('x0')!=TASK,m.read('x1')!=NAME,m.read('x2')!=S+0x98,m.read('x17')!=0xfe9e,cell(m,S+0x20,8)!=TASK)))
 m=run('secondary_error_init',0x10001408c,0x100014090,[('sp',S)]);qs.append(('all_secondary_error_cells_zero',cell(m,S+0x98,8)!=0))
 m=run('secondary_state_consumer',0x1005aa0c8,0x1005aa0e8,[('sp',S),('w25',0x502a)],[(S+0x6adc,4,C)]);qs.append(('all_state_words_post_NULL_marker',m.read('w10')!=z3.If(C==0,z3.BitVecVal(0x502f,32),z3.BitVecVal(0x502a,32))))
 MARK=z3.BitVec('ent_flow_secondary_marker8',8);m=run('secondary_marker_consumer',0x1004b52b8,0x1004b52d0,[('x27',S+0x10000),('w20',0x4061)],[(S+0x10cd0,1,MARK)]);qs.append(('all_secondary_marker_bytes',m.read('w8')!=z3.If(MARK==0x31,z3.BitVecVal(0x406b,32),z3.BitVecVal(0x4061,32))))
 return qs,counts
if __name__=='__main__':
 qs,counts=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('daemon_entitlement_flow_'+name+'_original.smt2');b=ROOT/('daemon_entitlement_flow_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer);b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_entitlement_flow_contracts.json','daemon_arena_lifetime_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_entitlement_flow_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
