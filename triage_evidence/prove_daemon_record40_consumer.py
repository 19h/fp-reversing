#!/usr/bin/env python3
"""Original-source mode/key, global-state, allocator/ABI, audit-copy and
marker identities. All-value local components have explicit readable-cell
premises; native framework results/admission remain outside the proof.
O(source/BV DAGs + solver resources) time/space. No native target or IPC.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE
from daemon_output_base_dispatch import CS
from daemon_arena_lifetime_symbolic import LifetimeFlags
from lskd_values_symbolic import mem,cell,resize
from capture_daemon_record720 import sha
from validate_daemon_record720_spill import parse_value
from prove_daemon_operation_heads import variables
def obligations():
 contract=json.loads((ROOT/'daemon_record40_consumer_contracts.json').read_text());profiles=json.loads((ROOT/'daemon_record40_consumer_profiles.json').read_text());qs=[];counts={}
 def run(name,a,z,seeds=(),memory=()):
  m=LifetimeFlags({'spans':[{'label':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
  for reg,x in seeds:m.seed(reg,x)
  for addr,n,x in memory:mem(m,addr,n,x)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('record40_'+name+'_entry_'+n)for n in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 P=z3.BitVec('record40_record_address64',64);pre=run('key_input',0x10046f070,0x10046f09c,[('x19',P)]);qs.append(('all_record_addresses_key_input',pre.read('w14')!=(z3.Extract(31,0,P)^0xc6d66014)))
 key_input,raw,phase,K=z3.BitVecs('record40_key_input32 record40_raw32 record40_phase32 record40_key32',32);m=run('key_decode',0x10046f09c,0x10046f0ac,[('x0',P),('w14',key_input)],[(P+24,4,raw)]);qs.append(('all_u32_control_decode',m.read('w14')!=raw+key_input*0x6b86592f));qs.append(('caller_callee_control_composition',(phase-K-0xa5d)+K!=phase-0xa5d));assert(0x960f-0xa5d)&0xffffffff==0x8bb2
 A,B,FP=z3.BitVecs('record40_old_header_A64 record40_old_header_B64 record40_frame_pointer64',64);m=run('paired_headers',0x10046f044,0x10046f070,[('x29',FP),('x14',A),('x15',B),('x9',0xa5cd4cf),('x24',0x1010c4eb0),('x25',0x1010c4670)]);new=((A-(FP-0x58)+B)^0x73d046208eaed1a6)*0xa5cd4cf;qs.append(('all_u64_paired_header_update',z3.Or(cell(m,0x1010c4eb0,8)!=new,cell(m,0x1010c4670,8)!=new)))
 parent=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in parent['cases']if c['path_class']=='allnonnull');v=variables(stage);ram={int(r['address'],16):parse_value(r['expression'],8,v)for r in stage['final_defined_bytes']};literal=bytes.fromhex(contract['literal']['bytes_hex']);base=int(contract['literal']['caller_pointer'],16);qs.append(('all_caller_inputs_constant_key_string',z3.Or(*[ram[base+j]!=b for j,b in enumerate(literal)])))
 strict=next(c for c in profiles['cases']if c['configuration']['API_model_mode']=='strict'and c['source_index']==0);extended=next(c for c in profiles['cases']if c['configuration']['API_model_mode']=='allocator_words'and c['source_index']==0);allocator,deallocator=z3.BitVecs('record40_allocator_ref64 record40_contents_deallocator_ref64',64);memory=[]
 for e in extended['source_reads']:
  if 0x1003336f8<=int(e['pc'],16)<0x10033376c:
   x=allocator if e['pc']=='0x1003336f8'else deallocator if e['pc']=='0x10033374c'else int.from_bytes(bytes.fromhex(e['bytes_hex']),'little');memory.append((int(e['address'],16),e['size_bytes'],x))
 seeds=[('x'+str(j),int(x,16))for j,x in enumerate(strict['boundary']['registers31'])]+[('sp',int(strict['boundary']['SP'],16))];m=run('string_arguments',0x1003336f8,0x10033376c,seeds,memory);qs.append(('all_allocator_words_string_call_arguments',z3.Or(m.read('x0')!=allocator,m.read('x1')!=base,m.read('w2')!=0x600,m.read('x3')!=deallocator,m.read('x8')!=int(extended['boundary']['detail']['target'],16),m.read('x17')!=0xd471)))
 SRC,DST=0x680005b2d0,0x680004f1a0;payload=z3.BitVec('record40_audit_payload256',256);data={SRC+j:z3.Extract(8*j+7,8*j,payload)for j in range(32)};bad=[]
 class Copy(LifetimeFlags):
  def load(self,a,n):
   at=z3.simplify(a);assert z3.is_bv_value(at);addr=at.as_long();return z3.Concat(*[data[addr+j]for j in reversed(range(n))])if n>1 else data[addr]
  def store(self,a,n,value,pc):
   at=z3.simplify(a);assert z3.is_bv_value(at);addr=at.as_long();value=resize(value,8*n)
   for j in range(n):data[addr+j]=z3.Extract(8*j+7,8*j,value)
 m=Copy({'spans':[]});m.seed('x0',SRC);m.seed('x1',DST);m.seed('x2',32);m.seed('x30',int(contract['source_copy_call']['pc'],16)+4);m.seed('sp',int(contract['source_copy_call']['SP'],16));m.negative,m.equal,m.carry,m.overflow=[z3.Bool('record40_audit_copy_'+n)for n in ['N','Z','C','V']];body=contract['source_copy_body']
 for j,row in enumerate(body):
  pc=int(row['pc'],16);ins=next(CS.disasm(bytes.fromhex(row['bytes_hex']),pc))
  if ins.mnemonic=='ret':continue
  if ins.mnemonic=='b'or ins.mnemonic.startswith('b.')or ins.mnemonic in ['cbz','cbnz']:
   if ins.mnemonic=='b':condition=z3.BoolVal(True);target=ins.operands[0].imm
   elif ins.mnemonic.startswith('b.'):condition=m.condition(ins.mnemonic[2:]);target=ins.operands[0].imm
   else:condition=m.read(ins.reg_name(ins.operands[0].reg))==0;target=ins.operands[1].imm;condition=z3.Not(condition)if ins.mnemonic=='cbnz'else condition
   bad.append(z3.If(condition,z3.BitVecVal(target,64),z3.BitVecVal(pc+4,64))!=int(body[j+1]['pc'],16));continue
  m.c={'spans':[{'label':'one','start':hex(pc),'bytes_hex':row['bytes_hex']}]};m.run('one')
 qs.append(('all_256_audit_bits_source_copy',z3.Or(*bad,*[data[DST+j]!=z3.Extract(8*j+7,8*j,payload)for j in range(32)],m.read('x0')!=SRC+32,m.read('x1')!=DST+32)));counts['audit_copy_source_visits']=len(body)
 S,REF=z3.BitVecs('record40_argument_SP64 record40_allocator_argument64',64);m=run('task_arguments',0x10047d998,0x10047d9ac,[('sp',S),('x21',REF)]);qs.append(('all_task_allocator_and_audit_address',z3.Or(m.read('x0')!=REF,m.read('x1')!=S+0x50,m.read('x17')!=0x2a84)))
 TASK,NAME=z3.BitVecs('record40_task_ref64 record40_name_ref64',64);m=run('query_arguments',0x1002b7718,0x1002b7728,[('sp',S),('x29',FP),('x0',TASK)],[(S+0x40,8,NAME)]);qs.append(('all_entitlement_query_arguments',z3.Or(m.read('x0')!=TASK,m.read('x1')!=NAME,m.read('x2')!=FP-0x60,m.read('x17')!=0xfe9e,cell(m,S+0x10,8)!=TASK)))
 m=run('error_output_init',0x10046f0b0,0x10046f0b4,[('x29',FP)]);qs.append(('all_frame_pointers_error_cell_zero',cell(m,FP-0x60,8)!=0))
 m=run('marker_write',0x1004b115c,0x1004b1160,[('x19',P),('w28',0x5b)]);qs.append(('all_record_addresses_marker_byte',z3.Or(cell(m,P+8,1)!=0x5b)))
 meta={'caller_control_phase32':'0x960f','decoded_record_control32':'0x8bb2','literal_bytes':len(literal),'allocator_and_deallocator_native_values_known':False,'audit_payload_bits':256,'audit_copy_source':hex(SRC),'audit_copy_destination':hex(DST),'paired_header_cells':['0x1010c4eb0','0x1010c4670'],'header_update':'u64(((oldA-(FP-0x58)+oldB) XOR 0x73D046208EAED1A6)*0x0A5CD4CF)','native_entitlement_value_known':False,'marker_5B_is_not_authorization_evidence':True}
 return qs,counts,meta
if __name__=='__main__':
 qs,counts,meta=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('daemon_record40_consumer_'+name+'_original.smt2');b=ROOT/('daemon_record40_consumer_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer);b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record40_consumer_contracts.json','daemon_record40_consumer_profiles.json','daemon_mig_handover_symbolic.json','daemon_arena_lifetime_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'metadata':meta,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_record40_consumer_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
