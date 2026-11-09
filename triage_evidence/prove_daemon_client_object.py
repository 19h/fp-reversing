#!/usr/bin/env python3
"""Local original-source BV/byte-array proofs for allocation selectors,
initialization widths, borrowed input representation and guarded index.
Fixed retained phases, valid/disjoint local extents and ABI preservation
are premises; no native allocation, pointer-extent or admission proof.
O(source/BV DAGs + solver resources) time and space.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE
from daemon_arena_lifetime_symbolic import LifetimeFlags
from lskd_values_symbolic import mem,cell,resize
from capture_daemon_record720 import sha
from prove_daemon_operation_heads import variables
from validate_daemon_record720_spill import parse_value
def obligations():
 qs=[];counts={}
 def run(name,a,z,seeds=(),memory=(),cls=LifetimeFlags):
  m=cls({'spans':[{'label':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
  for r,v in seeds:m.seed(r,v)
  for at,n,v in memory:mem(m,at,n,v)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('client_obj_'+name+'_'+f)for f in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 PTR,S=z3.BitVecs('client_obj_pointer64 client_obj_SP64',64)
 m=run('malloc32_pointer',0x10057014c,0x100570168,[('x0',PTR),('w19',0x6cf4),('w20',0x6cd0),('w21',0x4146)])
 qs.append(('all_malloc32_result_words',m.read('w8')!=z3.If(PTR==0,z3.BitVecVal(0x4146,32),z3.BitVecVal(0x4157,32))))
 m=run('malloc16_pointer',0x10069985c,0x100699878,[('x0',PTR),('sp',S),('w19',0x1892),('w20',0x7081)])
 qs.append(('all_malloc16_result_words',z3.Or(cell(m,S+0x2ff8,8)!=PTR,m.read('w8')!=z3.If(PTR==0,z3.BitVecVal(0x70bc,32),z3.BitVecVal(0x7081,32)))))
 class Bytes(LifetimeFlags):
  def __init__(self,c):super().__init__(c);self.array=z3.Array('client_obj_initial_bytes',z3.BitVecSort(64),z3.BitVecSort(8));self.before=self.array;self.stores=[]
  def load(self,a,n):return z3.Concat(*[z3.Select(self.array,resize(a,64)+k)for k in reversed(range(n))])if n>1 else z3.Select(self.array,resize(a,64))
  def store(self,a,n,v,pc):
   a=resize(a,64);v=resize(v,8*n);self.stores.append((a,n))
   for k in range(n):self.array=z3.Store(self.array,a+k,z3.Extract(8*k+7,8*k,v))
 m=run('initialize32',0x1005596c4,0x1005596e4,[('x0',PTR)],cls=Bytes);expected=bytes(8)+bytes.fromhex('51c63d8b')*3+bytes.fromhex('dc16894d51c63d8b');bad=[m.load(PTR+k,1)!=v for k,v in enumerate(expected)];bad +=[m.load(PTR+k,1)!=z3.Select(m.before,PTR+k)for k in range(28,32)];qs.append(('all_initial_bytes_object32',z3.Or(*bad)))
 Q=z3.BitVec('client_obj_arbitrary_address64',64);changed=z3.Or(*[Q==PTR+k for k in range(28)]);qs.append(('object32_frame_property',z3.And(z3.Not(changed),z3.Select(m.array,Q)!=z3.Select(m.before,Q))))
 m=run('initialize16',0x1008c3890,0x1008c3894,[('x0',PTR)],cls=Bytes);qs.append(('all_initial_bytes_pair16',z3.Or(*[m.load(PTR+k,1)!=0 for k in range(16)])))
 INPUT=z3.BitVec('client_obj_input_B08_64',64)
 m=run('input_length_codec',0x1005596ac,0x100559710,[('x0',z3.BitVecVal(0x4000,64)),('sp',z3.BitVecVal(0x10000,64)),('w20',0x6cd0)],[(0x10000+0x990,8,INPUT)])
 qs.append(('all_input_field64_length_representation',z3.Or(cell(m,0x10000+0x3d1c,4)!=(z3.Extract(31,0,INPUT)^0x8b3dc651),cell(m,0x10000+0x3650,8)!=0x4000)))
 CONTEXT=z3.BitVec('client_obj_context_encoded_length32',32);m=run('input_context_save',0x1006997c4,0x1006997f8,[('sp',S),('w9',CONTEXT),('x10',PTR),('x12',S+0x42e8)])
 init=run('pair_phase',0x1008c3880,0x1008c3890,[('w19',0x1892)])
 qs.append(('all_input_context_pointer_and_length_words',z3.Or(cell(m,S+0x3818,8)!=PTR,cell(m,S+0x7550,4)!=CONTEXT,cell(m,S+0x4d50,8)!=0,cell(m,S+0x1a74,4)!=0x8b3dc651,cell(m,S+0x7768,8)!=0x2c220a381b62f9ab,init.read('w10')!=0xa62b)))
 m=run('borrowed_pointer_gate',0x100559724,0x100559744,[('sp',S),('w19',0x6cf4),('w20',0x6cd0)],[(S+0x82d8,8,PTR)])
 qs.append(('all_borrowed_pointer_words',z3.Or(m.read('x10')!=PTR,m.read('w11')!=z3.If(PTR==0,z3.BitVecVal(0x6cd0,32),z3.BitVecVal(0x6cd4,32)))))
 ENCODED=z3.BitVec('client_obj_encoded_length32',32);CURSOR=z3.BitVec('client_obj_cursor64',64)
 m=run('remaining_length',0x1006d54e8,0x1006d5528,[('sp',S),('w10',0xa62b)],[(S+0x4d50,8,CURSOR),(S+0x7550,4,ENCODED)]);L=z3.ZeroExt(32,ENCODED^0x8b3dc651);REM=L-CURSOR
 qs.append(('all_encoded_length_and_cursor_words',z3.Or(m.read('x9')!=L,m.read('x13')!=REM,m.read('w14')!=0x9b50,m.read('w8')!=z3.If(z3.UGT(L,CURSOR),z3.BitVecVal(0xa633,32),z3.BitVecVal(0xa62b,32)))))
 m=run('span_pointer',0x1008cf2d8,0x1008cf310,[('sp',S),('w14',0x9b50)],[(S+0x3818,8,PTR)])
 qs.append(('all_span_pointer_words',z3.Or(m.read('w12')!=0x1a25,m.read('x10')!=PTR,m.read('w14')!=z3.If(PTR==0,z3.BitVecVal(0x9b55,32),z3.BitVecVal(0x9b50,32)))))
 m=run('remaining_threshold',0x10076b268,0x10076b28c,[('x13',REM),('w12',0x1a25)])
 qs.append(('all_remaining_length_words',z3.Or(m.read('w8')!=0xb9e,m.read('w13')!=z3.If(z3.UGT(REM,9),z3.BitVecVal(0x2496,32),z3.BitVecVal(0x1a25,32)))))
 m=run('read_index',0x10067046c,0x100670470,[('x11',CURSOR)]);qs.append(('all_cursor_words_guarded_read_index',z3.Or(m.read('x12')!=CURSOR+6,z3.And(z3.UGT(L,CURSOR),z3.UGT(REM,9),z3.Not(z3.ULT(m.read('x12'),L))))))
 STATUS,PHASE=z3.BitVecs('client_obj_status32 client_obj_status_phase32',32);m=run('outer_status',0x1007fb760,0x1007fb7a0,[('sp',S),('w19',PHASE)],[(S+0x44a4,4,STATUS)]);expected=z3.If(STATUS==0x8b3dc651,((PHASE-0x5bf2)|0x8a1)^0x19b5,z3.BitVecVal(0,32))^(PHASE-0x29f2)
 qs.append(('all_outer_status_and_phase_words',z3.Or(m.read('w6')!=STATUS,m.read('w9')!=expected)))
 raw=run('first_allocation_error',0x10057016c,0x100570174);m=run('failure_status_store',0x1004de1dc,0x1004de1e4,[('sp',S),('w6',raw.read('w6'))]);qs.append(('all_failure_frames_status',z3.Or(cell(m,S+0x44a4,4)!=0x74c29d85,(raw.read('w6')^0x8b3dc651)!=0xffff5bd4)))
 parent=next(c for c in json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text())['cases']if c['path_class']=='allnonnull');v=variables(parent);data={int(e['address'],16):parse_value(e['expression'],8,v)for e in parent['final_defined_bytes']};bad=[]
 for off,source in [(0x82d8,0),(0x990,8)]:
  for k in range(8):bad.append(data[0x680004f230+off+k]!=v['head_a70e6eb4_input_'+format(source+k,'02x')])
 qs.append(('all_parent_input_pointer_and_field_bits',z3.Or(*bad)));counts['parent_provenance_bytes']=16
 TASK=z3.BitVec('client_obj_task_export_word64',64);ADDRESS=z3.BitVec('client_obj_VM_address64',64);SIZE=z3.BitVec('client_obj_VM_encoded_size32',32);SP,OBJ,EXPORT=0x40000,0x50000,0x60000
 phase=run('cleanup_phase',0x100477624,0x100477638,[('sp',SP)],[(SP+0x9d0,8,z3.BitVecVal(0x6cf4,64))]);counts['cleanup_phase_value']=0x1074
 a=run('cleanup_task_address_size',0x100477640,0x100477654,[('sp',SP)],[(SP+0x348,8,EXPORT),(EXPORT,4,z3.Extract(31,0,TASK)),(SP+0x1930,8,OBJ),(OBJ,8,ADDRESS),(OBJ+8,4,SIZE)])
 key=run('cleanup_size_key',0x100477690,0x100477698)
 b=run('cleanup_size_codec',0x1004776a0,0x1004776a8,[('w8',a.read('w8')),('w11',key.read('w11')),('w19',phase.read('w19'))])
 qs.append(('all_cleanup_task_address_and_size_words',z3.Or(a.read('x0')!=z3.ZeroExt(32,z3.Extract(31,0,TASK)),a.read('x1')!=ADDRESS,b.read('x2')!=z3.ZeroExt(32,SIZE^0x8b3dc651))))
 return qs,counts
if __name__=='__main__':
 qs,counts=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('daemon_client_object_'+name+'_original.smt2');b=ROOT/('daemon_client_object_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer,s.model()if answer=='sat'else s.reason_unknown());b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_client_object_contracts.json','daemon_arena_lifetime_symbolic.py','lskd_values_symbolic.py','daemon_mig_handover_symbolic.json']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_client_object_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
