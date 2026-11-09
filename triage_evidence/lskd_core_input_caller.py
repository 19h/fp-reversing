#!/usr/bin/env python3
"""Source-local UserClient status publication after the selector18 provider call.

No provider, release or transport executes. Five private W0 fixtures execute
only status/count stores, stopping before descriptor release. All-word source
lemmas prove each store and the separate transport-return instruction.
O(B+I+C*V) time/space plus solver cost30 s/query.
"""
import hashlib,json
from pathlib import Path
import z3,unicorn as uc
from unicorn import arm64_const as ar
from kernel_native_reader import Kernel
from recover_carrier_control import span
from kext_port_tools import ROOT,SOURCE,IMAGE
from lskd_values_symbolic import Lift,part,mem,cell
P=0x6300020000;O=P+0x1000
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def queries(c):
 S=z3.BitVec('provider_return_status32',32);R=z3.BitVec('userclient_output64',64);rows=[]
 for label,a,z,regseeds in [('status32_store',0xfffffe000a504780,0xfffffe000a504784,[('w0',S),('x19',R)]),('nonzero_status_count_clear',0xfffffe000a504788,0xfffffe000a50478c,[('x19',R)]),('outer_transport_return',0xfffffe000a5047bc,0xfffffe000a5047c0,[])]:
  v=Lift(part(c,label,a,z))
  for n,val in regseeds:v.seed(n,val)
  v.run(label);q=cell(v,R+0xc14,4)!=S if label=='status32_store'else cell(v,R+12,4)!=0 if label=='nonzero_status_count_clear'else v.read('w0')!=0;rows.append((label,q,v.count))
 return rows
def main():
 k=Kernel();spans=[]
 for name,a,z in [('status_and_release_frontier',0xfffffe000a504780,0xfffffe000a5047ac),('outer_return_instruction',0xfffffe000a5047bc,0xfffffe000a5047c0)]:
  s=span(k,a,z);assert IMAGE.read(a,z-a).hex()==s['bytes_hex'];s['label']=name;spans.append(s)
 c={'spans':spans};proofs=[]
 for name,q,n in queries(c):
  original=z3.Solver();original.add(q);op=ROOT/f'lskd_core_input_caller_{name}_original.smt2';op.write_text(original.to_smt2());solver=z3.Solver();solver.set(timeout=30000);solver.add(z3.simplify(q));assert str(solver.check())=='unsat';p=ROOT/f'lskd_core_input_caller_{name}.smt2';p.write_text(solver.to_smt2());proofs.append({'name':name,'file':p.name,'sha256':sha(p),'original_file':op.name,'original_sha256':sha(op),'source_instructions_lifted':n,'result':'unsat'})
 rows=[]
 for status in[0,0xffff5966,0xffffffff,0x7fffffff,0x80000000]:
  u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);a=0xfffffe000a504780;u.mem_map(a&~4095,4096);u.mem_write(a,k.read(a,12));u.mem_map(P,8192);u.mem_write(P,b'\xa5'*8192);u.reg_write(ar.UC_ARM64_REG_X19,O);u.reg_write(ar.UC_ARM64_REG_W0,status);visits=[];writes=[]
  def code(u,pc,n,d):assert a<=pc<a+12;visits.append({'pc':hex(pc),'bytes_hex':bytes(u.mem_read(pc,4)).hex()})
  def write(u,access,at,n,val,d):assert at in[O+0xc14,O+12]and n==4;writes.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(at),'size_bytes':n,'value32':hex(val&0xffffffff)})
  u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_WRITE,write);u.emu_start(a,a+12,count=8);statusbytes=bytes(u.mem_read(O+0xc14,4));countbytes=bytes(u.mem_read(O+12,4));assert int.from_bytes(statusbytes,'little')==status and countbytes==(bytes(4)if status else b'\xa5'*4);assert len(visits)==(3 if status else 2)and len(writes)==(2 if status else 1)
  rows.append({'input_W0':hex(status),'output_status32_hex':statusbytes.hex(),'output_count32_hex':countbytes.hex(),'count_initialized_by_source':status!=0,'source_visits':visits,'source_writes':writes,'boundary':'before_descriptor_release','boundary_PC':'0xfffffe000a50478c','release_executed':False})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','recover_carrier_control.py','kext_port_tools.py','lskd_values_symbolic.py']},'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'spans':spans,'proofs':proofs,'cases':rows,'composition_premise':'Actual selector18 provider/core returns W0 and original UserClient keeps output in X19. Native descriptor release/transport are unexecuted. The outer W0=0 instruction is proved separately, conditional on reaching it.','model_memory_writes':0,'native_target_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_core_input_caller.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'local_status_cases':len(rows),'source_proof_pairs':len(proofs),'source_instruction_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
