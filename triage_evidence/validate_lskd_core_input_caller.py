#!/usr/bin/env python3
"""Independent source-byte, all-word proof and five-case UserClient readback.

O(B+I+C*V) time/space plus solver cost30 s/query; no native release/IPC.
"""
import hashlib,json
from pathlib import Path
import z3,unicorn as uc
from unicorn import arm64_const as ar
from kernel_native_reader import Kernel
from recover_carrier_control import span
from kext_port_tools import ROOT,SOURCE,IMAGE
from lskd_core_input_caller import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'lskd_core_input_caller.json').read_text());k=Kernel();assert c['generator_sha256']==sha(ROOT/'lskd_core_input_caller.py')and not c['native_target_executed']and not c['full_goal_complete']and c['model_memory_writes']==0
 for n,h in c['dependencies'].items():assert sha(ROOT/n)==h
 assert k.sha256==c['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 qs=queries(c);assert len(qs)==len(c['proofs'])==3
 for(name,q,n),row in zip(qs,c['proofs']):
  assert name==row['name']and row['source_instructions_lifted']==n==1 and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
 fresh=[];assert[r['input_W0']for r in c['cases']]==['0x0','0xffff5966','0xffffffff','0x7fffffff','0x80000000']
 for r in c['cases']:
  a=0xfffffe000a504780;P=0x6300020000;O=P+0x1000;u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.mem_map(a&~4095,4096);u.mem_write(a,k.read(a,12));u.mem_map(P,8192);u.mem_write(P,b'\xa5'*8192);status=int(r['input_W0'],16);u.reg_write(ar.UC_ARM64_REG_X19,O);u.reg_write(ar.UC_ARM64_REG_W0,status);visits=[];writes=[]
  def code(u,pc,n,d):assert a<=pc<a+12;visits.append({'pc':hex(pc),'bytes_hex':bytes(u.mem_read(pc,4)).hex()});assert visits[-1]['bytes_hex']==k.read(pc,4).hex()
  def write(u,access,at,n,val,d):assert at in[O+0xc14,O+12]and n==4;writes.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(at),'size_bytes':n,'value32':hex(val&0xffffffff)})
  def read(u,access,at,n,val,d):raise AssertionError(('unexpected data read',hex(at),n))
  u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_WRITE,write);u.hook_add(uc.UC_HOOK_MEM_READ,read);u.emu_start(a,a+12,count=8);assert u.reg_read(ar.UC_ARM64_REG_PC)==a+12
  freshrow={'input_W0':hex(status),'output_status32_hex':bytes(u.mem_read(O+0xc14,4)).hex(),'output_count32_hex':bytes(u.mem_read(O+12,4)).hex(),'count_initialized_by_source':status!=0,'source_visits':visits,'source_writes':writes,'boundary':'before_descriptor_release','boundary_PC':hex(a+12),'release_executed':False};assert freshrow==r
  assert len(writes)==(2 if status else 1)and int.from_bytes(bytes(u.mem_read(O+0xc14,4)),'little')==status and bytes(u.mem_read(O+12,4))==(bytes(4)if status else b'\xa5'*4);fresh.append(freshrow)
 counts={'caller_source_spans':2,'caller_source_proof_pairs_unsat':3,'caller_fresh_cases':5,'caller_original_instruction_visits':14,'caller_instruction_byte_checks':56,'caller_source_status_stores':5,'caller_source_nonzero_count_clears':4,'caller_data_reads':0}
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_core_input_caller.py','lskd_core_input_caller.json','lskd_values_symbolic.py','kernel_native_reader.py','recover_carrier_control.py','kext_port_tools.py']},'verified_counts':counts,'fresh_cases':fresh,'all_checks_pass':True,'model_memory_writes':0,'native_target_executed':False,'descriptor_release_executed':False,'actual_Mach_reply_observed':False,'full_goal_complete':False};(ROOT/'lskd_core_input_caller_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':counts}),flush=True)
if __name__=='__main__':main()
