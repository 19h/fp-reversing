#!/usr/bin/env python3
"""Original cleanup record codecs, dispatch targets and bounded scalar proofs.

Lifts original u32 operations; caller stack/pointer stores remain source
context. Five UNSAT obligations and a SAT alignment counterexample do not
prove native ownership, PAC, reachability or complete caller coverage.
O(B+F+I) extraction, five timeout-bounded SMT checks, O(largest profile) space.
"""
import hashlib,json,struct,subprocess
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,TABLE,qword,verify_original_fixups
from daemon_import_bindings import binding
from rpc502_parser_lift import Lift

RANGES=[(0x100444704,0x1004448f4),(0x1003aae74,0x1003aaf04),(0x1001f1988,0x1001f19f0),(0x1007483f0,0x100748510),(0x100723af8,0x100723bd0)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def helper(p):return Lift({'w0':p}).run(0x10044483c,0x100444870).regs['w11']
def secondary(p):return Lift({'w11':p}).run(0x100748414,0x100748448).regs['w11']
def primary(p):return Lift({'w10':p}).run(0x100723b08,0x100723b3c).regs['w10']
def selector(p,mode):
 k=helper(p);r=Lift({'w0':p},{'[x0, #0x10]':k^0x6922}).run(0x10044483c,0x100444878)
 # Original LDRB at444878 reads the declared mode-byte input.
 r.regs['w12']=z3.ZeroExt(24,mode);r.run(0x10044487c,0x100444890);r.run(0x1004448c4,0x1004448c8);return r.regs['w11']
def main():
 p=z3.BitVec('low32_argument_address',32);b=z3.BitVec('stored_mode_byte',8);h=helper(p);manual=((((0x3c642ede|(p<<1))-p+0xe1cde891)^0x885c4f7d)*0x592e2f77);queries=[('helper_formula',[],h!=manual),('secondary_codec',[],secondary(p)!=h),('primary_aligned_codec',[p&7==0],primary(p)!=h),('key_parity',[],h&1!=p&1),('dispatch_aligned',[p&7==0],selector(p,b)!=(z3.BitVecVal(0x6922,32)^z3.ZeroExt(24,b&1)*0xd323))];proofs=[]
 for name,assumptions,claim in queries:
  s=z3.Solver();s.set(timeout=60000);s.add(*assumptions,claim);path=ROOT/f'rpc502_cleanup_{name}.smt2';path.write_text('(set-option :timeout 60000)\n'+s.to_smt2());r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr;proofs.append({'name':name,'path':path.name,'sha256':sha(path),'result':'unsat','domain_assumptions':[str(a)for a in assumptions]})
 s=z3.Solver();s.set(timeout=60000);s.add(p&3==0,p&7!=0,primary(p)!=h);assert s.check()==z3.sat;m=s.model();w=m.eval(p).as_long();counterexample={'argument_low32':hex(w),'aligned4_not8':True,'helper_key':hex(m.eval(h).as_long()),'primary_constructor_key':hex(m.eval(primary(p)).as_long()),'scope':'Algebraic alignment counterexample only;not a runtime caller or exploit.'}
 profile=json.loads((ROOT/'rpc502_cleanup_profiles.json').read_text());fixups=set();targets=[]
 for row in profile['cases']:
  for e in row['source_fixups']:fixups.add(int(e['address'],16))
 for i in[0x6922,0x6922^0xd323]:
  a=TABLE+i*8;fixups.add(a);targets.append({'index':hex(i),'slot':hex(a),'word_hex':IMAGE.read(a,8).hex(),'target':hex(qword(a))})
 spans=[]
 for a,z in RANGES:
  raw=IMAGE.read(a,z-a);spans.append({'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]})
 original=[binding(a)if FIXUPS[a]['kind'].endswith('bind')else verify_original_fixups([a])['records'][0]for a in sorted(fixups)]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['probe_rpc502_cleanup.py','rpc502_cleanup_profiles.json','rpc502_parser_lift.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt']},'source_ranges':spans,'original_pointer_import_records':original,'selected_targets':targets,'proofs':proofs,'unaligned_counterexample':counterexample,'partial_argument_extent_bytes':24,'mapping_record_extent_bytes':32,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_cleanup_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_ranges':len(spans),'pointer_records':len(original),'proofs_unsat':len(proofs),'alignment_counterexample':counterexample}),flush=True)
if __name__=='__main__':main()
