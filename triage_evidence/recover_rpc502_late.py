#!/usr/bin/env python3
"""Original late width/pointer/hash/signature/public-operation contracts.

Two local scalar obligations60 s each;source spans/fixups/compiler metadata,
SDK partial views. O(B+V+E+S+R log F) recovery plus bounded solvers.
No native target/API/IDB action;not complete trust or protected processing.
"""
import bisect,hashlib,json,subprocess
from pathlib import Path
import z3
from daemon_receive_tools import IMAGE,SOURCE,ROOT,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_runtime import native
from recover_rpc502_parser_ownership import starts
from rpc502_startup_tools import unpack,journals
from rpc502_late_lifts import width_lift,auxiliary_offset_lift

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 count=z3.BitVec('stored_count32',32);C=z3.BitVec('C32',32);aux=z3.BitVec('auxiliary32',32);status=z3.BitVec('saved_status32',32);seed=z3.BitVec('dispatch_seed32',32);expected=(((seed+0x83b4)^0x8b3d25e5)+seed);offset=aux+seed+0xd59ecc1e-z3.If(status==expected,z3.BitVecVal(1,32),z3.BitVecVal(0,32));obligations=[('signature_width',width_lift(count,C)!=(C==4*(count-0x693be708)),'Originala21958..a21ac4;all32-bit count/C words,observed W12=1daa only;modular equality,not valid extent.'),('auxiliary_offset',auxiliary_offset_lift(aux,status,seed)!=offset,'Originala8b838..a8b878;all triples of32-bit aux/status/dispatch words;pointer ADD separately uses zero-extended32 offset.')];proofs=[]
 for name,expr,scope in obligations:
  s=z3.Solver();s.set(timeout=60000);s.add(expr);p=ROOT/('rpc502_late_'+name+'.smt2');p.write_text('(set-option :timeout 60000)\n'+s.to_smt2());r=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr;proofs.append({'path':p.name,'sha256':sha(p),'result':'unsat','scope':scope})
 fix={}
 for name in['rpc502_late_profiles.json','rpc502_late_span_profiles.json']:
  p=json.loads((ROOT/name).read_text())
  for w in p['cases']:
   for d in journals(unpack(w)):
    for e in d['original_fixup_reads']:fix[int(e['address'],16)]=e['original_fixup']
 spans=[(0x100747f6c,0x100747fd0),(0x100a8b838,0x100a8b8b4),(0x100976134,0x100976180),(0x100a21958,0x100a21ae8),(0x10065730c,0x1006574cc),(0x100647aa0,0x100647bc0),(0x10008ead0,0x10008eb40),(0x100919314,0x100919338),(0x100a0a5c0,0x100a0a610),(0x100450a5c,0x100450c14),(0x100950fd8,0x100951050),(0x100655808,0x100655830)]
 f,meta=starts();owners={}
 for a,z in spans:
  cur=a
  while cur<z:
   j=bisect.bisect_right(f,cur)-1;b,e=f[j:j+2];owners[b]={'start':hex(b),'end':hex(e),'sha256':hashlib.sha256(IMAGE.read(b,e-b)).hexdigest()};cur=min(z,e)
 sdk='/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk';cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',sdk,'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'rpc502_late_layouts.c'),'-o',str(ROOT/'rpc502_late_layouts.s')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 counter={'decoded_count32':'0x40000000','stored_count32':hex((0x693be708+0x40000000)&0xffffffff),'C32':0,'local_width_predicate':True,'valid_header_capacity_native_extent_or_reachability_not_asserted':True};assert z3.is_true(z3.simplify(width_lift(z3.BitVecVal(int(counter['stored_count32'],16),32),z3.BitVecVal(0,32))))
 deps=['rpc502_late_profiles.json','rpc502_late_span_profiles.json','probe_rpc502_late.py','probe_rpc502_late_cases.py','probe_rpc502_late_spans.py','rpc502_late_lifts.py','rpc502_parser_lift.py','rpc502_late_ida_context.json','rpc502_rsa_models.py','rpc502_startup_tools.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'source_ranges':[native(a,z)for a,z in spans],'compiler_ranges':list(owners.values()),'LC_FUNCTION_STARTS':meta,'consumed_pointer_import_records':[binding(a)if f['kind'].endswith('bind')else verify_original_fixups([a])['records'][0]for a,f in sorted(fix.items())],'proofs':proofs,'width_modular_counterexample':counter,'selected_public_operation_view':{'selected_built_prefix_bytes':80,'exponent_pointer64':8,'status_output32':16,'modulus_pointer64':32,'exported_extent_pointer64':40,'encoded_output_pointer64':56,'signature_input_pointer64':64,'other_fields_and_complete_type_unknown':True},'sdk_compile':{'command':cmd,'source_sha256':sha(ROOT/'rpc502_late_layouts.c'),'assembly_sha256':sha(ROOT/'rpc502_late_layouts.s'),'exit_code':0},'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'rpc502_late_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(spans),'compiler_ranges':len(owners),'pointer_records':len(fix),'proofs':len(proofs)}),flush=True)
if __name__=='__main__':main()
