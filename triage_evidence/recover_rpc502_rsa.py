#!/usr/bin/env python3
"""Original Montgomery/record interfaces,source provenance and scalar proofs.

O(B+V+E+S+R log F) bounded recovery;four local SMT obligations60 s each.
SDK compile only;no native target/API/IDB or actual trust-policy execution.
"""
import bisect,hashlib,json,subprocess
from pathlib import Path
import z3
from daemon_receive_tools import IMAGE,SOURCE,ROOT,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_runtime import native
from recover_rpc502_parser_ownership import starts
from rpc502_startup_tools import unpack,journals
from rpc502_rsa_models import square_key_lift,product_key_lift,count_magnitude_lift

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 P=z3.BitVec('argument_low32',32);x=z3.BitVec('word32',32);K=z3.BitVecVal(0xada56e3c,32);used=x-0x693be708;mag=z3.If(used>=0,used,-used)
 obligations=[('square_address_key',square_key_lift(P)!=((P^0x7a9247f6)*0x31b6b333),'All2^32 pointer low words;source539ff8..53a030.'),('product_address_key',product_key_lift(P)!=((P^0x966e5812)*0x592e2f77),'All2^32 pointer low words;source945a98..945ad4.'),('limb_store_codec',x-((K<<1)&(x<<1))+K!=(x^K),'All2^32 output words;source5fc110..120 and97fc10..20.'),('count_magnitude',z3.If((x+0x96c418f8)>=0,x+0x96c418f8,0x693be708-x)!=mag,'All2^32 stored counts;INT_MIN magnitude remains unsigned80000000;no source extent validity implied.')];proofs=[]
 for name,expr,scope in obligations:
  s=z3.Solver();s.set(timeout=60000);s.add(expr);path=ROOT/('rpc502_rsa_'+name+'.smt2');path.write_text('(set-option :timeout 60000)\n'+s.to_smt2());r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr;proofs.append({'path':path.name,'sha256':sha(path),'result':'unsat','scope':scope})
 p=json.loads((ROOT/'rpc502_rsa_profiles.json').read_text());fix={}
 for w in p['cases']:
  for d in journals(unpack(w)):
   for e in d['original_fixup_reads']:fix[int(e['address'],16)]=e['original_fixup']
 spans=[(0x100539ea0,0x100539f04),(0x100539fec,0x10053a09c),(0x10053db60,0x10053dbcc),(0x10053dca4,0x10053dcc0),(0x1005fc0d0,0x1005fc150),(0x10094593c,0x1009459a4),(0x100945a8c,0x100945b28),(0x100947eb0,0x100947f18),(0x100948018,0x100948038),(0x10097fbc8,0x10097fc60),(0x10091686c,0x1009168d8),(0x1009752e0,0x100975350)]
 f,meta=starts();owners={}
 for a,z in spans:
  cur=a
  while cur<z:
   j=bisect.bisect_right(f,cur)-1;b,e=f[j:j+2];owners[b]={'start':hex(b),'end':hex(e),'sha256':hashlib.sha256(IMAGE.read(b,e-b)).hexdigest()};cur=min(z,e)
 sdk='/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk';cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',sdk,'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'rpc502_rsa_layouts.c'),'-o',str(ROOT/'rpc502_rsa_layouts.s')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_rsa_profiles.json','probe_rpc502_rsa.py','probe_rpc502_rsa_cases.py','rpc502_rsa_fixtures.py','rpc502_rsa_models.py','rpc502_startup_tools.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt']},'source_ranges':[native(a,z)for a,z in spans],'compiler_ranges':list(owners.values()),'LC_FUNCTION_STARTS':meta,'consumed_pointer_import_records':[binding(a)if f['kind'].endswith('bind')else verify_original_fixups([a])['records'][0]for a,f in sorted(fix.items())],'proofs':proofs,'selected_record_views':{'integer':{'selected_extent_bytes':16,'capacity_u32':0,'biased_signed_count32':4,'count_bias':'0x693be708','limb_pointer64':8,'limb_byte_order':'little','limb_XOR32':'0xada56e3c'},'certificate':{'modulus_integer_offset':0x210,'exponent_integer_offset':0x320},'square':{'selected_extent_bytes':40,'context64':0,'add_mode32':8,'output64':16,'operand64':24,'modulus64':32,'mode_key':'((P_low32 XOR7a9247f6)*31b6b333) mod2^32','seed_add64':0x70},'product':{'selected_extent_bytes':48,'context64':0,'modulus64':8,'output64':16,'left64':24,'xor_mode32':32,'right64':40,'mode_key':'((P_low32 XOR966e5812)*592e2f77) mod2^32','seed_add64':0xe0},'context':{'selected_extent_bytes':24,'radix_integer64':0,'precomputation_integer64':8,'n0prime_u32':16,'padding20_unknown':True},'complete_types_unknown':True},'sdk_compile':{'command':cmd,'source_sha256':sha(ROOT/'rpc502_rsa_layouts.c'),'assembly_sha256':sha(ROOT/'rpc502_rsa_layouts.s'),'exit_code':0},'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_rsa_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(spans),'compiler_ranges':len(owners),'pointer_records':len(fix),'proofs':len(proofs)}),flush=True)
if __name__=='__main__':main()
