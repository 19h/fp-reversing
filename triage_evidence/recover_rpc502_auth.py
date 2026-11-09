#!/usr/bin/env python3
"""Original issuer-byte/length/status and verification-record contracts.

Source opcodes/fixups/compiler metadata;three full-domain scalar obligations,
a full-word status counterexample,original fixed DN and SDK partial views.
O(B+V+E+S+R log F) work/space plus60000 ms bounded local solvers.
No native authentication,target APIs or IDB mutations.
"""
import bisect,hashlib,json,subprocess
from pathlib import Path
import z3
from daemon_receive_tools import IMAGE,SOURCE,ROOT,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_runtime import native
from recover_rpc502_parser_ownership import starts
from rpc502_startup_tools import unpack,journals,certificate_view
from rpc502_auth_models import status_lift,length_lift,first_status_lift,name_text,K,E,D

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 A=z3.BitVec('saved_word32',32);B=z3.BitVec('prior_status32',32);i=z3.BitVec('next_index64',64);L=z3.BitVec('extent64',64);x=z3.BitVec('plaintext_byte8',8);y=z3.BitVec('encoded_byte8',8);s32=status_lift(A,B);byte_cond=z3.Extract(7,0,z3.SignExt(24,x)^z3.ZeroExt(24,y))==0x81
 obligations=[('first_status_byte',first_status_lift(A)!=z3.If(A&255==0xa2,z3.BitVecVal(K,32),z3.BitVecVal(E,32)),'Original950fd8..951038,all32-bit raw inputs,observed W9=W10=1;other seeds excluded.'),('status_low_bytes',s32!=z3.If(z3.And(A&255==0,B&255==0x51),z3.BitVecVal(K,32),z3.BitVecVal(E,32)),'Original896930..9a4,all pairs of32-bit words;high bytes are not tested.'),('biased_extent',length_lift(i,L)!=z3.ULT(i,L),'Original64b420..484,all64-bit next indices/extents;encoded limit=L+502230ca mod2^64,previous=i-1.'),('signed_byte_equal',byte_cond!=(x==(y^0x81)),'Originala46fc0..fd8;all65536 byte pairs,including signed LDRSB values.')];proofs=[]
 for name,expr,scope in obligations:
  s=z3.Solver();s.set(timeout=60000);s.add(expr);p=ROOT/('rpc502_auth_'+name+'.smt2');p.write_text('(set-option :timeout 60000)\n'+s.to_smt2());r=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr;proofs.append({'path':p.name,'sha256':sha(p),'result':'unsat','scope':scope})
 counter={'saved32':'0x100','prior32':'0x51','result32':hex(z3.simplify(z3.substitute(s32,(A,z3.BitVecVal(0x100,32)),(B,z3.BitVecVal(0x51,32)))).as_long()),'full_word_success_test_false':True,'source_state_or_native_reachability_not_asserted':True};assert int(counter['result32'],16)==K
 p=json.loads((ROOT/'rpc502_auth_profiles.json').read_text());fix={}
 for w in p['cases']:
  for d in journals(unpack(w)):
   for e in d['original_fixup_reads']:fix[int(e['address'],16)]=e['original_fixup']
 consumed=[binding(a)if f['kind'].endswith('bind')else verify_original_fixups([a])['records'][0]for a,f in sorted(fix.items())]
 literal=IMAGE.read(0x100f266a4,98);decoded=bytes(x^0x81 for x in literal);key=(ROOT/'rpc502_startup_key_services.der').read_bytes();assert decoded==name_text(certificate_view(key),'subject')+b'\0'
 spans=[(0x10064b420,0x10064b4ac),(0x100a46fc0,0x100a47008),(0x10076d108,0x10076d180),(0x100915078,0x10091509c),(0x10069cae8,0x10069cb18),(0x100a04b6c,0x100a04b84),(0x100890ff4,0x10089102c),(0x1009752e0,0x100975350),(0x100896930,0x1008969c4),(0x100950fd8,0x100951050),(0x10065f118,0x10065f134),(0x100a7da60,0x100a7dafc),(0x1009607b4,0x1009607e8),(0x100a70008,0x100a70038),(0x1000dd0d8,0x1000dd0e4),(0x100082318,0x10008237c),(0x100421ec4,0x100421fa0),(0x1002c3888,0x1002c3930),(0x1005fc0d0,0x1005fc150)]
 f,meta=starts();owners={}
 for a,z in spans:
  cur=a
  while cur<z:
   j=bisect.bisect_right(f,cur)-1;b,e=f[j:j+2];owners[b]={'start':hex(b),'end':hex(e),'sha256':hashlib.sha256(IMAGE.read(b,e-b)).hexdigest()};cur=min(z,e)
 sdk='/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk';cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',sdk,'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'rpc502_auth_layouts.c'),'-o',str(ROOT/'rpc502_auth_layouts.s')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_auth_profiles.json','probe_rpc502_auth.py','probe_rpc502_auth_cases.py','rpc502_auth_fixtures.py','rpc502_auth_models.py','rpc502_auth_certificate_inventory.json','rpc502_startup_tools.py','rpc502_startup_key_services.der','rpc502_startup_contracts.json','rpc502_parser_lift.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt']},'source_ranges':[native(a,z)for a,z in spans],'compiler_ranges':list(owners.values()),'LC_FUNCTION_STARTS':meta,'consumed_pointer_import_records':consumed,'proofs':proofs,'status_full_word_counterexample':counter,'fixed_issuer_DN':{'source_address':'0x100f266a4','size_bytes':98,'original_encoded_hex':literal.hex(),'byte_XOR':'0x81','decoded_ascii_including_NUL':decoded.decode('ascii'),'source_key_services_subject_matches':True},'signature_digest_partial_view':{'signature_offset':0x490,'signature_capacity_bytes':256,'signature_size_offset':0x590,'signature_size_XOR':hex(K),'digest_size_offset':0x594,'digest_offset':0x598,'digest_size_observed':20,'signature_bytes':'raw DER signature bytes','digest_byte_XOR':'0x98','child_register_at97531c':'X9','issuer_register_at97531c':'X11','complete_type_unknown':True},'sdk_compile':{'command':cmd,'source_sha256':sha(ROOT/'rpc502_auth_layouts.c'),'assembly_sha256':sha(ROOT/'rpc502_auth_layouts.s'),'exit_code':r.returncode},'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_auth_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(spans),'compiler_ranges':len(owners),'pointer_records':len(consumed),'proofs':len(proofs)}),flush=True)

if __name__=='__main__':main()
