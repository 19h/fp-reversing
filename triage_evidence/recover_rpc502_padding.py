#!/usr/bin/env python3
"""Original exported-block byte contracts,ROM prefixes and local scalar proofs.

Seven obligations with explicit input/seed domains and60 s solver bounds.
O(B+V+E+S+R log F) work/space;no native target/API or IDB mutation.
Does not prove complete malformed-input acceptance or all caller conditions.
"""
import bisect,hashlib,json,subprocess
from pathlib import Path
import z3
from daemon_receive_tools import IMAGE,SOURCE,ROOT,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_runtime import native
from recover_rpc502_parser_ownership import starts
from rpc502_startup_tools import unpack,journals
from rpc502_auth_models import first_status_lift
from rpc502_padding_lifts import header_lift,pad_lift,separator_lift,prefix_lift,difference_lift,failure_fold_lift
from rpc502_padding_oracles import PREFIX,H0,H1,H2

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 a=z3.ZeroExt(24,z3.BitVec('candidate_byte8',8));b=z3.ZeroExt(24,z3.BitVec('reference_byte8',8));e=z3.ZeroExt(24,z3.BitVec('prior_error8',8));A=z3.BitVec('candidate_word32',32);B=z3.BitVec('reference_word32',32);status=z3.BitVec('raw_status32',32)
 obligations=[('header_bytes',header_lift(a,b)!=(H0^((a^0x98)|(b^0x99))),'All65536 encoded-byte pairs;source9d8fd8..9010,observed W25=7249.'),('padding_byte',pad_lift(H0^e,b)!=(H0^(e|(b^0x67))),'All prior-error8/current-byte8 pairs;sourcea75c00..2c,observed W10=67d0.'),('separator_byte',separator_lift(H0^e,b)!=(H2^(e|(b^0x98))),'All prior-error8/separator-byte8 pairs;source9329a8..9e4,observed W10=67d0;LDRB result injected at the correct source point.'),('prefix_byte',prefix_lift(H1^e,a,b)!=(H1^(e|(a^b))),'All24-bit prior-error/current/reference triples;source656dc8..dd4;only the stated byte-mask state domain.'),('digest_difference',difference_lift(A,B)!=((A^0x98)-(B^0x98)),'All pairs of32-bit words;sourcea46c04..cc0,observed W15=4a29;actual inputs are LDRB bytes.'),('observed_failure_fold',failure_fold_lift(b)!=0x40df015d,'All256 selected bytes;sourcea7c674..6a0,fixed observed incoming failure word40df015d only;not arbitrary caller state.'),('first_status_reduction',first_status_lift(status)!=z3.If(status&255==0xa2,z3.BitVecVal(0x8b3dc651,32),z3.BitVecVal(0x74c29d8a,32)),'All raw32-bit words;source950fd8..1038,observed W9=W10=1;not a complete verification acceptance predicate.')];proofs=[]
 for name,expr,scope in obligations:
  s=z3.Solver();s.set(timeout=60000);s.add(expr);p=ROOT/('rpc502_padding_'+name+'.smt2');p.write_text('(set-option :timeout 60000)\n'+s.to_smt2());r=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr;proofs.append({'path':p.name,'sha256':sha(p),'result':'unsat','scope':scope})
 data=json.loads((ROOT/'rpc502_padding_profiles.json').read_text());fix={}
 for w in data['cases']:
  for d in journals(unpack(w)):
   for e in d['original_fixup_reads']:fix[int(e['address'],16)]=e['original_fixup']
 spans=[(0x1009d8fcc,0x1009d9014),(0x100a75be4,0x100a75c7c),(0x1009329a8,0x100932a04),(0x100656dbc,0x100656dfc),(0x10065a648,0x10065a67c),(0x100882dc0,0x100882dfc),(0x100a46c04,0x100a46cd0),(0x100a61544,0x100a61628),(0x100aa74ac,0x100aa7504),(0x100a7c62c,0x100a7c6bc),(0x100950fd8,0x100951050),(0x100896930,0x1008969c4)]
 f,meta=starts();owners={}
 for a,z in spans:
  cur=a
  while cur<z:
   j=bisect.bisect_right(f,cur)-1;b,e=f[j:j+2];owners[b]={'start':hex(b),'end':hex(e),'sha256':hashlib.sha256(IMAGE.read(b,e-b)).hexdigest()};cur=min(z,e)
 literals=[]
 for h,a in[(20,0x100ee5a50),(32,0x100f1fc42)]:
  raw=IMAGE.read(a,len(PREFIX[h]));decoded=bytes(x^0x98 for x in raw);assert decoded==PREFIX[h];literals.append({'address':hex(a),'digest_extent_bytes':h,'extent_bytes':len(raw),'original_encoded_hex':raw.hex(),'byte_XOR':'0x98','decoded_hex':decoded.hex()})
 deps=['rpc502_padding_profiles.json','probe_rpc502_padding.py','probe_rpc502_padding_cases.py','rpc502_padding_lifts.py','rpc502_padding_oracles.py','rpc502_parser_lift.py','rpc502_auth_models.py','rpc502_startup_tools.py','rpc502_startup_root.der','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'source_ranges':[native(a,z)for a,z in spans],'compiler_ranges':list(owners.values()),'LC_FUNCTION_STARTS':meta,'consumed_pointer_import_records':[binding(a)if f['kind'].endswith('bind')else verify_original_fixups([a])['records'][0]for a,f in sorted(fix.items())],'proofs':proofs,'DigestInfo_literals':literals,'complete_acceptance_language_unknown':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'rpc502_padding_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(spans),'compiler_ranges':len(owners),'pointer_records':len(fix),'proofs':len(proofs),'ROM_prefixes':len(literals)}),flush=True)
if __name__=='__main__':main()
