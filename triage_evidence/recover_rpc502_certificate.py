#!/usr/bin/env python3
"""Source-pinned TLV/schema/digest/atomic contracts and analytical SDK views.

Original bytes/fixups/compiler metadata;six local SMT obligations and one
unaligned counterexample. O(B+I+F+R log F) bounded time/space plus solver cost.
No target/IDB execution. Standards names are source-backed identifications,
not evidence of certificate trust,native protocol acceptance or conformance.
"""
import base64,bisect,hashlib,json,struct,subprocess,zlib
from pathlib import Path
import z3
from daemon_receive_tools import IMAGE,SOURCE,ROOT,FIXUPS,CS,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_runtime import native
from recover_rpc502_parser_ownership import starts
from rpc502_parser_lift import Lift,b32

T=0x1010389a0
NAMES=['Certificate','TBSCertificate','version_context0','version_INTEGER','serialNumber','tbs_signature_AlgorithmIdentifier','tbs_signature_OID','tbs_signature_parameters_NULL','issuer','validity','notBefore_UTCTime','notAfter_UTCTime','subject','subjectPublicKeyInfo','issuerUniqueID_context1','subjectUniqueID_context2','extensions_context3','Extensions_SEQUENCE','Extension_SEQUENCE','extension_OID','critical_BOOLEAN','extnValue_OCTET_STRING','signature_AlgorithmIdentifier','signature_OID','signature_parameters_NULL','signature_BIT_STRING']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 P=z3.BitVec('pointer32',32);tag=z3.BitVec('tag32',32);W=z3.BitVec('decoded_state_word32',32);K=(P^b32(0xe732d262))*b32(0xba209ef7);callee=Lift({'w0':P}).run(0x10044dd8c,0x10044ddc4);caller=Lift({'w10':P}).run(0x100a656dc,0x100a65714);tree=Lift({'w20':0x6dbd},{'[sp, #0x30c]':tag^b32(0x21e8ae22)}).run(0x1009106f8,0x100910768)
 E=W^b32(0xf4f92df7);a=z3.LShR(E,24);b=a^b32(-12);top=b-(((b&b32(0x1a))^(a&b32(2)))<<1)-b32(0x68);mid=z3.LShR(E,16)^b32(-7);mid=mid-((mid<<1)&b32(0x30))-b32(0x68);low=z3.LShR(E,8)^b32(0x2d);low=low-((low<<1)&b32(0x30))-b32(0x68);last=E^b32(0x6f);parts=[top,mid,low,last];writer=z3.Or(*[z3.Extract(7,0,v)!=z3.Extract(31-8*j,24-8*j,W)^z3.BitVecVal(0x98,8)for j,v in enumerate(parts)])
 byte=z3.BitVec('input_byte8',8);decoded=byte-((byte<<1)&z3.BitVecVal(0x44,8))+z3.BitVecVal(0x22,8)
 digest_key=Lift({'w0':P}).run(0x10045c53c,0x10045c570)
 obligations=[('digest_initializer_key',digest_key.regs['w10']!=(P^b32(0xf9d49974))*b32(0xda51a827),'Original45c53c..45c570;all32-bit pointers.'),('item_callee_key',callee.regs['w11']!=K,'Original44dd8c..ddc4,all32-bit P.'),('item_aligned_caller_key',z3.And(P&7==0,caller.regs['w9']!=K),'Originala656dc..a65714,8-byte-aligned argument pointer;unaligned equivalence is false.'),('tag_table_domain',tree.regs['w10']!=tag+b32(0x6ca5fa1a),'Original9106f8..910768,W20=0x6dbd,tag frame=tag XOR0x21e8ae22.'),('digest_writer',writer,'Original0c6974..0c6a04 state XOR0xf4f92df7 -> big-endian bytes XOR0x98;address offsets checked in actual stores.'),('tag_byte_codec',decoded!=(byte^z3.BitVecVal(0x22,8)),'Low8 original315aec..315b04;the low5==31 branch remains a separate predicate.')]
 proofs=[]
 for name,expr,scope in obligations:
  solver=z3.Solver();solver.set(timeout=60000);solver.add(expr);path=ROOT/('rpc502_certificate_'+name+'.smt2');path.write_text('(set-option :timeout 60000)\n'+solver.to_smt2());r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr);proofs.append({'path':path.name,'sha256':sha(path),'result':'unsat','scope':scope})
 solver=z3.Solver();solver.add(P&7!=0,caller.regs['w9']!=K);assert solver.check()==z3.sat;witness=solver.model()[P].as_long();ce={'pointer32':hex(witness),'caller_key':hex(z3.simplify(z3.substitute(caller.regs['w9'],(P,b32(witness)))).as_long()),'callee_key':hex(z3.simplify(z3.substitute(K,(P,b32(witness)))).as_long())}
 rows=[];slots=[]
 for j,name in enumerate(NAMES):
  a=T+48*j;raw=IMAGE.read(a,48);words=struct.unpack('<12I',raw);callback=FIXUPS[a+8]['target']if a+8 in FIXUPS else struct.unpack_from('<Q',raw,8)[0]
  if callback:slots.append(a+8)
  edges=[(words[k]-0x3fcc2052)&0xffffffff for k in [8,9]];assert all(e==0xffffffff or e<26 for e in edges);rows.append({'index':j,'address':hex(a),'raw_hex':raw.hex(),'decoded_tag':hex((words[0]-0x5cbf4ba3)&0xffffffff),'callback':hex(callback),'encoded_scalar16':hex(words[4]),'child':None if edges[0]==0xffffffff else edges[0],'sibling':None if edges[1]==0xffffffff else edges[1],'decoded_flags':hex((words[10]-0x2f9615c4)&0xffffffff),'RFC5280_schema_inference':name})
 visited=set();todo=[0]
 while todo:
  j=todo.pop()
  if j in visited:continue
  visited.add(j);todo.extend(v for v in [rows[j]['child'],rows[j]['sibling']]if v is not None)
 assert visited==set(range(26))
 spans=[(0x10044dd40,0x10044deac),(0x100a65678,0x100a657f8),(0x100315ac0,0x100315b30),(0x10022cb54,0x10022cbc4),(0x1002fe914,0x1002fe950),(0x1002f04d4,0x1002f04e0),(0x1009106f8,0x100910790),(0x1008c2d64,0x1008c2da0),(0x1009e5630,0x1009e567c),(0x100656f2c,0x100656f8c),(0x100a859c4,0x100a859fc),(0x10092445c,0x100924570),(0x10045c4f0,0x10045c61c),(0x100440be4,0x100440d6c),(0x1003c3b88,0x1003c3b9c),(0x100490494,0x1004904d0),(0x10031cf38,0x10031cf70),(0x1000a3d14,0x1000a3d90),(0x1000c6970,0x1000c6a10),(0x10026542c,0x1002654d0),(0x1002c3888,0x1002c3930),(0x10044f7a4,0x10044f7bc),(0x100a04c54,0x100a04c78)]
 profiles=json.loads((ROOT/'rpc502_certificate_profiles.json').read_text());allfix={}
 for wrapped in profiles['cases']:
  case=json.loads(zlib.decompress(base64.b64decode(wrapped['payload_zlib_base64'])))
  for e in case['original_fixup_reads']:allfix[int(e['address'],16)]=e['original_fixup']
 fixed=[]
 for a,e in sorted(allfix.items()):fixed.extend([binding(a)]if e['kind'].endswith('bind')else verify_original_fixups([a])['records'])
 funcs,meta=starts();owners={}
 for a,z in spans:
  cur=a
  while cur<z:
   i=bisect.bisect_right(funcs,cur)-1;b,e=funcs[i:i+2];owners[b]={'start':hex(b),'end':hex(e),'sha256':hashlib.sha256(IMAGE.read(b,e-b)).hexdigest()};cur=min(z,e)
 sdk='/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk';cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',sdk,'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'rpc502_certificate_layouts.c'),'-o',str(ROOT/'rpc502_certificate_layouts.s')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_certificate_profiles.json','probe_rpc502_body.py','probe_rpc502_certificate_cases.py','rpc502_body_fixtures.py','rpc502_parser_lift.py','daemon_receive_tools.py','daemon_receive_fixups.txt']},'schema_base':hex(T),'schema_stride_bytes':48,'schema_rows':rows,'root_reachable_schema_rows':sorted(visited),'schema_pointer_fixups':verify_original_fixups(slots),'all_observed_pointer_fixups':fixed,'original_ranges':[native(a,z)for a,z in spans],'compiler_ranges':list(owners.values()),'LC_FUNCTION_STARTS':meta,'proofs':proofs,'unaligned_counterexample':ce,'digest_initialization':{'encoded_words':['0x93bc0ef6','0x1b34867e','0x6c43f109','0xe4cb7981','0x372bcc07'],'word_xor_key':'0xf4f92df7','SHA1_IV':['0x67452301','0xefcdab89','0x98badcfe','0x10325476','0xc3d2e1f0'],'encoded_byte_key':'0x98'},'primary_references':[{'url':'https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A','used_for':'RSAPublicKey schema and signature algorithm OID names;not target acceptance'},{'url':'https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf','section':'5.3.1 and6.1','used_for':'SHA-1 constants and reference algorithm;not target trust'},{'url':'https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1','used_for':'Certificate schema field-name inference;not full conformance'},{'url':'https://www.rfc-editor.org/rfc/rfc1321.html','used_for':'Independent MD5 oracle for algorithm-OID4 fixture'}],'sdk_compile':{'command':cmd,'exit_code':r.returncode,'source_sha256':sha(ROOT/'rpc502_certificate_layouts.c'),'assembly_sha256':sha(ROOT/'rpc502_certificate_layouts.s')},'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_certificate_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(spans),'compiler_ranges':len(owners),'schema_rows':len(rows),'proofs':len(proofs),'unaligned_counterexample':ce}),flush=True)

if __name__=='__main__':main()
