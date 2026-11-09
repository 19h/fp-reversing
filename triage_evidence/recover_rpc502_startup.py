#!/usr/bin/env python3
"""Source-pinned startup/readiness/arena/embedded-certificate contracts.

Original opcodes,format12 fixups,compiler metadata;four local scalar proofs,
256-input pointer bank and SDK compile-only ABI checks. Certificate names and
RSA/SHA-1 relationships describe embedded bytes,not native trust acceptance.
O(B+V+E+S+R log F) bounded work plus timeout-limited solvers and integer pow.
"""
import base64,bisect,hashlib,json,struct,subprocess,zlib
from pathlib import Path
import z3
from daemon_receive_tools import IMAGE,SOURCE,ROOT,POOL,TABLE,FIXUPS,selected,qword,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_runtime import native
from recover_rpc502_parser_ownership import starts
from rpc502_parser_lift import Lift,b32
from rpc502_startup_tools import unpack,journals,certificate_view,rsa_sha1_relation

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 profiles=json.loads((ROOT/'rpc502_startup_profiles.json').read_text());fix={};apis={};results={}
 for w in profiles['cases']:
  r=unpack(w);results[w['case']['label']]=r
  for d in journals(r):
   for e in d['original_fixup_reads']:fix[int(e['address'],16)]=e['original_fixup']
   for e in d['records']:
    if e['kind']=='startup_declared_API_model':apis[e['name'],e['site']]=e
 consumed=[binding(a)if e['kind'].endswith('bind')else verify_original_fixups([a])['records'][0]for a,e in sorted(fix.items())]
 sx=lambda v:v-(1<<32)if v>>31 else v
 left=qword(POOL+0x29c8)+sx(0xaa591739);right=qword(POOL+0x4c18)+sx(0x8af86dcd);bank=selected(left,right,0xbb,0xf53,POOL,sx(0xd61754f2));assert bank['target']=='0x1010c5798'
 bank['left256_hex']=IMAGE.read(left,256).hex();bank['right256_hex']=IMAGE.read(right,256).hex();bank['inputs']=[{'input':x,'index':0xf53+(x^IMAGE.read(right,256)[IMAGE.read(left,256)[x]^0xbb])}for x in range(256)];bank['pointer_fixup']=verify_original_fixups([int(bank['slot'],16)])
 flag=z3.BitVec('ready_u8',8);seed=z3.BitVec('dispatch_seed_u32',32);v27=z3.BitVec('inherited_w27',32);pre=Lift({'w9':seed,'w27':v27}).run(0x100a0340c,0x100a03420);cond=Lift({'w10':z3.ZeroExt(24,flag)}).run(0x100a03428,0x100a03430).regs['w10'];coefficient=pre.regs['w8']*b32(0x4660)+pre.regs['w11']+b32(0x5c13);post=Lift({'w8':pre.regs['w8']*b32(0x4660)+pre.regs['w11'],'w9':seed,'w10':cond}).run(0x100a03438,0x100a03448);ptr=z3.BitVec('candidate_u64',64);null=Lift(loads={'[sp, #0xc4]':seed});null.cmp=(ptr,z3.BitVecVal(0,64));null.run(0x100a5c3d4,0x100a5c3e8);arena=Lift().run(0x10032a4dc,0x10032a4e4);error=Lift().run(0x100a5c3ec,0x100a5c3f4)
 obligations=[('readiness_index',post.regs['w8']!=(seed^z3.If(flag==1,coefficient,b32(0))),'Original a0340c..44;all u8 flags and all inherited u32 seed/W27. Only flag1 selects the readiness continuation.'),('NULL_candidate_index',null.regs['w8']!=(seed^z3.If(ptr==0,b32(0xfd6),b32(0))),'Original a5c3d0 comparison and a5c3d4..e4;all64-bit candidate pointers.'),('arena_size',arena.regs['w0']!=90000,'Original32a4dc..e0 MOV/MOVK W0;zero-extended malloc size.'),('allocation_error_codec',(error.regs['w10']^b32(0x8b3dc651))!=b32(0xffff5bd4),'Originala5c3ec/f0 constant;local encoded NULL result,not a universal error-name mapping.')]
 proofs=[]
 for name,expr,scope in obligations:
  s=z3.Solver();s.set(timeout=60000);s.add(expr);p=ROOT/('rpc502_startup_'+name+'.smt2');p.write_text('(set-option :timeout 60000)\n'+s.to_smt2());r=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr;proofs.append({'path':p.name,'sha256':sha(p),'result':'unsat','scope':scope})
 spans=[(0x100441470,0x1004414fc),(0x10045053c,0x100450788),(0x10032a480,0x10032a5e0),(0x10032ba44,0x10032bac0),(0x10046c73c,0x10046c77c),(0x100409548,0x100409598),(0x1002dc2f4,0x1002dc354),(0x1002dc380,0x1002dc414),(0x100193800,0x10019388c),(0x100130f94,0x100130fdc),(0x1003868b4,0x1003868f0),(0x100346520,0x100346570),(0x100969118,0x100969178),(0x100a04c54,0x100a04c78),(0x100a03408,0x100a03454),(0x1006521d4,0x100652250),(0x1009757d0,0x1009757e0),(0x100a5c3cc,0x100a5c400),(0x10065f100,0x10065f134),(0x1003466c0,0x100346744),(0x1003f0e48,0x1003f0e7c),(0x1003097fc,0x100309838),(0x1005fc0d0,0x1005fc150)]
 funcs,meta=starts();owners={}
 for a,z in spans:
  cur=a
  while cur<z:
   j=bisect.bisect_right(funcs,cur)-1;b,e=funcs[j:j+2];owners[b]={'start':hex(b),'end':hex(e),'sha256':hashlib.sha256(IMAGE.read(b,e-b)).hexdigest()};cur=min(z,e)
 certs=[]
 for label,off,n in [('root',0xe9eee0,1219),('key_services',0xf45a60,1035)]:
  raw=SOURCE.read_bytes()[off:off+n];decoded=bytes(x^0x98 for x in raw);der=decoded[4:];view=certificate_view(der);p=ROOT/('rpc502_startup_'+label+'.der');p.write_bytes(der);va=next(va+off-fo for va,fo,size in IMAGE.segments if fo<=off and off+n<=fo+size);assert IMAGE.read(va,n)==raw
  command=['/usr/bin/openssl','x509','-inform','DER','-in',str(p),'-noout','-subject','-issuer','-serial','-dates','-fingerprint','-sha256'];r=subprocess.run(command,capture_output=True,text=True,check=True);assert not r.stderr
  certs.append({'label':label,'source_file_offset':hex(off),'source_VA':hex(va),'source_size_bytes':n,'source_encoded_hex':raw.hex(),'codec_byte_XOR':'0x98','decoded_prefix4_hex':decoded[:4].hex(),'decoded_with_prefix_sha256':hashlib.sha256(decoded).hexdigest(),'DER_path':p.name,'DER_size_bytes':len(der),'DER_sha256':sha(p),'certificate_view':view,'independent_OpenSSL_command':command,'independent_OpenSSL_output':r.stdout})
 relations=[{'child':'root','issuer':'root',**rsa_sha1_relation(certs[0]['certificate_view'],certs[0]['certificate_view'])},{'child':'key_services','issuer':'root',**rsa_sha1_relation(certs[1]['certificate_view'],certs[0]['certificate_view'])}];assert all(e['exact_equality']for e in relations)
 sdk='/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk';cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',sdk,'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'rpc502_startup_layouts.c'),'-o',str(ROOT/'rpc502_startup_layouts.s')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_startup_profiles.json','probe_rpc502_startup.py','probe_rpc502_startup_cases.py','rpc502_startup_tools.py','rpc502_parser_lift.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','daemon_registration_contracts.json']},'entry':'0x10045053c','registered_once_call_site':'0x1004414e8','once_control':'0x1010b70c8','ready':'0x1010c5798','status':'0x1010b6360','source_ranges':[native(a,z)for a,z in spans],'compiler_ranges':list(owners.values()),'LC_FUNCTION_STARTS':meta,'ready_pointer_bank':bank,'local_dispatch_slots':[{'index':hex(i),'target':hex(qword(TABLE+i*8)),'pointer':verify_original_fixups([TABLE+i*8])['records'][0]}for i in [0x4891,0xa22f,0xa7ed,0xa83b]],'consumed_pointer_import_records':consumed,'startup_API_sites':[{'name':n,'site':s}for n,s in sorted(apis)],'proofs':proofs,'embedded_certificates':certs,'independent_RSA_SHA1_relations':relations,'sdk_compile':{'command':cmd,'source_sha256':sha(ROOT/'rpc502_startup_layouts.c'),'assembly_sha256':sha(ROOT/'rpc502_startup_layouts.s'),'exit_code':r.returncode},'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_startup_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(spans),'compiler_ranges':len(owners),'pointer_records':len(consumed),'proofs':len(proofs),'embedded_certificates':len(certs)}),flush=True)

if __name__=='__main__':main()
