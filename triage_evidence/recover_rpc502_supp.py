#!/usr/bin/env python3
"""Supplemental original-source ranges,local formulas,metadata and SDK view.

Read-only byte/fixup/LC_FUNCTION_STARTS recovery;five bounded32/64-bit SMT
obligations and compile-only arm64e C layout checks. O(B+I+E+F+R log F)
time/space apart from solver cost;no native target or IDB execution/mutation.
"""
import base64,bisect,hashlib,json,struct,subprocess,zlib
from pathlib import Path
import z3
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_runtime import native
from recover_rpc502_parser_ownership import starts
from rpc502_parser_lift import Lift,b32

K=0x8b3dc651

def unpack(row):return json.loads(zlib.decompress(base64.b64decode(row['payload_zlib_base64'])))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p=json.loads((ROOT/'rpc502_supp_profiles.json').read_text());cases={w['case']['label']:unpack(w)for w in p['cases']};sample=cases['byte_1'];D,B,N,P=[z3.BitVec(v,32)for v in ['cursor32','body_length32','extent32','pointer_low32']]
    guard=Lift({}, {'[x22, #0x5b4]':B^b32(K),'[x1, #0x1d80]':D,'[x1, #0x1d6c]':N+b32(0x4b224d13)}).run(0x10049bc34,0x10049bd4c)
    small=Lift({'w9':0x49db},{'[x21, #0x10]':N^b32(0xc8bcf32b)}).run(0x1008b5170,0x1008b5200)
    caller=Lift({'w20':P}).run(0x100500b58,0x100500b8c)
    P64=z3.BitVec('pointer64',64);C1=z3.BitVecVal(0xdb148e013b2a80e8,64);C2=~C1;C3=z3.BitVecVal(0x4f632cfcfdfce0fc,64);callee=(((P64|C1)-(P64|C2)+C2)^C3)*z3.BitVecVal(0x6b86592f,64)
    context=next(e for e in sample['supplemental_call_frames']if e['pc']=='0x1005b94fc');reg=[int(v,16)&0xffffffff for v in context['registers_x0_x28']];W=z3.BitVec('wire_word32',32);hi=W&b32(0xffffff00);lo=W&b32(255);a=(hi-((hi<<1)&b32(reg[6]))+b32(reg[7]))^b32(reg[20]);b=lo-((lo<<1)&b32(reg[23]))+b32(reg[2]);reader=((a&(b^b32(reg[5])))^(b&b32(reg[1])))^b32(reg[0])
    queries=[('minimum4_decode',small.regs['w11']!=N,'Original1008b5170..5200,W9=0x49db,mapping encoded low32=N XOR0xc8bcf32b;following CMP#4 is unsigned.'),('extent_guard',guard.regs['w12']!=z3.If(z3.UGT(D+B+b32(128),N),b32(1),b32(0)),'Original10049bc34..bd4c,frameAD80=D,frameAD6C=N+0x4b224d13,reader=B XOR K. Sum is modulo2^32,not a widened no-overflow proof.'),('caller_address_key',caller.regs['w17']!=(P^b32(0xc6d66014))*b32(0x6b86592f),'Original100500b58..b8c,W20=low32(argument pointer).'),('callee_address_key',z3.Extract(31,0,callee)!=(z3.Extract(31,0,P64)^b32(0xc6d66014))*b32(0x6b86592f),'Original64-bit OR/sub/add/XOR/multiply10099ac90..ace0;only low32keyequivalence claimed.'),('be32_reader',reader!=(W^b32(K)),'Original1005b94fc..954c and95b8 with retained parameter registers;universal32-bit word identity,context-specific source state.')]
    proofs=[]
    for name,expr,scope in queries:
        s=z3.Solver();s.set(timeout=30000);s.add(expr);path=ROOT/('rpc502_supp_'+name+'.smt2');path.write_text('(set-option :timeout 30000)\n'+s.to_smt2());r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr);proofs.append({'path':path.name,'sha256':sha(path),'result':'unsat','scope':scope})
    spans=[(0x1008b5170,0x1008b522c),(0x100895d54,0x100895db8),(0x10095e7f0,0x10095e828),(0x100a43b8c,0x100a43bc8),(0x1008776f4,0x100877734),(0x1005b94f0,0x1005b95e8),(0x10049bc34,0x10049bd80),(0x100500ad4,0x100500cd4),(0x100118ecc,0x100118f70),(0x100081080,0x100081238),(0x10010e334,0x10010e510),(0x10000b1a0,0x10000b380),(0x1009d53cc,0x1009d562c),(0x10099ab1c,0x10099ada8),(0x100a4fd10,0x100a4fd68),(0x1009519b8,0x100951a04),(0x100315a80,0x100315b30),(0x10022cb54,0x10022cbc4),(0x10065f118,0x10065f15c),(0x100c21198,0x100c21210),(0x100d943d0,0x100d944d0),(0x100cc0810,0x100cc0880),(0x100c85da8,0x100c85e6c),(0x100dacb54,0x100dacb78),(0x100dcf770,0x100dcf794),(0x1008ec6a0,0x1008ec720),(0x1003aae74,0x1003aaf04),(0x1001f1988,0x1001f19fc)]
    fixed={};apis={}
    for r in cases.values():
        for e in r['original_fixup_reads']:fixed[int(e['address'],16)]=e['original_fixup']
        for e in r['explicit_parser_models']:
            key=(e['name'],e['site']);apis[key]={'name':key[0],'site':key[1],'visits':apis.get(key,{}).get('visits',0)+1}
    fixups=[]
    for a,e in sorted(fixed.items()):fixups.extend([binding(a)]if e['kind'].endswith('bind')else verify_original_fixups([a])['records'])
    funcs,meta=starts();owners={};parts=[]
    for a,z in spans:
        cur=a;segments=[]
        while cur<z:
            i=bisect.bisect_right(funcs,cur)-1;start,end=funcs[i:i+2];owners[start]={'start':hex(start),'end':hex(end),'size_bytes':end-start,'sha256':hashlib.sha256(IMAGE.read(start,end-start)).hexdigest()};limit=min(z,end);segments.append({'start':hex(cur),'end':hex(limit),'compiler_range_start':hex(start)});cur=limit
        parts.append({'start':hex(a),'end':hex(z),'segments':segments})
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk');cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'rpc502_supp_layouts.c'),'-o',str(ROOT/'rpc502_supp_layouts.s')];run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0 and not run.stderr,(run.stdout,run.stderr)
    out={'scope':__doc__,'source_sha256':sha(SOURCE),'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_supp_profiles.json','probe_rpc502_supp.py','probe_rpc502_supp_cases.py','rpc502_parser_lift.py','daemon_receive_tools.py','daemon_import_bindings.py','recover_rpc502_parser_ownership.py','daemon_receive_fixups.txt']},'original_ranges':[native(a,z)for a,z in spans],'proofs':proofs,'be32_parameter_context':context,'observed_API_sites':list(apis.values()),'original_fixup_records':fixups,'LC_FUNCTION_STARTS':meta,'compiler_start_count':len(funcs),'compiler_ranges':list(owners.values()),'range_ownership':parts,'sdk_compile':{'command':cmd,'exit_code':run.returncode,'source_sha256':sha(ROOT/'rpc502_supp_layouts.c'),'assembly_sha256':sha(ROOT/'rpc502_supp_layouts.s'),'target_executed':False},'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_supp_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(spans),'compiler_ranges':len(owners),'fixups':len(fixups),'proofs':len(proofs),'API_sites':len(apis)}),flush=True)

if __name__=='__main__':main()
