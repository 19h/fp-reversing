#!/usr/bin/env python3
"""Original RPC502 parser guards,record codec,frame producers and cleanup ABI.

Read original bytes/fixups,construct local source-derived formulas,compile
record shapes and preserve observed boundaries. O(B+I+E) time/space apart from
seven timeout-bounded local SMT obligations. No native target or IDB mutation.
"""
import base64,hashlib,json,struct,subprocess,zlib
from pathlib import Path
import z3
from daemon_receive_tools import IMAGE,SOURCE,ROOT,FIXUPS,TABLE,CS,qword,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_runtime import native
from rpc502_parser_lift import Lift,b32


def unpack(row):return json.loads(zlib.decompress(base64.b64decode(row['payload_zlib_base64'])))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    p=json.loads((ROOT/'rpc502_parser_profiles.json').read_text());cases={v['case']['label']:unpack(v)for v in p['cases']};sample=cases['selector_0x1'];prep=next(v for v in sample['parser_points']if v['pc']=='0x1009b7728');w23=int(prep['registers_x0_x28'][23],16)&0xffffffff;assert w23==0x928
    n=z3.BitVec('length32',32);word=z3.BitVec('word32',32);selector=z3.BitVec('selector32',32);byte=z3.BitVec('byte8',8);K=0x8b3dc651;B=0xa30e544d
    regs={f'w{i}':int(v,16)&0xffffffff for i,v in enumerate(prep['registers_x0_x28'])};length=Lift(regs,{'[sp, #0x234]':n^b32(K)}).run(0x1009b7728,0x1009b787c);guard=Lift({'w9':word^b32(K^0xec3e0ab8),'w3':0x33a0},{'[sp, #0x1d8]':n+b32(B)}).run(0x100a50508,0x100a505ac)
    # Source comparisons at a6876c/ac0490/ac8354/ab6c3c are signed32.
    enc=word^b32(K);header_tree=z3.If(enc<b32(0x8b3dc652),enc==b32(0x8b3dc650),z3.If(enc<b32(0x8b3dc654),enc==b32(0x8b3dc652),enc==b32(0x8b3dc654)))
    typed=selector^b32(K);selector_tree=z3.If(typed>=b32(K^2),typed==b32(K^2),typed==b32(K^1))
    # Derive the selector threshold and equality basis from original ALU prefixes.
    a=Lift({'w3':0x33a0}).run(0x100644b70,0x100644b88);b=Lift({**a.regs,'w20':typed}).run(0x10064aa10,0x10064aa44);threshold=z3.simplify(b.cmp[1]);basis=z3.simplify(b.regs['w8']);assert threshold.as_long()==K^2 and basis.as_long()==K^1
    queries=[('frame_length_minus57',length.stores['[sp, #0x1d0]']!=n-b32(57),'original preparation W23=0x928,stack234=length32 XOR K'),('frame_length_additive',length.stores['[sp, #0x1d8]']!=n+b32(B),'same source preparation prefix'),('header_length_guard',guard.regs['w8']!=z3.If(z3.ULT(n,word),b32(0xbe39),b32(0xafe2)),'source W3=0x33a0,reader W9=word32 XOR0x6703cce9,stack1d8=length32+B'),('minimum57',z3.ULT(n-b32(57),b32(-57))!=z3.UGE(n,b32(57)),'source CMN/CSET LO condition at97288c/972890'),('header_set',header_tree!=z3.Or(*[word==b32(i)for i in [1,3,5]]),'local modern-constructor selection tree;earlier branches/native reachability excluded'),('selector_set',selector_tree!=z3.Or(selector==b32(1),selector==b32(2)),'source inner-selector tree with threshold/equality ALU prefixes checked'),('byte_codec',(byte-((byte<<1)&z3.BitVecVal(0x30,8))-z3.BitVecVal(0x68,8))!=(byte^z3.BitVecVal(0x98,8)),'low8 byte transformation;register-shift variants additionally checked in finite source cases')]
    proofs=[]
    for name,formula,scope in queries:
        solver=z3.Solver();solver.set(timeout=30000);solver.add(formula);path=ROOT/('rpc502_parser_'+name+'.smt2');path.write_text('(set-option :timeout 30000)\n'+solver.to_smt2());r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr);proofs.append({'path':path.name,'sha256':sha(path),'result':'unsat','scope':scope})
    spans=[(0x1009b7728,0x1009b787c),(0x1009b6eac,0x1009b7014),(0x100a49ca0,0x100a49cd0),(0x100a50508,0x100a505bc),(0x100930174,0x1009301f0),(0x100a386a8,0x100a386ec),(0x100a65870,0x100a658b0),(0x1008910f0,0x100891144),(0x100976f98,0x100976fe8),(0x100a68734,0x100a68794),(0x10099ffd4,0x1009a0040),(0x100ac0480,0x100ac04b4),(0x100ac8324,0x100ac8380),(0x100ab6c24,0x100ab6c6c),(0x100972888,0x1009728c8),(0x100913528,0x1009135d4),(0x1009d8804,0x1009d88f4),(0x100644b70,0x100644b9c),(0x10064aa10,0x10064aa5c),(0x100a604f0,0x100a60558),(0x1009e9afc,0x1009e9b30),(0x10094e1dc,0x10094e210),(0x100c717a0,0x100c717e0),(0x100656fe8,0x10065702c),(0x1009bb5c4,0x1009bb900),(0x100926bc0,0x100926c00),(0x100c116e4,0x100c11744),(0x10097d3f0,0x10097d460),(0x1008ec6a0,0x1008ec720),(0x1003aae74,0x1003aaf04),(0x1001f1988,0x1001f19fc),(0x1005eeb20,0x1005eebac),(0x100d943d0,0x100d944d0)]
    slots={};API={};shift_contexts=set()
    for r in cases.values():
        for e in r['original_fixup_reads']:slots[int(e['address'],16)]=e['original_fixup']
        for e in r['explicit_parser_models']:
            key=(e['name'],e['site']);API[key]={'name':key[0],'site':key[1],'visits':API.get(key,{}).get('visits',0)+1}
        for point in r['parser_points']:
            if point['pc']=='0x1009bb5c4':value=int(point['registers_x0_x28'][9],16)&0xffffffff;shift_contexts.add(value);assert (value+0x4da1)&31==1
    fixed=[]
    for address in sorted(slots):
        item=slots[address]
        if item['kind'].endswith('bind'):fixed.append(binding(address))
        else:fixed.extend(verify_original_fixups([address])['records']if isinstance(verify_original_fixups([address]),dict)else verify_original_fixups([address]))
    targetcells=[]
    for index,want in [(0xafe2,0x100aaea34),(0xbe39,0x100b6b01c)]:
        a=TABLE+8*index;assert qword(a)==want;targetcells.append({'index':hex(index),'slot':hex(a),'target':hex(want),'original_word_hex':IMAGE.read(a,8).hex(),'original_fixup':FIXUPS[a]})
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk');cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'rpc502_parser_layouts.c'),'-o',str(ROOT/'rpc502_parser_layouts.s')];run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0 and not run.stderr,(run.stdout,run.stderr)
    out={'scope':__doc__,'source_sha256':sha(SOURCE),'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_parser_profiles.json','probe_rpc502_parser.py','probe_rpc502_parser_cases.py','rpc502_parser_lift.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt']},'original_ranges':[native(a,z)for a,z in spans],'original_fixup_records':fixed,'header_guard_target_cells':targetcells,'local_formula_preconditions':{'frame_w23':hex(w23),'guard_w3':'0x33a0','encoded_length_key':hex(K),'additive_length_bias':hex(B),'selector_threshold':hex(threshold.as_long()),'selector_equality_basis':hex(basis.as_long()),'byte_copy_shift_W9_contexts':[hex(v)for v in sorted(shift_contexts)]},'observed_parser_API_sites':list(API.values()),'byte_codec_exhaustive_256':[{'input_u8':v,'source_u8':(v-((v<<1)&0x30)-0x68)&255,'xor_u8':v^0x98}for v in range(256)],'proofs':proofs,'sdk_compile':{'command':cmd,'exit_code':run.returncode,'source_sha256':sha(ROOT/'rpc502_parser_layouts.c'),'assembly_sha256':sha(ROOT/'rpc502_parser_layouts.s'),'target_executed':False},'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_parser_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(spans),'fixups':len(fixed),'proofs':len(proofs),'API_sites':len(API),'shift_contexts':len(shift_contexts)}),flush=True)

if __name__=='__main__':main()
