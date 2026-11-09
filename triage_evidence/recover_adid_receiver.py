#!/usr/bin/env python3
"""Recover adid receiver records, context gate and entitlement classifier.

Original bytes, exhaustive byte banks and source-derived signed CFG predicates.
No target/loader/API executes. O(B+F+R+256K+P), space O(B+F+R+P), where P
is the bounded acyclic classifier path count. SMT has a separate 30 s/query cap.
"""
import json
from pathlib import Path
import struct
import subprocess
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA


def classifier(s):
    a,z=0x100169ad4,0x100169f48
    ins={i.address:i for i in CS.disasm(s.read(a,z-a),a)};leaves={0x100169f48:'listed',0x10016a448:'zero',0x10016a118:'other'}
    paths=[];constants=set()
    def walk(pc,regs,cmp,path,visits):
        assert visits<512
        if pc in leaves:paths.append({'kind':leaves[pc],'condition':'(and '+' '.join(path)+')','leaf':hex(pc)});return
        i=ins[pc];op=i.op_str.split(', ');regs=dict(regs)
        if i.mnemonic in ('mov','movk') and op[0].startswith('w') and op[1].startswith('#'):
            v=int(op[1][1:],0)&0xffffffff
            if i.mnemonic=='movk':shift=int(op[2].split('#')[1]);v=(regs[op[0]]&~(65535<<shift))|(v<<shift)
            regs[op[0]]=v
        if i.mnemonic=='cmp':
            assert op[0]=='w8' and op[1] in regs;cmp=regs[op[1]];constants.add(cmp)
        if i.mnemonic=='b':return walk(int(op[0][1:],16),regs,cmp,path,visits+1)
        if i.mnemonic.startswith('b.'):
            cond={'b.le':'bvsle','b.gt':'bvsgt','b.eq':'=','b.ne':'distinct'}[i.mnemonic]
            test=f'({cond} key #x{cmp:08x})'
            walk(int(op[0][1:],16),regs,cmp,path+[test],visits+1)
            return walk(pc+4,regs,cmp,path+['(not '+test+')'],visits+1)
        assert i.mnemonic in ('mov','movk','cmp','ldr')
        walk(pc+4,regs,cmp,path,visits+1)
    walk(a,{},None,[],0)
    def concrete(key):
        pc=a;regs={};cmp=0;steps=0
        signed=lambda v:v-(1<<32) if v>>31 else v
        while pc not in leaves:
            steps+=1;assert steps<512;i=ins[pc];op=i.op_str.split(', ')
            if i.mnemonic in ('mov','movk') and op[0].startswith('w') and op[1].startswith('#'):
                v=int(op[1][1:],0)&0xffffffff
                if i.mnemonic=='movk':shift=int(op[2].split('#')[1]);v=(regs[op[0]]&~(65535<<shift))|(v<<shift)
                regs[op[0]]=v
            if i.mnemonic=='cmp':cmp=regs[op[1]]
            take=i.mnemonic=='b' or {'b.le':signed(key)<=signed(cmp),'b.gt':signed(key)>signed(cmp),'b.eq':key==cmp,'b.ne':key!=cmp}.get(i.mnemonic,False)
            pc=int(op[0][1:],16) if take else pc+4
        return leaves[pc]
    listed=sorted(c for c in constants if concrete(c)=='listed');zero=sorted(c for c in constants if concrete(c)=='zero')
    return {'start':hex(a),'end':hex(z),'bytes':s.read(a,z-a).hex(),'sha256':sha(s.read(a,z-a)),
        'paths':paths,'comparison_constants_u32':sorted(constants),'listed_keys_u32':listed,'zero_keys_u32':zero,
        'listed_values_under_XOR_u32':[c^0x3f4f8085 for c in listed],'decision_scope':'Original local CFG at encoded entitlement-key branch;surrounding prefix assumptions retained.'}


def main():
    s=Adid();cl=classifier(s);T=0x1002d8a80;banks=[]
    for label,a,b,key,c,offset,bias,expected in [
        ('getter_state1',0x1002c1f90,0x10027f330,0xff,5,0xac,0xc69b46f1,0x1002dcc10),
        ('getter_state2',0x1002c1f90,0x10027f330,0x26,29,0x15a,0x8af54b19,0x1002dcbb8),
        ('context_gate_cell',0x1002ade60,0x1002c1e90,0xf5,250,0x210,0xb8fcab7e,0x1002dd2e8)]:
        aa=s.read(a,256);bb=s.read(b,256);values=[j^bb[aa[j]^key] for j in range(256)];assert set(values)=={c}
        slot=T+(c+offset)*8;target=s.qword(slot)+struct.unpack('<i',struct.pack('<I',bias))[0];assert target==expected
        banks.append({'label':label,'first_address':hex(a),'second_address':hex(b),'first_bytes':aa.hex(),'second_bytes':bb.hex(),'key_u8':key,'constant_u8':c,
            'results_256':values,'pointer_slot':hex(slot),'pointer':s.decoded[slot],'signed_bias':struct.unpack('<i',struct.pack('<I',bias))[0],'resolved_address':hex(target)})
    def pred(kind):return '(or '+' '.join(p['condition'] for p in cl['paths'] if p['kind']==kind)+')'
    def member(values):return '(or '+' '.join(f'(= key #x{v:08x})' for v in values)+')'
    queries={
      'adid_entitlement_classifier.smt2':'(set-logic QF_BV)\n(set-option :timeout 30000)\n(declare-fun key () (_ BitVec 32))\n'+
          f'(assert (or (distinct {pred("listed")} {member(cl["listed_keys_u32"])}) (distinct {pred("zero")} {member(cl["zero_keys_u32"])})))\n(check-sat)\n',
      'adid_entitlement_number_XOR.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun value () (_ BitVec 32))
(define-fun folded () (_ BitVec 32) (bvsub (bvadd value #x3f4f8085) (bvand (bvshl value #x00000001) #x7e9f010a)))
(assert (distinct folded (bvxor value #x3f4f8085)))
(check-sat)
''',
      'adid_record_codec.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun address () (_ BitVec 64))
(declare-fun length () (_ BitVec 64))
(define-fun h () (_ BitVec 64) (bvmul (bvxor (bvadd (bvsub (bvor #xfe69be85c31ad656 (bvshl address #x0000000000000001)) address) #x80cb20bd1e7294d5) #x1f6967cae97a38fd) #x00000000255e728d))
(define-fun op () (_ BitVec 32) (bvsub #x00000d5b ((_ extract 31 0) h)))
(define-fun size () (_ BitVec 64) (bvadd length h))
(assert (or (distinct (bvadd op ((_ extract 31 0) h)) #x00000d5b) (distinct (bvsub size h) length)))
(check-sat)
'''}
    proofs=[]
    for name,q in queries.items():
        p=ROOT/name;p.write_text(q);run=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr
        proofs.append({'path':name,'sha256':sha(p.read_bytes()),'result':'unsat','scope':'Local CFG/value-fold/record arithmetic only;no native transaction or whole-program admission proof.'})
    small=[0x1000009f8,0x100029fc8,0x1000aa0ec,0x1000aab9c,0x1000621d4,0x100266dcc,0x10005cf44]
    ranges=[s.function(a) for a in small];large=[]
    for a in (s.entry,0x1001661f8):
        start,end=s.bounds(a);raw=s.read(a,end-a);large.append({'start':hex(a),'end':hex(end),'size_bytes':len(raw),'sha256':sha(raw),'full_body_retained':False})
    windows=[]
    for a,z,role in [(0x100169a1c,0x100169a60,'numeric entitlement MBA'),(0x1000aa7dc,0x1000aa854,'48-byte request encoding'),
        (0x1001695d0,0x100169a1c,'CF entitlement types/conversions'),(0x100168c10,0x100168c40,'audit ABI call'),
        (0x100168df0,0x1001691f4,'key/task/entitlement calls'),(0x100169f48,0x10016a118,'listed-value continuation'),
        (0x10016cb08,0x10016cc40,'effective UID and setup-file branch'),(0x100107630,0x100107680,'installation environment boundary'),
        (0x10016a7c0,0x10016a80c,'big-endian input-word loads')]:
        raw=s.read(a,z-a);windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'banks':banks,'classifier':cl,'proofs':proofs,
        'small_original_functions':ranges,'large_original_function_bounds':large,'selected_original_windows':windows,
        'literal_strings':[{'address':hex(a),'string':s.cstring(a,100),'bytes':(s.cstring(a,100).encode()+b'\0').hex()} for a in (0x1002baf90,0x1002a8c40,0x1002700a0,0x1002c219f,0x1002c2203,0x10028ed40,0x1002bccc5)],
        'sdk_headers':[{'path':str(p),'sha256':sha(p.read_bytes())} for p in [sdk/'usr/include/mach-o/fixup-chains.h',sdk/'usr/include/bsm/libbsm.h',sdk/'System/Library/Frameworks/CoreFoundation.framework/Headers/CFNumber.h']],
        'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','adid_inventory.json','corefp_client_paths_contracts.json']},
        'generator_sha256':sha(Path(__file__).read_bytes()),'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_receiver_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'listed_keys':len(cl['listed_keys_u32']),'zero_keys':cl['zero_keys_u32'],'listed_values_hex':[hex(v) for v in cl['listed_values_under_XOR_u32']],
        'banks':len(banks),'SMT_unsat':len(proofs)}))


if __name__=='__main__':main()
