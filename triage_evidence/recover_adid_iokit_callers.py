#!/usr/bin/env python3
"""Recover original caller prefixes, full-domain local codecs and call candidates.

Original source, fixups, SDK and finite retained private evidence only.
O(B+F+I+E) time/space for bytes,fixups,instructions and selected event records;
each SMT invocation has a separate 30 s timeout. No native target/API call.
"""
import collections
import json
from pathlib import Path
import subprocess
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA
from probe_adid_startup import unpack_records


def main():
    s=Adid();p=json.loads((ROOT/'adid_iokit_caller_profiles.json').read_text())
    queries={
    'adid_iokit_caller_primary_key32.smt2':'''(declare-fun a () (_ BitVec 32))
(define-fun original () (_ BitVec 32) (bvmul (bvxor (bvadd (bvsub (bvor #xf2429956 (bvshl a #x00000001)) a) #x86deb355) #xfa673807) #x0a42990d))
(assert (distinct original (bvmul (bvxor a #x834674ac) #x0a42990d)))''',
    'adid_iokit_caller_avp_key32.smt2':'''(declare-fun a () (_ BitVec 32))
(define-fun original () (_ BitVec 32) (bvmul (bvxor (bvadd (bvsub (bvor #x8531cf80 (bvshl a #x00000001)) a) #x3d671840) #x8c115aa6) #x0b08355f))
(assert (distinct original (bvmul (bvxor a #x4e89bd66) #x0b08355f)))''',
    'adid_iokit_caller_helper_keys32.smt2':'''(declare-fun a () (_ BitVec 32))
(define-fun primary () (_ BitVec 32) (bvmul (bvxor (bvadd (bvsub (bvor #x6ffa0856 (bvshl a #x00000001)) a) #xc802fbd5) #x3f0a57fd) #x255e728d))
(define-fun avp () (_ BitVec 32) (bvmul (bvxor (bvsub (bvand #x3214ed72 (bvnot a)) (bvor #x3214ed73 (bvnot a))) #xb15299df) #x0a42990d))
(assert (or (distinct primary (bvmul (bvxor a #x08f753d6) #x255e728d)) (distinct avp (bvmul (bvand (bvxor a #x834674ac) #xfffffffe) #x0a42990d)) (and (= (bvand a #x00000001) #x00000000) (distinct avp (bvmul (bvxor a #x834674ac) #x0a42990d)))))''',
    'adid_iokit_caller_status32.smt2':'''(declare-fun r () (_ BitVec 32))
(define-fun original () (_ BitVec 32) (bvadd (bvxor r #x43fff6ef) #xbc592da0 (bvand (bvshl r #x00000001) #x87ffedde)))
(assert (distinct original (bvadd r #x0059248f)))''',
    'adid_iokit_caller_size32.smt2':'''(declare-fun n () (_ BitVec 32))
(define-fun original () (_ BitVec 32) (bvadd (bvxor n #x424ef7af) #xbdf7df77 (bvand (bvshl n #x00000001) #x849def5e)))
(assert (distinct original (bvadd n #x0046d726)))''',
    'adid_iokit_caller_pointers64.smt2':'''(declare-fun p () (_ BitVec 64))
(define-fun primary () (_ BitVec 64) (bvadd p #x7e1f59740c8f6451))
(define-fun avp () (_ BitVec 64) (bvadd p #x68a91db5735d89de))
(assert (or (distinct (bvadd primary #x81e0a68bf3709baf) p) (distinct (bvadd avp #x9756e24a8ca27622) p) (distinct (= primary #x7e1f59740c8f6451) (= p #x0000000000000000)) (distinct (= avp #x68a91db5735d89de) (= p #x0000000000000000))))'''}
    proofs=[]
    for name,body in queries.items():
        path=ROOT/name;path.write_text('(set-logic QF_BV)\n(set-option :timeout 30000)\n'+body+'\n(check-sat)\n')
        run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr
        proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'Full stated local BV domain,under inspected source prefix;not full/native function proof.'})
    # Exhaustive text scan locates direct branches and exact immediate-modifier
    # sequences. A modifier candidate alone deliberately has no assigned target.
    text=next(x for x in s.meta['sections'] if x['section']=='__text');blob=s.read(text['address'],text['size']);tail=collections.deque(maxlen=12);candidates=[];direct=[];count=0
    scanner=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);scanner.skipdata=True;undecoded=[]
    for i in scanner.disasm(blob,text['address']):
        count+=1
        assert i.size==4
        if i.mnemonic=='.byte':
            undecoded.append({'address':hex(i.address),'bytes':bytes(i.bytes).hex()});tail.clear();continue
        if i.mnemonic in ('b','bl') and i.op_str in ('#0x1000208fc','#0x10002af70'):
            direct.append({'pc':hex(i.address),'mnemonic':i.mnemonic,'target':i.op_str[1:]})
        if i.mnemonic=='blraa' and i.op_str=='x8, x17' and tail and tail[-1]['mnemonic']=='mov' and tail[-1]['operands'] in ('x17, #0x2ea7','x17, #0xe41b'):
            a,z=s.bounds(i.address);start=int(tail[0]['ea'],16);raw=s.read(start,i.address+4-start)
            candidates.append({'pc':hex(i.address),'modifier':tail[-1]['operands'].split('#')[1],'compiler_start':hex(a),'compiler_end':hex(z),
                'window_start':hex(start),'window_bytes':raw.hex(),'window_sha256':sha(raw),'prefix_instructions':list(tail),'observed_private_targets':[]})
        tail.append({'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
    assert count*4==text['size']
    bypc={r['pc']:r for r in candidates};files=['adid_startup_profiles.json','adid_request_profiles.json','adid_context_profiles.json','adid_receiver_profiles.json','adid_iokit_caller_profiles.json'];observations={}
    for name in files:
        profiles=p['profiles'] if name==files[-1] else json.loads((ROOT/name).read_text())['profiles']
        for row in profiles:
            for e in unpack_records(row):
                if e['kind']=='PAC_bypassed_edge' and e.get('pc') in bypc:
                    key=(e['pc'],e['target']);o=observations.setdefault(key,{'source_file':name,'example_profile':row['fixture']['label'],'event':e,'occurrences':0});o['occurrences']+=1
    for (pc,target),o in observations.items():
        number=int(target,16);matches=[]
        for ptr in s.decoded.values():
            if ptr.get('diversity')!=o['event']['modifier']:continue
            actual=0x7c000000+ptr['import']['ordinal']*256 if ptr['bind'] else int(ptr['target'],16)
            if number==actual:matches.append(ptr)
        bypc[pc]['observed_private_targets'].append({**o,'matching_original_pointers':matches,'native_or_complete_static_reachability':False})
    collision=[r for r in s.decoded.values() if r.get('diversity') in ('0x2ea7','0xe41b','0xe258')]
    windows=[]
    for a,z,role in [(0x100058654,0x100058d48,'complete Avp selector100 caller'),(0x1000590ac,0x100059860,'complete primary initialization caller')]:
        raw=s.read(a,z-a);assert s.bounds(a)==(a,z)
        windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk');command=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'adid_iokit_caller_layouts.c'),'-o',str(ROOT/'adid_iokit_caller_layouts.s')]
    run=subprocess.run(command,capture_output=True,text=True);assert run.returncode==0 and not run.stderr
    header=sdk/'System/Library/Frameworks/IOKit.framework/Headers/IOKitLib.h'
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'proofs':proofs,'original_windows':windows,
        'rejected_unconditional_helper_key':{'address_u32':'0x84945e0f','scope':'Original Avp caller constructor masks low pointer bit;unconditional unmasked equality was falsified by SMT. The actual stack record address is even.',
            'correct_general_key':'((low32(P) XOR 0x834674ac) AND 0xfffffffe) * 0x0a42990d mod 2^32','aligned_corollary':'When P AND 1 = 0,the mask may be omitted.'},
        'whole_text_scan':{'address':hex(text['address']),'size_bytes':len(blob),'sha256':sha(blob),'four_byte_units':count,'decoded_instruction_count':count-len(undecoded),'undecoded_four_byte_units':undecoded,'direct_helper_branches':direct,'modifier_candidates':candidates,
            'scope':'Exact direct/immediate-modifier patterns only;not an exhaustive set of possible indirect callers.'},'modifier_collision_pointers':collision,
        'SDK_compile':{'command':command,'source_sha256':sha((ROOT/'adid_iokit_caller_layouts.c').read_bytes()),'assembly_sha256':sha((ROOT/'adid_iokit_caller_layouts.s').read_bytes()),'exit_code':run.returncode},
        'SDK_header':{'path':str(header),'sha256':sha(header.read_bytes())},'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_iokit_callers.py','adid_iokit_caller_profiles.json',*files[:-1]]},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_iokit_caller_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'proofs':len(proofs),'source_windows':len(windows),'text_instruction_scan':count,'modifier_candidates':len(candidates),
        'privately_observed_candidate_sites':len({k[0] for k in observations}),'collision_pointers':len(collision),'SDK_compile_exit':run.returncode}))


if __name__=='__main__':main()
