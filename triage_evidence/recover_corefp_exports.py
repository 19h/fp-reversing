#!/usr/bin/env python3
"""Original CoreFP exports, constant byte banks, ABI records and SDK context.

No target code/API/loader runs. O(B+F+256*K+R) time and O(B+F+R) space
for image bytes, fixups, bank pairs and retained small original ranges.
SMT solving is separate and bounded by a 30 s solver timeout per query.
"""
import json
from pathlib import Path
import plistlib
import subprocess
import struct
from corefp_fixups_reader import Pointers,ROOT,sha,THIN_SHA,SHA


def main():
    s=Pointers();t=0x1d05fa0;banks=[]
    specs=[('version_cell1',0x18ac270,0x1ac1ac0,0xc8,0xc0),
           ('version_cell2',0x18ac270,0x1ac1ac0,0xe7,0x1f),
           ('version_target',0x1ac19c0,0x1c78040,0x78,0x2e),
           ('version_table',0x1ac19c0,0x1c78040,0x78,0x2e),
           ('version_branch_table',0x174f220,0x18ac170,0xa5,0xd6),
           ('packet_cell1',0x174f320,0x18ac370,0xe4,0xec),
           ('packet_cell2',0x174f220,0x18ac170,0x0b,0x09),
           ('packet_target',0x174f220,0x18ac170,0xa5,0xd6),
           ('packet_table',0x174f320,0x18ac370,0xe5,0xaa)]
    for label,a,b,k,v in specs:
        aa=s.read(a,256);bb=s.read(b,256);values=[i^bb[aa[i]^k] for i in range(256)]
        assert set(values)=={v}
        banks.append({'label':label,'first_address':hex(a),'second_address':hex(b),
            'key_u8':k,'constant_u8':v,'first_bytes':aa.hex(),'second_bytes':bb.hex(),
            'results_256':values,'all_inputs_verified':True})
    slots=[t+off for off in [0xe750,0x3fc8,0x3560,0x55f0,0xab68,0x38d0]]
    slots += [0x1d0cc48,0x1d120a8,0x1d108e8,0x1d044b8,0x1c9aac8,0x1c9ab00,0x1d07590,0x1d04730]
    pointers=[s.decoded[a] for a in dict.fromkeys(slots)]
    assert s.qword(0x1d044b8)==0x20f6fc and s.qword(0x1d04730)==0x27afd4
    assert s.qword(0x1c9aac8)==0x20f820 and s.qword(0x1c9ab00)==0x20f7fc
    ranges=[]
    for at in [0xcd20,0x20f6fc,0xe160,0x27afd4,0x111e538,0x2f7030,0x28994,0x728048]:
        ix=s.starts.index(at);end=s.starts[ix+1];raw=s.read(at,end-at)
        row={'start':hex(at),'end':hex(end),'size_bytes':len(raw),'sha256':sha(raw),'complete_compiler_bounds':True}
        if len(raw)<=0x4000:row['original_function']=s.function(at)
        ranges.append(row)
    queries={
      'corefp_version_address_mix.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun p () (_ BitVec 32))
(define-fun encmix () (_ BitVec 32) (bvxor (bvadd (bvsub (bvor #xeeb345b4 (bvshl p #x00000001)) p) #x08a65d26) #xc773bcad))
(define-fun decmix () (_ BitVec 32) (bvxor (bvadd (bvsub (bvor p #x640e7db3) p) (bvand p #x9bf1824c)) #x542463c4))
(assert (or (distinct encmix (bvxor p #x302a1e77)) (distinct decmix (bvxor p #x302a1e77))))
(check-sat)
''',
      'corefp_version_operation.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
; Equal source mixes are proved in corefp_version_address_mix.smt2.
(declare-fun encmix () (_ BitVec 32))
(declare-fun decmix () (_ BitVec 32))
(assert (= encmix decmix))
(define-fun stored () (_ BitVec 32) (bvxor (bvmul encmix #xcae5b081) #x00003231))
(define-fun decoded () (_ BitVec 32) (bvxor stored (bvmul decmix #xcae5b081)))
(assert (distinct decoded #x00003231))
(check-sat)
''',
      'corefp_version_partition.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun ptr () (_ BitVec 64))
(define-fun c () (_ BitVec 32) (ite (= ptr #x0000000000000000) #x00000000 #x00000001))
(define-fun index () (_ BitVec 32) (bvxor #x00003231 (bvor c (bvshl c #x00000003))))
(assert (distinct index (ite (= ptr #x0000000000000000) #x00003231 #x00003238)))
(check-sat)
''',
      'corefp_packet_record_codec.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun p () (_ BitVec 32))
(declare-fun mode () (_ BitVec 32))
(declare-fun length () (_ BitVec 32))
(define-fun mixed () (_ BitVec 32) (bvxor (bvor (bvand p #x1202bc8f) (bvnot (bvor p #x1202bc8f))) #xdd69c4de))
(define-fun key () (_ BitVec 32) (bvmul mixed #x87cfdb29))
(define-fun encoded_mode () (_ BitVec 32) (bvadd mode key))
(define-fun encoded_length () (_ BitVec 32) (bvsub length key))
(assert (or (distinct mixed (bvxor p #x309487ae)) (distinct (bvsub encoded_mode key) mode) (distinct (bvadd encoded_length key) length)))
(check-sat)
'''}
    proofs=[]
    for name,q in queries.items():
        path=ROOT/name;path.write_text(q)
        result=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True)
        assert result.stdout.strip()=='unsat' and not result.stderr,(name,result.stdout,result.stderr)
        proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat',
            'scope':'Full-width local algebra only; packet inverse algebra does not establish a backend decoder.'})
    plist_path=Path('/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/Resources/Info.plist')
    raw=plist_path.read_bytes();plist=plistlib.loads(raw)
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
    sdk_headers=[{'path':str(sdk/x),'sha256':sha((sdk/x).read_bytes())}
                 for x in ['usr/include/unistd.h','usr/include/sys/mman.h','usr/include/pthread.h',
                           'usr/include/mach/message.h','usr/include/mach/ndr.h']]
    requests=[]
    for entry,call,mid,n,cap,const in [(0x8ae0,0x8ba8,1200,64,220,0x15d6970),
          (0x8d40,0x8e04,1201,164,44,0x15d6978),(0x8ed4,0x8f90,1202,84,80,0x15d6980),
          (0x90c8,0x914c,1203,24,60,0x15d6988),(0x1590824,0x15908c8,1200,56,64,0x15d6970)]:
        literal=s.read(const,8);assert struct.unpack('<II',literal)==(0,mid)
        requests.append({'entry':hex(entry),'callsite':hex(call),'request_id':mid,'send_bytes':n,'receive_capacity_bytes':cap,
            'header_voucher_and_id_literal':{'address':hex(const),'bytes':literal.hex()},'expected_reply_id':mid+100,
            'remote_port':'original W0','local_and_receive_port':'modeled _mig_get_reply_port result; actual name unknown',
            'mach_msg_options_u32':3,'remote_disposition_u8':19,'local_disposition_u8':21,
            'body_descriptors':0 if entry in (0x8d40,0x90c8) else 1,
            'endpoint_identity':'unknown','protected_export_reachability':'unknown'})
    targets={int(x['entry'],16) for x in requests}
    refs=[x for x in s.decoded.values() if not x['bind'] and int(x['target'],16) in targets]
    out={'scope':__doc__,'source_sha256':SHA,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'preferred_base':hex(s.base),
        'fixups_count':len(s.decoded),'imports_count':len(s.imports),'ranges':ranges,'banks':banks,'pointers':pointers,'proofs':proofs,
        'distinct_bank_identities':len({(a,b,k) for _,a,b,k,v in specs}),
        'fixup_inventory_sha256':sha((ROOT/'corefp_fixups_inventory.json').read_bytes()),
        'bundle':{'path':str(plist_path),'sha256':sha(raw),'identifier':plist['CFBundleIdentifier'],
            'short_version':plist['CFBundleShortVersionString'],'version':plist['CFBundleVersion']},
        'version_query':{'entry':'0xcd20','helper':'0x20f6fc','callsite':'0xcefc','operation_u32':0x3231,
            'record_size_bytes':16,'fields':[{'offset':0,'size':4,'role':'returned status'},
                {'offset':4,'size':4,'role':'address-encoded operation'},{'offset':8,'size':8,'role':'original X0 output pointer'}],
            'output_size_bytes':12,'output_u32':[6,8,3],'null_status_u32':0xffff5bd9,'nonnull_status_u32':0,
            'state_cells':['0x1d355c0','0x1d37f68','0x1d358b8'],'constant_C':'0x68001f0b','constant_K':'0x2a3c56842e5d49ec',
            'wrapper_state':'S=entrySP-0x30; r=(oldG1 XOR oldG2)+S; G1=r*C-K; G2=(r XOR K)*C; all mod2^64',
            'helper_state':'r2=oldG3-(S-0x10+8)+G2; G3=(r2*C) XOR K; G2=(r2 XOR K)*C; all mod2^64'},
        'packet':{'entry':'0xe160','helper':'0x27afd4','callsite':'0xe40c','record_pointer':'postprologue_SP+0x20',
            'known_written_extent_bytes':88,'complete_record_size':'unknown','returned_status_offset':16,'status_load':'0xe410',
            'key32':'((low32(record_pointer) XOR 0x309487ae)*0x87cfdb29) mod2^32',
            'fields':[{'offset':0,'size':4,'role':'key32+0x2472c1e1 mod2^32'},
                {'offset':8,'size':8,'role':'original X1'},{'offset':16,'size':4,'role':'returned status'},
                {'offset':24,'size':8,'role':'original X7'},{'offset':32,'size':4,'role':'original W4-key32 mod2^32'},
                {'offset':40,'size':8,'role':'original X3 certificate pointer in inspected caller'},
                {'offset':48,'size':8,'role':'original X6'},{'offset':56,'size':8,'role':'original X5'},
                {'offset':64,'size':4,'role':'original W0+key32 mod2^32'},
                {'offset':72,'size':8,'role':'original X2'},
                {'offset':80,'size':8,'role':'(postprologue_SP+8) XOR 0xc43af69d4c49fa99'}]},
        'initialization':{'once_call':'0x2f7200','control':'0x1d36080','initializer':'0x28994',
            'stack_probe_call':'0x9e8aec','stack_extent_x9_bytes':0x1c030,'stack_import':'___chkstk_darwin',
            'atomic_site':'0x28e4c','atomic_instruction':'swpal w8,w8,[x19]','atomic_cell':'0x1d49008',
            'sysconf_call':'0x28f40','sysconf_selector_u32':29,'mmap_call':'0x29028',
            'mmap_args_x0_x5':['0x0','0x10000','0x3','0x1002','0xffffffff','0x0'],
            'private_first_mapping_failure_public_status_u32':0xffffffff,
            'native_stack_binding':'unknown','native_allocation_and_concurrency':'unknown'},
        'mach_request_builders':requests,'mach_request_builder_pointer_references':refs,
        'import_calls_sha256':sha((ROOT/'corefp_import_calls.json').read_bytes()),
        'sdk_headers':sdk_headers,'generator_sha256':sha(Path(__file__).read_bytes()),
        'native_target_executed':False,'hardware_PAC_checked':False,'full_goal_complete':False}
    (ROOT/'corefp_exports_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'banks_256':len(banks),'distinct_bank_identities':out['distinct_bank_identities'],'smt_unsat':len(proofs),
                      'original_ranges':len(ranges),'selected_pointer_members':len(pointers),'version':out['bundle']['version']}))


if __name__=='__main__':main()
