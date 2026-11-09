#!/usr/bin/env python3
"""Original provider/IOKit/descriptor interfaces and local contract proofs.

Read source files, codesign display, SDK compilation and local SMT only.
No native target, IOKit or Mach operation. O(B+F+R+E) time/space; each
local SMT obligation has a separate 30 s timeout.
"""
import json
from pathlib import Path
import plistlib
import struct
import subprocess
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA,SOURCE
from resolve_kernel_collection_interfaces import commands
from probe_adid_startup import unpack_records


def parse_records(raw):
    rows=[];off=0
    while off<len(raw):
        assert off+10<=len(raw);key,tag,n=struct.unpack_from('>IHI',raw,off);end=off+10+n;assert end<=len(raw)
        assert tag in (0x9777,0x8485,0x50db) and (tag!=0x9777 or n==4) and (tag!=0x8485 or n==8)
        rows.append({'offset_bytes':off,'raw_key_be32':hex(key),'tag_u16':hex(tag),'payload_size_bytes':n,'payload_bytes':raw[off+10:end].hex()});off=end
    assert off==len(raw);return rows


def main():
    s=Adid();p=json.loads((ROOT/'adid_iokit_profiles.json').read_text());rows={r['fixture']['label']:r for r in p['profiles']}
    a=next(at for at,c,n in commands(s.data,0) if c==0x1d);off,size=struct.unpack_from('<II',s.data,a+8);sig=s.data[off:off+size];magic,length,count=struct.unpack_from('>III',sig);assert magic==0xfade0cc0 and length<=len(sig)
    blobs=[];xml=None
    for j in range(count):
        kind,pos=struct.unpack_from('>II',sig,12+8*j);bm,bn=struct.unpack_from('>II',sig,pos);assert pos+bn<=length;blob=sig[pos:pos+bn];blobs.append({'slot_type':kind,'magic':hex(bm),'relative_offset':pos,'size_bytes':bn,'sha256':sha(blob)})
        if kind==5:assert bm==0xfade7171;xml=blob[8:]
    assert xml is not None;ent=plistlib.loads(xml);assert ent=={'AvpFairPlayUserClient.access':True,'com.apple.private.FairPlayIOKitUserClient.access':True};(ROOT/'adid_iokit_entitlements.xml').write_bytes(xml)
    run=subprocess.run(['/usr/bin/codesign','-d','--arch','arm64e','--entitlements',':-',str(SOURCE)],capture_output=True,check=True);assert plistlib.loads(run.stdout)==ent
    signature={'thin_code_signature_file_offset':off,'reserved_size_bytes':size,'superblob_length':length,'blobs':blobs,'entitlements':ent,'XML_path':'adid_iokit_entitlements.xml','XML_sha256':sha(xml),'independent_codesign_command':['/usr/bin/codesign','-d','--arch','arm64e','--entitlements',':-',str(SOURCE)],'codesign_stdout':run.stdout.decode(),'codesign_stderr':run.stderr.decode(),'trust_or_effective_entitlements_established':False}
    queries={
      'adid_iokit_record_add32.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun a () (_ BitVec 32))
(define-fun x () (_ BitVec 32) (bvadd (bvor a #x9c6cff35) (bvsub #x639300ca (bvor a #x639300ca))))
(define-fun key () (_ BitVec 32) (bvmul (bvxor x #x1f2a8b99) #x0a42990d))
(assert (distinct key (bvmul (bvxor a #x834674ac) #x0a42990d)))
(check-sat)
''',
      'adid_iokit_output_pointer64.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun p () (_ BitVec 64))
(define-fun encoded () (_ BitVec 64) (bvadd p #x4a98f233707acdc1))
(define-fun decoded () (_ BitVec 64) (bvadd encoded #xb5670dcc8f85323f))
(assert (or (distinct decoded p) (distinct (= encoded #x4a98f233707acdc1) (= p #x0000000000000000))))
(check-sat)
''',
      'adid_iokit_name_byte.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun b () (_ BitVec 8))
(define-fun d () (_ BitVec 8) (bvadd (bvmul b #xa3) #xc6))
(assert (distinct (bvmul (bvadd d #x3a) #x0b) b))
(check-sat)
''',
      'adid_iokit_query_byte.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun status () (_ BitVec 32))
(declare-fun value () (_ BitVec 32))
(declare-fun old () (_ BitVec 8))
(define-fun index () (_ BitVec 32) (bvxor (ite (= status #x00000000) #x00003e23 #x00000000) #x0000191e))
(define-fun result () (_ BitVec 8) (ite (= index #x0000273d) (ite (= value #x00000000) #x00 #x01) old))
(assert (distinct result (ite (= status #x00000000) (ite (= value #x00000000) #x00 #x01) old)))
(check-sat)
'''}
    proofs=[]
    for name,text in queries.items():
        path=ROOT/name;path.write_text(text);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr;proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'Full stated BV domains under original local source prefix; no full/native protocol proof.'})
    windows=[]
    for a,z,role in [(0x100020a34,0x100020a58,'primary record decode'),(0x10002b0a8,0x10002b108,'Avp record decode and null output'),
        (0x100001450,0x100001514,'once callback query/store'),(0x10002b4fc,0x10002b640,'Avp class decode/matching'),(0x100020d2c,0x100020d68,'primary mainport API'),
        (0x1000211e0,0x1000212a0,'primary matching/dictionary/iterator APIs'),(0x100021430,0x100021480,'primary type0 open'),(0x10002b840,0x10002b8f0,'Avp type0 open and release'),
        (0x10002b928,0x10002ba20,'Avp iterator release,output,return'),(0x10001f8b0,0x10001f980,'indirect method26'),(0x100049630,0x1000496b0,'direct method26')]:
        raw=s.read(a,z-a);windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    primary=unpack_records(rows['first_getter_once_callback']);wire=next(e for e in primary if e['kind']=='original_IOConnect_structure_boundary');packet=bytes.fromhex(wire['pointed_bytes']);records=parse_records(packet);assert len(packet)==96 and len(records)==6 and records[-1]['raw_key_be32']=='0x0'
    legacy=next(e for e in unpack_records(rows['first_VMM_1']) if e['kind']=='original_IOConnect_structure_boundary');assert legacy['input_bytes']==packet.hex() and legacy['args_x0_x7'][3]=='0x60'
    name=next(e for e in unpack_records(rows['mainport_success']) if e['kind']=='original_AVP_name_source');encoded=s.read(int(name['address'],16),18);assert encoded.hex()==name['bytes18'] and bytes((v*-93-58)&255 for v in encoded)==b'AvpFairPlayDriver\0'
    block=0x1002c4060;descriptor=s.qword(block+24);assert s.qword(block+16)==0x100001250 and s.qword(descriptor+8)==32
    block_view={'address':hex(block),'raw32_bytes':s.read(block,32).hex(),'invoke':hex(s.qword(block+16)),'descriptor':hex(descriptor),'descriptor_size_u64':s.qword(descriptor+8)}
    query_branches=[]
    for success in (False,True):
        index=(0x3e23*int(success))^0x191e;slot=0x1002c40c0+index*8;query_branches.append({'query_success':success,'index_u32':index,'slot':hex(slot),'pointer':s.decoded[slot]})
    selected={'_IOMainPort','_IOServiceMatching','_IOServiceGetMatchingServices','_IOIteratorNext','_IOServiceOpen','_IOObjectRelease','_IOConnectCallStructMethod','_mach_task_self_','_dispatch_once'};imports=[v for v in s.decoded.values() if v['bind'] and v['import']['name'] in selected]
    table=0x100266cec;base=0x10019bb2c;rawtable=s.read(table,56*4);states=[{'state_u32':i,'target':hex(base+struct.unpack_from('<i',rawtable,i*4)[0])} for i in range(56)]
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk');cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'adid_iokit_layouts.c'),'-o',str(ROOT/'adid_iokit_layouts.s')];run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0 and not run.stderr
    header=sdk/'System/Library/Frameworks/IOKit.framework/Headers/IOKitLib.h'
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'embedded_signature_declaration':signature,'original_windows':windows,'source_import_pointers':imports,'proofs':proofs,'AVP_name_source':name,'once_block':block_view,'query_branch_pointers':query_branches,'method26_descriptor':wire,'method26_packet_records':records,
        'upstream_control_table':{'address':hex(table),'relative_base':hex(base),'raw224_bytes':rawtable.hex(),'states':states,'semantics':'Local control/continuation states,not 56 public operations.'},'SDK_compile':{'command':cmd,'source_sha256':sha((ROOT/'adid_iokit_layouts.c').read_bytes()),'assembly_sha256':sha((ROOT/'adid_iokit_layouts.s').read_bytes()),'exit_code':run.returncode},'SDK_header':{'path':str(header),'sha256':sha(header.read_bytes())},'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_iokit.py','adid_iokit_profiles.json','adid_peer_checkpoint.json','adid_context_profiles.json','selector26_core_rpc_native.json','daemon_abi_native.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_iokit_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs':len(proofs),'windows':len(windows),'imports':len(imports),'packet_bytes':len(packet),'records':len(records),'control_states':len(states),'entitlements':ent}))


if __name__=='__main__':main()
