#!/usr/bin/env python3
"""Original CoreFP request1200 paths,encoded certificate and CoreADI context.

No native target/loader/API executes. O(B+F+R+256*K) static recovery time,
O(B+F+R) space. Offline X.509 parsing is metadata only. Two bounded SMT queries
cover full selector/status domains;neither proves a native transaction.
"""
import json
from pathlib import Path
import plistlib
import struct
import subprocess
from corefp_fixups_reader import Pointers,ROOT,sha,THIN_SHA
from resolve_kernel_collection_interfaces import macho,commands


def main():
    s=Pointers();T=0x1d1bf30;B=0x1d16370;banks=[]
    for label,a,b,k,c in [('secondary_state_and_table',0x1c79380,0x1c797a0,0xba,0x8e),
        ('secondary_state2',0x1c78f20,0x1c79180,0xe0,0x52),
        ('secondary_first_malloc',0x1c798a0,0x1c79bd0,0x2f,0x43)]:
        aa=s.read(a,256);bb=s.read(b,256);v=[i^bb[aa[i]^k] for i in range(256)];assert set(v)=={c}
        banks.append({'label':label,'first_address':hex(a),'second_address':hex(b),'key_u8':k,'constant_u8':c,
            'first_bytes':aa.hex(),'second_bytes':bb.hex(),'results_256':v})
    assert s.qword(T+(0x8e-0x7f)*8)-8==B
    assert s.qword(T+(0x8e-0x7a)*8)-4==0x1d441a8
    assert s.qword(T+(0x52-0x2d)*8)==0x1d44158
    assert s.decoded[B+(0xabc+0x43)*8]['import']['name']=='_malloc'
    slots=[0x1d04218,0x1d1bba8,0x1d1bfa8,0x1d1bfd0,0x1d1c058,0x1d1bb68,
        0x1d1bd50,0x1d1bd78,0x1d1bdd8,0x1d1be18,0x1d1be58,0x1d1be60,0x1d1be88,0x1d1bea8,0x1d1bec8,0x1d1bed0,
        0x1d16350,0x1d16360,0x1d16368,0x1d1c028]
    pointers=[s.decoded[a] for a in slots]
    cache_refs=[p for p in s.decoded.values() if not p['bind'] and p['target']=='0x1d49068'];assert cache_refs
    cache_seg=next(x for x in s.meta['segments'] if x['address']+x['file_size']<=0x1d49068 and 0x1d4906c<=x['address']+x['vm_size'])
    cert_source=0x185c226;encoded=s.read(cert_source,760);decoded=bytes(v^0xba for v in encoded)
    prefix=decoded[:4];der=decoded[4:];assert prefix.hex()=='01000007' and len(der)==756 and der[:4]==bytes.fromhex('308202f0')
    cert_path=ROOT/'corefp_fppineboard_certificate.der';cert_path.write_bytes(der)
    cmd=['/usr/bin/openssl','x509','-inform','DER','-in',str(cert_path),'-noout','-subject','-issuer','-serial','-dates','-fingerprint','-sha256','-text']
    parsed=subprocess.run(cmd,capture_output=True,text=True,check=True)
    cm={'source_CoreFP_thin_sha256':THIN_SHA,'encoded_source_address':hex(cert_source),'encoded_size_bytes':760,
        'encoded_bytes':encoded.hex(),'xor_byte':0xba,'decoded_prefix4_bytes':prefix.hex(),'prefix_semantic_role':'unknown',
        'DER_size_bytes':756,'DER_sha256':sha(der),
        'parser_command':cmd,'parser_output':parsed.stdout,'parser_stderr':parsed.stderr,'certificate_authentication_executed':False,
        'native_target_executed':False}
    (ROOT/'corefp_fppineboard_certificate.json').write_text(json.dumps(cm,indent=2)+'\n')
    queries={
      'corefp_secondary_selector.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun selector () (_ BitVec 64))
(define-fun index () (_ BitVec 64) (bvadd selector #x0000000000000008))
(define-fun shifted () (_ BitVec 32) (bvlshr #x0000007d ((_ zero_extend 27) ((_ extract 4 0) index))))
(define-fun accepts () Bool (and (bvule index #x0000000000000006) (= (bvand shifted #x00000001) #x00000001)))
(define-fun expected () Bool (or (= selector #xfffffffffffffff8) (= selector #xfffffffffffffffa) (= selector #xfffffffffffffffb) (= selector #xfffffffffffffffc) (= selector #xfffffffffffffffd) (= selector #xfffffffffffffffe)))
(assert (distinct accepts expected))
(check-sat)
''',
      'corefp_secondary_destination_retry.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun result () (_ BitVec 32))
(define-fun mixed () (_ BitVec 32) (bvadd (bvadd (bvxor result #x7cbc9ff9) (bvand (bvshl result #x00000001) #xf9793ff2)) #xd76ffa88))
(assert (distinct (= mixed #x642c9a84) (= result #x10000003)))
(check-sat)
'''}
    proofs=[]
    for name,q in queries.items():
        path=ROOT/name;path.write_text(q);result=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True)
        assert result.stdout.strip()=='unsat' and not result.stderr,(name,result.stdout)
        proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'Local full64-bit selector/full32-bit status predicate only.'})
    functions=[s.function(a) for a in [0x8ae0,0x1590824,0x15cc6f4,0x246ea0,0x15a4c14]]
    main_idx=s.starts.index(0x8e81c8);end=s.starts[main_idx+1];mainraw=s.read(0x8e81c8,end-0x8e81c8)
    launch_path=Path('/System/Library/LaunchDaemons/com.apple.adid.plist');lpraw=launch_path.read_bytes();launch=plistlib.loads(lpraw)
    provider=Path(launch['Program']);raw=provider.read_bytes();assert sha(raw)=='58eeb13dade3e1867641345b38961344fe53e6319928a1503bdb3315681fe929'
    slices=[]
    for j in range(struct.unpack_from('>I',raw,4)[0]):
        cpu,sub,off,n,al=struct.unpack_from('>5I',raw,8+j*20);slices.append({'cpu':hex(cpu),'subtype':hex(sub),'offset':off,'size_bytes':n,'sha256':sha(raw[off:off+n])})
    sel=next(x for x in slices if x['cpu']=='0x100000c' and x['subtype']=='0x80000002');data=raw[sel['offset']:sel['offset']+sel['size_bytes']]
    meta=macho(data,0,'CoreADI adid selected arm64e');assert meta['uuid']=='4d24325f-3529-39b1-bbf8-64bbcf406049'
    environment={'launchd_path':str(launch_path),'launchd_sha256':sha(lpraw),'launchd_plist':launch,'provider_path':str(provider),
        'provider_resolved_path':str(provider.resolve()),'provider_sha256':sha(raw),'slices':slices,'selected_slice':sel,'macho':meta,
        'dyld_info_fixups_path':'adid_fixups.txt','dyld_info_fixups_sha256':sha((ROOT/'adid_fixups.txt').read_bytes()),
        'running_job_and_port_identity':'unknown','receiver_protocol_implementation':'unknown','native_target_executed':False}
    (ROOT/'corefp_adid_environment.json').write_text(json.dumps(environment,indent=2)+'\n')
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
    out={'scope':__doc__,'CoreFP_thin_sha256':THIN_SHA,'CoreFP_uuid':s.meta['uuid'],'banks':banks,'pointers':pointers,'cache_pointer_references':cache_refs,
        'cache_storage':{'address':'0x1d49068','segment':cache_seg,'initial_private_zero_fill_u32':0,'native_value':'unknown'},
        'proofs':proofs,'original_functions':functions,'main_caller':{'start':'0x8e81c8','end':hex(end),'sha256':sha(mainraw),'size_bytes':len(mainraw)},
        'main_request':{'parent_call':'0x8ea14c','builder':'0x8ae0','emission':'0x8ba8','id':1200,'send_bytes':64,'receive_capacity_bytes':220,
            'mode_u32':2,'count_input_u32':2,'allocation_bytes':760,'payload_bytes':756,'allocation_call':'0x249368','temporary_free_call':'0x8e9fa8',
            'certificate_metadata':'corefp_fppineboard_certificate.json','certificate_path':cert_path.name},
        'secondary':{'entry':'0x15cc6f4','accepted_selectors_signed64':[-8,-6,-5,-4,-3,-2],'rejection_u32':0xffff5037,
            'allocations_bytes':[24,4096],'allocation_calls':['0x15cc8e4','0x15cc9dc'],'allocation_failure_u32':0xffff5035,
            'XPC_service':'com.apple.adid','service_string_address':'0x1c79aa0','data_key':'data','data_key_address':'0x1c79120',
            'XPC_dictionary_call':'0x15ce9d8','XPC_set_data_call':'0x15cea8c','queue_create_call':'0x15ceae8',
            'connection_create_call':'0x15ceb94','XPC_send_call':'0x15ced04','XPC_get_data_call':'0x15cf394',
            'event_handler_block':'0x1d16350','event_handler_invoke':'0x15a4c14','event_description_call':'0x15a4d8c',
            'wire_size_bytes':28,'wire_fields':[{'offset':0,'width':4,'observed_value':1},{'offset':4,'width':4,'observed_value':'0x632b8d6e'},
                {'offset':8,'width':4,'observed_value':1},{'offset':12,'width':8,'role':'original signed selector'},
                {'offset':20,'width':8,'role':'original X1 opaque u64 value;semantic role unknown'}],
            'wire_integer_order':'big endian','legacy_builder':'0x1590824','legacy_emission':'0x15908c8','legacy_id':1200,
            'legacy_send_bytes':56,'legacy_receive_capacity_bytes':64,'legacy_cache':'0x1d49068',
            'first_legacy_parent_call':'0x15d008c','lookup_call':'0x15d0174','retry_parent_call':'0x15d022c',
            'lookup_on_status_u32':0x10000003,'lookup_error_result_u32':0xffff5027,'other_transport_error_result_u32':0xffff5028},
        'adid_environment':'corefp_adid_environment.json','dependencies':{name:sha((ROOT/name).read_bytes()) for name in ['corefp_fixups_inventory.json','corefp_lookup_contracts.json']},
        'sdk_headers':[{'path':str(sdk/x),'sha256':sha((sdk/x).read_bytes())} for x in ['usr/include/mach/message.h','usr/include/xpc/connection.h']],
        'generator_sha256':sha(Path(__file__).read_bytes()),'native_target_executed':False,'hardware_PAC_checked':False,'full_goal_complete':False}
    (ROOT/'corefp_client_paths_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'banks':len(banks),'pointers':len(pointers),'proofs_unsat':len(proofs),'certificate_bytes':len(der),'adid_uuid':meta['uuid']}))


if __name__=='__main__':main()
