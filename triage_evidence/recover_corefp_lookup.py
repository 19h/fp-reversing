#!/usr/bin/env python3
"""Original CoreFP bootstrap/cache record and cross-image metadata contracts.

Static bytes/fixups/banks only;no native target/loader/API executes. O(B+F+R+
256*K) time,O(B+F+R) space. Three local SMT obligations are capped at30 s each.
"""
import json
from pathlib import Path
import struct
import subprocess
from corefp_fixups_reader import Pointers,ROOT,sha,THIN_SHA,SHA
from daemon_receive_tools import IMAGE,SOURCE,FIXUPS,verify_original_fixups
from resolve_kernel_collection_interfaces import commands


def main():
    s=Pointers();T=0x1d05fa0;B=0x1c81940
    specs=[('cells_and_bootstrap_primary',0x1ac19c0,0x1c78040,0x20,0x94),
        ('second_state_cell',0x174f320,0x18ac370,0xe4,0xec),
        ('once_target',0x18ac070,0x1ac18c0,0x58,0x7e),
        ('branch_table_and_primary_string',0x174f220,0x18ac170,0xb,9),
        ('once_control_and_metadata_target',0x1ac19c0,0x1c78040,0x27,0x18),
        ('lock_record_pointer',0x1ac1bc0,0x1c78140,0x4c,0x35),
        ('lock_helper_and_fallback_string',0x18ac070,0x1ac18c0,0xc5,2),
        ('reset_helper',0x174f220,0x18ac170,0xa5,0xd6),
        ('cached_name',0x18ac270,0x1ac1ac0,0xc8,0xc0),
        ('fallback_target_and_caller_lookup_target',0x18ac270,0x1ac1ac0,0xe7,0x1f),
        ('default_lock_pointer',0x18ac070,0x1ac18c0,7,0x61)]
    banks=[]
    for label,a,b,k,c in specs:
        aa=s.read(a,256);bb=s.read(b,256);values=[i^bb[aa[i]^k] for i in range(256)];assert set(values)=={c}
        banks.append({'label':label,'first_address':hex(a),'second_address':hex(b),'key_u8':k,'constant_u8':c,
            'first_bytes':aa.hex(),'second_bytes':bb.hex(),'results_256':values})
    resolutions=[('branch_table',T+(0x1520+9)*8,-4,B),
        ('once',B+(0x1039a+0x1b+0x7e)*8,0,'libSystem/_pthread_once'),
        ('once_control',T+(0x114+0x18)*8,-12,0x1d34f90),
        ('lock_helper',B+(0x1039a+2)*8,0,0x20f37c),
        ('lock_input_pointer_cell',T+(0x1b23+0x35)*8,-4,0x1d444a8),
        ('optional_lock_input_value',0x1d444a8,0,0),
        ('default_lock_pointer_cell',T+(0x1211+0x61)*8,0,0x1d383d8),
        ('default_lock_object',0x1d383d8,0,0x1d27bf0),
        ('reset_helper',B+(0x1039a+0x3e+0xd6)*8,0,0x57a67c),
        ('cache_cell',T+(0xca3+0xc0)*8,0,0x1d44448),
        ('metadata_structure',T+(0x10fa+0x94)*8,-12,0x1d37838),
        ('bootstrap_namespace_data',T+(0x4fa+0x94)*8,0,'libSystem/_bootstrap_port'),
        ('primary_name_pointer_cell',T+(0x1ca9+9)*8,0,0x1d33ee0),
        ('primary_name_bytes',0x1d33ee0,0,0x1746bf0),
        ('fallback_name_pointer_cell',T+(0xc8+2)*8,0,0x1d37f40),
        ('fallback_name_bytes',0x1d37f40,0,0x1915ec0),
        ('bootstrap_primary',B+(0x1039a+0x30d+0x94)*8,0,'libSystem/_bootstrap_look_up'),
        ('bootstrap_fallback',B+(0x1039a+0x382+0x1f)*8,0,'libSystem/_bootstrap_look_up'),
        ('metadata_client',B+(0x1039a+0x45a+0x18)*8,0,0x90c8),
        ('caller_lookup',B+(0x10351+0x330+0x1f)*8,0,0x1cdb24)]
    resolved=[]
    for label,slot,bias,expected in resolutions:
        value=s.qword(slot);actual=value+bias if isinstance(value,int) else value;assert actual==expected,(label,actual,expected)
        resolved.append({'label':label,'slot':hex(slot),'bias_signed_bytes':bias,'target':hex(actual) if isinstance(actual,int) else actual,
            'original_pointer':s.decoded.get(slot),'original_bytes':s.read(slot,8).hex()})
    strings=[]
    for address,size,key,want in [(0x1746bf0,15,0x19,b'com.apple.fpsd\0'),(0x1915ec0,20,0xf7,b'com.apple.fairplayd\0')]:
        raw=s.read(address,size);decoded=bytes(v^key for v in raw);assert decoded==want
        strings.append({'address':hex(address),'size_bytes':size,'xor_key_u8':key,'bytes':raw.hex(),'decoded_bytes':decoded.hex(),'name':decoded[:-1].decode()})
    ranges=[]
    for at in [0x1cdb24,0x20f37c,0x57a67c,0x4a21e0,0x59e868,0x90c8]:
        row=s.function(at);ranges.append(row)
    caller=s.read(0x8e81c8,0x3b8)
    queries={
      'corefp_lookup_record_codec.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun p () (_ BitVec 32))
(declare-fun tag () (_ BitVec 32))
(declare-fun flag () (_ BitVec 8))
(define-fun mixed () (_ BitVec 32) (bvxor (bvadd (bvsub (bvor p #x20d7d4ce) p) (bvand p #xdf282b31)) #xab997307))
(define-fun key () (_ BitVec 32) (bvmul mixed #x0bcb7857))
(define-fun storedtag () (_ BitVec 32) (bvadd key tag))
(define-fun storedflag () (_ BitVec 8) (bvadd ((_ extract 7 0) key) flag))
(assert (or (distinct mixed (bvxor p #x8b4ea7c9)) (distinct (bvsub storedtag key) tag) (distinct (bvsub storedflag ((_ extract 7 0) key)) flag)))
(check-sat)
''',
      'corefp_lookup_partitions.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun flag () (_ BitVec 8))
(declare-fun cached () (_ BitVec 32))
(define-fun v () (_ BitVec 32) (bvmul (bvxor #x0000ba27 #x0000ba70) #x0000006f))
(define-fun q () (_ BitVec 32) (bvor (bvadd v #x00005a47) #x00001d91))
(define-fun initial () (_ BitVec 32) (bvxor #x0000ba27 (bvmul (ite (= flag #x09) #x00000001 #x00000000) (bvsub q #x00009d28))))
(define-fun cachedindex () (_ BitVec 32) (bvxor q (bvmul (ite (= cached #x00000000) #x00000001 #x00000000) (bvadd (bvsub (bvsub q #x00012000) #x00000754) (bvadd q #x00004324)))))
(assert (or (distinct v #x000025b9) (distinct q #x00009d91) (distinct initial (ite (= flag #x09) #x0000ba4e #x0000ba27)) (distinct cachedindex (ite (= cached #x00000000) #x0000cb63 #x00009d91))))
(check-sat)
''',
      'corefp_lookup_caller_record.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun p () (_ BitVec 64))
(define-fun mixed () (_ BitVec 64) (bvxor (bvadd (bvsub (bvor p #x08ae71402ff5057c) p) (bvand p #xf7518ebfd00afa83)) #x8c1900eef68afb44))
; Non-NULL required pointer inputs select CSET eq=0 in this local branch.
(define-fun inputop () (_ BitVec 32) #x0000c1f7)
(define-fun base () (_ BitVec 32) (bvsub inputop #x000081d5))
(define-fun guardindex () (_ BitVec 32) (bvxor inputop (bvmul (bvand #x00000001 (bvnot base)) #x000003fd)))
(define-fun childtag () (_ BitVec 32) (bvadd (bvor base #x00000744) #x000072c1))
(assert (or (distinct mixed (bvxor p #x84b771aed97ffe38)) (distinct guardindex #x0000c20a) (distinct childtag #x0000ba27)))
(check-sat)
'''}
    proofs=[]
    for name,query in queries.items():
        path=ROOT/name;path.write_text(query);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True)
        assert run.stdout.strip()=='unsat' and not run.stderr,(name,run.stdout,run.stderr)
        proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'Local source-width algebra and stated record preconditions;excludes native paths/PAC/concurrency.'})
    daemon_ranges=[]
    for a,z in [(0x100004918,0x100004ae4),(0x100004ae4,0x100004b80),(0x100004b80,0x100004c10),(0x100006424,0x100006448)]:
        raw=IMAGE.read(a,z-a);daemon_ranges.append({'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':sha(raw)})
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
    at=0x1010b1e10;word=struct.unpack('<Q',IMAGE.read(at,8))[0]
    lc=next(a for a,c,n in commands(IMAGE.data,0) if c==0x80000034);fo=struct.unpack_from('<I',IMAGE.data,lc+8)[0]
    ver,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',IMAGE.data,fo);assert fmt==2
    iw,addend=struct.unpack_from('<Ii',IMAGE.data,fo+imports+8*(word&0xffffff));no=fo+symbols+(iw>>9)
    symbol=IMAGE.data[no:IMAGE.data.index(0,no)].decode();assert symbol=='_NDR_record' and addend==0 and word>>62&1
    ndr={'address':hex(at),'word':hex(word),'authenticated':bool(word>>63),'import_ordinal':word&0xffffff,
        'import_name':symbol,'import_addend':addend,'reference':FIXUPS[at]}
    out={'scope':__doc__,'CoreFP_source_sha256':SHA,'CoreFP_thin_sha256':THIN_SHA,'CoreFP_uuid':s.meta['uuid'],
        'daemon_thin_sha256':sha(SOURCE.read_bytes()),'banks':banks,'resolutions':resolved,'strings':strings,'CoreFP_original_functions':ranges,
        'caller_prefix':{'start':'0x8e81c8','end':'0x8e8580','bytes':caller.hex(),'sha256':sha(caller)},
        'branch_slots':[s.decoded[a] for a in [0x1c94708,0x1cdea78,0x1cdebb0,0x1cd05c8,0x1ce7458,0x1cf1d38,0x1cf1ee8,0x1ce2990]],
        'proofs':proofs,'daemon_original_ranges':daemon_ranges,
        'daemon_pointer_provenance':verify_original_fixups([0x1010380e0,0x101038108]),'daemon_NDR_data_binding':ndr,
        'lookup':{'entry':'0x1cdb24','record_size_bytes':32,'record_fields':[
            {'offset':0,'size':4,'role':'encoded status marker'},{'offset':8,'size':8,'role':'u32 port-name output pointer'},
            {'offset':16,'size':8,'role':'u32 metadata-flags output pointer'},{'offset':24,'size':1,'role':'address-encoded flag'},
            {'offset':28,'size':4,'role':'address-encoded tag;0xba27 in recovered caller'}],
            'key32':'((low32(record_pointer) XOR 0x8b4ea7c9)*0x0bcb7857) mod2^32',
            'success_marker_u32':0xba1df9db,'failure_marker_u32':0x45e2a2e3,'cache_cell':'0x1d44448',
            'secondary_cache_cell':'0x1d37838','metadata_cells':['0x1d37990','0x1d37994','0x1d37998','0x1d3799c'],
            'primary_lookup_call':'0x1ce1bc','fallback_lookup_call':'0x1ce448','fallback_condition_u32':1102,
            'metadata_call':'0x1ce274','metadata_result_observation':'0x1ce278','metadata_flag_default_mask_u32':10,
            'outer_once_control':'0x1d34f90','outer_once_initializer':'0x4a21e0',
            'lock_once_control':'0x1d37f50','lock_once_initializer':'0x59e868','write_lock_call':'0x20f6cc','write_lock_object':'0x1d27bf0',
            'reset_calls':['0x57a988','0x57aa2c'],'metadata_status_consumed_by_local_continuation':False},
        'protocol_pair':{'CoreFP_request_id':1203,'CoreFP_request_bytes':24,'CoreFP_expected_reply_id':1303,
            'CoreFP_receive_capacity_bytes':60,'daemon_same_id_stub':'0x100004918','daemon_same_id_requires_complex':True,
            'daemon_same_id_required_bytes':100,'daemon_rejection_status_signed32':-304,
            'daemon_metadata_request_id':1204,'daemon_metadata_stub':'0x100004ae4','daemon_metadata_handler':'0x100006424',
            'daemon_metadata_reply_bytes':52,'daemon_metadata_reply_id':1304,'daemon_metadata_u32':[76,9,0,42],
            'native_image_pairing':'unknown','meaning_of_four_metadata_words':'unknown'},
        'dependencies':{name:sha((ROOT/name).read_bytes()) for name in ['corefp_fixups_inventory.json','daemon_mig_tables.json','daemon_registration_contracts.json']},
        'sdk_headers':[{'path':str(sdk/x),'sha256':sha((sdk/x).read_bytes())} for x in ['usr/include/servers/bootstrap_defs.h','usr/include/mach/mig_errors.h']],
        'generator_sha256':sha(Path(__file__).read_bytes()),'native_target_executed':False,'hardware_PAC_checked':False,'full_goal_complete':False}
    (ROOT/'corefp_lookup_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'banks_256':len(banks),'selected_resolutions':len(resolved),'SMT_unsat':len(proofs),'source_functions':len(ranges),'daemon_ranges':len(daemon_ranges)}))


if __name__=='__main__':main()
