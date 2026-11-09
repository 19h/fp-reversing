#!/usr/bin/env python3
"""Source-pinned notification names,post banks,cache/time and SDK contracts.

O(B+F+R+256P) time/space, P paired byte banks; seven separate30 s queries.
Compile/display original SDK declarations only;no target/loader/native API.
Provider fragments retain explicit unproved predecessor/record boundaries.
"""
import json
from pathlib import Path
import struct
import subprocess
from akd_client_reader import Akd,ROOT,THIN_SHA as CLIENT_SHA,CS,sha
from adid_reader import Adid,THIN_SHA as PROVIDER_SHA
from probe_adid_notifications import NAMES,CACHE_START,CACHE_SIZE
from probe_adid_startup import unpack_records


def main():
    client=Akd();provider=Adid();profiles=json.loads((ROOT/'adid_notification_profiles.json').read_text());posts=json.loads((ROOT/'adid_notification_post_profiles.json').read_text());names=[]
    for label,source,addresses in [('client',client,[0x100347d23,0x100347d05,0x100347d3f]),('provider',provider,[0x1002941f0,0x1002a16b0,0x1002ad240])]:
        for address,name in zip(addresses,NAMES):assert source.read(address,len(name)+1)==name.encode()+b'\0';names.append({'image':label,'address':hex(address),'name':name,'bytes':source.read(address,len(name)+1).hex()})
    windows=[]
    for label,s,a,z,role in [('client',client,0x100308ad4,0x100308b64,'timeval call,signed division and asymmetric unsigned bucket gate'),('client',client,0x100308edc,0x100309164,'selected token API paths'),('client',client,0x100309a18,0x100309fbc,'three registrations,initial baseline checks,exit registration and ready publication'),('client',client,0x10030a074,0x10030a0b0,'two-record publication index'),('client',client,0x10030bb04,0x10030bb34,'OTP count,unsigned32 division and DSID publication'),('client',client,0x100309510,0x100309640,'common byte-copy destination and three-byte loop'),('provider',provider,0x100218fbc,0x1002191a8,'status gate,DSID-derived notification class and post call')]:
        raw=s.read(a,z-a);windows.append({'image':label,'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    functions=[{'image':'client',**client.function(a)} for a in [0x100308278,0x1002dcbec]]
    specs=[('provider_name_V1.5',0x1002c1f90,0x10027f330,0x5b,0x6e),('provider_name_V1',0x1002add60,0x1002c1d90,0x66,0x9c),('provider_name_V3',0x10027f230,0x100294230,0x85,0xb4),('provider_post_import',0x1002c1f90,0x10027f330,0x26,0x1d)];banks=[]
    for role,a,b,key,want in specs:
        first=provider.read(a,256);second=provider.read(b,256);values=[i^second[first[i]^key] for i in range(256)];assert values==[want]*256;banks.append({'role':role,'first_address':hex(a),'second_address':hex(b),'first_bytes':first.hex(),'second_bytes':second.hex(),'input_XOR_u8':key,'low_byte_result':want,'all256_original_reductions':values})
    slots=[0x1002d9f48,0x1002d9b90,0x1002d8f60,0x1002d83c8,0x1002c5a18,0x1002d8048,0x1002cbb58,0x1002c6428];pointers=[provider.decoded[a] for a in slots]
    checks=[(0x1002d9f48,0xffffffffcc28f949,0x1002a16b0),(0x1002d9b90,0xffffffffd1a02026,0x1002941f0),(0x1002d8f60,0xffffffffd6a13ebe,0x1002ad240)]
    decoded_names=[]
    for slot,add,target in checks:
        assert (int(provider.decoded[slot]['target'],16)+add)&((1<<64)-1)==target;decoded_names.append({'slot':hex(slot),'addend_u64':hex(add),'decoded_name_address':hex(target)})
    queries={
      'adid_notification_name_class64.smt2':'''(set-logic QF_BV)
(declare-fun dsid () (_ BitVec 64))
(define-fun field () (_ BitVec 64) (bvxor dsid #xda8ca8cae5dfbd2d))
(define-fun shifted () (_ BitVec 64) (bvadd field #xda8ca8cae5dfbd2d #x0000000000000003))
(define-fun bit () (_ BitVec 32) (bvand #x00000001 (bvlshr #x000000eb ((_ zero_extend 27) ((_ extract 4 0) shifted)))))
(define-fun v3 () Bool (and (bvult shifted #x0000000000000008) (= bit #x00000001)))
(define-fun source () (_ BitVec 2) (ite v3 #b10 (ite (= field #x257357351a2042d2) #b01 #b00)))
(define-fun reserved () Bool (or (= dsid #xfffffffffffffff8) (= dsid #xfffffffffffffffa) (= dsid #xfffffffffffffffb) (= dsid #xfffffffffffffffc) (= dsid #xfffffffffffffffd) (= dsid #xfffffffffffffffe)))
(define-fun compact () (_ BitVec 2) (ite reserved #b10 (ite (= dsid #xffffffffffffffff) #b01 #b00)))
(define-fun client () (_ BitVec 2) (ite (bvult (bvadd dsid #x0000000000000006) #x0000000000000005) #b10 (ite (= dsid #xffffffffffffffff) #b01 (ite (= dsid #xfffffffffffffff8) #b10 #b00))))
(assert (or (distinct source compact) (distinct client compact)))''',
      'adid_notification_status32.smt2':'''(set-logic QF_BV)
(declare-fun status () (_ BitVec 32))
(define-fun index () (_ BitVec 32) (bvxor (bvsub #x00000d5b #x000008ee) (ite (= status #x0059248f) #x0000239c #x00000000)))
(assert (or (distinct (= index #x000027f1) (= status #x0059248f)) (distinct (= index #x0000046d) (distinct status #x0059248f))))''',
      'adid_notification_bucket_gate32.smt2':'''(set-logic QF_BV)
(declare-fun cached () (_ BitVec 32))
(declare-fun now () (_ BitVec 32))
(define-fun carry () Bool (bvuge cached now))
(define-fun source_ccmp_C () Bool (ite carry (bvuge (bvsub cached now) #x0000012c) true))
(define-fun source_accept () Bool (not source_ccmp_C))
(define-fun compact () Bool (and (bvuge cached now) (bvult (bvsub cached now) #x0000012c)))
(assert (distinct source_accept compact))''',
      'adid_notification_time_div30.smt2':'''(set-logic QF_LIA)
(declare-fun seconds () Int)
(assert (and (<= (- 9223372036854775808) seconds) (<= seconds 9223372036854775807)))
(define-fun high () Int (div (* seconds (- 8608480567731124087)) 18446744073709551616))
(define-fun summed () Int (+ high seconds))
(define-fun quotient () Int (+ (div summed 16) (ite (< summed 0) 1 0)))
(define-fun expected () Int (ite (< seconds 0) (- (div (- seconds) 30)) (div seconds 30)))
(assert (or (< summed (- 9223372036854775808)) (> summed 9223372036854775807) (distinct quotient expected)))''',
      'adid_notification_time_shift32.smt2':'''(set-logic QF_BV)
(declare-fun summed () (_ BitVec 64))
(define-fun sign () (_ BitVec 32) ((_ zero_extend 31) ((_ extract 63 63) summed)))
(define-fun logical () (_ BitVec 32) (bvadd ((_ extract 31 0) (bvlshr summed #x0000000000000004)) sign))
(define-fun arithmetic () (_ BitVec 32) (bvadd ((_ extract 31 0) (bvashr summed #x0000000000000004)) sign))
(assert (distinct logical arithmetic))''',
      'adid_notification_clock_publication32.smt2':'''(set-logic QF_LIA)
(declare-fun seconds () Int)
(assert (and (<= 0 seconds) (<= seconds 4294967295)))
(define-fun published () Int (div (mod seconds 4294967296) 30))
(define-fun lookup () Int (mod (div seconds 30) 4294967296))
(assert (distinct published lookup))''',
      'adid_notification_publication_index64.smt2':'''(set-logic QF_BV)
(declare-fun key () (_ BitVec 64))
(declare-fun first () (_ BitVec 64))
(define-fun first_cmp_NE () Bool (distinct key first))
(define-fun source_ccmp_Z () Bool (ite first_cmp_NE (= first #x0000000000000000) true))
(define-fun source_index () (_ BitVec 1) (ite source_ccmp_Z #b0 #b1))
(define-fun compact () (_ BitVec 1) (ite (and (distinct key first) (distinct first #x0000000000000000)) #b1 #b0))
(assert (distinct source_index compact))'''}
    proofs=[]
    for name,q in queries.items():
        lines=q.splitlines();text=lines[0]+'\n(set-option :timeout 30000)\n'+'\n'.join(lines[1:])+'\n(check-sat)\n';path=ROOT/name;path.write_text(text);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr,(name,run.stdout,run.stderr);proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat'})
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk');cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'adid_notification_layouts.c'),'-o',str(ROOT/'adid_notification_layouts.s')];run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0 and not run.stderr
    headers=[sdk/'usr/include'/n for n in ['notify.h','sys/time.h','stdlib.h']]
    bridges=[]
    for key in [-8,-1,1]:
        pr=next(r for r in posts['profiles'] if r['fixture']['label']=='DSID_'+str(key));event=next(e for e in unpack_records(pr) if e.get('name')=='_notify_post');case=next(r for r in profiles['cases'] if r['case']['label']=='changed_'+str(key)+'_'+event['notification_name'].rsplit('.',1)[-1]);warm=case['calls'][1];checks=[e for e in unpack_records(warm) if e.get('name')=='_notify_check'];assert len(checks)==1 and checks[0]['notification_name']==event['notification_name'] and checks[0]['changed_u32']==1;bridges.append({'DSID_signed64':key,'provider_fragment_label':pr['fixture']['label'],'provider_post_site':event['callsite'],'client_case_label':case['case']['label'],'client_check_site':checks[0]['callsite'],'exact_original_name':event['notification_name'],'provider_entry_requires_analyst_frame_record_register_fixtures':True,'notification_delivery_and_native_pairing_established':False,'meaning':'Conditional original provider name -> explicit check flag -> original warm cache miss/XPC refresh;no actual post/delivery executed.'})
    deps=['akd_client_reader.py','adid_reader.py','probe_adid_notifications.py','adid_notification_profiles.json','probe_adid_notification_posts.py','adid_notification_post_profiles.json','adid_driver_dispatch_frame.json','akd_client_inventory.json'];out={'scope':__doc__,'client_thin_sha256':CLIENT_SHA,'provider_thin_sha256':PROVIDER_SHA,'original_names':names,'original_windows':windows,'complete_client_functions':functions,'provider_byte_banks':banks,'provider_chain_members':pointers,'provider_name_pointer_reductions':decoded_names,'cache_layout':{'base':'0x100450550','record_count':2,'record_size_bytes':40,'fields':[{'offset':0,'width_bytes':8,'role':'DSID64;zero used as empty key'},{'offset':8,'width_bytes':8,'role':'private cached MID pointer64'},{'offset':16,'width_bytes':4,'role':'MID count32'},{'offset':24,'width_bytes':8,'role':'private cached OTP pointer64'},{'offset':32,'width_bytes':4,'role':'OTP count32'},{'offset':36,'width_bytes':4,'role':'floor(low32(seconds64)/30);unsigned32 publication'}]},'lookup_time_bucket':'low32(trunc_toward_zero(signed_seconds64/30));distinct from unsigned32 publication','notification_tokens':dict(zip(NAMES,['0x100450548','0x1004505a4','0x1004505ac'])),'ready_byte':'0x1004505a8','atexit_callback':'0x1002dcbec','provider_post_site':'0x100219198','provider_fragment_entry':'0x100218fbc','provider_fragment_continuation':'0x1002191a8','conditional_event_bridges':bridges,'proofs':proofs,'SDK_compile':{'command':cmd,'exit_code':run.returncode,'source_sha256':sha((ROOT/'adid_notification_layouts.c').read_bytes()),'assembly_sha256':sha((ROOT/'adid_notification_layouts.s').read_bytes())},'SDK_headers':[{'path':str(path),'sha256':sha(path.read_bytes())} for path in headers],'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in deps},'native_target_executed':False,'full_goal_complete':False};(ROOT/'adid_notification_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'client_cases':len(profiles['cases']),'client_calls':sum(len(r['calls']) for r in profiles['cases']),'local_provider_cases':len(posts['profiles']),'name_bridges':len(bridges),'proofs_unsat':len(proofs),'original_byte_banks':len(banks)}),flush=True)


if __name__=='__main__':main()
