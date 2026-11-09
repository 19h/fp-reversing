#!/usr/bin/env python3
"""Protected AMS disposal/creation bank decoding and private record contracts.

All byte banks are checked on all256 byte inputs. Original cache chains and
exact exports supply targets. No target API/code executes here. O(B+256*K+P)
extraction for bytes, K bank pairs and selected pointers; SMT cost separate.
"""
import json
import bisect
from pathlib import Path
import subprocess
from ams_core_reader import Core,ROOT,sha


def main():
    c=Core();cache=c.cache;lib=c.ams;banks=[]
    specs=[('dispose_cell1',0x19cb42870,0x19cb72ff0,0x60,0xe7),
        ('dispose_cell2',0x19cb86130,0x19cb2f640,0x1d,0xb6),
        ('dispose_code_table',0x19cb42770,0x19cb72cf0,0xa6,0x18),
        ('dispose_free_target',0x19cb42770,0x19cb72cf0,0x6c,0x85),
        ('create_cell1',0x19cb188f0,0x19cb19f70,0x90,0xeb),
        ('create_cell2',0x19cb189f0,0x19cb1a370,0x25,0x62),
        ('create_target_index',0x19cb1a170,0x19cb1b460,0x4c,0xa0),
        ('create_table_index',0x19cb188f0,0x19cb19f70,0x86,0x36)]
    for label,a,b,key,constant in specs:
        aa=cache.read(a,256);bb=cache.read(b,256);results=[i^bb[aa[i]^key] for i in range(256)];assert set(results)=={constant}
        banks.append({'label':label,'first_address':hex(a),'second_address':hex(b),'first_bytes':aa.hex(),'second_bytes':bb.hex(),
            'key_u8':key,'constant_u8':constant,'results_256':results,'all_inputs_verified':True})
    slots=[0x1e0f75858,0x1e0f757d0,0x1e0f75b20,0x1e0f754b8,0x1e0f75730,0x1e0f74788,0x1e0f75048,
        0x1e449e840,0x1e449e8f0,0x1e44a3508,0x1e0f73f70,0x1e0f73df0,0x1e0f73da0,0x1e0f73ac0,
        0x1e0f73eb0,0x1e0f73ee0,0x1e0f73dd0,0x1e4499ad8]
    pointers=[c.pointer(a) for a in slots]
    from bootpolicy_cache_reader import Dylib
    malloc=Dylib(cache,'/usr/lib/system/libsystem_malloc.dylib');free=int(c.pointer(0x1e44a3508)['target'],16)
    assert free==malloc.exports['_free']['address']==0x181e7a6f0
    ranges=[]
    for a in [0x19ca1dd68,0x19c9e12a0,0x19c237b30,0x19ca0d0e4,0x19c9ec168]:
        r=lib.function(a);r['original_names']=lib.symbols_at(a);ranges.append(r)
    loader_start=lib.functions[bisect.bisect_right(lib.functions,0x19c1f5c60)-1];loader=lib.function(loader_start)
    cert_address=0x19cb1a483;cert=cache.read(cert_address,0x37b);assert cert[:4]==bytes.fromhex('30820377')
    cert_path=ROOT/'ams_core_certificate.der';cert_path.write_bytes(cert)
    cert_command=['/usr/bin/openssl','x509','-inform','DER','-in',str(cert_path),'-noout','-subject','-issuer','-serial','-dates','-fingerprint','-sha256']
    parsed=subprocess.run(cert_command,capture_output=True,text=True,check=True)
    cert_meta={'source_cache_uuid':cache.uuid,'source_ams_uuid':lib.uuid,'source_address':hex(cert_address),'size_bytes':len(cert),'sha256':sha(cert),
        'original_der_extent_matches_header':True,'parser_command':cert_command,'parser_output':parsed.stdout,'parser_stderr':parsed.stderr,
        'certificate_authentication_executed':False,'native_target_executed':False}
    (ROOT/'ams_core_certificate.json').write_text(json.dumps(cert_meta,indent=2)+'\n')
    queries={
      'ams_dispose_partition.smt2':'''(set-logic QF_BV)
(declare-fun pointer () (_ BitVec 64))
(define-fun index () (_ BitVec 32) (bvxor (bvmul (ite (= pointer #x0000000000000000) #x00000000 #x00000001) #x000000f6) #x00000870))
(assert (distinct index (ite (= pointer #x0000000000000000) #x00000870 #x00000886)))
(check-sat)
''',
      'ams_create_record_operation.smt2':'''(set-logic QF_BV)
(declare-fun address () (_ BitVec 32))
(define-fun mixed () (_ BitVec 32) (bvxor (bvsub (bvadd address #x6b98ed43) (bvshl (bvand address #x6b98ed43) #x00000001)) #x66693479))
(define-fun stored () (_ BitVec 32) (bvadd (bvmul mixed #x7f12daa3) #x00000c4b))
(define-fun body_mix () (_ BitVec 32) (bvxor (bvsub (bvor address #x8a09c380) (bvand address #x8a09c380)) #x87f81aba))
(define-fun decoded () (_ BitVec 32) (bvsub stored (bvmul body_mix #x7f12daa3)))
(assert (or (distinct mixed (bvxor address #x0df1d93a)) (distinct decoded #x00000c4b)))
(check-sat)
'''}
    proofs=[]
    for name,q in queries.items():
        p=ROOT/name;p.write_text(q);run=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True)
        assert run.stdout.strip()=='unsat' and not run.stderr
        proofs.append({'path':name,'sha256':sha(p.read_bytes()),'result':'unsat','scope':'Original local fixed-width algebra; excludes PAC/concurrency and native target behavior.'})
    out={'scope':__doc__,'cache_uuid':cache.uuid,'ams_uuid':lib.uuid,'ams_path':lib.path,'ranges':ranges,'banks':banks,
        'pointers':pointers,'proofs':proofs,'external_inventory_sha256':sha((ROOT/'ams_core_pointer_inventory.json').read_bytes()),
        'free_binding':{'slot':'0x1e44a3508','target':hex(free),'library':malloc.path,'uuid':malloc.uuid,'exact_export':'_free'},
        'loader_original_function':loader,'dynamic_loader':{'path_address':'0x19cb19e08','path':cache.cstring(0x19cb19e08),
            'flags_u32':5,'dlopen_call':'0x19c1f5c60','dlsym_calls':['0x19c1f5c78','0x19c1f5c94','0x19c1f5cb0','0x19c1f5ccc','0x19c1f5ce8'],
            'requested_names':['WIn9UJ86JKdV4dM','X46O5IeS','YlCJ3lg','lxpgvVMLd0S7uRl','dku592fbFAj'],
            'first_export_call':'0x19c20e2f0','next_export_call':'0x19c20e690','actual_native_library_selection':'unknown'},
        'CoreFP_library_inventory_sha256':sha((ROOT/'corefp_library_inventory.json').read_bytes()),
        'certificate':{'path':cert_path.name,'metadata_path':'ams_core_certificate.json','sha256':sha(cert),'source_address':hex(cert_address),'size_bytes':len(cert)},
        'dispose':{'entry':'0x19ca1dd68','null_target':'0x19ca1df0c','nonnull_target':'0x19ca1deb0',
            'null_status_u32':(-0xa427)&0xffffffff,'nonnull_status_u32':0,'free_call':'0x19ca1df00',
            'state_cells':['0x1ebbfdbf0','0x1ebbfdf10'],
            'state_update':'new64=((old_cell2-old_cell1+(postprologue_SP+8)) XOR 0xa0fb9d7d32f316e4)*0x74b92847 modulo2^64; both cells receive new64'},
        'create':{'entry':'0x19c9e12a0','target':'0x19c237b30','callsite':'0x19c9e1464','record_size_bytes':48,
            'operation_u32':0xc4b,'encoded_status_xor_u32':0x0ef7dc36,
            'fields':[{'offset':0,'size':8,'role':'original X1'},{'offset':8,'size':4,'role':'encoded operation'},
                {'offset':12,'size':4,'role':'uninitialized padding'},{'offset':16,'size':8,'role':'original X3 context-ID output cell'},
                {'offset':24,'size':8,'role':'original X0'},{'offset':32,'size':4,'role':'encoded returned status'},
                {'offset':36,'size':4,'role':'uninitialized padding'},{'offset':40,'size':8,'role':'original X2 path'}]},
        'generator_sha256':sha(Path(__file__).read_bytes()),'native_target_executed':False,'hardware_PAC_checked':False,'full_goal_complete':False}
    (ROOT/'ams_core_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'original_ranges':len(ranges),'banks_256':len(banks),'selected_pointer_chains':len(pointers),'proofs_unsat':len(proofs)}))


if __name__=='__main__':main()
