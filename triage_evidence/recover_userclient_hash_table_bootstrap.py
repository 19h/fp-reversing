#!/usr/bin/env python3
"""Original shared FPHashTable bootstrap and teardown fallback.
O(B+I+256R) extraction time/space; no target or IDB execution.
"""
import json
import struct
from kext_port_tools import ROOT, SOURCE, IMAGE, POOL, TABLE, qword, selected, CS
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_userclient_uidlist_cleanup as UID

P='userclient_hash_table_bootstrap'
SCOPE='Original-source marker-unequal cleanup global FPHashTable guard, typed allocation/initializer request, conditional publication, rollback and null-holder fallback to UIDList free. The initializer record decoder/header prefix is joined; its remaining array construction, table operations, node identity, concurrency and native pairing remain unknown.'
SPANS={
    'holder_guard':(0xfffffe000a626a40,0xfffffe000a626af0),
    'allocate':(0xfffffe000a626af8,0xfffffe000a626b74),
    'allocation_gate':(0xfffffe000a626b78,0xfffffe000a626ba0),
    'initializer_request':(0xfffffe000a626ba8,0xfffffe000a626c68),
    'initializer_gate':(0xfffffe000a626c6c,0xfffffe000a626ca4),
    'rollback':(0xfffffe000a626cac,0xfffffe000a626d44),
    'rollback_return':(0xfffffe000a626d48,0xfffffe000a626d50),
    'reload_guard':(0xfffffe000a626d58,0xfffffe000a626d98),
    'publish':(0xfffffe000a626da0,0xfffffe000a626dc4),
    'initializer_header':(0xfffffe000a62750c,0xfffffe000a627560),
}
TRANSFERS={0xfffffe000a626af0:('braa','x8, x17'),0xfffffe000a626b74:('blraa','x10, x17'),
           0xfffffe000a626ba0:('braa','x8, x17'),0xfffffe000a626c68:('blraa','x8, x17'),
           0xfffffe000a626ca4:('braa','x8, x17'),0xfffffe000a626d44:('blraa','x10, x17'),
           0xfffffe000a626d50:('braa','x8, x17'),0xfffffe000a626d98:('braa','x8, x17'),
           0xfffffe000a626dc4:('braa','x8, x17')}
BRANCHES={0x8c8:(0xfffffe000a626af4,0x678),0x370:(0xfffffe000a626dc8,0x678),
          0x397:(0xfffffe000a626d54,0x4b85),0x3a6:(0xfffffe000a626ba4,0x4b85),
          0x7b9:(0xfffffe000a626d9c,0x9766),0x7d3:(0xfffffe000a626ca8,0x9766),
          0x39b:(0xfffffe000a626920,0x678)}
FALSE=UID.FALSE+['full_hash_table_initializer_established','native_global_holder_coherence_established']
DEPS=['recover_userclient_uidlist_cleanup.py','audit_userclient_uidlist_cleanup.py',
      'userclient_uidlist_cleanup_checks.json','userclient_uidlist_cleanup_audit.json',
      'userclient_context_lifecycle_source.json','userclient_context_lifecycle_checks.json',
      'kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py',
      'recover_kext_aes_handoff.py','lskd_values_symbolic.py']

def build():
    base=UID.build();k=Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
    parent=json.loads(read(ROOT/'userclient_context_lifecycle_source.json'))['functions']['destroy']
    initializer=function(k,entry,0xfffffe000a627400)
    raw=bytes.fromhex(initializer['bytes_hex']);assert raw==IMAGE.read(int(initializer['start'],16),len(raw))
    spans=list(base['spans'])
    for label,(a,z) in SPANS.items():
        raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a)
        rows=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]
        assert len(rows)*4==len(raw)
        f=initializer if label=='initializer_header' else parent
        assert rows==[i for i in f['instructions'] if a<=int(i['ea'],16)<z]
        spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'instructions':rows})
    transfers=list(base['transfers'])
    for a,want in TRANSFERS.items():
        raw=k.read(a,4);assert raw==IMAGE.read(a,4);i=next(CS.disasm(raw,a));assert (i.mnemonic,i.op_str)==want
        transfers.append({'pc':hex(a),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
    pools=list(base['pool_pointers'])
    for off in [0x840,0xbb8,0x4f0,0x578,0xc08,0x158]:
        p=pointer(k,POOL+off);assert int(p['target'],16)==qword(POOL+off);pools.append(p)
    pairs={'T':(qword(POOL+0x840),qword(POOL+0xbb8)),
           'U':(qword(POOL+0x4f0)-4,qword(POOL+0x578)-4),
           'V':(qword(POOL+0xc08)-8,qword(POOL+0x158)-4),
           'free':(qword(POOL+0x458)-8,qword(POOL+0x638)-12)}
    banks=dict(base['banks'])
    for n in ['T','U','V']:
        for side,a in zip(['L','R'],pairs[n]):banks[n+side]={'address':hex(a),'bytes_hex':IMAGE.read(a,256).hex()}
    rules=list(base['bank_rules'])
    for n,pair,key,add,b,bias,div in [
        ('holder','T',0xb4,0x13e,POOL,-4,None),('allocate','T',0x3e,0xebf,TABLE,0,0xd0c8),
        ('allocate_descriptor','T',0x16,-0x57,POOL,-4,None),('initialize','U',0x37,0xf3d,TABLE,0,0x2bbe),
        ('rollback_free','free',0x47,0xeb0,TABLE,0,0x4d6a),('rollback_descriptor','V',5,0x22,POOL,-4,None)]:
        r=selected(*pairs[pair],key,add,b,bias);r['name']=n;r['pair']=pair;r['original_pointer']=pointer(k,int(r['slot'],16))
        assert (int(r['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(r['target'],16)
        if div is not None:assert r['original_pointer']['authenticated'] and int(r['original_pointer']['diversity'],16)==div
        rules.append(r)
    branches=list(base['branch_pointers'])
    for ix,(target,div) in BRANCHES.items():
        p=pointer(k,TABLE+8*ix);assert (int(p['target'],16),int(p['diversity'],16))==(target,div)
        p['index']=ix;p['landing_bytes_hex']=k.read(target,4).hex();p['landing_instruction']=next(CS.disasm(k.read(target,4),target)).mnemonic
        assert IMAGE.read(target,4).hex()==p['landing_bytes_hex'] and p['landing_instruction']=='bti';branches.append(p)
    descriptors=[]
    for a in [0xfffffe000847b960,0xfffffe000847b9a0]:
        raw=IMAGE.read(a,64);np,sp=[struct.unpack_from('<Q',raw,off)[0] for off in [16,32]]
        name=IMAGE.read(np,64).split(b'\0')[0];sig=IMAGE.read(sp,64).split(b'\0')[0];flags,size=struct.unpack_from('<2I',raw,40)
        assert (name,sig,flags,size)==(b'site.FPHashTable',b'21',0x64,16)
        pn,ps=pointer(k,a+16),pointer(k,a+32)
        assert (int(pn['target'],16),int(ps['target'],16))==(np,sp) and k.read(a+40,8)==raw[40:48]
        assert k.read(np,len(name)+1)==name+b'\0' and k.read(sp,len(sig)+1)==sig+b'\0'
        descriptors.append({'address':hex(a),'normalized64_bytes_hex':raw.hex(),'original64_bytes_hex':k.read(a,64).hex(),
                            'name':name.decode(),'signature':sig.decode(),'flags_u32':flags,'size_bytes':size,'name_pointer':pn,'signature_pointer':ps})
    assert descriptors[0]['normalized64_bytes_hex']==descriptors[1]['normalized64_bytes_hex']
    holder=0xfffffe000ccceac0
    assert k.read(holder,8)==bytes(8)
    try:IMAGE.read(holder,8)
    except ValueError:holder_normalized_file_backed=False
    else:raise AssertionError('holder unexpectedly file-backed in normalized image')
    adapters={'allocate':k.function(0xfffffe000c4ba154),'free':base['free_adapter']}
    syms=k.symbols([0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000a627400])
    assert any(r['name']=='_IOMallocTypeImpl' for r in syms['0xfffffe000c4ba154'])
    return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),
            'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'spans':spans,'transfers':transfers,'banks':banks,'bank_rules':rules,
            'pool_pointers':pools,'branch_pointers':branches,'typed_descriptor':base['typed_descriptor'],
            'hash_table_descriptors':descriptors,'global_holder':{'address':hex(holder),'original_collection_bytes_hex':k.read(holder,8).hex(),'normalized_file_backed':holder_normalized_file_backed,'native_current_value_known':False},
            'initializer_function':initializer,'kernel_adapters':adapters,'exact_symbols':syms,
            'verified_counts':{'source_spans':len(spans),'source_instructions':sum(len(s['instructions']) for s in spans),
                               'terminal_transfers':len(transfers),'literal_bank_arrays':len(banks),'bank_input_cases':256*len(rules),
                               'pool_pointers':len(pools),'branch_pointers':len(branches),'new_typed_descriptors':2,
                               'initializer_captured_instructions':len(initializer['instructions']),'node_bytes':16,'hash_table_bytes':16,'context_bytes':24},
            'conditional_global_hash_table_bootstrap_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
