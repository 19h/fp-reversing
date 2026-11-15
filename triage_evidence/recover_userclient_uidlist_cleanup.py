#!/usr/bin/env python3
"""Capture the original populated-context UIDList fast cleanup path.
O(B+I+256R) extraction time/space for image bytes B, instructions I,
and bank pairs R. Read-only source analysis; no target executes.
"""
import json
import struct
from kext_port_tools import ROOT, SOURCE, IMAGE, POOL, TABLE, qword, selected, CS
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read, sha

P='userclient_uidlist_cleanup'
SCOPE='Original-source marker-equal 16 B UIDList cleanup and successor loop, conditionally joining the previously proved 24 B context cleanup. Marker-unequal cleanup, list producers, UID semantics, native deallocation and daemon-kext transactions remain unknown.'
SPANS={
    'root_literals':(0xfffffe000a62667c,0xfffffe000a626694),
    'head_phase':(0xfffffe000a6267d4,0xfffffe000a6267f0),
    'node_gate':(0xfffffe000a6269e8,0xfffffe000a626a38),
    'node_free':(0xfffffe000a626924,0xfffffe000a6269b4),
    'node_continue':(0xfffffe000a6269b8,0xfffffe000a6269e0),
}
TRANSFERS={0xfffffe000a626a38:('braa','x9, x17'),
           0xfffffe000a6269b4:('blraa','x11, x17'),
           0xfffffe000a6269e0:('braa','x8, x17')}
BRANCHES={0xea5:(0xfffffe000a626920,0x234d),
          0xe5e:(0xfffffe000a626a3c,0x234d),
          0x980:(0xfffffe000a626838,0xc338),
          0x9a4:(0xfffffe000a6269e4,0xc338)}
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py',
      'lskd_values_symbolic.py','userclient_context_lifecycle_source.json',
      'userclient_context_lifecycle_checks.json']
FALSE=['native_API_executed','native_deallocation_established','native_PAC_authenticated',
       'native_daemon_kext_pairing_established','full_populated_cleanup_established',
       'UID_business_semantics_established','whole_machine_context_lifetime_established',
       'IDB_modified','full_goal_complete']

def build():
    assert sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
    k=Kernel();parent=json.loads(read(ROOT/'userclient_context_lifecycle_source.json'))
    f=parent['functions']['destroy'];a=int(f['start'],16);raw=bytes.fromhex(f['bytes'])
    assert k.read(a,len(raw))==IMAGE.read(a,len(raw))==raw
    spans=[]
    for label,(a,z) in SPANS.items():
        raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a)
        rows=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]
        assert len(rows)*4==len(raw)
        assert rows==[i for i in f['instructions'] if a<=int(i['ea'],16)<z]
        spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'instructions':rows})
    transfers=[]
    for a,want in TRANSFERS.items():
        raw=k.read(a,4);assert raw==IMAGE.read(a,4);i=next(CS.disasm(raw,a))
        assert (i.mnemonic,i.op_str)==want
        transfers.append({'pc':hex(a),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
    pool=[pointer(k,POOL+off) for off in [0xb70,0xa10,0x458,0x638]]
    assert all(int(p['target'],16)==qword(int(p['slot'],16)) for p in pool)
    pairs={'free':(qword(POOL+0x458)-8,qword(POOL+0x638)-12),
           'descriptor':(qword(POOL+0xb70),qword(POOL+0xa10))}
    banks={n+side:{'address':hex(a),'bytes_hex':IMAGE.read(a,256).hex()} for n,pair in pairs.items() for side,a in zip(['L','R'],pair)}
    rules=[]
    for n,key,add,base in [('free',0x87,0xe4c,TABLE),('descriptor',0x92,0xdb,POOL)]:
        row=selected(*pairs[n],key,add,base);row['name']=n
        row['original_pointer']=pointer(k,int(row['slot'],16))
        assert int(row['original_pointer']['target'],16)==int(row['target'],16)
        rules.append(row)
    assert [(r['index'],r['target']) for r in rules]==[('0xf2b','0xfffffe000c4ba368'),('0x17d','0xfffffe000847b2a0')]
    assert rules[0]['original_pointer']['authenticated'] and rules[0]['original_pointer']['diversity']=='0x4d6a'
    branches=[]
    for ix,(target,div) in BRANCHES.items():
        p=pointer(k,TABLE+8*ix)
        assert (int(p['target'],16),int(p['diversity'],16))==(target,div)
        p['index']=ix;branches.append(p)
        assert IMAGE.read(target,4)==k.read(target,4)
        p['landing_bytes_hex']=k.read(target,4).hex()
        p['landing_instruction']=next(CS.disasm(k.read(target,4),target)).mnemonic
        assert p['landing_instruction']=='bti'
    a=0xfffffe000847b2a0;raw=IMAGE.read(a,64)
    nameptr,sigptr=[struct.unpack_from('<Q',raw,off)[0] for off in [16,32]]
    name=IMAGE.read(nameptr,64).split(b'\0')[0];sig=IMAGE.read(sigptr,64).split(b'\0')[0]
    flags,size=struct.unpack_from('<2I',raw,40)
    assert (name,sig,flags,size)==(b'site.UIDList',b'21',0x64,16)
    np,sp=pointer(k,a+16),pointer(k,a+32)
    assert (int(np['target'],16),int(sp['target'],16))==(nameptr,sigptr)
    assert k.read(a+40,8)==raw[40:48]
    assert k.read(nameptr,len(name)+1)==name+b'\0' and k.read(sigptr,len(sig)+1)==sig+b'\0'
    desc={'address':hex(a),'normalized64_bytes_hex':raw.hex(),'original64_bytes_hex':k.read(a,64).hex(),
          'name_pointer':np,'signature_pointer':sp,'name':name.decode(),'signature':sig.decode(),
          'flags_u32':flags,'size_bytes':size}
    adapter=k.function(0xfffffe000c4ba368);assert adapter==parent['kernel_functions']['free_adapter']
    syms=k.symbols([0xfffffe000c4ba368])
    assert any(r['name']=='_IOFreeTypeImpl' for r in syms['0xfffffe000c4ba368'])
    return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),
            'kernel_collection_sha256':k.sha256,'parent_destroy_sha256':f['sha256'],
            'dependencies':{n:sha(ROOT/n) for n in DEPS},'spans':spans,'transfers':transfers,
            'pool_pointers':pool,'banks':banks,'bank_rules':rules,'branch_pointers':branches,
            'entry_frame_seam':{'parent_head_save_pc':'0xfffffe000a6267d0',
                                'context_pointer_SP_offset':8,'original_cell_SP_offset':16,
                                'free_bank_pair_save_pc':'0xfffffe000a626828','free_bank_pair_SP_offsets':[80,88],
                                'controller_pair_save_pc':'0xfffffe000a62682c','controller_pair_SP_offsets':[104,112],
                                'X2':'0xfffffe000ccc32f8','X3':'0xfffffe000ccc3330',
                                'X25':hex(POOL),'X27':hex(TABLE),
                                'head_load_pc':'0xfffffe000a6267f0','head_register':'X20'},
            'typed_descriptor':desc,'free_adapter':adapter,'exact_symbols':syms,
            'verified_counts':{'source_spans':5,'source_instructions':sum(len(s['instructions']) for s in spans),
                               'terminal_transfers':3,'literal_bank_arrays':4,'bank_input_cases':512,
                               'pool_pointers':4,'branch_pointers':4,'new_typed_descriptors':1,'node_bytes':16,'context_bytes':24},
            'conditional_UIDList_fast_cleanup_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
    s=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(s,indent=2)+'\n')
    print(json.dumps(s['verified_counts']),flush=True)
