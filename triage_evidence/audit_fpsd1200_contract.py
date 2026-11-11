#!/usr/bin/env python3
"""Independent scalar byte/ABI oracle plus fresh bounded original-code replay.

O(C*(B+F+K)+R+256*N) time; O(B+F+C*K+R) space. Oracle fields and predicates
are written independently of the instruction hooks. Finite replay is not a
proof over all payloads, pointer mappings, PAC states or native interleavings.
"""
import json
import struct
from recover_fpsd1200_contract import sources,selectors,Server,Client,SHA,ROOT,IMAGE,read

U32=lambda b,o:struct.unpack_from('<I',b,o)[0]
U64=lambda b,o:struct.unpack_from('<Q',b,o)[0]
M32=(1<<32)-1;M64=(1<<64)-1


def server_status(b,fixture):
    if not(U32(b,0)&0x80000000)or U32(b,24)!=1 or U32(b,4)!=64:return (-304)&M32,False
    if b[39]!=1 or U32(b,40)!=U32(b,60):return (-300)&M32,False
    if U32(b,64)!=0 or U32(b,68)<=31:return (-309)&M32,False
    return fixture.get('core_status',0),True


def client_status(b,transport):
    if transport:return transport,('_mig_put_reply_port'if transport in [0x10000002,0x10000003,0x10000010]else '_mig_dealloc_reply_port')
    status=0
    if U32(b,20)==71:status=(-308)&M32
    elif U32(b,20)!=1300:status=(-301)&M32
    elif U32(b,0)&0x80000000:
        if not(U32(b,24)==2 and U32(b,4)==212 and U32(b,8)==0 and b[39]==1 and b[54:56]==b'\x11\x00'and U32(b,40)==U32(b,196)):status=(-300)&M32
    elif U32(b,4)!=36 or U32(b,32)==0 or U32(b,8)!=0:status=(-300)&M32
    else:status=U32(b,32)
    return status,'_mach_msg_destroy'if status else None


def audit():
    e=json.loads(read(ROOT/'fpsd1200_contract_checks.json'));att,f,stubs,wire=sources()
    assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1200_contract.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h,n
    banks,fixups=selectors();assert banks==e['selectors'] and fixups==e['fixups']
    source_ins={}
    for s in e['daemon_source_spans']:
        a,z=int(s['start'],16),int(s['end'],16);raw=IMAGE.read(a,z-a)
        assert raw.hex()==s['bytes_hex']and SHA(raw)==s['sha256']
        source_ins.update({int(i['ea'],16):i for i in s['instructions']})
    assert f==e['CoreFP_function']
    for a,m,o in [(0x10000465c,'stp','x14, x11, [sp, #0x20]'),(0x100004660,'stp','x12, x13, [sp, #0x10]'),
      (0x100004670,'stp','x10, x9, [sp]'),(0x10000467c,'bl','#0x100007b28'),
      (0x10000468c,'bl','#0x100e2ab40'),(0x100004690,'stur','xzr, [x21, #0x1c]'),
      (0x100004694,'str','wzr, [x21, #0x28]'),(0x100007d8c,'blraa','x8, x17'),
      (0x100007f18,'blraa','x8, x17'),(0x100007f20,'ldur','x9, [x29, #-0x90]')]:
        assert(source_ins[a]['mnemonic'],source_ins[a]['operands'])==(m,o),(hex(a),source_ins[a])
    accepted=0;success=0;guards={};payloads=0
    for saved in e['server_cases']:
        r=Server(wire,saved['fixture']).run_case();assert r==saved,r['fixture']
        req=bytes.fromhex(r['request_received128']);reply=bytes.fromhex(r['reply212']);status,app=server_status(req,r['fixture'])
        assert r['recognized']==1 and r['stop_reason']=='returned_to_fixture'
        assert U32(reply,4)==(212 if status==0 else 36)
        assert U32(reply,8)==U32(req,8)and U32(reply,12)==0 and U32(reply,20)==1300
        assert len(r['modeled_deallocation'])==int(app)
        if not app:
            guards[r['fixture']['label']]=status
            assert U32(reply,32)==status and r['application_args14']is None and r['protected_core_boundary']is None
            assert bytes.fromhex(r['request_ool_after16'])==req[28:44]
            continue
        accepted+=1
        assert r['modeled_deallocation'][0]['args_x0_x1']==[hex(U64(req,28)),hex(U32(req,40))]
        after=bytes.fromhex(r['request_ool_after16']);assert after[:8]==bytes(8)and after[8:12]==req[36:40]and after[12:]==bytes(4)
        args=[int(x,16)for x in r['application_args14']];b=r['protected_core_boundary']
        p,n,q,d=(int(b[k],16)for k in ['address','nested','payload','delta_cell'])
        assert n==p-32 and d==p-16 and q==p-0x88
        assert args[:2]==[U32(req,12),U32(req,52)]and args[3]==0x70001038 and args[4:6]==[U64(req,28),U32(req,40)]
        assert args[6:9]==[0x70002044,0x7000201c,0x700020c4]
        assert args[10:]==[0x700020c8,0x700020cc,0x700020d0,0x7000202c]
        carrier=bytes.fromhex(b['carrier28_before']);nested=bytes.fromhex(b['nested24_before']);payload=bytes.fromhex(b['payload104_before'])
        key=(((p&M32)^0xeaae0ac9)*0x7398180b)&M32
        assert U64(carrier,0)==(n^0x1c0b9f7ce10f2255)and U32(carrier,8)==(key^0x6cf4)and U32(carrier,12)==(key^0xad952088)and U64(carrier,16)==q
        assert U32(nested,0)==((n+0xea06b394)&M32)and U64(nested,8)==n and U64(nested,16)==0xcbfeb095c4fbe881
        expected=bytearray(b'\xa5'*104)
        struct.pack_into('<II',expected,0,*args[:2]);expected[8:40]=req[84:116]
        struct.pack_into('<I',expected,40,U32(req,56));struct.pack_into('<Q',expected,48,U64(req,28));struct.pack_into('<I',expected,56,U32(req,40))
        struct.pack_into('<QQI',expected,64,args[6],0xa5a5a5a5a5a5a5a5,0)
        assert payload==bytes(expected);payloads+=1
        g1,g2=r['fixture'].get('states',[0,0]);mix=(g1+g2+p-8)&M64
        assert r['states_after']==[hex((mix*0xa5cd4cf+0x8c2fb9df71512e5a)&M64),hex(((mix^0x73d046208eaed1a6)*0xa5cd4cf)&M64)]
        if status:
            assert U32(reply,32)==status and U32(reply,0)==18
            continue
        success+=1
        assert U32(reply,0)==0x80000012 and U32(reply,24)==2
        assert U64(reply,28)==0x33445000 and reply[36:40]==bytes.fromhex('01010001')and U32(reply,40)==13
        assert U32(reply,44)==0x8844 and reply[48:56]==bytes.fromhex('0000000000001300')
        assert reply[56:64]==bytes.fromhex('0000000001000000')and U32(reply,64)==U32(req,56)
        assert reply[68:196]==bytes(i^0x5a for i in range(128))and struct.unpack_from('<4I',reply,196)==(13,0x11223344,0x55667788,0x99aabbcc)
    for saved in e['client_cases']:
        b=bytes.fromhex(saved['received212']);status,cleanup=client_status(b,saved['fixture'].get('transport_status',0))
        assert saved['status_u32']==status and [r['name']for r in saved['cleanup']]==([]if cleanup is None else[cleanup])
        # The received bytes already include the recorded adapter changes.
        # A fresh run applies only receive conversion without a second mutation.
        r=Client(f,stubs,saved['received212'],{'label':'oracle_replay','transport_status':saved['fixture'].get('transport_status',0),'normalize_port_disposition':False}).run_case()
        # Restore the mutated received remote field for a faithful independent replay.
        if U32(b,8)!=0:
            r=Client(f,stubs,saved['received212'],{'label':'oracle_replay','transport_status':saved['fixture'].get('transport_status',0),'normalize_port_disposition':False,'reply_changes':[[8,U32(b,8),4]]}).run_case()
        assert r['status_u32']==status and r['outputs']==saved['outputs']and r['visited']==saved['visited']
        if status:
            assert saved['outputs']==[(b'\xa5'*(144 if i==1 else 16)).hex()for i in range(8)]
        else:
            vals=[struct.pack('<I',U32(b,64)),b[68:196],b[28:36],b[40:44],b[200:204],b[204:208],b[208:212],b[44:48]]
            for i,v in enumerate(vals):assert saved['outputs'][i]==(v+b'\xa5'*((144 if i==1 else 16)-len(v))).hex()
    assert len(e['server_cases'])==13 and len(e['client_cases'])==22 and accepted==payloads==6 and success==4
    assert len(guards)==7
    return {'server_cases':13,'client_cases':22,'application_entries':accepted,'successful_fixture_replies':success,
      'full_payload104_comparisons':payloads,'request_guard_cases':7,'bank_inputs':1536,'original_fixup_words':15,
      'source_IDA_range_comparisons':11,'all_checks_pass':True}


if __name__=='__main__':print(json.dumps(audit()))
