#!/usr/bin/env python3
"""Conditional original process-path continuation to network-identity record.

Three source-initializer-compatible roots are separate same-cell premises;
no initializer/caller epoch join is asserted. Warm-cache and direct-return
controls remain distinct. O(receipts+cases*(visits+effects)+source+queries)
time/space; 30 s/query. No native API/IPC, allocation/free or hardware PAC.
"""
import itertools,json,struct
from collections import Counter
import z3
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,TABLE,selected
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell,resize
import recover_daemon_network_identity as Parent

P='daemon_network_record';ENTRY=0x10044167c;NETWORK_CALL=0x1004418a8;AFTER_NETWORK=NETWORK_CALL+4
CALL=0x1005c524c;AFTER_CALL=CALL+4;RECORD=0x1010c5764
ROOTS={0x858:(0x1010c8268,0x1004c2d30),0x5f0:(0x101031da0,0x1004c25cc),0x5e0:(0x100e99900,0x1004c3480)}
FOLLOW_ROOTS={0x5d0:(0x100e99800,0x1004c26b0),0x5d8:(0x100f4e290,0x1004c26c8)}
ONCE=0x10043e508
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_network_identity.py',
      'daemon_network_identity_checks.json','daemon_network_identity_audit.json',
      'recover_daemon_pidpath_consumer.py','audit_daemon_pidpath_consumer.py',
      'recover_daemon_return_bank_origins.py','daemon_return_bank_origins_checks.json',
      'audit_daemon_return_bank_origins.py','recover_daemon_environment_outputs.py','probe_daemon_descriptor_producers.py']

def restore(row):
    v=Parent.Run(row['configuration']);v.cut_stops=set()
    for j,x in enumerate(row['boundary']['registers31']):v.set(j,int(x,16))
    v.u.reg_write(ar.UC_ARM64_REG_SP,int(row['boundary']['SP'],16));v.u.reg_write(ar.UC_ARM64_REG_NZCV,int(row['boundary_NZCV'],16))
    for f in row['initial_private_fixtures']:v.fixture(int(f['address'],16),bytes.fromhex(f['bytes_hex']))
    for f in row['initial_image_fixtures']:v.image_fixture(int(f['address'],16),bytes.fromhex(f['bytes_hex']),f['provenance'])
    for w in row['source_writes']:
        a=int(w['address'],16);raw=bytes.fromhex(w['after_hex'])
        if Parent.Parent.Base.P<=a<a+len(raw)<=Parent.Parent.Base.P+Parent.Parent.Base.SIZE:v.fixture(a,raw)
        else:v.image_fixture(a,raw,'preceding_original_source_write')
    return v

def root_evidence():
    p=json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'));out=[]
    for j,c in enumerate(p['upstream_cases']):
        s=int(c['frame_base'],16);fields=[]
        for off,(value,pc) in (ROOTS|FOLLOW_ROOTS).items():
            writes=[w for w in c['source_writes'] if int(w['address'],16)<s+off+8 and s+off<int(w['address'],16)+w['size_bytes']]
            assert len(writes)==1 and writes[0]['size_bytes']==8 and writes[0]['pc']==hex(pc)
            assert int.from_bytes(bytes.fromhex(writes[0]['after_hex']),'little')==value
            fields.append({'offset_bytes':off,'writer':writes[0],'later_overwrites':0})
        out.append({'initializer_profile_index':j,'frame_base':hex(s),'boundary':c['boundary'],'fields':fields})
    assert len(out)==12
    return out

def conditional(c):
    row=c['trace'];v=restore(row);rows=[];effects=[];s=v.C
    for off,(value,pc) in ROOTS.items():
        assert row['boundary']['kind']=='before_unknown_private_read'
        d=row['boundary']['detail'];assert d['address']==hex(s+off) and d['size_bytes']==8 and d['snapshot']['known_mask_hex']=='00'*8
        v.fixture(s+off,struct.pack('<Q',value));effects.append({'address':hex(s+off),'bytes_hex':struct.pack('<Q',value).hex(),
            'source_initializer_writer':hex(pc),'separate_caller_premise':True,'before_known_mask_hex':'00'*8})
        v.cut_stops={Parent.ENTRY};row=v.interval(int(row['boundary']['pc'],16),'additional_initializer_compatible_root');rows.append(row)
    assert row['boundary']['pc']==hex(Parent.ENTRY)
    assert row['boundary']['SP']==hex(s-0x70) and row['boundary']['registers31'][0]==hex(s-0x6e)
    return {'parent_case_index':c['parent_case_index'],'root_premises':effects,'intervals':rows,'native_epoch_join_established':False}

def follow(row):
    v=restore(row);rows=[];effects=[];image=[];row=v.interval(AFTER_CALL,'network_record_pointer_consumer');rows.append(row)
    for off,(value,pc) in FOLLOW_ROOTS.items():
        assert row['boundary']['kind']=='before_unknown_private_read'
        d=row['boundary']['detail'];assert d['address']==hex(v.C+off) and d['size_bytes']==8 and d['snapshot']['known_mask_hex']=='00'*8
        v.fixture(v.C+off,struct.pack('<Q',value));effects.append({'address':hex(v.C+off),'bytes_hex':struct.pack('<Q',value).hex(),
            'source_initializer_writer':hex(pc),'separate_caller_premise':True,'before_known_mask_hex':'00'*8})
        if off==0x5d8:
            at=0x1010b66a8;raw=bytes(v.u.mem_read(at,8));assert raw==struct.pack('<Q',v.cfg['controllers'][0])
            image.append({'address':hex(at),'bytes_hex':raw.hex(),'provenance':'separate_acquisition_controller_image_premise'})
            v.image_fixture(at,raw,image[-1]['provenance'])
        row=v.interval(int(row['boundary']['pc'],16),'additional_acquisition_bank_root');rows.append(row)
    assert row['boundary']['pc']==hex(ONCE) and row['boundary']['detail']['symbol']=='libSystem/_pthread_once'
    assert row['boundary']['registers31'][:2]==['0x1010b8cd0','0x10040ebd4'] and row['boundary']['registers31'][19]=='0x0'
    return {'intervals':rows,'root_premises':effects,'additional_image_premises':image,'native_API_executed':False}

def warm(c,flag,data):
    v=restore(c['intervals'][-1]);v.cfg={**v.cfg,'network_flag8':flag,'MAC6_hex':data.hex()}
    v.image_fixture(Parent.CACHE,bytes([flag])+data,'declared_warm_network_cache')
    v.image_fixture(RECORD-4,b'\xa5'*4+b'\xee'*10+b'\x5a'*4,'declared_record_and_neighbor_bytes')
    v.cut_stops={AFTER_CALL};row=v.interval(Parent.ENTRY,'original_warm_cache_and_record_publication')
    assert row['boundary']['pc']==hex(AFTER_CALL) and row['boundary']['SP']==hex(v.C)
    assert bytes(v.u.mem_read(RECORD,10))==struct.pack('<I',6)+data
    assert bytes(v.u.mem_read(RECORD-4,4))==b'\xa5'*4 and bytes(v.u.mem_read(RECORD+10,4))==b'\x5a'*4
    assert int.from_bytes(v.u.mem_read(v.C+0x10cb8,8),'little')==RECORD
    continuation=follow(row)
    return {'parent_case_index':c['parent_case_index'],'configuration':v.cfg,'trace':row,'continuation':continuation,
            'record10_hex':(struct.pack('<I',6)+data).hex(),'record_pointer64':hex(RECORD),'native_API_executed':False}

def cold(c):
    v=restore(c['intervals'][-1]);v.image_fixture(Parent.CACHE,b'\0','separate_cold_cache_flag_premise')
    row=v.interval(Parent.ENTRY,'conditional_cold_cache_to_main_port_boundary')
    assert row['boundary']['pc']=='0x1000040d8' and row['boundary']['detail']['symbol']=='IOKit/_IOMainPort'
    assert row['boundary']['SP']==hex(v.C-0xb0) and row['boundary']['registers31'][:2]==['0x0',hex(v.C-0xb0)]
    return {'parent_case_index':c['parent_case_index'],'trace':row,'native_API_executed':False}

def zero_return(c):
    before=c['intervals'][-1];v=restore(before);v.cfg={**v.cfg,'separate_network_return32':0}
    for j in range(1,18):v.set(j,((j+1)*0xabcdef0102030405)&((1<<64)-1))
    v.set(0,0);v.u.reg_write(ar.UC_ARM64_REG_NZCV,0xa0000000);v.cut_stops={AFTER_CALL}
    event={'original_internal_call':hex(NETWORK_CALL),'component_entry':hex(Parent.ENTRY),'continuation_PC':hex(AFTER_NETWORK),
           'return_registers31':[hex(v.reg(j)) for j in range(31)],'return_NZCV':'0xa0000000','return32':0,
           'separate_internal_component_return_premise':True,'component_output_effects_modeled':False,'native_API_executed':False}
    row=v.interval(AFTER_NETWORK,'separate_zero_network_return_and_record_consumer')
    assert row['boundary']['pc']==hex(AFTER_CALL) and int.from_bytes(v.u.mem_read(v.C+0x10cb8,8),'little')==0
    v.cut_stops={0x100671718};suffix=v.interval(AFTER_CALL,'zero_record_pointer_and_inner_cursor_restoration')
    assert suffix['boundary']['pc']=='0x100671718'
    assert int.from_bytes(v.u.mem_read(v.C+0x16d0,8),'little')==v.cfg['cursor64']+0x420
    return {'parent_case_index':c['parent_case_index'],'return_premise':event,'trace':row,'record_pointer64':'0x0',
            'suffix':suffix,'inner_32_byte_cursor_restored':True,'native_API_executed':False}

def source():
    ranges=[('adapter_record',0x1005c5184,0x1005c5288),('identity_adapter',ENTRY,0x1004418d4),
            ('record_publication',0x100268010,0x1002680e4),('record_pointer_return',0x10020eb48,0x10020eb6c),
            ('next_record',0x1004f7460,0x1004f753c),('acquisition_adapter',0x10043e280,ONCE+4),
            ('inner_reservation',0x1004dbdf0,0x1004dbe60),('inner_restoration',0x10084ac58,0x10084ac78)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in ranges]

def banks():
    return [selected(0x101031da0,0x100e99900,0x0a,0xcc25),
            selected(0x101031da0,0x100e99900,0x86,0xcead),
            selected(0x100e99800,0x100f4e290,0x61,0xcbda)]

def intervals(e):
    return [r for c in e['conditional_cases'] for r in c['intervals']]+[c['trace'] for c in e['cold_cases']]+[
        r for c in e['warm_cases'] for r in [c['trace'],*c['continuation']['intervals']]]+[
        r for c in e['zero_cases'] for r in [c['trace'],c['suffix']]]

def obligations():
    qs=[];s=z3.BitVec('nr_SP64',64);c=s+0x10cb8;status=z3.BitVec('nr_network_status32',32)
    pointer=z3.BitVec('nr_record_pointer64',64)
    def prove(label,bad,premise=z3.BoolVal(True)):
        q=z3.Solver();q.set(timeout=30000);q.add(premise);assert q.check()==z3.sat;q.add(bad);assert q.check()==z3.unsat,label
        qs.append({'label':label,'query':q.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    v=Algebra();v.seed('sp',s);v.seed('w11',0x8224);v.run_block(0x1005c5184,0x1005c51e0)
    h=Algebra();h.seed('x19',c);h.seed('x0',c);h.memory=v.memory.copy();h.run_block(0x1004417bc,0x1004417fc)
    prove('all_SP64_network_adapter_record_decodes_7657',h.read('w26')!=0x7657)
    v=Algebra();v.seed('w0',status);v.seed('w26',0x7657);v.run_block(AFTER_NETWORK,0x1004418c8)
    prove('network_status_low32_selects_null_or_record_route',z3.Or(v.read('x20')!=0,v.read('w8')!=z3.If(status==0,z3.BitVecVal(0x7657,32),z3.BitVecVal(0x7677,32))))
    v=Algebra();v.seed('x20',RECORD);v.run_block(0x100268060,0x100268068)
    prove('record_length_is_exactly_six_bytes',cell(v,RECORD,4)!=6)
    v=Algebra();v.seed('x20',RECORD);v.seed('sp',s);v.run_block(0x1002680c4,0x1002680d4)
    prove('identity_copy_arguments_are_local_six_to_record_plus_four',z3.Or(v.read('x0')!=s+2,v.read('x1')!=RECORD+4,v.read('x2')!=6,v.read('x17')!=0x34a1))
    v=Algebra();v.seed('x20',pointer);v.seed('x19',c);v.run_block(0x10020eb48,0x10020eb4c)
    prove('record_pointer_return_is_eight_byte_caller_cell',cell(v,c,8)!=pointer)
    v=Algebra();v.seed('sp',s);v.seed('x19',s+0x10000);v.seed('w23',0x6cf4);v.seed('w20',0x8468);v.seed('w22',0x8240)
    mem(v,c,8,pointer);mem(v,s+0x858,8,0x1010c8268);v.run_block(AFTER_CALL,0x1005c5274)
    prove('caller_null_record_selects_exact_indices',z3.Or(v.read('x16')!=pointer,v.read('w8')!=z3.If(pointer==0,z3.BitVecVal(0x8468,32),z3.BitVecVal(0x8240,32))))
    v=Algebra();v.seed('sp',s);v.seed('x21',pointer);v.seed('x16',RECORD);v.seed('w24',0x9e4b)
    v.run_block(0x1004f7460,0x1004f74b0)
    h=Algebra();h.seed('x0',c);h.run_block(0x10043e3ac,0x10043e3d4)
    prove('exact_acquisition_prehash_key_agreement_domain',
          (v.read('w10')==h.read('w11'))!=((s&6)==0))
    # Compose the exact-domain lemma with an arbitrary common prehash key;
    # avoid repeating a difficult 32-bit multiply/XOR bit-blast.
    common=z3.BitVec('nr_common_prehash32',32);v.seed('w10',common);v.run_block(0x1004f74b0,0x1004f74d0)
    h.seed('w11',common);h.memory=v.memory.copy();h.run_block(0x10043e3d4,0x10043e3ec)
    prove('composed_acquisition_record_decodes_593d_and_null_capture',z3.Or(h.read('w26')!=0x593d,h.read('x19')!=0))
    return qs

def build():
    p=json.loads(read(ROOT/'daemon_network_identity_checks.json'));conditional_cases=[conditional(c) for c in p['retained_cases']]
    patterns=[bytes(6),b'\xff'*6,bytes.fromhex('0123456789ab'),bytes.fromhex('80017fff00fe')]
    warm_cases=[warm(c,f,d) for c,f,d in itertools.product(conditional_cases,[1,3,255],patterns)]
    zero_cases=[zero_return(c) for c in conditional_cases]
    e={'conditional_cases':conditional_cases,'cold_cases':[cold(c) for c in conditional_cases],'warm_cases':warm_cases,'zero_cases':zero_cases};counts=Counter()
    for r in intervals(e):counts.update(source_visits=len(r['source_visits']),reads=len(r['source_reads']),writes=len(r['source_writes']),logical_edges=len(r['logical_edges']))
    used={int(x['address'],16) for r in intervals(e) for x in r['source_reads'] if int(x['address'],16) in FIXUPS}
    e.update(scope=__doc__,generator_sha256=sha(__file__),source_sha256=sha(SOURCE),dependencies={n:sha(ROOT/n) for n in DEPS},
             root_writer_evidence=root_evidence(),source_regions=source(),bank_rules=banks(),source_fixups=Parent.Parent.Env.fixups(used),
             source_proofs=obligations(),verified_counts={'conditional_cases':8,'cold_cases':8,'warm_cases':96,'zero_cases':8,'intervals':len(intervals(e)),**counts},
             native_API_executed=False,native_daemon_kext_pairing_established=False,native_epoch_join_established=False,full_goal_complete=False)
    return e

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
