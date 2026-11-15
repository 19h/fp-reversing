#!/usr/bin/env python3
"""Independent source proofs, scalar replay and scratch byte-epoch audit.
O(P+C*E+Q*log(E+Q)+32V+proof DAG) time and O(parent receipts+largest
interval+selected frames+proof DAG) space; P parent bytes, C chunks,
E events/fixture bytes, Q selected read-byte queries, V selected visits.
Solver search additional, 30 s/query.
No native target/API/IPC, hardware PAC or IDB operation.
"""
import gc
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_record_extension import unpack
from recover_daemon_record_banks import instruction
from audit_daemon_record_input_origin import replay, independent_origins
from audit_daemon_alternative_fill import Source
from audit_daemon_append_fields import Lift
from audit_daemon_state_table_mixing import Scalar
import recover_daemon_payload_scalar_mixers as R

DEPS=['audit_daemon_record_input_origin.py','audit_daemon_append_fields.py','audit_daemon_alternative_fill.py',
      'audit_daemon_state_table_mixing.py','lskd_values_symbolic.py']


def obligations():
    out=[]
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat
        s.add(z3.simplify(bad));result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
        out.append({'label':label,'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
        print(json.dumps({'source_proof':label,'result':'unsat'}),flush=True)
    raw,position,selector,cell=z3.BitVecs('psm_A32 psm_position32 psm_selector32 psm_cell32',32)
    base,table,callee,holder,fp,owner=z3.BitVecs('psm_base64 psm_table64 psm_callee64 psm_holder64 psm_fp64 psm_owner64',64)
    bs=z3.BitVecs('psm_b0_8 psm_b1_8 psm_b2_8 psm_b3_8',8)
    pcs=[0x100a8d8a4,0x100a8d8b8,0x100a8d8cc,0x100a8d8e4]
    v=Source({0x100a8d894:(8,callee),**{pc:(1,b) for pc,b in zip(pcs,bs)}})
    for n,x in {'w8':position,'x21':base,'x20':table,'w19':selector,**R.PHASE}.items():v.seed(n,x)
    v.run_block(0x100a8d894,0x100a8d924)
    expected={0x100a8d894:table+8*z3.SignExt(32,selector),
              **{pc:base+z3.ZeroExt(32,position+0xfe53bc45+k) for k,pc in enumerate(pcs)}}
    prove('original_BE32_reader_all_32_input_bits_and_modular_addresses',z3.Or(
        v.read('w8')!=(z3.Concat(*bs)^0x6703cce9),v.read('x9')!=callee,v.read('x17')!=0x68f8,
        *[a!=expected[pc] for pc,a,n in v.loads]))
    x=z3.BitVec('psm_stage32',32)
    for j,(start,first,second,end,bias,delta,off) in enumerate(R.SPANS):
        v=Lift();v.seed('w8',raw);v.run_block(start,first)
        prove('original_variant_'+str(j)+'_triple_XOR_addition',v.read('w8')!=((raw^0x6703cce9)+0x74c239af))
        v=Lift();v.seed('w8',x);v.run_block(first,second)
        prove('original_variant_'+str(j)+'_multiply_add',v.read('w8')!=x*0x01ef2eff+bias)
        values={end-0x30:(8,owner),end-0x24:(4,cell)}
        v=Source(values)
        for n,t in {'w8':x,'x6':holder,'x29':fp}.items():v.seed(n,t)
        v.run_block(second,end)
        expected={end-0x30:holder+0x18,end-0x24:fp-off}
        prove('original_variant_'+str(j)+'_carry_network_and_side_loads',z3.Or(
            v.read('w11')!=((x+delta)^0xe4b5bf34),v.read('x9')!=owner,
            v.read('w10')!=cell+0xa7a8e5ca,*[a!=expected[pc] for pc,a,n in v.loads]))
        composed=((((raw^0x6703cce9)+0x74c239af)*0x01ef2eff+bias+delta)^0xe4b5bf34)
        prove('composed_variant_'+str(j)+'_affine_normalized_word',composed!=(((raw^0x6703cce9)*0x01ef2eff+0x00833631)^0xe4b5bf34))
    d=z3.BitVec('psm_input32',32);value=d*0x01ef2eff+0x00833631
    prove('all_u32_affine_inverse_and_injectivity',(value-0x00833631)*0xa46fd0ff!=d)
    v=Scalar();v.seed('w19',raw);v.seed('w10',0xbc66);v.run_block(0x100a7ccc0,0x100a7ccf0)
    y=raw^z3.LShR(raw,11);y^=(y<<7)&0x9d2c5680;y^=(y<<15)&0xefc60000;y^=z3.LShR(y,18)
    prove('original_scratch_word_tempering_all_u32',v.read('w9')!=y)
    source,dest=z3.BitVecs('psm_copy_source64 psm_copy_dest64',64)
    cursor,origin,phase=z3.BitVecs('psm_copy_cursor32 psm_copy_origin32 psm_copy_phase32',32)
    byte=z3.BitVec('psm_copy_byte8',8);v=Source({0x100a396a4:(1,byte)})
    for n,t in {'x1':source,'x25':dest,'w9':cursor,'w22':origin,'w21':phase,
                'w14':0x66e2,'w12':11,'w15':0xb5c7bc9b}.items():v.seed(n,t)
    v.run_block(0x100a39694,0x100a396b0);w,=v.stores
    prove('original_prefix_byte_copy_addresses_and_value',z3.Or(
        v.loads[0][1]!=source+z3.ZeroExt(32,(((phase^0x66e2)*11)^0xb5c7bc9b)+cursor),
        w['address']!=dest+z3.ZeroExt(32,cursor-origin),w['value']!=byte))
    assert len(out)==12
    return out


def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')))
    for p,h in R.PINS.items():assert sha(ROOT/p)==h
    parent=json.loads(read(ROOT/'daemon_record_extension_checks.json'));totals=Counter();cases=[]
    for c in e['cases']:
        ci=c['class_index'];item=parent['classes'][ci]['intervals'][3]
        assert c['parent_interval_sha256']==item['interval_packed']['decoded_sha256'];row=unpack(item['interval_packed'])
        for p in c['chunks']:
            lo,hi=p['start_visit'],p['end_visit_exclusive']
            assert p['visits']==row['source_visits'][lo:hi]
            assert p['frames']==[{k:v for k,v in f.items() if k!='Q_registers32'} for f in row['source_frames'][lo:hi+1]]
            assert all(f['Q_registers32']==p['Q_registers32_preserved'] for f in row['source_frames'][lo:hi+1])
            for k,f in [('reads','source_reads'),('writes','source_writes'),('edges','logical_edges')]:
                assert p[k]==[x for x in row[f] if lo<=x['source_visit_index']<hi]
            totals.update(replay(p))
        totals.update({'selected_read_'+k:v for k,v in independent_origins(row,c).items()})
        for k,f in enumerate(c['fields']):
            lo=f['reader_start_visit'];end=f['mixer_start_visit'];frames=row['source_frames']
            assert f['owner_offset_bytes']==117+4*k and row['source_visits'][end]['pc']==f['mixer_start_pc']
            rr=[x for x in row['source_reads'] if lo<=x['source_visit_index']<end and x['size_bytes']==1]
            assert rr==f['source_reads'] and len(rr)==4
            d=int.from_bytes(bytes.fromhex(''.join(x['bytes_hex'] for x in rr)),'big')
            v=int(f['normalized_word_hex'],16)
            assert ((v-0x00833631)*0xa46fd0ff)&0xffffffff==d==f['decoded_input32']
            assert int(f['entry_A32'],16)==d^0x6703cce9==int(frames[end]['registers31'][8],16)&0xffffffff
            assert int(f['writer_W11'],16)==v^0xe4b5bf34
            for n,value in R.PHASE.items():assert int(frames[lo]['registers31'][int(n[1:])],16)&0xffffffff==value
            base=int(frames[lo]['registers31'][21],16);off=(int(frames[lo]['registers31'][8],16)+0xfe53bc45)&0xffffffff
            assert f['source_base']==hex(base) and f['source_offset32']==off
            assert [int(x['address'],16) for x in rr]==[base+((off+j)&0xffffffff) for j in range(4)]
            totals.update({'input_'+key:value for key,value in independent_origins(row,{'selected_read_origins':f['source_origins']}).items()})
            p,=[p for p in c['chunks'] if p['start_visit']==lo and p['kind']=='reader_mixer_to_word_emissions']
            wordstores=[w for w in p['writes'] if w['pc'] in ['0x100c70e28','0x100c70e80','0x100c70ed0','0x100c70f18']]
            assert len(wordstores)==4
            normalized=bytes(bytes.fromhex(w['after_hex'])[0]^bytes.fromhex('d98c9317498b221182b3198570dd904f')[(117+4*k+j)&15] for j,w in enumerate(wordstores))
            assert normalized.hex()==f['normalized_word_hex']
            totals['BE32_fields_checked']+=1;totals['word_emission_bytes_checked']+=4
        scratch=int(c['fields'][1]['source_reads'][0]['address'],16);cut=c['fields'][1]['reader_start_visit']
        writes=[w for w in row['source_writes'] if scratch<=int(w['address'],16)<scratch+4 and w['source_visit_index']<cut]
        assert writes==c['scratch_writes'] and len(writes)==6
        state={};snapshots=[]
        for j,w in enumerate(writes):
            state[int(w['address'],16)-scratch]=bytes.fromhex(w['after_hex'])[0]
            if j in [3,5]:snapshots.append(bytes(state[k] for k in range(4)).hex())
            totals['scratch_write_events_checked']+=1
        assert snapshots==['20a363fd','000063fd']
        for j,w in enumerate(writes[4:]):
            r=c['scratch_copy_reads'][j];assert r['source_visit_index']==w['source_visit_index']-2
            assert r['bytes_hex']==w['after_hex']=='00' and int(r['address'],16)==0x6500115b44+j
            totals['scratch_prefix_copies_checked']+=1
        totals.update({'copy_'+k:v for k,v in independent_origins(row,{'selected_read_origins':c['scratch_copy_origins']}).items()})
        for a in c['fields'][0]['incoming_source_fixtures']:
            assert len(a)==1 and a[0]['fixture_address']=='0x6500115b20' and a[0]['byte']==0
        for enc in c['scratch_encoders']:
            p,=[p for p in c['chunks'] if p['start_visit']==enc['start_visit'] and p['kind']=='scratch_byte_encoder']
            registers=[int(x,16) for x in p['frames'][0]['registers31']];w,=p['writes'];a=int(w['address'],16)
            assert enc['source_W9']==hex(registers[9]&0xffffffff) and enc['shift_bits']==registers[8]&31
            vals={int(r['pc'],16):int.from_bytes(bytes.fromhex(r['bytes_hex']),'little') for r in p['reads']}
            cache=vals[0x100a0c9d8];mask=vals[0x100a0c9f8]^0xa7a730ec;text=vals[0x100a0ca14]^0x12af5504870a589f
            index=(cache+(a&0xffffffff))&0xffffffff
            locations=[text+(((index+k)&0xffffffff)&mask) for k in [0x0ba3ccc8,0x0ba3ccca]]
            tb=bytes(IMAGE.read(x,1)[0] for x in locations)
            assert registers[10]&0xffffffff==0xbc66 and enc['text_addresses']==[hex(x) for x in locations]
            assert enc['text_bytes_hex']==tb.hex() and enc['destination']==hex(a)
            actual=((registers[9]>>(registers[8]&31))^(31*(a&0xffffffff))^tb[0]^tb[1]^0xd7)&255
            assert actual==bytes.fromhex(w['after_hex'])[0] and enc['stored_byte_hex']==w['after_hex']
            totals['scratch_byte_encoders_checked']+=1
        t=c['scratch_tempering'];lo=t['start_visit'];raw=int(row['source_frames'][lo]['registers31'][19],16)&0xffffffff
        y=raw^(raw>>11);y^=(y<<7)&0x9d2c5680;y^=(y<<15)&0xefc60000;y^=y>>18
        assert t['input_W19']==hex(raw) and t['output_W9']==hex(y) and t['phase_W10']=='0xbc66'
        for p in t['preservation']:
            end=p['consumer_start_visit'];assert p['frame_checks']==end-(lo+12)+1
            assert all((int(f['registers31'][9],16)&0xffffffff)==y for f in row['source_frames'][lo+12:end+1])
            for v in row['source_visits'][lo+12:end]:
                i=instruction(int(v['pc'],16));assert not any(i.reg_name(r) in ['w9','x9'] for r in i.regs_access()[1])
            totals['W9_preserved_frame_checks']+=p['frame_checks']
        totals['scratch_tempered_words_checked']+=1
        cases.append({'class_index':ci,'input_BE32_words':[f['raw_BE32_hex'] for f in c['fields']],
                      'normalized_output_words':[f['normalized_word_hex'] for f in c['fields']],
                      'scratch_snapshots':snapshots,'context_byte_offsets':[32,33,34,35,36,37]})
        print(json.dumps({'audit_class':ci,'visits':totals['source_visits']}),flush=True)
        del row;gc.collect()
    proofs=obligations();totals['new_source_queries_unsat']=len(proofs)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'parent_pins':R.PINS,
            'dependencies':{p:sha(ROOT/p) for p in DEPS},'cases':cases,'independent_totals':dict(totals),
            'source_proofs':proofs,'retained_payload_scalar_contract_established':True,
            'native_schema_established':False,'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'full_goal_complete':False}


if __name__=='__main__':
    x=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(x,indent=2)+'\n')
    print(json.dumps(x['independent_totals']),flush=True)
