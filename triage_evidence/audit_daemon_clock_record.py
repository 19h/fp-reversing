#!/usr/bin/env python3
"""Independent source replay and exact clock/random record and pointer joins.

O(receipts+visits*(register state+byte effects)+query DAG) time/space;
solver work separate, 30 s/query. No native API/IPC/PAC or IDB mutation.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_context_state_publish import Lift,return_join,sdk_checks
from audit_daemon_environment_outputs import DEC
from audit_daemon_network_record import state_bytes,fixture_bytes,join
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_clock_record as R

def comparison_records(row):
    out=[];mask64=(1<<64)-1
    for call in row['source_calls']:
        at=int(call['arguments8'][0],16);state=fixture_bytes(row,'private')|fixture_bytes(row,'image')
        for w in row['source_writes']:
            if w['source_visit_index']<call['source_visit_index']:state.update({int(w['address'],16)+j:b for j,b in enumerate(bytes.fromhex(w['after_hex']))})
        raw=bytes(state[at+j] for j in range(40));u=lambda o,n:int.from_bytes(raw[o:o+n],'little')
        if call['target']=='0x100427514':
            key=((at^0x0179fa0fe732d262)*0xba209ef7)&mask64;k=key&0xffffffff
            a,b=(u(0,8)+key)&mask64,u(24,8)^key;mode=u(8,4)^k
            yes,no,mask=u(16,4)^k,(u(20,4)+k)&0xffffffff,u(32,4)^k
            assert (a,b,mode)==(623,2,0);choose=a<b;off=12;writer='0x1004275ac';index=0x17ba;target=0x100a894b0
        else:
            assert call['target']=='0x100444d6c'
            key=((at^0x823819558515cfbd)*0xc7f6dca7)&mask64;k=key&0xffffffff
            a,b=(u(16,8)+key)&mask64,u(32,8)^key;mode=u(12,4)^k
            yes,no,mask=u(28,4)^k,(u(8,4)-k)&0xffffffff,(u(4,4)+k)&0xffffffff
            assert (a,b,mode)==(1,3,1);choose=a>b;off=0;writer='0x100444df4';index=0x1752;target=0x100a075e0
        result=mask^(yes if choose else no);assert result==index
        w=[w for w in row['source_writes'] if w['pc']==writer];assert len(w)==1 and w[0]['address']==hex(at+off) and w[0]['after_hex']==struct.pack('<I',result).hex()
        assert FIXUPS[TABLE+8*index]['target']==target
        out.append({'call_site':call['pc'],'target':call['target'],'record':hex(at),'decoded_A64':a,'decoded_B64':b,'mode32':mode,
                    'true_choice32':hex(yes),'false_choice32':hex(no),'mask32':hex(mask),'predicate':choose,
                    'result_index32':hex(result),'selected_slot':hex(TABLE+8*index),'selected_target':hex(target),
                    'accessed_extent_bytes':36 if off else 40,'output_offset_bytes':off})
    assert len(out)==2;return out

def interfaces(e):
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));counts=Counter();comparisons=[]
    for c in e['clock_cases']:
        before=parent['entropy_cases'][c['parent_entropy_case_index']]['intervals'][-1];row=c['intervals'][0]
        return_join(before,c['import_return'],row,c['effects']);counts['clock_return_joins']+=1
        assert before['foreign_owners']==row['foreign_owners']
        out=int(c['timeval_address'],16);rec=int(c['record_address'],16)
        assert out==int(before['boundary']['SP'],16)+0x230 and rec==out-16
        assert not c['import_return']['timeval_padding_defined']
        padding=set(range(out+12,out+16))
        assert all(not padding.intersection(range(int(f['address'],16),int(f['address'],16)+len(bytes.fromhex(f['bytes_hex'])))) for f in row['initial_private_fixtures'])
        assert all(not padding.intersection(range(int(x['address'],16),int(x['address'],16)+x['size_bytes'])) for x in row['source_reads']+row['source_writes'])
        assert not row['source_calls']
        if c['clock_fields'] is None:
            assert not c['effects'] and not row['source_visits'] and not row['source_reads'] and not row['source_writes']
            b=row['boundary'];assert b['pc']==hex(R.ENTRY) and b['kind']=='before_unknown_private_read'
            assert b['detail']['address']==hex(out) and b['detail']['size_bytes']==8 and b['detail']['snapshot']['known_mask_hex']=='00'*8
            counts['undefined_clock_output_stops']+=1
        else:
            sec,usec=c['clock_fields'];assert 0<=usec<1000000
            assert c['effects']==[{'address':hex(out),'bytes_hex':struct.pack('<q',sec).hex(),'field':'tv_sec_signed64_seconds','separate_API_output_premise':True},
                                 {'address':hex(out+8),'bytes_hex':struct.pack('<i',usec).hex(),'field':'tv_usec_signed32_microseconds','separate_API_output_premise':True}]
            rs=[r for r in row['source_reads'] if out<=int(r['address'],16)<out+16]
            assert [(r['pc'],r['address'],r['size_bytes']) for r in rs]==[(hex(R.ENTRY),hex(out),8),('0x100b4db54',hex(out+8),4)]
            ws=row['source_writes'];assert len(ws)==2
            assert [(w['pc'],w['address'],w['size_bytes']) for w in ws]==[('0x100b4db58',hex(rec+4),4),('0x100b4db58',hex(rec+8),4)]
            assert [w['after_hex'] for w in ws]==[struct.pack('<I',usec).hex(),struct.pack('<I',sec&0xffffffff).hex()]
            assert row['boundary']['pc']==hex(R.RANDOM2) and row['boundary']['detail']['symbol']=='libSystem/_arc4random'
            assert len(row['source_visits'])==22
            counts.update(defined_clock_field_controls=1,clock_field_read_bytes=12,clock_record_write_bytes=8,untouched_padding_bytes=4)
    for c in e['random_cases']:
        p=e['clock_cases'][c['parent_clock_case_index']];before=p['intervals'][-1];rec=int(p['record_address'],16)
        r2,r3=[int(x,16) for x in c['random_return_pair32']]
        for row,event in zip(c['intervals'],c['import_returns']):
            return_join(before,event,row);assert before['foreign_owners']==row['foreign_owners'];before=row;counts['random_return_joins']+=1
        a,b=c['intervals'];assert len(a['source_writes'])==1
        assert a['source_writes'][0]['pc']=='0x100b4dbac' and a['source_writes'][0]['address']==hex(rec+12)
        assert a['source_writes'][0]['after_hex']==struct.pack('<I',r2).hex()
        w=b['source_writes'][0];assert w['pc']=='0x100b4dc00' and w['address']==hex(rec) and w['after_hex']==struct.pack('<I',r3).hex()
        sec,usec=p['clock_fields'];expected=struct.pack('<4I',r3,usec,sec&0xffffffff,r2)
        end=state_bytes(b);assert bytes(end[rec+j] for j in range(16))==expected==bytes.fromhex(c['record16_hex'])
        initial=state_bytes(a);base=0x1010c784c
        old0=int.from_bytes(bytes(initial[base+j] for j in range(4)),'little')
        old1=int.from_bytes(bytes(initial[base+4+j] for j in range(4)),'little')
        mixed=((old1^((old0^(old0>>30))*1664525&0xffffffff))+r3)&0xffffffff
        global_writes=[w for w in b['source_writes'] if int(w['address'],16)<0x6000000000]
        assert len(global_writes)==1 and global_writes[0]['pc']=='0x1009c470c' and global_writes[0]['address']==hex(base+4)
        assert global_writes[0]['after_hex']==struct.pack('<I',mixed).hex()
        contracts=comparison_records(b);comparisons.append({'random_case_index':len(comparisons),'contracts':contracts})
        counts.update(first_state_mix_equations_checked=1,comparison_record_contracts_checked=2)
        point=b['boundary'];sp=int(point['SP'],16)
        assert point['pc']==hex(R.STOP) and point['kind']=='before_explicit_source_cut' and point['registers31'][10]=='0x4'
        # Independently bound the unexecuted load and verify the source-derived
        # zero pointer cell remains the latest memory epoch at the demand.
        i=next(DEC.disasm(IMAGE.read(R.STOP,4),R.STOP));assert i.mnemonic=='ldr' and i.op_str=='w15, [x10]'
        assert bytes(end[sp+0x190+j] for j in range(8))==bytes(8)
        assert not any(int(o['address'],16)<=4<8<=int(o['address'],16)+o['size_bytes'] for o in b['foreign_owners'])
        assert not any(int(x['address'],16)<8 and 4<int(x['address'],16)+x['size_bytes'] for x in b['source_reads']+b['source_writes'])
        for pc in [0x100a075e8,0x100a075ec]:
            frame=b['source_frames'][next(j for j,v in enumerate(b['source_visits']) if int(v['pc'],16)==pc)]
            assert frame['registers31'][8]=='0x4'
            if pc==0x100a075ec:assert frame['registers31'][9]=='0x0'
        counts.update(record16_compositions_checked=1,record_bytes_checked=16,unexecuted_computed_read_cuts=1,source_zero_pointer_cells_checked=1)
    # The status-only pair carries identical output fields and identical source
    # route/effects. X0 remains the explicit API return until the next API call.
    for j in range(8):
        a,b=e['clock_cases'][5*j+1]['intervals'][0],e['clock_cases'][5*j+4]['intervals'][0]
        assert a['source_visits']==b['source_visits'] and a['source_reads']==b['source_reads'] and a['source_writes']==b['source_writes'] and a['logical_edges']==b['logical_edges']
        counts['status_only_route_controls_checked']+=1
    origins=R.pointer_origin(parent);assert e['pointer_origin_evidence']==origins
    for c in origins:
        o=c['origin'];row=parent['cases'][c['parent_main_case_index']]['intervals'][o['interval_index']]
        k,j=o['zero_producer_visit_index'],o['pointer_store_visit_index']
        for v in row['source_visits'][k+1:j]:
            pc=int(v['pc'],16);i=next(DEC.disasm(IMAGE.read(pc,4),pc))
            assert not any(i.reg_name(r) in ['x16','w16'] for r in i.regs_access()[1])
        counts['parent_zero_to_pointer_store_chains_checked']+=1
    return {'verified_counts':dict(counts),'comparison_records':comparisons,'scope':'Exact local composition under separate output/return premises. Native clock outcomes, pointer validity, reachability and daemon-kext pairing remain unknown.'}

def obligations():
    qs=[]
    def prove(label,bad):
        q=z3.Solver();q.set(timeout=30000);assert q.check()==z3.sat;q.add(z3.simplify(bad));assert q.check()==z3.unsat,label
        qs.append({'label':label,'query':q.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    sec=z3.BitVec('cr_seconds64',64);usec,status,upper=z3.BitVecs('cr_usec32 cr_status32 cr_upper32',32)
    rec=0x680005ff00;v=Algebra();v.seed('x24',rec);v.seed('x0',z3.Concat(upper,status));mem(v,rec+16,8,sec);mem(v,rec+24,4,usec)
    v.run_block(R.ENTRY,0x100b4db5c)
    prove('all_time_fields_original_record_is_usec32_and_low_seconds32',z3.Or(cell(v,rec+4,4)!=usec,cell(v,rec+8,4)!=z3.Extract(31,0,sec)))
    prove('clock_return_full_X0_untouched_by_first_field_consumers',v.read('x0')!=z3.Concat(upper,status))
    value=z3.BitVec('cr_random32',32)
    v=Algebra();v.seed('x24',rec);v.seed('x0',z3.Concat(upper,value));v.run_block(R.RANDOM2+4,R.RANDOM2+8)
    prove('second_random_store_uses_only_low32',cell(v,rec+12,4)!=value)
    v=Algebra();v.seed('x24',rec);v.seed('x0',z3.Concat(upper,value));v.run_block(R.RANDOM3+4,R.RANDOM3+12)
    prove('third_random_store_uses_only_low32_and_zeroes_index',z3.Or(cell(v,rec,4)!=value,v.read('x27')!=0))
    prior=z3.BitVec('cr_prior_X16_64',64);v=Algebra();v.seed('x16',prior);v.run_block(0x100b73fa0,0x100b73fa4)
    prove('original_pointer_producer_overwrites_all_prior_X16_values',v.read('x16')!=0)
    v.seed('sp',0x680005fce0);v.run_block(0x100a8c054,0x100a8c058)
    prove('original_saved_pointer_is_full_u64_zero',cell(v,0x680005fe70,8)!=0)
    base,index=z3.BitVecs('cr_saved_base64 cr_index64',64);v=Algebra();v.seed('sp',0x680005fce0);v.seed('x27',index);mem(v,0x680005fe70,8,base)
    v.run_block(0x100a075e0,0x100a075f0)
    formula=base+(z3.ZeroExt(32,z3.Extract(31,0,index))<<2)
    prove('original_computed_word_address_uses_low32_index',v.read('x10')!=formula)
    old0,old1,key=z3.BitVecs('cr_previous_word32 cr_current_word32 cr_key_word32',32)
    v=Algebra();v.seed('x20',0x1010c784c);v.seed('w19',1);v.seed('w27',0);v.seed('sp',0x680005fce0)
    mem(v,0x1010c784c,4,old0);mem(v,0x1010c7850,4,old1);mem(v,0x680005fea0,8,rec);mem(v,rec,4,key)
    v.run_block(0x1009c46dc,0x1009c4714)
    prove('all_words_first_key_mix_uses_third_random_word',z3.Or(cell(v,0x1010c7850,4)!=((old1^((old0^z3.LShR(old0,30))*1664525))+key),v.read('w19')!=2))
    return qs

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    lifts=[];totals=Counter()
    for j,row in enumerate(R.intervals(e)):
        a=Lift(row).run();a['interval_index']=j;lifts.append(a);totals.update(a['verified_counts'])
        if j%8==0:print(json.dumps({'interval':j,'source_visits':totals['source_visits']}),flush=True)
    qs=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
        'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],
        'independent_lifts':lifts,'independent_totals':dict(totals),'interfaces':interfaces(e),'source_proofs':qs,'source_queries_unsat':len(qs),
        'SDK_checks':sdk_checks(),'all_checks_pass':True,'native_API_executed':False,'native_daemon_kext_pairing_established':False,
        'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'interfaces':e['interfaces']}),flush=True)
