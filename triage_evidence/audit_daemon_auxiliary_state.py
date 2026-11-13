#!/usr/bin/env python3
"""Independent auxiliary initializer, table decoder and strict boundary audit.

O(receipts+visits*(register state+byte effects)+query DAG) time/space;
30 s/query. Original-code replay and compact equations are local conditional
evidence. Native ownership, caller epochs and transport remain unknown.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_readiness_arena import Lift
from audit_daemon_context_state_publish import return_join
from audit_daemon_network_record import fixture_bytes,state_bytes
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_auxiliary_state as R

M32=(1<<32)-1;M64=(1<<64)-1;F=0x01000193;INV=0x359c449b
def u32(x):return x&M32
def raw(s,a,n):return bytes(s[a+j] for j in range(n))
def word(s,a,n=8):return int.from_bytes(raw(s,a,n),'little')
def selected(row,pc,kind='source_reads'):return [x for x in row[kind] if x['pc']==hex(pc)]

def cached_value(value,first):
    mask,c1,c2=(0x1eb684772ee1201f,0x9436845702010016,0x2bc109a8bdeca409) if first else (0x4d6e4499c38fc7bc,0x810a0410008a0104,0x6c74d9cfd335c6ba)
    t=(value&mask)^c1
    return (((value&0x7fffffffffffffff)^c2^t)-t)&M64

def decode_record(encoded,control):
    p=u32(control*0x41da4f94);a=u32(u32(p*p)^p);b=u32(u32((p|1)*p)^p)
    x=encoded^(a|(b<<32))
    data=bytearray(struct.pack('<II',u32((u32(x)-a)*INV),u32(((x>>32)-b)*INV)))
    index={i:u32(u32(u32(p+i)^p)*F)%i for i in [3,5,6,7]}
    low,high=data[:4],data[4:]
    data[1]=low[0];data[0]=low[2];data[2]=low[1]
    k=index[3];data[k],data[3]=data[3],data[k]
    data[0],data[4]=high[0],data[0]
    for i in [5,6,7]:
        k=index[i];data[k],data[i]=data[i],data[k]
    return int.from_bytes(data,'little'),{'control32':hex(control),'mixed_control32':hex(p),'indices':index,
                                           'affine_offsets32':[hex(a),hex(b)],'decoded64':hex(int.from_bytes(data,'little'))}

def contract(c,parent):
    before=R.unpack(parent['intervals'][-1]['packed']);row=R.unpack(c['intervals_packed'][0]);result=int(c['pointer_return64'],16)
    assert c['parent_case_index'] in [0,1] and c['ABI_clobber_pattern'] in [0,1]
    ev=c['import_return'];return_join(before,ev,row,c['effects'])
    assert ev['pointer_return64']==hex(result) and ev['allocated_owner_premise']==({'address':hex(result),'size_bytes':104,'initial_bytes_defined':False} if result else None)
    assert row['entry_registers31'][0]==hex(result) and not any(R.B+k in fixture_bytes(row,'image') for k in range(R.N))
    owners=before['foreign_owners']+([{'address':hex(result),'size_bytes':104}] if result else [])
    assert row['foreign_owners']==owners
    if result:
        assert result==R.B and all(not(a<result+104 and result<a+n) for a,n in [(int(o['address'],16),o['size_bytes']) for o in before['foreign_owners']])
    if c['table_NULL_control']:
        assert c['effects']==[{'address':hex(R.J+0x100),'bytes_hex':'00'*8,'provenance':'separate_existing_table_NULL_control'}]
        assert row['boundary']['pc']==hex(R.SKIP) and row['boundary']['kind']=='before_explicit_source_cut'
    else:
        assert not c['effects'] and row['boundary']['pc']==hex(R.STOP) and row['boundary']['kind']=='before_undefined_foreign_owner_read'
    initial=fixture_bytes(row,'private')|fixture_bytes(row,'image');final=state_bytes(row);model=Counter(import_return_joins_checked=1)
    heap=[w for w in row['source_writes'] if R.B<=int(w['address'],16)<R.B+R.N]
    generated=raw(initial,R.J+0x34,32);assert raw(final,R.J+0x34,32)==generated
    assert not any(int(x['address'],16)<R.J+0x54 and R.J+0x34<int(x['address'],16)+x['size_bytes'] for x in row['source_reads']+row['source_writes'])
    model['generated_bytes_preserved_without_access_checked']+=32
    pointer_stores=selected(row,0x1007fcdfc,'source_writes')
    defaults={0:(4,0x8b3dc651),4:(4,0x8b3dc651),8:(8,0xe3b88695c0d52dbc),16:(8,0),24:(4,0x8b3dc651),
              32:(8,0),40:(4,0),48:(8,0xe3b88695c0d52dbc),56:(8,0xe3b88695c0d52dbc),64:(8,0),88:(8,0),96:(4,0x8b3dc651),100:(1,1)}
    cache=[]
    if result:
        for pc,off,first,at in [(0x1007fcd44,72,True,0x6500115e24),(0x1007fcda8,80,False,0x6500115e34)]:
            rr=selected(row,pc);assert len(rr)==1 and rr[0]['address']==hex(at) and rr[0]['size_bytes']==8
            value=int.from_bytes(bytes.fromhex(rr[0]['bytes_hex']),'little');defaults[off]=(8,cached_value(value,first))
            cache.append({'source_read':rr[0],'output_offset_bytes':off,'encoded64':hex(defaults[off][1])})
        expected={off+j:b for off,(n,value) in defaults.items() for j,b in enumerate(value.to_bytes(n,'little'))}
        actual={int(w['address'],16)-result+j:b for w in heap for j,b in enumerate(bytes.fromhex(w['after_hex']))}
        assert actual==expected and len(heap)==15 and sum(w['size_bytes'] for w in heap)==len(expected)==93
        gaps=[j for j in range(104) if j not in expected];assert gaps==list(range(28,32))+list(range(44,48))+list(range(101,104))
        assert all(result+j not in final for j in gaps) and all(final[result+j]==b for j,b in expected.items())
        assert not any(result<=int(x['address'],16)<result+104 for x in row['source_reads'])
        assert len(pointer_stores)==1 and pointer_stores[0]['address']==hex(R.J+0x1e0) and pointer_stores[0]['after_hex']==struct.pack('<Q',result).hex()
        assert all(w['source_visit_index']<pointer_stores[0]['source_visit_index'] for w in heap)
        model.update(auxiliary_bytes_initialized_checked=93,auxiliary_gaps_undefined_checked=11,raw_pointer_publications_checked=1,cached_word_transforms_checked=2)
    else:
        assert not heap and not pointer_stores and raw(final,R.J+0x1e0,8)==raw(initial,R.J+0x1e0,8)
        model['NULL_allocation_skips_publication_checked']+=1
    rr=selected(row,0x10050e024);assert len(rr)==1 and rr[0]['address']==hex(R.J+0x100)
    decoder=None
    if not c['table_NULL_control']:
        assert rr[0]['bytes_hex']=='2e4c2bee000003c5'
        control=u32(word(initial,0x6500115e00,4)^0x41da4f94)
        mask=word(initial,0x1010c6800)^0xfff0c012a7a730ec;text=word(initial,0x1010ca2a8)^0x12af5504870a589f
        lookups=[]
        for pc in range(0x100865e48,0x100865ec0,16):
            address=text+(control&mask);value=int.from_bytes(IMAGE.read(address,4),'little')
            reads=selected(row,pc);assert len(reads)==1 and reads[0]['address']==hex(address) and reads[0]['bytes_hex']==value.to_bytes(4,'little').hex()
            lookups.append(reads[0]);control^=value
        decoded,decoder=decode_record(int.from_bytes(bytes.fromhex(rr[0]['bytes_hex']),'little'),control)
        assert decoded==0x6500115274 and row['boundary']['registers31'][12]==hex(decoded) and row['boundary']['registers31'][14]==hex(decoded+8)
        assert row['boundary']['registers31'][11]=='0x1' and row['boundary']['registers31'][13]=='0x0'
        assert word(final,0x680006b7a0)==decoded
        assert row['boundary']['detail']=={'address':hex(decoded+8),'size_bytes':8}
        assert all(decoded+j not in final for j in range(273*8))
        assert not any(decoded<=int(x['address'],16)<decoded+273*8 for x in row['source_reads']+row['source_writes'])
        decoder['source_control_lookups']=lookups;decoder['pending_table_size_bytes']=273*8
        model.update(table_record_decodes_checked=1,table_read_undefined_bytes_checked=8,table_control_lookups_checked=8)
    else:
        assert rr[0]['bytes_hex']=='00'*8 and not selected(row,0x100865dfc)
        model['table_NULL_routes_checked']+=1
    assert row['source_calls']==[]
    return {'parent_case_index':c['parent_case_index'],'ABI_clobber_pattern':c['ABI_clobber_pattern'],
            'pointer_return64':c['pointer_return64'],'table_NULL_control':c['table_NULL_control'],
            'field_layout':{hex(off):{'width_bytes':n,'value':hex(value)} for off,(n,value) in defaults.items()} if result else None,
            'cached_word_sources':cache,'table_decoder':decoder,'model_checks':dict(model),'all_checks_pass':True}

def obligations():
    out=[]
    def prove(label,bad,premise=z3.BoolVal(True)):
        s=z3.Solver();s.set(timeout=30000);s.add(premise);assert s.check()==z3.sat
        s.add(z3.simplify(bad));result=s.check();assert result==z3.unsat,(label,str(result))
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    ptr=z3.BitVec('aux_pointer64',64);v=Algebra();v.seed('x0',ptr);v.seed('w21',0x4b15);v.seed('w19',0x8371);v.seed('w22',0x4a95)
    v.run_block(R.ENTRY,0x10054b45c)
    prove('all_pointer64_original_NULL_partition',v.read('w8')!=z3.If(ptr==0,z3.BitVecVal(0x4b15,32),z3.BitVecVal(0x4a95,32)))
    v=Algebra();v.seed('x0',ptr);v.run_block(0x1007fcce8,0x1007fcd24)
    fields={0:(4,0x8b3dc651),4:(4,0x8b3dc651),8:(8,0xe3b88695c0d52dbc),16:(8,0),24:(4,0x8b3dc651),32:(8,0),40:(4,0),48:(8,0xe3b88695c0d52dbc),56:(8,0xe3b88695c0d52dbc),64:(8,0),100:(1,1)}
    prove('all_pointer64_original_fixed_initializer_fields',z3.Or(*[cell(v,ptr+off,n)!=value for off,(n,value) in fields.items()]))
    left,right=z3.BitVecs('aux_cache_first64 aux_cache_second64',64);index=z3.BitVec('aux_cache_index32',32);base=z3.BitVec('aux_cache_base64',64);sp=0x6800060100
    v=Algebra();v.seed('x0',ptr);v.seed('sp',sp);v.seed('x19',0x8371)
    mem(v,sp+0x878,8,0x1010c67d4);mem(v,0x1010c67d4,4,index);mem(v,sp+0x858,8,0x1010c8268);mem(v,0x1010c8268,8,base)
    mem(v,base+(z3.SignExt(32,index)&0xfffffffffdae14b8),8,left);mem(v,base+(z3.SignExt(32,index)&0xffffffff9171abc8),8,right)
    v.seed('w9',0x8b3dc651);v.run_block(0x1007fcd24,0x1007fcdfc)
    def encoded(x,m,c1,c2):
        t=(x&m)^c1;return ((x&0x7fffffffffffffff)^c2^t)-t
    ranges=[(ptr,104),(z3.BitVecVal(sp+0x878,64),8),(z3.BitVecVal(sp+0x858,64),8),
            (z3.BitVecVal(0x1010c67d4,64),4),(z3.BitVecVal(0x1010c8268,64),8),
            (base+(z3.SignExt(32,index)&0xfffffffffdae14b8),8),(base+(z3.SignExt(32,index)&0xffffffff9171abc8),8)]
    disjoint=z3.And(*[z3.ULE(a,M64-n) for a,n in ranges],
                    *[z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)) for k,(a,n) in enumerate(ranges) for b,m in ranges[k+1:]])
    prove('disjoint_inputs_all_cache_words_index_base_original_two_field_transforms',z3.Or(cell(v,ptr+72,8)!=encoded(left,0x1eb684772ee1201f,0x9436845702010016,0x2bc109a8bdeca409),
          cell(v,ptr+80,8)!=encoded(right,0x4d6e4499c38fc7bc,0x810a0410008a0104,0x6c74d9cfd335c6ba),cell(v,ptr+88,8)!=0,cell(v,ptr+96,4)!=0x8b3dc651),disjoint)
    context=z3.BitVec('aux_context64',64);v=Algebra();v.seed('x0',ptr);v.seed('x20',context);v.run_block(0x1007fcdfc,0x1007fce00)
    prove('all_contexts_pointers_original_full_raw_publication',cell(v,context+0x1e0,8)!=ptr)
    v=Algebra();v.seed('sp',sp);v.seed('x20',context);v.seed('w19',0x8371);mem(v,context+0x100,8,ptr);v.run_block(0x10050e008,0x10050e040)
    prove('all_existing_table_words_original_NULL_admission',z3.Or(v.read('w21')!=0xb39,v.read('w9')!=z3.If(ptr==0,z3.BitVecVal(0x8371,32),z3.BitVecVal(0x838b,32)),cell(v,sp+0xa6e0,8)!=context+0x100))
    key,i=z3.BitVecs('aux_shuffle_key32 aux_shuffle_index32',32);v=Algebra();v.seed('w9',key);v.seed('w11',i);v.seed('w10',F);v.run_block(0x1008660d8,0x1008660ec)
    numerator=((key+i)^key)*F;expression=numerator-z3.If(i==0,z3.BitVecVal(0,32),z3.UDiv(numerator,i))*i
    prove('all_key_index32_original_shuffle_quotient_subtraction',v.read('w13')!=expression,z3.And(z3.UGE(i,1),z3.ULE(i,272)))
    numerator=z3.BitVec('aux_arbitrary_numerator32',32)
    prove('unsigned_remainder_bound_for_table_indices',z3.UGE(z3.URem(numerator,i),i),z3.And(z3.UGE(i,1),z3.ULE(i,272)))
    aa,bb=z3.BitVecs('aux_swap_left64 aux_swap_right64',64);at=0x6500115274
    v=Algebra();v.seed('x12',at);v.seed('x14',at+8);v.seed('w13',0);mem(v,at,8,aa);mem(v,at+8,8,bb);v.run_block(R.STOP,0x100866118)
    prove('all_distinct_slot_words_original_three_XOR_swap',z3.Or(cell(v,at,8)!=bb,cell(v,at+8,8)!=aa))
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS} and e['source_regions']==R.source()
    cases=[];counts=Counter();model=Counter()
    for j,c in enumerate(e['cases']):
        r=R.unpack(c['intervals_packed'][0]);lift=Lift(r).run();assert lift['all_checks_pass'];counts.update(lift['verified_counts'])
        check=contract(c,parent['cases'][c['parent_case_index']]);model.update(check['model_checks']);cases.append({'independent_lift':lift,'contract':check})
        print(json.dumps({'case':j,'source_visits':counts['source_visits']}),flush=True)
    proofs=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'cases':cases,
            'independent_totals':dict(counts),'model_checks':dict(model),'source_proofs':proofs,'source_queries_unsat':len(proofs),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'model':e['model_checks'],'queries':e['source_queries_unsat']}),flush=True)
