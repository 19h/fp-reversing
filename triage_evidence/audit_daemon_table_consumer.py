#!/usr/bin/env python3
"""Mixed-table consumer contracts, all-parent admission and source equations.

Full instruction replay is a separately pinned receipt. Byte-pass equations,
ordered block footprints, private-state decoding and original status/cursor
transfers are checked independently. No native target operation or IDB mutation.
O(receipts+visits+parents*requirements+text words+query DAG) time/storage;
30 s/query. Native ownership, algorithm identity and epoch joins remain unknown.
"""
import json,struct
from collections import Counter
from hashlib import sha256
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes,fixture_bytes
from lskd_values_symbolic import mem,cell,resize
from recover_daemon_iokit_census import text_section
import recover_daemon_table_consumer as R
import replay_daemon_table_consumer as Replay
import audit_daemon_state_table_mixing as Prior

AD=['audit_daemon_state_table_mixing.py','audit_daemon_state_emitter_completion.py',
    'audit_daemon_network_record.py','recover_daemon_return_bank_origins.py',
    'lskd_values_symbolic.py','recover_daemon_iokit_census.py',
    'daemon_return_bank_origins_checks.json']
PRE_TABLES=[0x100e5d890,0x100e4c173,0x100ffe717]
POST_TABLES=[0x100fed074,0x100e9a435,0x100e3d370]
SEED_TABLES=[0x100f6b3c0,0x100f6f7d0,0x100ecd420]
READ_ORDER=[9,7,8,10,5,12,0,1,2,14,6,11,15,4,3,13]
WRITE_ORDER=[7,15,0,10,12,8,9,11,13,4,1,3,6,5,2,14]

def rows(c):return [R.unpack(x['interval_packed']) for x in c['intervals']]
def raw(m,a,n):return bytes(m[a+j] for j in range(n))
def selected(row,pc,kind='source_reads'):return [x for x in row[kind] if x['pc']==hex(pc)]
def at(frame,j):return int(frame['registers31'][j],16)

def coverage(e,parents):
    totals=Counter();out=[];indices=set();views={x['parent_index']:x for x in e['coverage']}
    for ci,c in enumerate(e['classes']):
        rr=rows(c);rep=parents[c['representative_parent_index']];projection=R.registers(rr)
        assert projection==c['register_projection']
        need,effects,counts=Prior.Prior.requirements(rep,rr);totals.update(counts);repbytes=state_bytes(rep)
        members=set(c['member_parent_indices']);assert len(members)==len(c['member_parent_indices'])
        assert R.key(rep)==c['class_key']
        for i in members:
            assert i not in indices;indices.add(i);parent=parents[i]
            assert R.key(parent)==c['class_key'] and R.Parent.machine(parent)==R.Parent.machine(rep)
            memory,values=Prior.admission(parent,rep,need,projection)
            terminal=R.unpack(views[i]['derived_terminal_state_packed']);assert views[i]['class_index']==ci
            Prior.expected(parent,terminal,effects,projection,rr[-1],memory,values)
            u=int(terminal['boundary']['SP'],16)+0x5b0
            assert all(a not in state_bytes(terminal) for a in range(u,u+8))
            totals.update(admitted_parent_states=1,incoming_byte_requirements_checked=len(need),
                          incoming_register_requirements_checked=len(projection['required']),
                          terminal_bytes_checked=len(memory|effects),undefined_boundary_bytes_preserved=8,
                          terminal_vector_values_preserved=32,
                          unread_original_byte_differences_preserved=sum(a not in need and b!=repbytes.get(a) for a,b in memory.items()))
        address=next(a for a,(b,o) in sorted(need.items()) if o=='incoming' and 0x6800000000<=a<0x6800100000)
        bad=dict(repbytes);bad[address]^=1
        try:Prior.admission(rep,rep,need,projection,memory=bad)
        except AssertionError:totals['changed_demanded_byte_rejected']+=1
        else:raise AssertionError('changed demanded byte admitted')
        for name in ['SP','X0']:
            bad=R.Parent.machine(rep);bad[name]=hex(int(bad[name],16)^16)
            try:Prior.admission(rep,rep,need,projection,values=bad)
            except AssertionError:totals['changed_required_register_rejected']+=1
            else:raise AssertionError('changed required register admitted')
        bad={**rep,'foreign_owners':rep['foreign_owners'][:-1]}
        try:Prior.admission(bad,rep,need,projection)
        except AssertionError:totals['changed_owner_rejected']+=1
        else:raise AssertionError('changed owner admitted')
        for name in ['Q0','X18']:
            assert name not in projection['required'] and name not in projection['written']
            bad=R.Parent.machine(rep);bad[name]=hex(int(bad[name],16)^1)
            _,values=Prior.admission(rep,rep,need,projection,values=bad);assert values[name]==bad[name]
            totals['unused_register_preserved_controls']+=1
        unused=next(a for a in sorted(repbytes) if a not in need and a not in effects and 0x6800000000<=a<0x6800100000)
        bad=dict(repbytes);bad[unused]^=1;memory,_=Prior.admission(rep,rep,need,projection,memory=bad)
        assert (memory|effects)[unused]==bad[unused];totals['unused_byte_preserved_controls']+=1
        out.append({'class_index':ci,'members':sorted(members),'required_bytes':Prior.requirement_receipt(need),
                    'required_byte_count':len(need),'effect_bytes':len(effects),'all_checks_pass':True})
    assert indices==set(range(76)) and len(views)==76
    return {'classes':out,'verified_counts':dict(totals),'all_checks_pass':True}

def mask(tables,multiplier,bias):
    return bytes(IMAGE.read(tables[0]+j,1)[0]^IMAGE.read(tables[1]+j,1)[0]^IMAGE.read(tables[2]+j,1)[0]^((j*multiplier)&255)^bias for j in range(16))

def contracts(e,parents):
    out=[];counts=Counter();pre=mask(PRE_TABLES,0x57,0xe8);post=mask(POST_TABLES,0x5f,0x56)
    for c in e['classes']:
        call,tail=rows(c);initial=state_bytes(parents[c['representative_parent_index']]);final=state_bytes(call)
        source=raw(initial,R.FIRST,256);memory=fixture_bytes(call,'private')|fixture_bytes(call,'image')
        snapshots=[];table_events=[]
        for w in call['source_writes']:
            a=int(w['address'],16);b=bytes.fromhex(w['after_hex']);memory.update({a+j:x for j,x in enumerate(b)})
            if R.FIRST<=a<a+len(b)<=R.FIRST+256:table_events.append(w)
        assert len(table_events)==768 and all(w['size_bytes']==1 for w in table_events)
        first,core,last=table_events[:256],table_events[256:512],table_events[512:]
        before_core=bytes(source[j]^pre[j&15] for j in range(256));middle=bytearray(before_core)
        for j,w in enumerate(first):
            i=255-j;assert (w['pc'],w['address'],w['after_hex'])==('0x100012040',hex(R.FIRST+i),bytes([before_core[i]]).hex())
        reads=[r for r in call['source_reads'] if R.FIRST<=int(r['address'],16)<R.FIRST+256]
        assert len(reads)==768
        assert [(r['pc'],r['address'],r['bytes_hex']) for r in reads[:256]]==[
            ('0x100012004',hex(R.FIRST+i),bytes([source[i]]).hex()) for i in range(255,-1,-1)]
        for block in range(16):
            rr=reads[256+16*block:256+16*(block+1)];ww=core[16*block:16*(block+1)]
            assert [int(r['address'],16)-R.FIRST for r in rr]==[16*block+j for j in READ_ORDER]
            assert [int(w['address'],16)-R.FIRST for w in ww]==[16*block+j for j in WRITE_ORDER]
            assert max(r['source_visit_index'] for r in rr)<min(w['source_visit_index'] for w in ww)
            assert all(bytes.fromhex(r['bytes_hex'])[0]==before_core[int(r['address'],16)-R.FIRST] for r in rr)
            for w in ww:middle[int(w['address'],16)-R.FIRST]=bytes.fromhex(w['after_hex'])[0]
            snapshots.append({'block':block,'input16_hex':before_core[16*block:16*(block+1)].hex(),
                              'output16_hex':middle[16*block:16*(block+1)].hex(),'read_order':READ_ORDER,'write_order':WRITE_ORDER})
        result=bytes(middle[j]^post[j&15] for j in range(256))
        for j,w in enumerate(last):
            i=255-j;assert (w['pc'],w['address'],w['after_hex'])==('0x1000f71d8',hex(R.FIRST+i),bytes([result[i]]).hex())
        assert raw(final,R.FIRST,256)==result and raw(final,R.SECOND,256)==raw(initial,R.SECOND,256)
        # Every finite table lookup in the pre/post passes is tied to original
        # source read sites, not inferred merely from the final XOR equality.
        for pcs,tables in [([0x100012010,0x100012018,0x100012020],PRE_TABLES),
                           ([0x1000f71bc,0x1000f71c4,0x1000f71c8],POST_TABLES)]:
            for pc,base in zip(pcs,tables):
                rr=selected(call,pc);assert len(rr)==256
                assert [(r['address'],r['bytes_hex']) for r in rr]==[(hex(base+(i&15)),IMAGE.read(base+(i&15),1).hex()) for i in range(255,-1,-1)]
        seed=selected(call,0x1000ac840,'source_writes');assert len(seed)==16
        seedbytes=bytearray(16)
        for j,w in enumerate(seed):
            i=15-j;b=IMAGE.read(0x100fe69d4+i,1)[0]
            value=((b^0x6a)+((b<<1)&0xd4)+0x39)&255
            value^=IMAGE.read(SEED_TABLES[0]+i,1)[0]^IMAGE.read(SEED_TABLES[1]+i,1)[0]^IMAGE.read(SEED_TABLES[2]+i,1)[0]^((i*0x7b)&255)^0xb
            assert w['address']==hex(int(call['caller_SP'],16)-0x80+i) and w['after_hex']==bytes([value]).hex();seedbytes[i]=value
        for pc,base in zip([0x1000ac770,0x1000ac7c8,0x1000ac818,0x1000ac824],[0x100fe69d4,*SEED_TABLES]):
            rr=selected(call,pc);assert len(rr)==16 and [(r['address'],r['bytes_hex']) for r in rr]==[(hex(base+i),IMAGE.read(base+i,1).hex()) for i in range(15,-1,-1)]
        pointer_reads=selected(call,0x1000ac768);assert len(pointer_reads)==16
        assert all((r['address'],r['size_bytes'],r['bytes_hex'])==('0x6800070dd8',8,'d469fe0001000000') for r in pointer_reads)
        fs=call['source_frames'];heads=[j for j,f in enumerate(fs) if f['pc']=='0x1000591ac'];assert len(heads)==16
        common=list(range(0x1000591ac,0x10005b1c4,4));assert len(common)==2054
        for h in heads:assert [int(f['pc'],16) for f in fs[h:h+2054]]==common
        feedback=[j for j,f in enumerate(fs) if f['pc']=='0x1000bcd5c'];assert len(feedback)==15
        for j,h in enumerate(feedback):
            assert h==heads[j]+2054 and heads[j+1]==h+24
            assert [int(f['pc'],16) for f in fs[h:h+24]]==list(range(0x1000bcd5c,0x1000bcdbc,4))
        g1=int.from_bytes(bytes.fromhex(selected(call,0x100417330)[0]['bytes_hex']),'little')
        g2=int.from_bytes(bytes.fromhex(selected(call,0x1004173b4)[0]['bytes_hex']),'little')
        sp=int(call['caller_SP'],16);d=(g1-(sp-0x88)+g2)&((1<<64)-1);constant=0x73d046208eaed1a6
        globals_after=[(d*0xa5cd4cf+constant)&((1<<64)-1),((d^constant)*0xa5cd4cf)&((1<<64)-1)]
        global_writes=[w for w in call['source_writes'] if int(w['address'],16)<0x6000000000]
        assert [(w['pc'],w['address'],w['size_bytes'],w['after_hex']) for w in global_writes]==[
            (hex(pc),hex(address),8,struct.pack('<Q',value).hex()) for pc,address,value in
            zip([0x1004173e0,0x1004173e8],[0x1010b6890,0x1010c4670],globals_after)]
        status=selected(call,0x10002fce4,'source_writes');assert len(status)==1
        assert (status[0]['address'],status[0]['size_bytes'],status[0]['after_hex'])==('0x6800070db8',4,'51c63d8b')
        assert call['source_calls'][0]['pc']==hex(R.ENTRY) and call['source_calls'][0]['target']==hex(R.CALLEE) and len(call['source_calls'])==1
        assert [(x['pc'],x['target']) for x in call['logical_edges'] if x['kind']=='retab']==[('0x10002fd1c',hex(R.RETURN))]
        assert call['boundary']['SP']==call['caller_SP'] and call['boundary']['registers31'][19:30]==call['entry_registers31'][19:30]
        assert call['boundary']['Q_registers32']==call['entry_Q_registers32']
        assert tail['boundary']['pc']==hex(R.UNKNOWN) and not tail['source_calls']
        assert selected(tail,0x1004d5df4)[0]['bytes_hex']=='51c63d8b'
        assert selected(tail,0x1004d5e0c,'source_writes')[0]['after_hex']=='8005000000000000'
        assert selected(tail,0x1004d5dfc)[0]['bytes_hex']=='8006000000000000'
        assert selected(tail,0x1004d5e30)[0]['address']==hex(TABLE+8*0x5ade)
        for row in [call,tail]:
            for ev in row['source_reads']+row['source_writes']:
                a=int(ev['address'],16);n=ev['size_bytes']
                assert all(not(a<base+size and base<a+n) for base,size in [(R.S,64),(R.T,21),(R.U,48),(R.J,552)])
        counts.update(prepass_bytes_checked=256,postpass_bytes_checked=256,central_input_bytes_checked=256,
                      central_output_bytes_checked=256,complete_blocks_checked=16,common_block_source_visits_checked=32864,
                      feedback_transfers_checked=15,seed_input_bytes_checked=16,seed_output_bytes_checked=16,
                      mask_table_reads_checked=1536,original_status_stores_checked=1,logical_returns_checked=1,
                      cursor_rollbacks_checked=1,preserved_heap_and_context_intervals_checked=2,shared_global_u64_updates_checked=2)
        out.append({'representative_parent_index':c['representative_parent_index'],'pre_mask16_hex':pre.hex(),'post_mask16_hex':post.hex(),
                    'seed16_hex':bytes(seedbytes).hex(),'pre_core256_hex':before_core.hex(),'central256_hex':bytes(middle).hex(),
                    'final256_hex':result.hex(),'final256_sha256':sha256(result).hexdigest(),'blocks':snapshots,
                    'common_block_span':[hex(common[0]),hex(common[-1]+4)],'feedback_span':['0x1000bcd5c','0x1000bcdbc'],
                    'shared_global_updates':{'before':[hex(g1),hex(g2)],'after':[hex(x) for x in globals_after],'writes':global_writes},
                    'status32':'0x8b3dc651','status_store':status[0],'caller_success_slot':hex(TABLE+8*0x5ade),
                    'cursor_before':0x680,'cursor_after':0x580,'unknown_field':tail['boundary']['detail'],
                    'all_checks_pass':True})
    assert len({x['final256_sha256'] for x in out})==1
    return {'cases':out,'verified_counts':dict(counts),'all_checks_pass':True,
            'standard_algorithm_identity_established':False,'core_semantic_simplification_complete':False}

class Reads(Prior.Scalar):
    def __init__(self,values):super().__init__();self.supplied=list(values);self.reads=[]
    def load(self,a,n):
        self.reads.append((a,n));assert self.supplied;return resize(self.supplied.pop(0),8*n)

def obligations():
    out=[]
    def prove(label,bad,premises=()):
        solver=z3.Solver();solver.set(timeout=30000);solver.add(*premises);assert solver.check()==z3.sat
        solver.add(z3.simplify(bad));assert solver.check()==z3.unsat,label
        out.append({'label':label,'query':solver.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    sp,ptr=z3.BitVecs('tc_SP64 tc_pointer64',64);producer=Prior.Scalar()
    producer.seed('sp',sp);producer.seed('w27',0xa537);producer.seed('x21',ptr)
    producer.run_block(R.Parent.EXIT,0x1004d5d2c);r=sp+0x10cb8;v=Prior.Scalar();v.seed('x0',r);v.seed('sp',sp-0x1f0)
    for off,n in [(4,4),(8,4),(16,8),(24,8)]:mem(v,r+off,n,cell(producer,r+off,n))
    v.run_block(0x1004173ec,0x1004174a8)
    prove('all_even_SP_pointer_bits_original_record_decodes_extent256_control616f_and_alias',z3.Or(
        v.values[(0x100417438,'w0')]!=256,v.values[(0x100417478,'w12')]!=0x616f,
        v.read('x11')!=ptr,v.read('x8')!=ptr,v.read('w16')!=0),[(sp&1)==0])
    n=z3.BitVec('tc_count64',64);src,dst=z3.BitVecs('tc_src64 tc_dst64',64);b,a,c,d=z3.BitVecs('tc_byte8 tc_table_a8 tc_table_b8 tc_table_c8',8)
    v=Reads([b,a,c,d]);tables=[0x100e5d890,0x100e4c170,0x100ffe717]
    for name,value in {'x0':n,'x8':src,'x11':dst,'x14':tables[0],'x13':tables[1],'x15':tables[2],'w10':0x56da,'w1':0xe8}.items():v.seed(name,value)
    v.run_block(0x100011ffc,0x100012044);i=n-1;j=i&15
    prove('all_byte_count_bits_original_prepass_xor_and_descending_addresses',z3.Or(v.stores[-1]['address']!=dst+i,
        v.stores[-1]['value']!=(b^a^c^d^resize(j*0x57,8)^0xe8),v.read('x0')!=i,
        *[x!=y for (x,_),y in zip(v.reads,[src+i,tables[0]+j,tables[1]+j+3,tables[2]+j])]),[z3.UGE(n,1),z3.ULE(n,256)])
    j32=z3.BitVec('tc_seed_index32',32);image,outptr,record=z3.BitVecs('tc_seed_image64 tc_seed_output64 tc_record64',64)
    v=Reads([image,b]);v.seed('x8',record);v.seed('x13',z3.ZeroExt(32,j32));v.seed('x15',outptr)
    for name,value in {'w16':0x6101,'w0':0xffffffd4,'w1':0x6a}.items():v.seed(name,value)
    v.run_block(0x1000ac768,0x1000ac78c)
    for name,value in {'w12':c,'w28':a,'w26':d,'w22':0x7b,'w23':0xb}.items():v.seed(name,value)
    v.run_block(0x1000ac828,0x1000ac844)
    normalized=(resize(b,32)^0x6a)+((resize(b,32)<<1)&0xffffffd4)+0x39
    prove('all_byte_index_bits_original_image16_state_decoder',z3.Or(v.stores[-1]['address']!=outptr+z3.ZeroExt(32,j32),
        v.stores[-1]['value']!=(resize(normalized,8)^a^c^d^resize(j32*0x7b,8)^0xb),
        v.reads[0][0]!=record+32,v.reads[1][0]!=image+z3.ZeroExt(32,j32)),[z3.ULE(j32,15)])
    v=Prior.Scalar();v.seed('x14',n);v.seed('x15',0x616f);v.run_block(0x1000f7100,0x1000f7110)
    prove('all_nonzero_bounded_counts_original_postpass_decrements_and_low_nibble',z3.Or(v.read('x14')!=n-1,v.read('x10')!=((n-1)&15)),[z3.UGE(n,1),z3.ULE(n,256)])
    index=z3.BitVec('tc_post_index64',64);v=Reads([b,a,c,d]);v.seed('x11',dst);v.seed('x14',index);v.seed('x10',index&15)
    for name,value in {'x25':POST_TABLES[0]+(index&15),'x26':POST_TABLES[1]+(index&15),'x12':POST_TABLES[2]+(index&15),'w22':0x5f,'w23':0x56}.items():v.seed(name,value)
    v.run_block(0x1000f7198,0x1000f719c);v.run_block(0x1000f71b4,0x1000f71dc)
    prove('all_byte_index_bits_original_postpass_xor_given_selected_table_pointers',z3.Or(v.stores[-1]['address']!=dst+index,
        v.stores[-1]['value']!=(b^a^c^d^resize((index&15)*0x5f,8)^0x56)),[z3.ULE(index,255)])
    state,status=z3.BitVecs('tc_completion_state32 tc_status32',32);fp,record=z3.BitVecs('tc_FP64 tc_status_record64',64)
    v=Prior.Scalar();v.seed('sp',sp);v.seed('x29',fp);mem(v,fp-0xb4,4,state);mem(v,sp+0x10,8,record)
    v.run_block(0x10002fcbc,0x10002fce8)
    prove('all_completion_states_original_record_status_store',z3.Or(v.stores[-1]['address']!=record,
        v.stores[-1]['value']!=z3.If(state==0x21fb086f,z3.BitVecVal(0x8b3dc651,32),z3.BitVecVal(0x74c29d89,32))))
    cursor=z3.BitVec('tc_cursor64',64);v=Prior.Scalar()
    for name,value in {'sp':sp,'x22':sp+0x10000,'x26':0x6cf4,'w24':0x6cf4,'w20':0x5205}.items():v.seed(name,value)
    mem(v,sp+0x10cb8,4,status);mem(v,sp+0x16d0,8,cursor);v.run_block(R.RETURN,0x1004d5e30)
    prove('all_status_cursor_bits_original_caller_copy_rewind_and_success_partition',z3.Or(cell(v,sp+0x2d70,4)!=status,
        cell(v,sp+0x16d0,8)!=cursor-256,v.read('w8')!=z3.If(status==0x8b3dc651,z3.BitVecVal(0x5ade,32),z3.BitVecVal(0x5205,32))))
    a0,a1,a2,a3,a4,a5=z3.BitVecs('tc_feedback0 tc_feedback1 tc_feedback2 tc_feedback3 tc_feedback4 tc_feedback5',32);v=Prior.Scalar()
    for name,value in {'sp':sp,'w1':a0,'w10':a1,'w8':a2,'w0':a3,'w2':a4,'w21':a5}.items():v.seed(name,value)
    v.run_block(0x1000bcd5c,0x1000bcdac)
    prove('all_word_bits_original_interblock_feedback_transfer',z3.Or(v.read('w7')!=a0,v.read('w15')!=(a1^0x29fd2e49),
        v.read('w19')!=((a0+0xa21b06bd)^a2),cell(v,sp+0x98,4)!=(a3^0xf4b8b043),
        v.read('w2')!=(a4^0xb41558cc),v.read('w5')!=(a5^0x22b89c83)))
    g1,g2=z3.BitVecs('tc_global_first64 tc_global_second64',64);v=Prior.Scalar()
    for name,value in {'x8':g1,'x12':0x1010c4670,'x29':sp-0x10,'x14':0xa5cd4cf,'x30':0x1010b6000}.items():v.seed(name,value)
    mem(v,0x1010c4670,8,g2);v.run_block(0x1004173b4,0x1004173ec);d=g1-(sp-0x88)+g2;constant=0x73d046208eaed1a6
    prove('all_SP_global_bits_original_two_shared_u64_updates_given_selected_cell',z3.Or(
        cell(v,0x1010b6890,8)!=d*0xa5cd4cf+constant,cell(v,0x1010c4670,8)!=(d^constant)*0xa5cd4cf))
    assert len(out)==9;return out

def foundation():
    a,n=text_section();data=IMAGE.read(a,n);stores=[];branches=[];pattern=0xf9000000|((0x5b0//8)<<10)|(31<<5)
    for j,(word,) in enumerate(struct.iter_unpack('<I',data)):
        pc=a+j*4
        if word&0xffffffe0==pattern:stores.append({'pc':hex(pc),'word':hex(word),'register':word&31})
        if word&0x7c000000==0x14000000:
            disp=word&0x3ffffff;disp-=1<<26 if disp>>25 else 0
            if pc+4*disp==R.CALLEE:branches.append({'pc':hex(pc),'kind':'bl' if word>>31 else 'b','target':hex(R.CALLEE)})
    assert len(stores)==16 and any(x['pc']=='0x1004c2b98' for x in stores)
    p=json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'));examples=[]
    assert p['source_sha256']==sha(SOURCE) and not p['initializer_to_caller_control_join_established']
    for j,c in enumerate(p['upstream_cases']):
        fs=int(c['frame_base'],16);ws=selected(c,0x1004c2b98,'source_writes');assert len(ws)==1;w=ws[0]
        assert (w['address'],w['size_bytes'],w['after_hex'])==(hex(fs+0x5b0),8,'e05d0b0101000000')
        assert not any(int(x['address'],16)<fs+0x5b8 and fs+0x5b0<int(x['address'],16)+x['size_bytes'] for x in c['source_writes'] if x['source_visit_index']>w['source_visit_index'])
        examples.append({'initializer_profile_index':j,'frame_base':hex(fs),'writer':w,'later_overwrites':0})
    assert len(examples)==12
    return {'text_address':hex(a),'text_bytes':n,'text_sha256':sha256(data).hexdigest(),'text_words_scanned':n//4,
            'direct_u64_SP_plus5b0_store_candidates':stores,'direct_branches_to_callee':branches,
            'fixup_references_to_callee':[{'slot':hex(a),**r} for a,r in FIXUPS.items() if r['target']==R.CALLEE],
            'separate_initializer_examples':examples,'initializer_to_current_constructor_join_established':False,
            'scope':'Complete direct opcode census only; alias-base stores, indirect callers, noncontiguous chunks and native epoch joins remain unknown.'}

def address_controls():
    cases=[]
    for sp in [0x6800060100,0x6800060101]:
        producer=Prior.Scalar();producer.seed('sp',sp);producer.seed('w27',0xa537);producer.seed('x21',R.FIRST)
        producer.run_block(R.Parent.EXIT,0x1004d5d2c);r=sp+0x10cb8;v=Prior.Scalar();v.seed('x0',r);v.seed('sp',sp-0x1f0)
        for off,n in [(4,4),(8,4),(16,8),(24,8)]:mem(v,r+off,n,cell(producer,r+off,n))
        v.run_block(0x1004173ec,0x1004174a8)
        number=lambda x:z3.simplify(x).as_long()
        extent=number(v.values[(0x100417438,'w0')]);control=number(v.values[(0x100417478,'w12')])
        assert (extent==256 and control==0x616f)==(sp&1==0)
        cases.append({'SP':hex(sp),'record':hex(r),'decoded_extent32':extent,'decoded_control32':hex(control),
                      'matching_producer_consumer_fields':sp&1==0,'original_instructions_lifted':True,'target_executed':False})
    return {'cases':cases,'scope':'Algebraic alignment fault controls only; no odd-SP target execution or native pointer validity is claimed.'}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));replay=json.loads(read(ROOT/(R.P+'_replay.json')))
    p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));parents={x['parent_index']:R.unpack(x['derived_terminal_state_packed']) for x in p['coverage']}
    assert replay['all_checks_pass'] and e['generator_sha256']==sha(R.__file__) and replay['replayer_sha256']==sha(Replay.__file__)
    proofs=obligations();cov=coverage(e,parents);model=contracts(e,parents);found=foundation()
    return {'scope':__doc__,'auditor_sha256':sha(__file__),'generator_sha256':sha(R.__file__),'replayer_sha256':sha(Replay.__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'replay_sha256':sha(ROOT/(R.P+'_replay.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},
            'verified_counts':e['verified_counts'],'independent_totals':replay['independent_totals'],
            'coverage':cov,'model':model,'foundation':found,'address_controls':address_controls(),'source_proofs':proofs,'source_queries_unsat':len(proofs),
            'all_checks_pass':True,'native_API_executed':False,'native_daemon_kext_pairing_established':False,
            'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps({'coverage':e['coverage']['verified_counts'],'model':e['model']['verified_counts'],'queries_unsat':e['source_queries_unsat']}),flush=True)
