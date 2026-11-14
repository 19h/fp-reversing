#!/usr/bin/env python3
"""Conditional root admission, gate/arena/object contracts and source equations.
Full independent instruction replay is separately pinned. O(receipts+visits+
parents*requirements+initializer journals+query DAG) time/storage; 30 s/query.
Source-compatible roots do not establish native epochs, ownership or IPC.
"""
import json,struct
from collections import Counter
from hashlib import sha256
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes
from audit_daemon_state_table_mixing import Scalar,admission,expected,requirement_receipt
from audit_daemon_state_emitter_completion import requirements
from recover_daemon_iokit_census import text_section
from lskd_values_symbolic import mem,cell
import recover_daemon_constructor_gate as R
import replay_daemon_constructor_gate as Replay
AD=['audit_daemon_state_table_mixing.py','audit_daemon_state_emitter_completion.py',
    'audit_daemon_network_record.py','lskd_values_symbolic.py','recover_daemon_return_bank_origins.py','recover_daemon_iokit_census.py']

def selected(row,pc,kind='source_reads'):return [x for x in row[kind] if x['pc']==hex(pc)]
def raw(memory,a,n):return bytes(memory[a+j] for j in range(n))

def coverage(e,parents):
    totals=Counter();out=[];indices=set();views={x['parent_index']:x for x in e['coverage']}
    for ci,c in enumerate(e['classes']):
        row=R.unpack(c['interval_packed']);rep,fx=R.premised(parents[c['representative_parent_index']],e['root_provenance'])
        assert fx==c['entry_premises'];projection=R.registers([row]);assert projection==c['register_projection']
        need,effects,counts=requirements(rep,[row]);totals.update(counts);repbytes=state_bytes(rep)
        assert R.key(rep)==c['class_key']
        for i in c['member_parent_indices']:
            assert i not in indices;indices.add(i);parent,premises=R.premised(parents[i],e['root_provenance'])
            assert R.key(parent)==c['class_key'] and R.Parent.Parent.machine(parent)==R.Parent.Parent.machine(rep)
            memory,values=admission(parent,rep,need,projection)
            terminal=R.unpack(views[i]['derived_terminal_state_packed'])
            assert views[i]['class_index']==ci and views[i]['entry_premises']==premises
            expected(parent,terminal,effects,projection,row,memory,values)
            u=int(terminal['boundary']['SP'],16)+0x260
            assert all(a not in state_bytes(terminal) for a in range(u,u+8))
            totals.update(admitted_parent_states=1,new_root_premise_bytes_checked=88,incoming_byte_requirements_checked=len(need),
                          incoming_register_requirements_checked=len(projection['required']),terminal_bytes_checked=len(memory|effects),
                          undefined_boundary_bytes_preserved=8,terminal_vector_values_preserved=32,
                          unread_original_byte_differences_preserved=sum(a not in need and b!=repbytes.get(a) for a,b in memory.items()))
        for f in fx:
            a=int(f['address'],16);bad=dict(repbytes);bad[a]^=1
            try:admission(rep,rep,need,projection,memory=bad)
            except AssertionError:totals['changed_root_premise_byte_rejected']+=1
            else:raise AssertionError('changed root byte admitted')
            bad=dict(repbytes);del bad[a]
            try:admission(rep,rep,need,projection,memory=bad)
            except AssertionError:totals['missing_root_premise_byte_rejected']+=1
            else:raise AssertionError('missing root byte admitted')
        for name in ['SP',next(x for x in projection['required'] if x.startswith('X'))]:
            bad=R.Parent.Parent.machine(rep);bad[name]=hex(int(bad[name],16)^16)
            try:admission(rep,rep,need,projection,values=bad)
            except AssertionError:totals['changed_required_register_rejected']+=1
            else:raise AssertionError('changed register admitted')
        bad={**rep,'foreign_owners':rep['foreign_owners'][:-1]}
        try:admission(bad,rep,need,projection)
        except AssertionError:totals['changed_owner_rejected']+=1
        else:raise AssertionError('changed owner admitted')
        for name in ['Q0','X18']:
            assert name not in projection['required'] and name not in projection['written']
            bad=R.Parent.Parent.machine(rep);bad[name]=hex(int(bad[name],16)^1)
            _,values=admission(rep,rep,need,projection,values=bad);assert values[name]==bad[name]
            totals['unused_register_preserved_controls']+=1
        unused=next(a for a in sorted(repbytes) if a not in need and a not in effects and 0x6800000000<=a<0x6800100000)
        bad=dict(repbytes);bad[unused]^=1;memory,_=admission(rep,rep,need,projection,memory=bad)
        assert (memory|effects)[unused]==bad[unused];totals['unused_byte_preserved_controls']+=1
        out.append({'class_index':ci,'members':c['member_parent_indices'],'required_bytes':requirement_receipt(need),
                    'required_byte_count':len(need),'effect_bytes':len(effects),'all_checks_pass':True})
    assert indices==set(range(76)) and len(views)==76
    return {'classes':out,'verified_counts':dict(totals),'all_checks_pass':True}

def contracts(e,parents):
    out=[];totals=Counter();S,T,U,J=R.Parent.S,R.Parent.T,R.Parent.U,R.Parent.J
    for ci,c in enumerate(e['classes']):
        r=R.unpack(c['interval_packed']);before,_=R.premised(parents[c['representative_parent_index']],e['root_provenance'])
        initial=state_bytes(before);final=state_bytes(r);sp=int(r['caller_SP'],16)
        gates=[w for w in r['source_writes'] if int(w['address'],16)<R.GATE+4 and R.GATE<int(w['address'],16)+w['size_bytes']]
        assert [(w['pc'],w['address'],w['size_bytes'],w['after_hex']) for w in gates]==[
            ('0x1006b7730',hex(R.GATE),4,'ef940a00'),('0x100775768',hex(R.GATE),4,'965d0000')]
        assert raw(initial,R.GATE,4)==raw(final,R.GATE,4)==bytes.fromhex('965d0000')
        flag=selected(r,0x10082552c);assert len(flag)==1 and (flag[0]['address'],flag[0]['size_bytes'],flag[0]['bytes_hex'])==(hex(R.FLAG),1,'01')
        clear=selected(r,0x10054b73c,'source_writes');assert len(clear)==296
        stack,arena=clear[:4],clear[4:]
        assert [int(w['address'],16) for w in stack]==list(range(sp+0x651f,sp+0x651b,-1))
        assert [int(w['address'],16) for w in arena]==list(range(0x650011525b,0x6500115137,-1))
        assert bytes.fromhex(''.join(w['after_hex'] for w in stack))==bytes.fromhex('428ef03c')
        assert bytes.fromhex(''.join(w['after_hex'] for w in arena[:4]))==bytes.fromhex('428ef03c')
        for w in clear:
            f=r['source_frames'][w['source_visit_index']];a=int(f['registers31'][10],16);b=int(f['registers31'][2],16)
            assert int(w['after_hex'],16)==((a^b)*(a+17))&255
        arena_events=[w for w in r['source_writes'] if w['pc'] in ['0x1007cf774','0x1007cf790','0x1007cf7cc','0x1007cf7e0','0x1007cf7f0']]
        assert len(arena_events)==6 and all(gates[0]['source_visit_index']<w['source_visit_index']<gates[1]['source_visit_index'] for w in arena_events)
        assert selected(r,0x1007cf7f0,'source_writes')[0]['address']==hex(R.D+40)
        assert raw(final,J,552)==raw(initial,J,552) and all(not(int(w['address'],16)<J+552 and J<int(w['address'],16)+w['size_bytes']) for w in r['source_writes'])
        uws=[w for w in r['source_writes'] if U<=int(w['address'],16)<U+48]
        assert len(uws)==7 and all(U+j not in initial for j in range(48))
        defined=[j for j in range(48) if U+j in final];assert defined==list(range(28))+list(range(32,44))
        assert raw(final,U,8)==bytes(8) and int.from_bytes(raw(final,U+8,8),'little')==T
        assert raw(final,U+16,4)==raw(final,U+20,4)==bytes.fromhex('26c4ec10')
        assert raw(final,U+24,4)==bytes.fromhex('81ead876') and int.from_bytes(raw(final,U+32,8),'little')==0x650011519c
        assert raw(final,U+40,4)==bytes.fromhex('42e699d2')
        publish=selected(r,0x1008258d8,'source_writes');assert len(publish)==1 and (publish[0]['address'],publish[0]['size_bytes'],publish[0]['after_hex'])==(hex(S),8,U.to_bytes(8,'little').hex())
        assert all(w['source_visit_index']<publish[0]['source_visit_index'] for w in uws)
        assert [j for j in range(64) if S+j in final]==[j for j in range(64) if S+j in initial]
        assert raw(final,S+8,40)==raw(initial,S+8,40) and raw(final,S+56,5)==raw(initial,S+56,5)
        tws=[w for w in r['source_writes'] if T<=int(w['address'],16)<T+21];assert len(tws)==14
        assert raw(final,T,21).hex()=='06a2b5113d35bd9145be84e9f3294b55898a446d91'
        assert len(r['source_calls'])==12 and Counter(x['target'] for x in r['source_calls'])==Counter({hex(t):3 for t in [0x100add594,0x100acd9c4,0x10041a5e0,0x100427514]})
        b=r['boundary'];assert b['kind']=='before_unknown_private_read' and b['pc']==hex(R.UNKNOWN)
        assert b['detail']['address']==hex(sp+0x260) and b['detail']['snapshot']['known_mask_hex']=='00'*8
        totals.update(gate_acquisitions_checked=1,gate_releases_checked=1,readiness_reads_checked=1,arena_header_effects_checked=6,
                      arena_fill_bytes_checked=292,stack_fill_bytes_checked=4,U_defined_bytes_checked=40,U_undefined_bytes_preserved=8,
                      S_pointer_stores_checked=1,T_byte_stores_checked=14,context_bytes_preserved=552,internal_calls_checked=12)
        out.append({'class_index':ci,'gate_effects':gates,'readiness_read':flag[0],'arena_effects':arena_events,
                    'U_effects':uws,'S_pointer_store':publish[0],'U_defined_offsets':defined,'U_unknown_offsets':[j for j in range(48) if U+j not in final],
                    'T_effects':tws,'T_final_hex':raw(final,T,21).hex(),'T_changed_offsets':[j for j in range(21) if final[T+j]!=initial[T+j]],
                    'internal_calls':r['source_calls'],'boundary':b['pc'],'all_checks_pass':True})
    return {'cases':out,'verified_counts':dict(totals),'all_checks_pass':True,'native_ownership_established':False,'new_Mach_or_IOKit_emission_established':False}

class Gate(Scalar):
    def one(self,i):
        if i.mnemonic=='casal':
            assert i.address==0x1006b7730 and i.op_str=='w13, w10, [x19]'
            a=self.address(i,i.operands[2]);old=self.load(a,4)
            self.store(a,4,z3.If(old==self.read('w13'),self.read('w10'),old),i.address);self.write('w13',old);return
        return super().one(i)

def obligations():
    out=[]
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    word=z3.BitVec('constructor_gate32',32);v=Gate()
    for n,x in {'x19':R.GATE,'w10':0xa94ef,'w11':0x5d96,'w12':0x28a6,'w8':0x9b84}.items():v.seed(n,x)
    mem(v,R.GATE,4,word);v.run_block(0x1006b772c,0x1006b7734)
    prove('all_u32_original_CAS_returns_old_conditionally_acquires',z3.Or(v.read('w13')!=word,cell(v,R.GATE,4)!=z3.If(word==0x5d96,z3.BitVecVal(0xa94ef,32),word)))
    v.run_block(0x1006b7734,0x1006b7744)
    prove('all_u32_original_gate_dispatch_partition',v.read('w13')!=z3.If(word==0x5d96,z3.BitVecVal(0xb322,32),z3.BitVecVal(0x9b84,32)))
    b=z3.BitVec('constructor_ready8',8);v=Scalar();v.seed('x10',R.FLAG);v.seed('w8',0x99c);v.seed('w9',0x99f);mem(v,R.FLAG,1,b)
    v.run_block(0x10082552c,0x100825548)
    prove('all_u8_original_readiness_exact_one_partition',v.read('w9')!=z3.If(b==1,z3.BitVecVal(0xafb5,32),z3.BitVecVal(0x99f,32)))
    v=Scalar();v.seed('sp',0x6800060100);mem(v,0x68000606b0,8,z3.BitVecVal(R.GATE,64));v.run_block(0x100775760,0x10077576c)
    prove('original_plain_release_restores_available_u32',cell(v,R.GATE,4)!=0x5d96)
    phase,a=z3.BitVecs('constructor_phase32 constructor_field32',32);v=Scalar();v.seed('sp',0x6800060100);v.seed('x11',R.Parent.U);v.seed('w8',phase);mem(v,0x6800063708,4,a)
    v.run_block(0x100825894,0x1008258b0);f=a+(phase^0x9a13b551)
    prove('all_u32_original_U_duplicated_fields_and_source_word',z3.Or(cell(v,R.Parent.U+16,4)!=f,cell(v,R.Parent.U+20,4)!=f,cell(v,R.Parent.U+24,4)!=a))
    v=Scalar();v.seed('sp',0x6800060100);v.seed('x11',R.Parent.U);mem(v,0x680006672f,1,b);mem(v,0x68000637e8,8,z3.BitVecVal(R.Parent.S,64))
    v.run_block(0x1008258b0,0x1008258dc)
    prove('all_u8_original_U_flag_word_and_S_pointer_store',z3.Or(cell(v,R.Parent.U+40,4)!=z3.If(b!=0,z3.BitVecVal(0xd299e642,32),z3.BitVecVal(0xd299e646,32)),cell(v,R.Parent.S,8)!=R.Parent.U))
    cursor=z3.BitVec('constructor_cursor64',64);v=Scalar();v.seed('sp',0x6800060100);mem(v,0x68000617d0,8,cursor);v.run_block(0x10068ae70,0x10068ae7c)
    prove('all_u64_original_post_U_cursor_rewind32',cell(v,0x68000617d0,8)!=cursor-32)
    base,pointer,n=z3.BitVecs('constructor_fill_base64 constructor_fill_counter_pointer64 constructor_fill_remaining64',64)
    mask=z3.BitVec('constructor_fill_mask32',32);v=Scalar()
    for name,x in {'sp':0x6800060100,'x20':base,'x10':pointer,'x8':n,'w2':mask}.items():v.seed(name,x)
    v.run_block(0x10054b728,0x10054b744);last=v.stores[-1]
    value=z3.Extract(7,0,(z3.Extract(31,0,pointer)^mask)*(z3.Extract(31,0,pointer)+17))
    prove('all_u64_original_descending_address_derived_byte_fill',z3.Or(v.read('x8')!=n-1,v.read('x10')!=pointer+1,last['address']!=base+n-1,last['value']!=value))
    return out

def foundation(e):
    a,n=text_section();data=IMAGE.read(a,n);patterns={0xf9000000|((off//8)<<10)|(31<<5):off for off in R.OFFSETS+[0x260]};stores={off:[] for off in patterns.values()}
    for j,(word,) in enumerate(struct.iter_unpack('<I',data)):
        off=patterns.get(word&0xffffffe0)
        if off is not None:stores[off].append({'pc':hex(a+j*4),'word_hex':struct.pack('<I',word).hex(),'source_register':word&31})
    for field in e['root_provenance']['fields']:
        for x in field['examples']:
            pc=int(x['writer']['pc'],16);word=IMAGE.read(pc,4).hex();assert word==x['source_word_hex']
            assert any(r['pc']==hex(pc) and r['word_hex']==word for r in stores[field['offset_bytes']])
    fields=e['root_provenance']['fields'];unknown=fields[-1];assert not unknown['supplied_to_separate_entry']
    values=[int.from_bytes(bytes.fromhex(x['writer']['after_hex']),'little') for x in unknown['examples']]
    assert len(set(values))==4
    routes=[]
    for index,target,modifier in [(0xb322,0x100825508,0xe155),(0x9b84,0x1006b772c,0xe155),(0xafb5,0x10076d73c,0x48e8),(0x99f,0x100775760,0x48e8)]:
        slot=TABLE+8*index;word=int.from_bytes(IMAGE.read(slot,8),'little');assert FIXUPS[slot]['target']==target and (word>>32)&65535==modifier and not((word>>48)&7)
        routes.append({'index':hex(index),'slot':hex(slot),'target':hex(target),'IA_modifier':hex(modifier),'word_hex':IMAGE.read(slot,8).hex()})
    return {'text_address':hex(a),'text_bytes':n,'text_words_scanned':n//4,'text_sha256':sha256(data).hexdigest(),'gate_and_readiness_routes':routes,
            'direct_u64_SP_store_candidates':{hex(off):rows for off,rows in stores.items()},'initializer_source_words_checked':144,
            'unknown_SP_plus260_distinct_profile_values':[hex(x) for x in sorted(set(values))],
            'scope':'Exact direct unsigned-immediate STR Xn,[SP,#offset] opcode census. Aliased-base, indexed, paired and indirect stores are not enumerated; matching offsets do not join frames or epochs.'}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));replay=json.loads(read(ROOT/(R.P+'_replay.json')))
    p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));parents={x['parent_index']:R.unpack(x['derived_terminal_state_packed']) for x in p['coverage']}
    assert e['root_provenance']==R.roots() and replay['all_checks_pass']
    return {'scope':__doc__,'auditor_sha256':sha(__file__),'replayer_sha256':sha(Replay.__file__),'generator_sha256':sha(R.__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'replay_sha256':sha(ROOT/(R.P+'_replay.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},
            'verified_counts':e['verified_counts'],'independent_totals':replay['independent_totals'],'coverage':coverage(e,parents),
            'model':contracts(e,parents),'foundation':foundation(e),'source_proofs':obligations(),'source_queries_unsat':8,
            'all_checks_pass':True,'native_API_executed':False,'native_epoch_join_established':False,
            'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'coverage':e['coverage']['verified_counts'],'model':e['model']['verified_counts'],'source_queries_unsat':e['source_queries_unsat']}),flush=True)
