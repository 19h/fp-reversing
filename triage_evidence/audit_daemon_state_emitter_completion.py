#!/usr/bin/env python3
"""Independent21B generation/copy and all76 deterministic-input coverage audit.

Four journals receive full GP/Q/NZCV/byte replay. Every parent is additionally
checked against exact machine-entry state and read-before-write byte demands;
ordered source effects produce its own terminal definitions, retaining all
unread differences. Fault controls reject changed live bytes/registers/owners.
O(representative visits*(state+effects)+parents*requirements+joins+query DAG)
time; O(receipts+largest interval+requirements+parent state) storage;30 s/query.
No native target API/IPC/filesystem/allocation/free/PAC or IDB mutation runs.
"""
import json,struct
from collections import Counter
from hashlib import sha256
from functools import lru_cache
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes,fixture_bytes
from audit_daemon_environment_outputs import DEC,loaded_bytes,R as Env
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import audit_daemon_generated_stream as GS
import audit_daemon_postseed_output as PO
import recover_daemon_state_emitter_completion as R

AD=['audit_daemon_generated_stream.py','audit_daemon_postseed_output.py','audit_daemon_readiness_arena.py',
    'audit_daemon_network_record.py','audit_daemon_environment_outputs.py','recover_daemon_environment_outputs.py',
    'daemon_context_transfer_symbolic.py','probe_daemon_descriptor_producers.py',
    'recover_daemon_return_bank_origins.py','lskd_values_symbolic.py']

class Lift(GS.Lift):
    SAVED_ORIGINS={**GS.Lift.SAVED_ORIGINS,
                   0x1005068ac:(0x1004e01e0,0x101043300,0x1007cf718,0x1007cf720,0x10059cd50,'x0')}
    def __init__(self,row,before):
        super().__init__(row)
        if row['entry_PC']==hex(R.COPY):
            origin=GS.selected(before,0x1006d7f48);assert len(origin)==1;origin=origin[0]
            assert (origin['address'],origin['size_bytes'],origin['bytes_hex'])==('0x10109fc88',8,'9cf8460001000000')
            assert FIXUPS[0x10109fc88]['target']==0x10046f89c and row['entry_registers31'][11]=='0x10046f89c'
            for visit in before['source_visits'][origin['source_visit_index']+1:]:
                pc=int(visit['pc'],16);ins=next(DEC.disasm(IMAGE.read(pc,4),pc))
                assert not any(ins.reg_name(reg) in ['x11','w11'] for reg in ins.regs_access()[1])
            self.last_authenticated_load=(0x10109fc88,0x10046f89c);self.counts['cross_interval_copy_target_origins_checked']+=1

def audit_class(c,parent):
    before=R.unpack(parent['refill_comparison']['interval_packed']);initial=state_bytes(before);mt=list(struct.unpack('<624I',GS.raw(initial,R.G,2496)))
    generation=index=9;total=Counter();model=Counter();lifts=[];attempts=[];comparisons=[];completed=None
    assert len(c['intervals'])==80 and R.key(before)==c['class_key']
    for j,item in enumerate(c['intervals']):
        row=R.unpack(item['interval_packed']);GS.joined(before,row);lift=Lift(row,before).run();lifts.append(lift);total.update(lift['verified_counts'])
        label=item['label'];s=state_bytes(row)
        if label in ['twist227','twist396','twist_last_and_index']:
            part=['twist227','twist396','twist_last_and_index'].index(label);indices=[range(227),range(227,623),range(623,624)][part]
            pc=[0x100a5e93c,0x100b312a4,0x100a2f634][part];writes=GS.selected(row,pc,'source_writes');assert len(writes)==len(indices)
            for i,w in zip(indices,writes):
                nxt=mt[(i+1)%624];y=(mt[i]&0x80000000)|(nxt&0x7fffffff)
                mt[i]=(mt[(i+397)%624]^(y>>1)^(0x9908b0df if nxt&1 else 0))&0xffffffff
                assert (w['address'],w['after_hex'])==(hex(R.G+4*i),struct.pack('<I',mt[i]).hex());model['twist_word_updates_checked']+=1
        if label=='refill_to_twist227' and row['entry_PC']==hex(R.GS.REFILL):
            q=GS.comparison(row,'refill');assert q['A64']==generation and not q['predicate'];comparisons.append(q);model['nonzero_refill_records_checked']+=1
        if label=='selection_counter_comparison':
            q=GS.comparison(row,'selection');assert q['B64']==generation and not q['predicate'];comparisons.append(q)
            assert int(row['boundary']['registers31'][19],16)==mt[index];index+=1
            assert GS.word(s,int(row['caller_SP'],16)+0x1ec)==GS.word(s,0x1010c67dc)==index;model['selected_words_checked']+=1
        if label=='counter_and_temper':
            raw=int(row['entry_registers31'][19],16);t=raw^(raw>>11);t=(t^((t<<7)&0x9d2c5680))&0xffffffff;t=(t^((t<<15)&0xefc60000))&0xffffffff;t^=t>>18
            generation+=1;assert GS.word(s,0x1010c8258)==generation and int(row['boundary']['registers31'][9],16)==t;model['tempered_words_checked']+=1
        if label=='byte_attempt':attempts.append(GS.codec(row));model['encoded_byte_attempts_checked']+=1
        if label=='completion_and_adapter_return':
            completed=GS.raw(s,R.OUTPUT,R.N);assert completed.hex()==c['generated21_hex'] and all(completed)
            assert [(x['pc'],x['target']) for x in row['logical_edges']]==[('0x100a6d3c8','0x100add7d8'),('0x100add7f8',hex(R.RETURN))]
            assert [(w['address'],w['size_bytes'],w['after_hex']) for w in row['source_writes']]==[('0x6800070db8',4,'51c63d8b'),('0x680006bda0',8,'00'*8)]
            rr=GS.selected(row,0x100add7d8);assert len(rr)==1 and rr[0]['address']=='0x6800060070' and rr[0]['bytes_hex']=='c5f9f82e'
            assert row['boundary']['SP']=='0x6800060100';model.update(completion_status_stores_checked=1,adapter_zero_adjustment_stores_checked=1,logical_returns_checked=2)
        if label=='caller_setup_to256B_copy':
            reads=GS.selected(row,0x100576f10);writes=GS.selected(row,0x100576f28,'source_writes');assert len(reads)==len(writes)==21
            for k,(rr,w) in enumerate(zip(reads,writes)):
                i=20-k;assert (rr['address'],rr['bytes_hex'])==(hex(R.OUTPUT+i),completed[i:i+1].hex())
                assert (w['address'],w['size_bytes'],w['after_hex'])==(hex(R.T+i),1,bytes([completed[i]^0x98]).hex())
            assert GS.raw(s,R.T,21)==bytes(b^0x98 for b in completed)
            assert row['boundary']['registers31'][:3]==['0x100e406a0','0x680006c6f0','0x100']
            assert GS.word(s,0x68000617d0,8)==0x680 and GS.word(s,0x6800062d40,8)==R.U+32
            model.update(generated_to_heap_byte_pairs_checked=21,new_private_cursor512_reservations_checked=1,carried_U_plus32_private_stores_checked=1)
        if label=='original256B_copy':
            table=IMAGE.read(0x100e406a0,256);assert len(set(table))==256 and GS.raw(s,0x680006c6f0,256)==table
            assert len(row['source_calls'])==1 and row['source_calls'][0]['target']=='0x10046f89c' and row['source_calls'][0]['modifier']=='0x34a1'
            assert len(row['source_reads'])==len(row['source_writes'])==32
            for i,(rr,w) in enumerate(zip(row['source_reads'],row['source_writes'])):
                assert (rr['address'],rr['size_bytes'],rr['bytes_hex'])==(hex(0x100e406a0+8*i),8,table[8*i:8*i+8].hex())
                assert (w['address'],w['size_bytes'],w['after_hex'])==(hex(0x680006c6f0+8*i),8,table[8*i:8*i+8].hex())
            model['image_table_copy_bytes_checked']+=256
        assert GS.raw(s,R.G,2496)==struct.pack('<624I',*mt);model['complete_state_boundary_words_checked']+=624
        assert GS.word(s,0x1010b5de0)==0x5d96
        assert {a:v for a,v in s.items() if R.S<=a<R.S+64}=={a:v for a,v in initial.items() if R.S<=a<R.S+64}
        assert not any(R.U+j in s for j in range(48)) and not any(R.Parent.Parent.A+j in s for j in range(R.Parent.Parent.N))
        assert not any(GS.R.Parent.Parent.GATE_WORD==int(w['address'],16) for w in row['source_writes'])
        assert not any(R.U<=int(x['address'],16)<R.U+48 for x in row['source_reads']+row['source_writes'])
        assert GS.raw(s,R.J+0x34,32)==GS.raw(initial,R.J+0x34,32) and not any(R.J+0x68<=int(w['address'],16)<R.J+0x70 for w in row['source_writes'])
        model.update(container_mask_preservation_intervals_checked=1,U48_undefined_intervals_checked=1,old_stream_preservation_intervals_checked=1)
        before=row
        if j%24==0:print(json.dumps({'class_representative':c['representative_parent_index'],'interval':j,'source_visits':total['source_visits']}),flush=True)
    assert generation==index==15 and len(attempts)==21 and all(x['stored8_hex']!='00' for x in attempts)
    assert [x['address'] for x in attempts]==[hex(R.OUTPUT+j) for j in range(20,-1,-1)]
    assert [x['shift_before'] for x in attempts]==[0,8,16,24]*5+[0]
    assert c['final_boundary']==before['boundary'] and c['final_NZCV']==before['boundary_NZCV'] and before['boundary']['pc']==hex(R.AFTER_COPY)
    return {'independent_lifts':lifts,'independent_totals':dict(total),'model_checks':dict(model),'byte_attempts':attempts,'comparisons':comparisons,
            'generated21_hex':completed.hex(),'heap21_hex':GS.raw(s,R.T,21).hex(),'final_array_sha256':sha256(struct.pack('<624I',*mt)).hexdigest(),
            'image_table256_sha256':sha256(IMAGE.read(0x100e406a0,256)).hexdigest(),'all_checks_pass':True}

@lru_cache(maxsize=None)
def immutable_byte(address):
    assert address<0x6000000000
    slot=address&~7
    if slot in FIXUPS:
        target=FIXUPS[slot]['target'];base=Env.Base
        value=(base.GUARD if target=='libSystem/___stack_chk_guard' else base.HELPER if target=='libSystem/___chkstk_darwin'
               else base.IMPORTS[target] if isinstance(target,str) else target)+base.ADDENDS.get(slot,0)
        return ((value&((1<<64)-1)).to_bytes(8,'little'))[address-slot]
    return loaded_bytes(address,1)[0]

def requirements(parent,rows):
    initial=state_bytes(parent);seen=set();need={};effects={};counts=Counter();code=set()
    for row in rows:
        reads={};writes={}
        for x in row['source_reads']:reads.setdefault(x['source_visit_index'],[]).append(x)
        for x in row['source_writes']:writes.setdefault(x['source_visit_index'],[]).append(x)
        for visit in row['source_visits']:
            ix=visit['source_visit_index'];pc=int(visit['pc'],16);code.update(range(pc,pc+4))
            for rr in reads.get(ix,[]):
                a=int(rr['address'],16);data=bytes.fromhex(rr['bytes_hex']);assert rr.get('known_mask_hex','01'*len(data))=='01'*len(data)
                for j,b in enumerate(data):
                    at=a+j
                    if at in seen:assert effects[at]==b
                    else:
                        expected=initial[at] if at in initial else immutable_byte(at);assert b==expected
                        origin='incoming' if at in initial else 'immutable_image'
                        if at in need:assert need[at]==(b,origin)
                        need[at]=(b,origin)
                    counts['ordered_read_bytes_checked']+=1
            for ww in writes.get(ix,[]):
                a=int(ww['address'],16);data=bytes.fromhex(ww['after_hex'])
                for j,b in enumerate(data):seen.add(a+j);effects[a+j]=b
                counts['ordered_write_bytes_checked']+=len(data)
    assert not code&seen
    return need,effects,counts

def machine(row):
    b=row['boundary'];return (b['pc'],b['registers31'],b['Q_registers32'],b['SP'],row['boundary_NZCV'],row['foreign_owners'],row['configuration'])

def admit(parent,representative,need):
    assert machine(parent)==machine(representative);memory=state_bytes(parent)
    for address,(value,origin) in need.items():
        if origin=='incoming':assert memory.get(address)==value
        else:assert (memory[address] if address in memory else immutable_byte(address))==value
    return memory

def coverage(e,parents):
    out=[];totals=Counter();indices=set()
    for ci,c in enumerate(e['classes']):
        rows=list(R.context_intervals(c));rep=R.unpack(parents['contexts'][c['representative_parent_index']]['refill_comparison']['interval_packed'])
        need,effects,counts=requirements(rep,rows);totals.update(counts);repbytes=state_bytes(rep)
        views=[x for x in e['coverage'] if x['class_index']==ci];assert {x['parent_index'] for x in views}==set(c['member_parent_indices'])
        for x in views:
            pi=x['parent_index'];assert pi not in indices;indices.add(pi);parent=R.unpack(parents['contexts'][pi]['refill_comparison']['interval_packed'])
            memory=admit(parent,rep,need);expected=memory|effects;terminal=R.unpack(x['derived_terminal_state_packed'])
            assert state_bytes(terminal)==expected and machine(terminal)==machine(rows[-1])
            assert terminal['role']=='derived_terminal_state_from_verified_class_effects' and not terminal['source_visits'] and not terminal['native_target_executed']
            totals.update(admitted_parent_states=1,incoming_byte_requirements_checked=len(need),derived_terminal_bytes_checked=len(expected),
                          unread_original_byte_differences_preserved=sum(a not in need and b!=repbytes.get(a) for a,b in memory.items()))
        # Changed demanded bytes must fail; an unused private byte must survive.
        address=next(a for a,(b,origin) in sorted(need.items()) if origin=='incoming' and 0x6800000000<=a<0x6800100000)
        def altered(at,value):
            p={**rep,'initial_private_fixtures':rep['initial_private_fixtures']+[{'address':hex(at),'bytes_hex':bytes([value]).hex()}],'source_writes':[]}
            # Keep the complete parent definitions while applying one byte change.
            memory=state_bytes(rep);memory[at]=value;p['initial_private_fixtures']=[];p['initial_image_fixtures']=[]
            for a,b in memory.items():p['initial_'+('private' if 0x6800000000<=a<0x6800100000 else 'image')+'_fixtures'].append({'address':hex(a),'bytes_hex':bytes([b]).hex()})
            return p
        bad=altered(address,need[address][0]^1)
        try:admit(bad,rep,need)
        except AssertionError:totals['live_byte_fault_controls_rejected']+=1
        else:raise AssertionError('changed live byte admitted')
        for field in ['registers31','Q_registers32','SP']:
            bad={**rep,'boundary':dict(rep['boundary'])}
            if field=='SP':bad['boundary'][field]=hex(int(rep['boundary'][field],16)+16)
            else:bad['boundary'][field]=rep['boundary'][field].copy();bad['boundary'][field][0]=hex(int(bad['boundary'][field][0],16)^1)
            try:admit(bad,rep,need)
            except AssertionError:totals['machine_state_fault_controls_rejected']+=1
            else:raise AssertionError('changed machine state admitted')
        for field in ['boundary_NZCV','foreign_owners']:
            bad={**rep}
            if field=='boundary_NZCV':bad[field]=hex(int(rep[field],16)^0x10000000)
            else:bad[field]=rep[field][:-1]
            try:admit(bad,rep,need)
            except AssertionError:totals['machine_state_fault_controls_rejected']+=1
            else:raise AssertionError('changed flags or owners admitted')
        unused=next(a for a in sorted(state_bytes(rep)) if 0x6800000000<=a<0x6800100000 and a not in need and a not in effects)
        changed=state_bytes(rep)[unused]^1;memory=admit(altered(unused,changed),rep,need);assert (memory|effects)[unused]==changed
        totals['unused_byte_fault_controls_preserved']+=1
        required_json=[{'address':hex(a),'value8':b,'origin':origin} for a,(b,origin) in sorted(need.items())]
        out.append({'class_index':ci,'representative_parent_index':c['representative_parent_index'],'members':c['member_parent_indices'],
                    'read_before_write_requirements':required_json,'requirements_sha256':sha256(json.dumps(required_json,sort_keys=True).encode()).hexdigest(),
                    'effect_bytes':len(effects),'required_bytes':len(need),'all_checks_pass':True})
    assert indices==set(range(76));return {'classes':out,'verified_counts':dict(totals),'all_checks_pass':True}

def obligations():
    relevant_po={'all_words_offsets_original_first_twist_equation_and_table_address','all_words_offsets_original_second_twist_equation_and_table_address',
                 'all_words_original_last_twist_equation_and_table_address','all_raw_words_original_phase1_tempering',
                 'all_candidates_addresses_counts_original_store_reject_zero_and_transfer'}
    relevant_gs={'all_shift32_original_word_exhaustion_partition','all_records_original_equality_or_unsigned_greater_leaf',
                 'all_byte8_original_arena_copy_transform','all_phases_saved_pointer_original_status_store','all_adapter_values_pointers_original_low16_delta_store'}
    out=[q for q in PO.obligations() if q['label'] in relevant_po]+[q for q in GS.obligations() if q['label'] in relevant_gs]
    assert len(out)==10
    sp,delta,base=z3.BitVecs('emitter_return_SP64 emitter_adjustment64 emitter_adjustment_base64',64)
    v=Algebra();v.seed('sp',sp);v.seed('x23',base);mem(v,base+0xca0,8,delta);v.run_block(R.RETURN,0x10093ca94)
    solver=z3.Solver();solver.set(timeout=30000);assert solver.check()==z3.sat;solver.add(z3.simplify(v.read('sp')!=sp+delta));assert solver.check()==z3.unsat
    out.append({'label':'all_SP_adjustment_bits_original_caller_frame_restore','query':solver.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    classes=[];counts=Counter();model=Counter()
    for c in e['classes']:
        a=audit_class(c,p['contexts'][c['representative_parent_index']]);classes.append(a);counts.update(a['independent_totals']);model.update(a['model_checks'])
    covered=coverage(e,p);proofs=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},
            'verified_counts':e['verified_counts'],'classes':classes,'independent_totals':dict(counts),'model_checks':dict(model),
            'coverage':covered,'source_proofs':proofs,'source_queries_unsat':len(proofs),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'independent':e['independent_totals'],
             'model':e['model_checks'],'coverage':e['coverage']['verified_counts'],'queries':e['source_queries_unsat']}),flush=True)
