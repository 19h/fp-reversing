#!/usr/bin/env python3
"""Independent record-extension replay, complete admissions and publication custody.
O(visits*frame state + admissions*demands + proof DAG) time;
O(receipts+parent maps+largest interval+proof DAG) space, excluding solver
search complexity. ABI/owner effects are declared premises; no native API.
"""
import json
from copy import deepcopy
from collections import Counter
from hashlib import sha256
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE, CS, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_network_record import state_bytes
from audit_daemon_state_table_mixing import Scalar, admission, expected, requirement_receipt
from audit_daemon_state_emitter_completion import requirements
from lskd_values_symbolic import mem
import recover_daemon_record_extension as R
import recover_daemon_descriptor_growth as Growth
from recover_daemon_append_fields import custody
from audit_daemon_alternative_fill import Source
import replay_daemon_constructor_buffer as Replay

DEPS = ['replay_daemon_constructor_buffer.py','replay_daemon_descriptor_growth.py',
        'recover_daemon_append_fields.py','audit_daemon_alternative_fill.py',
        'audit_daemon_state_table_mixing.py',
        'audit_daemon_state_emitter_completion.py', 'lskd_values_symbolic.py']
OBJECTS=[('S',R.B.S,64),('U',R.B.U,48),('J',R.B.J,552)]
BIAS=0x4aba552460e435c6


def adc_value(a,b,carry):
    return a+b+z3.If(carry,z3.BitVecVal(1,a.size()),z3.BitVecVal(0,a.size()))


def ccmn_flags(a,b,choose,fallback):
    n=a.size();result=a+b
    sign_a=z3.Extract(n-1,n-1,a);sign_b=z3.Extract(n-1,n-1,b)
    sign_result=z3.Extract(n-1,n-1,result)
    values=[sign_result==1,result==0,z3.ULT(result,a),
            z3.And(sign_a==sign_b,sign_result!=sign_a)]
    return [z3.If(choose,v,z3.BoolVal(bool(fallback&(8>>j)))) for j,v in enumerate(values)]


class ExtensionLift(Replay.Lift):
    def one(self,i):
        if i.mnemonic=='adc':
            dst=i.reg_name(i.operands[0].reg);n=self.width(dst)
            self.write(dst,adc_value(self.operand(i,i.operands[1],n),
                                    self.operand(i,i.operands[2],n),self.carry))
            self.counts['ADC_value_transitions_checked']+=1
            return
        if i.mnemonic=='ccmn':
            n=self.width(i.reg_name(i.operands[0].reg))
            choose=self.condition(i.op_str.rsplit(',',1)[1].strip())
            self.n,self.z,self.carry,self.overflow=ccmn_flags(
                self.operand(i,i.operands[0],n),self.operand(i,i.operands[1],n),
                choose,i.operands[2].imm)
            self.flag_change=True
            self.counts['CCMN_flag_transitions_checked']+=1
            return
        return super().one(i)


def ccmn_controls():
    count=0
    for n in [32,64]:
        mask=(1<<n)-1
        for a in [0,1,(1<<(n-1))-1,1<<(n-1),mask]:
            for b in [0,1,mask]:
                for choose in [False,True]:
                    result=(a+b)&mask
                    actual_flags=((result>>(n-1))<<3)|((result==0)<<2)|((a+b>mask)<<1)|int(
                        ((a>>(n-1))==(b>>(n-1))) and ((result>>(n-1))!=(a>>(n-1))))
                    for fallback in range(16):
                        values=ccmn_flags(z3.BitVecVal(a,n),z3.BitVecVal(b,n),z3.BoolVal(choose),fallback)
                        actual=sum((8>>j) for j,v in enumerate(values) if z3.is_true(z3.simplify(v)))
                        assert actual==(actual_flags if choose else fallback)
                        count+=1
    return count


def adc_controls():
    count=0
    for n in [32,64]:
        mask=(1<<n)-1
        for a in [0,1,(1<<(n-1))-1,1<<(n-1),mask]:
            for b in [0,1,mask]:
                for carry in [False,True]:
                    actual=z3.simplify(adc_value(z3.BitVecVal(a,n),z3.BitVecVal(b,n),z3.BoolVal(carry)))
                    assert actual.as_long()==(a+b+int(carry))&mask
                    count+=1
    return count


def obligations():
    out = []
    def prove(label, bad):
        solver = z3.Solver()
        solver.set(timeout=30000)
        assert solver.check() == z3.sat
        solver.add(z3.simplify(bad))
        result = solver.check()
        assert result == z3.unsat, (label, str(result), solver.reason_unknown())
        out.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': solver.to_smt2()})
    i, src, dst = z3.BitVecs('extension_i64 growth_src64 growth_dst64', 64)
    byte = z3.BitVec('extension_byte8', 8)
    v = Scalar()
    for name, value in {'x9': i+1, 'x24': src, 'x10': dst}.items():
        v.seed(name, value)
    mem(v, src+i, 1, byte)
    v.run_block(0x100b5c9b0, 0x100b5c9bc)
    assert len(v.stores) == 1
    w = v.stores[0]
    prove('all_u64_indices_original_byte_copy_step', z3.Or(v.read('x9') != i, w['address'] != dst+i, w['value'] != byte))
    old, a, b = z3.BitVecs('extension_old_raw32 growth_phase_a32 growth_phase_b32', 32)
    v = Scalar()
    for name, value in {'w22': old, 'w8': a, 'w21': b}.items():
        v.seed(name, value)
    v.run_block(0x100c05638, 0x100c0564c)
    prove('all_u32_original_extent_update_equation', v.read('w8') != old-a+b+0x74c239af)
    raw = z3.BitVec('extension_new_raw32', 32)
    v = Scalar()
    v.seed('w8', raw)
    v.seed('w10', 0xc4eb)
    v.run_block(0x100d64024, 0x100d64054)
    prove('all_u32_original_allocation_count_in_recovered_phase', v.read('x0') != z3.ZeroExt(32, raw+0xef133bef))
    frame,destination,raw_s=z3.BitVecs('extension_frame64 extension_destination64 extension_S64',64)
    encoded=raw_s+BIAS
    v=Source({0x100901494:(8,destination)})
    v.seed('sp',frame);v.seed('x20',encoded)
    v.run_block(0x100901494,0x10090149c)
    assert len(v.loads)==len(v.stores)==1
    w=v.stores[0]
    prove('original_publication_copies_encoded_S_to_saved_destination',z3.Or(
        v.loads[0][1]!=frame+0x6608,w['address']!=destination,w['size_bytes']!=8,
        w['value']!=raw_s+BIAS,w['value']-BIAS!=raw_s))
    v=Source();v.seed('x20',encoded)
    v.run_block(0x1006b22f0,0x1006b2308)
    assert len(v.stores)==1
    w=v.stores[0]
    prove('original_S30_zero_initialization_decodes_additive_pointer',z3.Or(
        w['address']!=raw_s+0x30,w['size_bytes']!=8,w['value']!=0))
    return out


def abi_tags(tags, event):
    regs = {n: o for n, o in tags[0].items() if n.startswith('X') and 18 <= int(n[1:]) <= 29}
    memory = dict(tags[1])
    for span in event['invalidated_spans']:
        a, n = int(span['address'], 16), span['size_bytes']
        memory = {at: o for at, o in memory.items() if not a <= at < a+n}
    if event.get('allocated_owner_premise'):
        o = event['allocated_owner_premise']
        a, n = int(o['address'], 16), o['size_bytes']
        assert not any(a <= at < a+n for at in memory)
    return regs, memory


def snapshot(row, memory=None):
    m=state_bytes(row) if memory is None else memory
    objects=OBJECTS+[("buffer_"+str(j),a,n) for j,(a,n) in enumerate(sorted(
        (int(o['address'],16),o['size_bytes']) for o in row['foreign_owners']
        if int(o['address'],16)>=Growth.H and int(o['address'],16)<0x6700000000))]
    out={}
    for name,a,n in objects:
        raw=bytes(m.get(a+j,0) for j in range(n));mask=bytes(int(a+j in m) for j in range(n))
        out[name]={'address':hex(a),'extent_bytes':n,'known_bytes':sum(mask),'known_mask_hex':mask.hex(),
            'bytes_hex':raw.hex() if name!='J' else None,'masked_bytes_sha256':sha256(raw).hexdigest(),
            'owner_present':{'address':hex(a),'size_bytes':n} in row['foreign_owners']}
    return out


def semantics(c,rows,entries,terminals):
    timeline=[];publications=[];copy_runs=[];tag_calls=[];allocation_sizes=[];node_reads=[]
    late_zero=[]
    first_memory=state_bytes(entries[0])
    assert all(R.B.S+0x30+j not in first_memory for j in range(8))
    for ii,(item,row,entry,terminal) in enumerate(zip(c['intervals'],rows,entries,terminals)):
        event=item['API_return_premise'];before=state_bytes(entry);after=state_bytes(terminal)
        allocated=event.get('allocated_owner_premise');retired=event.get('retired_owner_premise')
        if allocated:
            a,n=int(allocated['address'],16),allocated['size_bytes'];allocation_sizes.append(n)
            assert all(a+j not in before for j in range(n))
            loads=[r for r in row['source_reads'] if r['pc']=='0x100b5c9b4']
            stores=[w for w in row['source_writes'] if w['pc']=='0x100b5c9b8']
            old=int.from_bytes(bytes(before[R.B.U+8+j] for j in range(8)),'little')
            old_n=next(o['size_bytes'] for o in entry['foreign_owners'] if int(o['address'],16)==old)
            assert len(loads)==len(stores)==old_n
            pairs=[]
            for j,(rr,ww) in enumerate(zip(loads,stores)):
                k=old_n-1-j
                assert rr['address']==hex(old+k) and ww['address']==hex(a+k)
                assert rr['bytes_hex']==ww['after_hex']==bytes([before[old+k]]).hex()
                assert rr['size_bytes']==ww['size_bytes']==1 and rr['source_visit_index']+1==ww['source_visit_index']
                pairs.append({'index':k,'read':rr,'write':ww})
            old_writes=[w for w in row['source_writes'] if int(w['address'],16)<old+old_n and old<int(w['address'],16)+w['size_bytes']]
            assert old_writes and min(w['source_visit_index'] for w in old_writes)>stores[-1]['source_visit_index']
            assert {int(w['address'],16)+j for w in old_writes for j in range(w['size_bytes'])}==set(range(old,old+old_n))
            assert row['boundary']['detail']['symbol']=='libSystem/_free' and row['boundary']['registers31'][0]==hex(old)
            assert sum(a+j in after for j in range(n))==old_n
            assert int.from_bytes(bytes(after[R.B.U+8+j] for j in range(8)),'little')==a
            assert all((int.from_bytes(bytes(after[R.B.U+off+j] for j in range(4)),'little')+0xef133bef)&0xffffffff==n for off in [0x10,0x14])
            copy_runs.append({'interval_index':ii,'old_buffer':hex(old),'old_extent_bytes':old_n,
                'new_buffer':hex(a),'new_extent_bytes':n,'copy_pairs':pairs,'old_bytes_overwritten_after_copy':old_n,
                'new_defined_bytes_before_free':old_n})
        if retired:
            a,n=int(retired['address'],16),retired['size_bytes']
            assert all(a+j not in before for j in range(n))
            assert not any(int(o['address'],16)==a for o in entry['foreign_owners'])
        for j,v in enumerate(row['source_visits']):
            if v['pc']=='0x1005015e8':
                f=row['source_frames'][j];tag=int(f['registers31'][12],16)&0xffffffff
                ascii_tag=tag.to_bytes(4,'big')
                tag_calls.append({'interval_index':ii,'source_visit_index':j,'pc':v['pc'],'raw_tag32':hex(tag),
                    'ASCII_literal':ascii_tag.decode('ascii') if all(32<=b<127 for b in ascii_tag) else None,
                    'first_word32':hex(int(f['registers31'][8],16)&0xffffffff),
                    'count_word32':hex(int(f['registers31'][11],16)&0xffffffff),'SP':f['SP']})
        jw=[w for w in row['source_writes'] if int(w['address'],16)<R.B.J+552 and R.B.J<int(w['address'],16)+w['size_bytes']]
        for w in row['source_writes']:
            if int(w['address'],16)<R.B.S+0x38 and R.B.S+0x30<int(w['address'],16)+w['size_bytes']:
                assert w['pc']=='0x1006b2304' and w['address']==hex(R.B.S+0x30)
                assert w['size_bytes']==8 and w['after_hex']=='00'*8
                late_zero.append({'interval_index':ii,'writer':w})
        for w in jw:
            assert w['pc']=='0x100901498' and w['address']==hex(R.B.J+0x68) and w['size_bytes']==8
            encoded=(R.B.S+BIAS)&((1<<64)-1)
            assert int.from_bytes(bytes.fromhex(w['after_hex']),'little')==encoded
            rr=next(r for r in row['source_reads'] if r['source_visit_index']==w['source_visit_index']-1)
            assert rr['pc']=='0x100901494' and int.from_bytes(bytes.fromhex(rr['bytes_hex']),'little')==R.B.J+0x68
            m=dict(before)
            for ww in row['source_writes']:
                if ww['source_visit_index']>=w['source_visit_index']:break
                a=int(ww['address'],16);m.update({a+j:b for j,b in enumerate(bytes.fromhex(ww['after_hex']))})
            active=int.from_bytes(bytes(m[R.B.U+8+j] for j in range(8)),'little')
            size=next(o['size_bytes'] for o in entry['foreign_owners'] if int(o['address'],16)==active)
            assert bytes(m[R.B.S+j] for j in range(8))==R.B.U.to_bytes(8,'little')
            assert bytes(m[R.B.S+0x30+j] for j in range(8))==bytes(8)
            assert len(late_zero)==1 and late_zero[0]['interval_index']==ii
            assert w['source_visit_index']-late_zero[0]['writer']['source_visit_index']==15
            publications.append({'interval_index':ii,'writer':w,'destination_read':rr,'destination_custody':custody(row,rr),
                'encoded_S64':hex(encoded),'decoded_S64':hex((encoded-BIAS)&((1<<64)-1)),
                'previous_raw_J68':hex(int.from_bytes(bytes(m[R.B.J+0x68+j] for j in range(8)),'little')),
                'active_buffer':hex(active),'active_extent_bytes':size,
                'active_defined_bytes_at_publication':sum(active+j in m for j in range(size)),
                'snapshot_before_publication':snapshot(entry,m),
                'later_active_buffer_writes':[ww for ww in row['source_writes'] if ww['source_visit_index']>w['source_visit_index']
                    and int(ww['address'],16)<active+size and active<int(ww['address'],16)+ww['size_bytes']]})
        node_reads.extend({'interval_index':ii,'read':rr} for rr in row['source_reads'] if rr['pc'] in ['0x100a5eac8','0x100a5eacc'])
        touched={}
        for name,a,n in OBJECTS:
            ww=[w for w in row['source_writes'] if int(w['address'],16)<a+n and a<int(w['address'],16)+w['size_bytes']]
            touched[name]={'store_events':len(ww),'PCs':dict(Counter(w['pc'] for w in ww)),
                'distinct_written_bytes':len({int(w['address'],16)+j for w in ww for j in range(w['size_bytes'])})}
        timeline.append({'interval_index':ii,'API_return_premise':event,'snapshot':snapshot(terminal),
            'object_writes':touched,'boundary':terminal['boundary']})
    final=terminals[-1];m=state_bytes(final)
    if not c['normal_branch']:
        assert len(rows)==3 and not allocation_sizes and not publications and not late_zero
        assert final['boundary']['pc']=='0x10074abc8'
        assert bytes(m[R.B.S+j] for j in range(8))==bytes(8)
        assert all(R.B.S+0x30+j not in m for j in range(8))
        assert not any(int(o['address'],16) in [Growth.H,R.B.U] for o in final['foreign_owners'])
    else:
        assert allocation_sizes==[97,125,145,185,224] and len(rows)==10 and len(publications)==1
        assert final['boundary']['pc']=='0x10084fdcc' and final['boundary']['detail']['address']==hex(0x6800060100+0x390)
        assert all(0x6800060100+0x390+j not in m for j in range(8))
        assert int.from_bytes(bytes(m[R.B.J+0x68+j] for j in range(8)),'little')==(R.B.S+BIAS)&((1<<64)-1)
        assert all({'address':hex(a),'size_bytes':n} in final['foreign_owners'] for a,n in [(R.B.S,64),(R.B.U,48),(R.FRESH_BASE+4*R.MAX_FRESH_EXTENT,224)])
    return {'timeline':timeline,'allocation_sizes_bytes':allocation_sizes,'copy_runs':copy_runs,
        'parent_publications':publications,'nested_tag_calls':tag_calls,'descriptor_node_reads':node_reads,
        'S30_zero_initialization':late_zero,
        'native_execution':False,'later_NULL_outcomes_established':False}


def prior_tags():
    poly = json.loads(read(ROOT/'daemon_descriptor_polynomial_checks.json'))
    walk = json.loads(read(ROOT/'daemon_descriptor_walk_checks.json'))
    walk_views = {c['cohort_index']: c for c in walk['coverage']}
    initial_tags = {}
    for ci, c in enumerate(poly['classes']):
        old_ci = walk_views[c['representative_cohort_index']]['class_index']
        _, tags, _ = Replay.origins(R.unpack(walk['classes'][old_ci]['interval_packed']))
        _, initial_tags[ci], _ = Replay.origins(R.unpack(c['interval_packed']), tags)
    growth=json.loads(read(ROOT/'daemon_descriptor_growth_checks.json'))
    growth_tags={}
    from replay_daemon_descriptor_growth import abi_tags as old_abi_tags
    for gi,gc in enumerate(growth['classes']):
        if gc['pointer_return64']=='0x0':continue
        tags=initial_tags[gc['polynomial_class_index']]
        for item in gc['intervals']:
            _,tags,_=Replay.origins(R.unpack(item['interval_packed']),old_abi_tags(tags,item['API_return_premise']))
        growth_tags[gi]=tags
    return growth_tags


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__)
    assert e['dependencies']=={p:sha(ROOT/p) for p in R.DEPS}
    assert e['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    incoming = R.parents()
    for p, digest in R.PINS.items():
        assert sha(ROOT/p) == digest
    growth_tags=prior_tags()
    totals, admissions = Counter(), Counter()
    classes, seen, slots = [], set(), set()
    views = {(c['parent_index'], c['ABI_clobber_pattern'], c['normal_branch']): c for c in e['coverage']}
    for ci, c in enumerate(e['classes']):
        rep = incoming[c['representative_parent_index']]['state']
        tags_by_parent={k:growth_tags[k] for k in {incoming[m['parent_index']]['growth_class_index'] for m in c['members']}}
        steps, rows, entries, terminals, lifts = [], [], [], [], []
        current = rep
        for ii, item in enumerate(c['intervals']):
            entry, ev = R.returned(current, item['API_return_premise'])
            assert ev == item['API_return_premise']
            for pattern in [0, 1]:
                _, fresh = R.event(current, pattern, int(item['API_return_premise']['pointer_return64'],16) if item['API_return_premise']['symbol']=='libSystem/_malloc' else None)
                _, constructed = R.returned(current, item['API_return_premise'], pattern)
                assert fresh == constructed
                admissions['fresh_ABI_recipe_checks'] += 1
            row = R.unpack(item['interval_packed'])
            Replay.GS.joined(entry, row)
            journal = None
            origins = []
            for parent_ci, tags in list(tags_by_parent.items()):
                own_journal, tags_by_parent[parent_ci], counts = Replay.origins(row, abi_tags(tags, ev))
                assert journal is None or journal == own_journal
                journal = own_journal
                origins.append({'growth_class_index': parent_ci, 'verified_counts': counts})
            deps = {'required': set(), 'written': set()}
            lift = ExtensionLift(row, deps, journal).run()
            totals.update(lift['verified_counts'])
            projection = R.B.registers([row])
            assert projection == item['register_projection']
            assert deps['required'] <= set(projection['required']) and deps['written'] == set(projection['written'])
            need, effects, _ = requirements(entry, [row])
            terminal = R.B.export(entry, row, projection)
            rows.append(row);entries.append(entry);terminals.append(terminal)
            steps.append((entry, row, projection, need, effects))
            lifts.append({'full_replay': lift, 'pointer_origins': origins, 'required_bytes': requirement_receipt(need)})
            if terminal['boundary']['kind'] == 'before_unmodeled_import_call':
                instruction = next(CS.disasm(IMAGE.read(int(terminal['boundary']['pc'],16),4),int(terminal['boundary']['pc'],16)))
                assert instruction.mnemonic == 'blraa'
                name = instruction.op_str.split(',')[0].upper()
                pending_origins = {tags[0][name] for tags in tags_by_parent.values()}
                assert len(pending_origins) == 1
                slot, target = pending_origins.pop()
                assert target == int(terminal['boundary']['detail']['target'],16)
                slots.add(slot)
                lifts[-1]['pending_import_origin'] = {'slot': hex(slot), 'model_target': hex(target), 'source_word_hex': IMAGE.read(instruction.address,4).hex()}
            current = terminal
            print(json.dumps({'class':ci,'interval':ii,'source_visits_replayed':totals['source_visits']}),flush=True)
        meaning = semantics(c, rows, entries, terminals)
        for member in c['members']:
            j, pattern = member['parent_index'], member['ABI_clobber_pattern']
            key = j, pattern, c['normal_branch']
            assert key not in seen
            seen.add(key)
            current = incoming[j]['state']
            for item, (rep_entry, row, projection, need, effects) in zip(c['intervals'], steps):
                entry, ev = R.returned(current, item['API_return_premise'], pattern)
                memory, values = admission(entry, rep_entry, need, projection)
                terminal = R.B.export(entry, row, projection)
                expected(entry, terminal, effects, projection, row, memory, values)
                admissions.update(interval_admissions=1, incoming_byte_demands=len(need), incoming_register_demands=len(projection['required']))
                current = terminal
            assert current == R.unpack(views[key]['derived_terminal_state_packed']) and views[key]['class_index'] == ci
            admissions.update(branch_admissions=1, terminal_exports=1)
        # Fault controls reject one demanded byte, a changed SP and a missing owner.
        entry, row, projection, need, effects = steps[0]
        demanded = next(a for a, (b, origin) in need.items() if origin == 'incoming')
        for remove in [False, True]:
            memory = state_bytes(entry)
            if remove: del memory[demanded]
            else: memory[demanded] ^= 1
            try: admission(entry, entry, need, projection, memory=memory)
            except AssertionError: admissions['incoming_byte_fault_controls_rejected'] += 1
            else: raise AssertionError('bad demanded byte admitted')
        values = R.B.machine(entry);values['SP'] = hex(int(values['SP'],16)^16)
        try: admission(entry, entry, need, projection, values=values)
        except AssertionError: admissions['changed_SP_rejected'] += 1
        else: raise AssertionError('bad SP admitted')
        try: admission({**entry, 'foreign_owners': entry['foreign_owners'][:-1]}, entry, need, projection)
        except AssertionError: admissions['changed_owner_rejected'] += 1
        else: raise AssertionError('bad owner admitted')
        # A reserved saved register survives both ABI and each source interval.
        probe = deepcopy(rep)
        probe['boundary']['registers31'][18] = hex(int(probe['boundary']['registers31'][18],16)^1)
        for item, (rep_entry, row, projection, need, effects) in zip(c['intervals'], steps):
            assert 'X18' not in projection['required'] and 'X18' not in projection['written']
            entry, _ = R.returned(probe, item['API_return_premise'])
            memory, values = admission(entry, rep_entry, need, projection)
            probe = R.B.export(entry, row, projection)
            expected(entry, probe, effects, projection, row, memory, values)
        assert probe['boundary']['registers31'][18] != terminals[-1]['boundary']['registers31'][18]
        admissions['per_parent_saved_X18_controls'] += 1
        classes.append({'class_index': ci, 'intervals': lifts, 'semantics': meaning, 'all_checks_pass': True})
        print(json.dumps({'class': ci, 'source_visits_replayed': totals['source_visits'], 'admitted_branches': admissions['branch_admissions']}), flush=True)
    assert seen == set(views) and len(seen) == 1216
    proofs = obligations()
    return {'scope': __doc__, 'replayer_sha256': sha(__file__), 'generator_sha256': sha(R.__file__),
            'checks_sha256': sha(ROOT/(R.P+'_checks.json')), 'source_sha256': sha(SOURCE),
            'replayer_dependencies': {p: sha(ROOT/p) for p in DEPS}, 'verified_counts': e['verified_counts'],
            'independent_totals': dict(totals), 'admissions': dict(admissions), 'classes': classes,
            'ADC_integer_controls': adc_controls(), 'CCMN_integer_controls': ccmn_controls(), 'source_proofs': proofs, 'source_queries_unsat': len(proofs), 'pending_import_fixups': verify_original_fixups(sorted(slots)),
            'native_API_executed': False, 'native_daemon_kext_pairing_established': False,
            'initializer_to_current_caller_join_established': False, 'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    result = audit()
    (ROOT/(R.P+'_replay.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'independent_totals': result['independent_totals'], 'admissions': result['admissions'],
                      'source_queries_unsat': result['source_queries_unsat']}), flush=True)
