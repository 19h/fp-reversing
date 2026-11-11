#!/usr/bin/env python3
"""Original AES software-ring geometry, cursor writers and interrupt wakeup.

Static source/ABI certificates; allocator zeroing, object lifetime, alias closure,
serialization, real register delivery and native progress remain premises.
O(B+I+P) collection/source/path time and space; SMT cost separate.
No allocation, interrupt, MMIO, key, IPC or IDB operation executes.
"""
import argparse
import bisect
import json
from hashlib import sha256

import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM

from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_kext_aes_handoff import function, starts
from recover_kext_cold_init import pointer
from recover_aes_configuration_commands import ConfigLift, fork, H
from lskd_values_symbolic import resize, part
from verify_daemon_reader_record_payloads_publication import read, sha

VIEW = 0xfffffe00082fe4e8
FUNCTIONS = {'meta_C1': H+0xe540, 'meta_C2': H+0xe684, 'class_alloc': H+0xe6d0,
             'typed_C1': H+0xe5cc, 'typed_C2': H+0xe594, 'default_C1': H+0xe750, 'default_C2': H+0xe7ac,
             'start': H+0xead0, 'enable': H+0xf964, 'complete': H+0x1153c, 'push': H+0x11e38,
             'interrupt': H+0xf558, 'configure': H+0xfcf8}
SLEEP_SITES = [(H+0xfeec,H+0xff28),(H+0xffa8,H+0xffe8),(H+0x10228,H+0x10268),
               (H+0x102b4,H+0x102f4),(H+0x10334,H+0x10370),(H+0x1044c,H+0x1048c),
               (H+0x105d4,H+0x10610),(H+0x106bc,H+0x106fc)]
KERNEL = {'typed_new': 0xfffffe000c4458c4, 'gate_wakeup': 0xfffffe000c51e19c}
# Each record is split into branch-free pointer/payload/update source pieces.
RECORDS = [
    ('start_enter', H+0xf434, H+0xf450, H+0xf450, H+0xf458, H+0xf458, H+0xf468, 'x20', 'x22', 'x10', 1, 1),
    ('start_leave', H+0xf480, H+0xf498, H+0xf498, H+0xf4a4, H+0xf4a4, H+0xf4b4, 'x20', 'x22', 'x10', 1, 2),
    ('enable_enter', H+0xf9a8, H+0xf9c4, H+0xf9c4, H+0xf9e0, H+0xf9fc, H+0xfa00, 'x20', 'x21', 'x9', 1, 1),
    ('disable_enter', H+0xf9a8, H+0xf9c4, H+0xf9c4, H+0xf9e0, H+0xfa4c, H+0xfa50, 'x20', 'x21', 'x9', 1, 3),
    ('state_leave', H+0xfb6c, H+0xfb88, H+0xfb88, H+0xfbc0, H+0xfbc0, H+0xfbc0, 'x20', 'x21', 'x11', 1, None),
    ('completion_status', H+0x11590, H+0x115ac, H+0x115ac, H+0x115e4, H+0x115e4, H+0x115e4, 'x19', 'x27', 'x11', 3, None),
    ('completion_progress', H+0x11794, H+0x117b0, H+0x117b0, H+0x117cc, H+0x117cc, H+0x117cc, 'x19', 'x27', 'x11', 4, None),
    ('command_word', H+0x11eb8, H+0x11ed4, H+0x11ed4, H+0x11ef0, H+0x11ef0, H+0x11ef0, 'x20', 'x24', 'x11', 2, None),
]


class TraceLift(ConfigLift):
    def store(self, address, n, value, pc):
        # Retain conditional trace addresses, then prove their bounds below.
        if getattr(self, 'admit_trace_writes', False):
            assert n in [4, 8]
            self.fixed_stores.add((z3.simplify(resize(address, 64)).sexpr(), n))
        super().store(address, n, value, pc)

    def run(self, label):
        saved = self.c; row = next(r for r in saved['spans'] if r['label'] == label)
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); cs.detail = True
        raw = bytes.fromhex(row['bytes_hex']); insns = list(cs.disasm(raw, int(row['start'], 16)))
        assert len(insns)*4 == len(raw)
        for ins in insns:
            self.pc = ins.address
            if ins.mnemonic == 'movi':
                assert ins.op_str in ['v0.2s, #1', 'v0.2s, #2', 'v0.2s, #4']
                n = ins.operands[1].imm; self.write('q0', n | (n << 32)); self.count += 1
            else:
                self.c = {'spans': [{'label': label, 'start': hex(ins.address), 'bytes_hex': bytes(ins.bytes).hex()}]}
                super().run(label)
        self.c = saved; return self


def interrupt_paths(capture, provider, registers, enabled, waiting, version, status, control):
    row = next(r for r in capture['spans'] if r['label'] == 'interrupt')
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); cs.detail = True
    code = {i.address: i for i in cs.disasm(bytes.fromhex(row['bytes_hex']), int(row['start'], 16))}
    obj = TraceLift({'spans': []}); obj.seed('x0', provider)
    for at, n, value in [(provider+0x1f8, 1, enabled), (provider+0x150, 1, waiting),
                          (provider+0x178, 8, registers), (registers+0x18, 4, status), (registers+0x1c, 4, control), (provider+0x128, 4, version)]:
        obj.fixed[(z3.simplify(resize(at, 64)).sexpr(), n)] = resize(value, n*8)
    obj.fixed_stores.update([(z3.simplify(registers+0x18).sexpr(), 4), (z3.simplify(registers+0x1c).sexpr(), 4), (z3.simplify(provider+0x150).sexpr(), 1)])
    stops = {H+0xf5c4, H+0xf5f8, H+0xf608, H+0xf62c, H+0xf630}
    pending = [(H+0xf570, obj, z3.BoolVal(True), [])]; leaves = []
    while pending:
        pc, obj, predicate, visits = pending.pop(); assert len(visits) < 64
        if pc in stops: leaves.append((pc, obj, predicate, visits)); continue
        ins = code[pc]; m, ops = ins.mnemonic, ins.operands; visits = visits+[pc]
        condition = None
        if m.startswith('b.'): condition = obj.condition(m[2:])
        elif m in ['tbz', 'tbnz']:
            condition = (obj.read(ins.reg_name(ops[0].reg)) & (1 << ops[1].imm)) == 0
            if m == 'tbnz': condition = z3.Not(condition)
        if condition is not None:
            pending.append((ops[-1].imm & ((1 << 64)-1), fork(obj), z3.And(predicate, condition), visits))
            pending.append((pc+4, fork(obj), z3.And(predicate, z3.Not(condition)), visits))
        else:
            assert m in ['mov', 'ldr', 'ldrb', 'str', 'strb', 'movk', 'add', 'cmp', 'csel', 'tst', 'and']
            obj.c = {'spans': [{'label': 'irq', 'start': hex(pc), 'bytes_hex': bytes(ins.bytes).hex()}]}
            obj.run('irq'); pending.append((pc+4, obj, predicate, visits))
    return leaves


def prove(capture):
    queries, pieces, counts, record_rows = {}, {}, {}, []
    P, R, G, S = z3.BitVecs('provider64 register_base64 gate64 declared_source64', 64)
    index, payload, version, status = z3.BitVecs('cursor32 payload32 version32 interrupt_status32', 32)
    enabled, waiting = z3.BitVecs('enabled_byte8 wait_byte8', 8)
    control = z3.BitVec('interrupt_control32', 32)
    valid = z3.ULE(index, 255); next_index = z3.If(z3.ULT(index, 255), index+1, resize(0, 32))
    at = P+0x1fc+z3.ZeroExt(32, index)*8

    def run(name, a, z, seeds, cells=(), writes=()):
        obj = TraceLift(part(capture, name, a, z))
        obj.admit_trace_writes = any(name == r[0]+suffix for r in RECORDS for suffix in ['_record', '_payload'])
        for reg, value in seeds.items(): obj.seed(reg, value)
        for address, n, value in cells: obj.fixed[(z3.simplify(resize(address, 64)).sexpr(), n)] = resize(value, n*8)
        for address, n in writes: obj.fixed_stores.add((z3.simplify(resize(address, 64)).sexpr(), n))
        obj.run(name); assert obj.count == (z-a)//4
        pieces[name] = {'start': hex(a), 'end': hex(z), 'instructions': obj.count}; counts[name] = obj.count
        return obj

    def cell(obj, address, n): return obj.fixed[(z3.simplify(resize(address, 64)).sexpr(), n)]

    for name, a, z, b, q, u, v, provider_reg, base_reg, pointer_reg, tag, fixed_payload in RECORDS:
        seeds = {provider_reg: P, base_reg: P+0x1fc}
        if name == 'start_leave': seeds['w8'] = index
        obj = run(name+'_pointer', a, z, seeds, [(P+0x9fc, 4, index)])
        queries[name+'_pointer'] = z3.And(valid, obj.read(pointer_reg) != at)
        common = {provider_reg: P, base_reg: P+0x1fc, pointer_reg: at, 'sp': 0xfffffe0053000000}
        cells, writes = [], [(at, 4), (at+4, 4), (at, 8), (P+0x9fc, 4)]
        if name == 'start_enter': common['w8'] = index
        elif name == 'start_leave': common['w8'] = index; cells.append((0xfffffe000771c5f8, 8, 0x200000001))
        elif name in ['enable_enter', 'disable_enter']: common['w10'] = index
        elif name == 'state_leave': common.update(w9=index, w8=payload)
        elif name == 'completion_status': common.update(w9=index, w26=payload)
        elif name == 'completion_progress': common.update(w9=index, x8=P+0x164); cells.append((P+0x164, 4, payload))
        elif name == 'command_word': common.update(w9=index, x8=S); cells.append((S, 4, payload))
        obj = run(name+'_record', b, q, common, cells, writes)
        value = resize(fixed_payload, 32) if fixed_payload is not None else payload
        if name in ['enable_enter', 'disable_enter']:
            # Shared first-field/next-index cut, then the selected source arm.
            queries[name+'_tag'] = cell(obj, at, 4) != tag
            queries[name+'_next_register'] = obj.read('w10') != next_index
            a2, z2, preg = (H+0xf9e4, H+0xf9fc, 'x11') if name == 'enable_enter' else (H+0xfa30, H+0xfa4c, 'x8')
            tail = run(name+'_payload', a2, z2, {base_reg: P+0x1fc, 'x9': (z3.ZeroExt(32, index) << 3) | 4, 'w8': 1}, writes=[(at+4, 4)])
            queries[name+'_payload'] = z3.And(valid, z3.Or(tail.read(preg) != at+4, tail.stores[-1]['address'] != at+4, tail.stores[-1]['value'] != value))
            upd = run(name+'_cursor', u, v, {provider_reg: P, 'w10': next_index}, writes=[(P+0x9fc, 4)])
            queries[name+'_cursor'] = cell(upd, P+0x9fc, 4) != next_index
        else:
            if name in ['start_enter', 'start_leave', 'completion_progress', 'command_word']:
                queries[name+'_record'] = cell(obj, at, 8) != z3.Concat(value, resize(tag, 32))
            else:
                queries[name+'_record'] = z3.And(valid, z3.Or(obj.stores[0]['address'] != at, obj.stores[0]['value'] != tag, obj.stores[1]['address'] != at+4, obj.stores[1]['value'] != value))
            if u < v:
                obj = run(name+'_cursor', u, v, {provider_reg: P, 'w8': index}, writes=[(P+0x9fc, 4)])
            queries[name+'_cursor'] = cell(obj, P+0x9fc, 4) != next_index
        record_rows.append({'name': name, 'pointer_piece': name+'_pointer', 'tag32': tag, 'fixed_payload32': fixed_payload,
                            'cursor_store': hex(v-4 if u < v else q-4)})
    queries['next_cursor_bounded'] = z3.UGT(next_index, 255)
    queries['ring_extent'] = z3.And(valid, z3.Or(z3.ULT(0x1fc+z3.ZeroExt(32,index)*8, 0x1fc),
        z3.UGT(0x1fc+z3.ZeroExt(32,index)*8+8, 0x9fc)))
    queries['ring_cursor_class_extent'] = z3.Or(resize(0x1fc+256*8,64) != 0x9fc, resize(0x9fc+4,64) != 0xa00)
    # Two successive serial applications keep every read cursor in bounds.
    queries['serial_cursor_induction_step'] = z3.And(valid, z3.UGT(next_index, 255))
    obj = run('allocation_arguments', H+0xe6e4, H+0xe6f0, {})
    queries['allocation_arguments'] = z3.Or(obj.read('x0') != VIEW, obj.read('w1') != 2560)
    for label, a in [('meta_C1_size', H+0xe560), ('meta_C2_size', H+0xe6a4)]:
        obj = run(label, a, a+4, {}); queries[label] = obj.read('w3') != 2560
    obj = run('typed_size_comparison', 0xfffffe000c4458d8, 0xfffffe000c4458e4,
              {'x0': VIEW, 'x1': 2560}, [(VIEW+0x2c, 4, 2560)])
    queries['typed_size_admitted'] = z3.UGT(obj.cmp_left, obj.cmp_right)
    obj = run('typed_zero_flag', 0xfffffe000c445908, 0xfffffe000c44590c, {})
    queries['typed_zero_flag'] = obj.read('w1') != 4
    obj = run('interrupt_mask', H+0xf588, H+0xf5a0, {'x0': P, 'w20': status}, [(P+0x128,4,version)])
    mask = z3.If(z3.ULT(version,2), resize(0x1ffde,32), resize(0x3efde,32))
    queries['interrupt_mask'] = obj.read('w9') != mask
    leaves = interrupt_paths(capture, P, R, enabled, waiting, version, status, control)
    active = (enabled & 1) != 0; admitted = z3.And(active, (status & mask) == 0)
    wake = z3.And(admitted, (status & 1) != 0, (waiting & 1) != 0)
    outcomes = {H+0xf5c4: wake, H+0xf62c: z3.Not(active), H+0xf630: z3.And(active,(status&mask)!=0),
                H+0xf608: z3.And(admitted,z3.Not(wake),(status&32)!=0),
                H+0xf5f8: z3.And(admitted,z3.Not(wake),(status&32)==0)}
    for pc, expected in outcomes.items(): queries['interrupt_frontier_'+hex(pc)] = z3.Or(*[p for a,_,p,_ in leaves if a==pc]) != expected
    predicates = [p for _,_,p,_ in leaves]
    queries['interrupt_coverage'] = z3.Not(z3.Or(*predicates))
    queries['interrupt_disjoint'] = z3.Or(*[z3.And(a,b) for i,a in enumerate(predicates) for b in predicates[i+1:]])
    for j,(pc,obj,predicate,_) in enumerate(leaves):
        if pc==H+0xf5c4:
            queries['wake_clear_'+str(j)] = z3.And(predicate, cell(obj,P+0x150,1)!=0)
            queries['wake_control_clear_'+str(j)] = z3.And(predicate, cell(obj,R+0x1c,4)!=(control&0xfffffffe))
        if pc not in [H+0xf62c]:
            ack=next(s for s in obj.stores if s['pc']==H+0xf584)
            queries['status_ack_'+str(j)] = z3.And(predicate,z3.Or(ack['address']!=R+0x18,ack['value']!=status,cell(obj,R+0x18,4)!=status))
    for label,a,value in [('enabled_leave_value',H+0xfb68,2),('disabled_leave_value',H+0xfad8,4)]:
        obj=run(label,a,a+4,{});queries[label]=obj.read('w8')!=value
    obj = run('completion_status_arguments', H+0x11588, H+0x11590, {'w8': payload, 'x19': P})
    queries['completion_status_arguments'] = z3.Or(obj.read('w26')!=(payload&255),obj.read('x27')!=P+0x1fc)
    obj = run('wake_arguments', H+0xf5e4, H+0xf5ec, {'x19': P})
    queries['wake_arguments'] = z3.Or(obj.read('x1')!=P+0x150,obj.read('w2')!=0)
    obj = run('wake_receiver', H+0xf5c4, H+0xf5c8, {'x19': P}, [(P+0x1c8,8,G)])
    queries['wake_receiver'] = obj.read('x0')!=G
    for j,(_,call) in enumerate(SLEEP_SITES):
        obj = run('sleep_arguments_'+str(j), call-12, call-4, {'x19': P})
        queries['sleep_arguments_'+str(j)] = z3.Or(obj.read('x1')!=P+0x150,obj.read('w2')!=2)
    obj=run('wait_one_register',H+0x10204,H+0x10208,{})
    queries['wait_one_register']=obj.read('w27')!=1
    obj=run('wait_request',H+0x10228,H+0x1023c,{'x19':P,'w27':1},
            [(P+0x178,8,R),(R+0x1c,4,control)],[(P+0x150,1),(R+0x1c,4)])
    queries['wait_request']=z3.Or(cell(obj,P+0x150,1)!=1,cell(obj,R+0x1c,4)!=(control|1))
    controls = {'arbitrary_initial_cursor_not_bounded': z3.UGT(index,255),
                'interrupt_wake_not_unconditional': z3.And(active,(status&1)!=0,z3.Not(wake))}
    proofs = {}
    for name, query in queries.items():
        solver = z3.Solver(); solver.set(timeout=15000); solver.add(query); result = solver.check()
        assert result==z3.unsat,(name,str(result),solver.reason_unknown())
        proofs[name]={'result':'unsat','query':solver.sexpr()}; print(name,result,flush=True)
    negative={}
    for name,query in controls.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(query);assert solver.check()==z3.sat
        negative[name]={'result':'sat','query':solver.sexpr(),'scope':'Abstract premise control; no native reachability claim.'}
    ledger=[]
    for pc,_,predicate,visits in leaves:
        solver=z3.Solver();solver.set(timeout=15000);solver.add(predicate);assert solver.check()==z3.sat
        ledger.append({'frontier':hex(pc),'path':[hex(a)for a in visits],'path_condition':predicate.sexpr(),
                       'declared_snapshot_feasibility':'sat','feasibility_query':solver.sexpr()})
    return {'proofs':proofs,'negative_controls':negative,'source_pieces':pieces,'source_lift_counts':counts,
            'record_writers':record_rows,'interrupt_paths':ledger,
            'configuration_sleep_sites':[{'wait_byte_store':hex(store),'sleep_call':hex(call)}for store,call in SLEEP_SITES],
            'verified_counts':{'queries_unsat':len(proofs),'controls_sat':len(negative),'source_pieces':len(pieces),
                               'source_lifted_instances':sum(counts.values()),'record_writers':len(record_rows),
                               'interrupt_paths_sat':len(ledger)}}


def build():
    k=Kernel(); e=next(e for e in k.entries if e['name']=='com.apple.driver.AppleS8000AES'); spans=[]
    for label,address in FUNCTIONS.items():r=function(k,e,address);r['label']=label;spans.append(r)
    for label,address in KERNEL.items():
        r=k.function(address);r['label']=label;r['bytes_hex']=r.pop('bytes');spans.append(r)
    stubs={'typed_new_stub':H+0x12ae4,'meta_ctor_stub':H+0x12b24,'base_ctor_stub':H+0x12b84,'instance_stub':H+0x12c34}
    for label,address in stubs.items():
        raw=k.read(address,16);spans.append({'label':label,'start':hex(address),'end':hex(address+16),'bytes_hex':raw.hex(),
          'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(raw,address)]})
    slots={hex(a):pointer(k,a)for a in [0xfffffe00082fe580,0xfffffe00082fe5a0,0xfffffe00082fe5d0,0xfffffe00082fe628,
                                       0xfffffe0007f3fdb8,0xfffffe0007f3fdb0,VIEW+16,VIEW+32]}
    section=next(s for s in e['sections']if s['section']=='__text'); a,n=section['address'],section['size'];raw=k.read(a,n)
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;ins=list(cs.disasm(raw,a));assert len(ins)*4==n
    catalog=starts(k,e);hits=[]
    for i in ins:
        if any(o.type==ARM64_OP_MEM and o.mem.disp==0x9fc for o in i.operands):
            ix=bisect.bisect_right(catalog,i.address)-1
            hits.append({'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,
                         'compiler_start':hex(catalog[ix]),'compiler_end':hex(catalog[ix+1])})
    result=prove({'spans':spans});result['verified_counts'].update(spans=len(spans),instructions=sum(len(r['instructions'])for r in spans),
          code_B=sum(len(bytes.fromhex(r['bytes_hex']))for r in spans),original_slots=len(slots),
          census_instructions=len(ins),literal_cursor_reads=sum(r['mnemonic']=='ldr'for r in hits),literal_cursor_stores=sum(r['mnemonic']=='str'for r in hits))
    prior=json.loads(read(ROOT/'aes_carrier_initialization_source.json'))['separately_versioned_reference']
    return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,'spans':spans,'slots':slots,
        'exact_symbols':k.symbols(list(FUNCTIONS.values())+list(KERNEL.values())+[int(r['target'],16)for r in slots.values()]+[VIEW]),
        'typed_view':{'address':hex(VIEW),'bytes_hex':k.read(VIEW,64).hex(),'size_low24':int.from_bytes(k.read(VIEW+0x2c,4),'little')&0xffffff,
                      'name_bytes_hex':k.read(int(slots[hex(VIEW+16)]['target'],16),30).hex(),'native_zone_identity_established':False},
        'startup_constant':{'address':'0xfffffe000771c5f8','bytes_hex':k.read(0xfffffe000771c5f8,8).hex()},
        'cursor_census':{'entry':e['name'],'entry_uuid':e['uuid'],'start':hex(a),'size_bytes':n,'sha256':sha256(raw).hexdigest(),
                         'bytes_hex':raw.hex(),'instructions':len(ins),'literal_0x9fc_memory_operands':hits,
                         'alias_or_indirect_writer_closure_established':False},
        'separately_versioned_zero_flag_reference':prior,
        'dependencies':{p:sha(ROOT/p)for p in ['recover_aes_configuration_commands.py','aes_configuration_commands_checks.json',
                'aes_carrier_initialization_source.json','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py',
                'lskd_values_symbolic.py','verify_daemon_reader_record_payloads_publication.py']},
        'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False,**result}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    result=build();path=ROOT/'aes_trace_wakeup_checks.json'
    if args.verify:assert json.loads(read(path))==result
    else:path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result['verified_counts']))
