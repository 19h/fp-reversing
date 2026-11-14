#!/usr/bin/env python3
"""Audit complete mixing, all76 dependency admissions and next-call records.

Independent instruction replay is a separately pinned primary receipt.
Fresh ordered byte effects, conservative/semantic register dependencies,
source equations and all parent-specific exports establish conditional scope.
O(receipts+visits+parents*requirements+query DAG) time/storage;30 s/query.
No native target API, IPC, allocation/free, hardware PAC or IDB mutation.
"""
import json,struct
from collections import Counter
from hashlib import sha256
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import resize,mem,cell
import audit_daemon_state_emitter_completion as Prior
import recover_daemon_state_table_mixing as R
import replay_daemon_state_table_mixing as Replay

AD=['audit_daemon_state_emitter_completion.py','audit_daemon_network_record.py','audit_daemon_environment_outputs.py',
    'recover_daemon_return_bank_origins.py','lskd_values_symbolic.py']

def admission(parent,rep,need,projection,memory=None,values=None):
    assert parent['boundary']['pc']==rep['boundary']['pc']
    assert parent['configuration']==rep['configuration'] and parent['foreign_owners']==rep['foreign_owners']
    memory=state_bytes(parent) if memory is None else memory;values=R.machine(parent) if values is None else values;expected=R.machine(rep)
    assert all(values[n]==expected[n] for n in projection['required'])
    for a,(b,origin) in need.items():
        actual=memory.get(a) if origin=='incoming' else memory[a] if a in memory else Prior.immutable_byte(a)
        assert actual==b
    return memory,values

def expected(parent,terminal,effects,projection,last,memory=None,values=None):
    memory=state_bytes(parent) if memory is None else memory;values=R.machine(parent) if values is None else values
    assert state_bytes(terminal)==memory|effects
    actual=R.machine(terminal);end=R.machine(last);written=set(projection['written'])
    assert actual=={n:end[n] if n in written else value for n,value in values.items()}
    assert terminal['boundary']['pc']==last['boundary']['pc'] and terminal['configuration']==parent['configuration']
    assert terminal['foreign_owners']==parent['foreign_owners'] and not terminal['source_visits'] and not terminal['native_target_executed']

def requirement_receipt(need):
    rows=[{'address':hex(a),'value8':b,'origin':origin} for a,(b,origin) in sorted(need.items())]
    return {'bytes':rows,'sha256':sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest()}

def coverage(e,parents):
    rows=list(R.shared_intervals(e));rep=parents[0];projection=R.registers(rows);assert projection==e['register_projection']
    need,effects,counts=Prior.requirements(rep,rows);shared={};repbytes=state_bytes(rep);counts=Counter(counts)
    for i,parent in parents.items():
        memory,values=admission(parent,rep,need,projection)
        terminal=R.terminal(parent,rows,projection);expected(parent,terminal,effects,projection,rows[-1]);shared[i]=terminal
        counts.update(shared_parent_admissions_checked=1,shared_input_bytes_checked=len(need),shared_terminal_bytes_checked=len(memory|effects),
                      shared_register_requirements_checked=len(projection['required']),
                      unread_original_byte_differences_preserved=sum(a not in need and b!=repbytes.get(a) for a,b in memory.items()))
    # Negative demanded-byte and register/owner controls; positive pass-through
    # Q/GP and dead-input controls check the projection boundary explicitly.
    address=next(a for a,(b,o) in sorted(need.items()) if o=='incoming' and 0x6800000000<=a<0x6800100000)
    bad=dict(repbytes);bad[address]^=1
    try:admission(rep,rep,need,projection,memory=bad)
    except AssertionError:counts['changed_demanded_byte_rejected']+=1
    else:raise AssertionError('changed demanded byte admitted')
    for name in ['SP','X20']:
        bad=R.machine(rep);bad[name]=hex(int(bad[name],16)^16)
        try:admission(rep,rep,need,projection,values=bad)
        except AssertionError:counts['changed_required_register_rejected']+=1
        else:raise AssertionError('changed required register admitted')
    bad={**rep,'foreign_owners':rep['foreign_owners'][:-1]}
    try:admission(bad,rep,need,projection)
    except AssertionError:counts['changed_owner_rejected']+=1
    else:raise AssertionError('changed owner admitted')
    for name in ['Q0','X18','X0','NZCV']:
        assert name not in projection['required'];bad=R.machine(rep);bad[name]=hex(int(bad[name],16)^1)
        memory,values=admission(rep,rep,need,projection,values=bad)
        end={n:R.machine(rows[-1])[n] if n in projection['written'] else value for n,value in values.items()}
        if name in projection['written']:assert end[name]==R.machine(rows[-1])[name];counts['dead_changed_input_overwritten_controls']+=1
        else:assert end[name]==bad[name];counts['unused_changed_register_preserved_controls']+=1
    unused=next(a for a in sorted(repbytes) if a not in need and a not in effects and 0x6800000000<=a<0x6800100000)
    bad=dict(repbytes);bad[unused]^=1;memory,_=admission(rep,rep,need,projection,memory=bad)
    assert (memory|effects)[unused]==bad[unused];counts['unused_changed_byte_preserved_controls']+=1
    handoffs=[];indices=set();views={x['parent_index']:x for x in e['coverage']}
    for ci,c in enumerate(e['handoff_classes']):
        row=R.unpack(c['interval_packed']);rep=shared[c['representative_parent_index']];pr=R.registers([row]);required,writes,ct=Prior.requirements(rep,[row]);counts.update(ct)
        assert R.Parent.key(rep)==c['class_key'];members=set(c['member_parent_indices'])
        for i in members:
            assert i not in indices;indices.add(i);parent=shared[i]
            assert R.Parent.key(parent)==c['class_key'] and R.machine(parent)==R.machine(rep)
            memory,values=admission(parent,rep,required,pr);terminal=R.unpack(views[i]['derived_terminal_state_packed'])
            assert views[i]['handoff_class_index']==ci;expected(parent,terminal,writes,pr,row)
            counts.update(handoff_parent_admissions_checked=1,handoff_input_bytes_checked=len(required),final_terminal_bytes_checked=len(memory|writes),
                          terminal_vector_registers_preserved=32)
        handoffs.append({'class_index':ci,'members':sorted(members),'required_bytes':requirement_receipt(required),'all_checks_pass':True})
    assert indices==set(range(76)) and len(views)==76
    return {'shared_required_bytes':requirement_receipt(need),'shared_register_projection':projection,'handoff_classes':handoffs,
            'verified_counts':dict(counts),'all_checks_pass':True}

class Scalar(Algebra):
    def one(self,ins):
        if ins.mnemonic=='sxtb':
            self.write(ins.reg_name(ins.operands[0].reg),z3.SignExt(24,resize(self.read(ins.reg_name(ins.operands[1].reg)),8)));return
        if ins.mnemonic=='smull':
            a=z3.SignExt(32,resize(self.read(ins.reg_name(ins.operands[1].reg)),32));b=z3.SignExt(32,resize(self.read(ins.reg_name(ins.operands[2].reg)),32))
            self.write(ins.reg_name(ins.operands[0].reg),a*b);return
        return super().one(ins)

class ByteInput(Scalar):
    def __init__(self,b):super().__init__();self.input_byte=b;self.addresses=[]
    def load(self,a,n):assert n==1;self.addresses.append(a);return self.input_byte

def root_control(b,counter=0):
    v=ByteInput(b)
    for n,x in {'x21':R.FIRST,'x10':counter,'w12':0x5cf4,'w8':0xef,'w3':0xffff757c,'w4':0x5321,'w5':0x198b,'w6':0x4f}.items():v.seed(n,x)
    v.run_block(R.HEAD,0x1004f6a44);v.run_block(0x1005cffd0,0x1005d0000);return v

def obligations(e):
    out=[]
    def prove(label,bad,premises=()):
        solver=z3.Solver();solver.set(timeout=30000);solver.add(*premises);assert solver.check()==z3.sat
        solver.add(z3.simplify(bad));assert solver.check()==z3.unsat,label
        out.append({'label':label,'query':solver.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    b=z3.BitVec('table_input8',8);v=ByteInput(b)
    for n,x in {'x11':R.J+0x23,'w22':37,'w23':74,'w27':0xa537,'w24':0x36,'w25':9}.items():v.seed(n,x)
    v.run_block(0x10058c40c,0x10058c454);bound=256*(10+z3.URem(z3.ZeroExt(24,b),7))+9
    prove('all_u8_original_bound_is_256_times_10_plus_remainder7_plus9',v.read('w13')!=bound)
    n=z3.BitVec('table_counter32',32);byte=z3.BitVec('table_stored8',8);v=Scalar()
    for name,value in {'x21':R.FIRST,'x30':z3.ZeroExt(32,n&255),'w10':n,'w27':0xa537,'w28':0xffffb7bd,'w7':0xffffa30d,'w13':z3.ZeroExt(24,byte)}.items():v.seed(name,value)
    v.run_block(0x10058c3fc,0x10058c40c)
    prove('all_u32_original_counter_increment_and_current_byte_store',z3.Or(v.read('w10')!=n+1,v.stores[-1]['address']!=R.FIRST+z3.ZeroExt(32,n&255),v.stores[-1]['value']!=byte))
    v=root_control(b);index=v.read('w12')
    prove('all_u8_original_root_dispatch_uses_bit1',index!=z3.If((b&2)==0,z3.BitVecVal(0x9708,32),z3.BitVecVal(0x9704,32)))
    for label,start,end,name,condition in [('low','0x100866d98','0x100866de0','w16',(b&2)==0),('high','0x100779dac','0x100779dd4','w14',(b&2)!=0)]:
        v=root_control(b);v.run_block(int(start,16),int(end,16));value=v.read(name)
        choices=[]
        for low in ([0,1] if label=='low' else [2,3]):choices.append(z3.simplify(z3.substitute(value,(b,z3.BitVecVal(low,8)))).as_long())
        prove('all_u8_original_'+label+'_subdispatch_uses_bit0',value!=z3.If((b&1)==0,z3.BitVecVal(choices[0],32),z3.BitVecVal(choices[1],32)),[condition])
        assert all(isinstance(FIXUPS[TABLE+8*i]['target'],int) for i in choices)
    sp,ptr=z3.BitVecs('table_handoff_SP64 table_handoff_pointer64',64);v=Scalar();v.seed('sp',sp);v.seed('w27',0xa537);v.seed('x21',ptr)
    v.run_block(R.EXIT,0x1004d5d2c);r=sp+0x10cb8;low=z3.Extract(31,0,r)
    k=(((low|0x1a6e4f73)+(~low|0xe591b08c))^0x9f7b80cf)*0xc7f6dca7
    prove('all_SP_pointer_bits_original_handoff_record_fields',z3.Or(cell(v,r+16,8)!=ptr,cell(v,r+24,8)!=ptr,
          cell(v,r+4,4)!=0x5205-k+0xf6a,cell(v,r+8,4)!=0x7b7676a7-k))
    return out

PROGRAMS={0:[(0x100866d98,0x100866de0),(0x10076276c,0x1007629b8)],
          1:[(0x100866d98,0x100866de0),(0x10047c518,0x10047c694)],
          2:[(0x100779dac,0x100779dd4),(0x10080c604,0x10080c740),(0x10051979c,0x100519914)],
          3:[(0x100779dac,0x100779dd4),(0x10051979c,0x100519914)]}
PHASES={'w12':0x5cf4,'w8':0xef,'w3':0xffff757c,'w4':0x5321,'w5':0x198b,'w6':0x4f,'w7':0xffffa30d,
        'w9':8,'w28':0xffffb7bd,'w22':37,'w23':74,'w24':0x36,'w25':9,'w26':0x7b}

class Point(Scalar):
    def __init__(self,array,table,counter):
        super().__init__();self.array=array;self.table=table;self.accesses=[]
        for name,value in {**PHASES,'x21':R.FIRST,'x20':R.SECOND,'x10':counter}.items():self.seed(name,value)
    def number(self,x):
        x=z3.simplify(x);assert z3.is_bv_value(x);return x.as_long()
    def load(self,address,n):
        a=self.number(address);assert n==1
        if R.FIRST<=a<R.FIRST+256:value=self.array[a-R.FIRST]
        else:assert R.SECOND<=a<R.SECOND+256;value=self.table[a-R.SECOND]
        self.accesses.append(('read',hex(self.pc),hex(a),value));return z3.BitVecVal(value,8)
    def store(self,address,n,value,pc):
        a=self.number(address);b=self.number(resize(value,8));assert n==1 and R.FIRST<=a<R.FIRST+256
        self.array[a-R.FIRST]=b;self.accesses.append(('write',hex(pc),hex(a),b))
    def step(self,tag):
        self.run_block(R.HEAD,0x1004f6a44);self.run_block(0x1005cffd0,0x1005d0000)
        for a,b in PROGRAMS[tag]:self.run_block(a,b)
        self.run_block(0x10058c3fc,0x10058c40c)

def contracts(e):
    rows=list(R.shared_intervals(e));first=rows[0];counts=Counter();route_counts=Counter();array=bytearray([0x98]*256);table=IMAGE.read(0x100e406a0,256)
    writes=first['source_writes'];assert len(writes)==256
    for i,w in enumerate(writes):
        assert (w['pc'],w['address'],w['size_bytes'],w['after_hex'])==('0x10059d5a8',hex(R.FIRST+i),1,'98')
    rr=Prior.GS.selected(first,0x10059d518);assert len(rr)==256
    assert [(r['address'],r['bytes_hex']) for r in rr]==[(hex(R.J+0x20+i%6),'00') for i in range(256)]
    counts.update(initialized_scratch_bytes_checked=256,cyclic_context_reads_checked=256)
    iterations=[];j=0
    for row in rows[1:]:
        starts=[k for k,v in enumerate(row['source_visits']) if v['pc']==hex(R.HEAD)];assert starts and starts[0]==0
        by_event={}
        for kind in ['source_reads','source_writes']:
            for x in row[kind]:by_event.setdefault(x['source_visit_index'],[]).append((kind,x))
        for lo,hi in zip(starts,starts[1:]+[len(row['source_visits'])]):
            n=int(row['source_frames'][lo]['registers31'][10],16);assert n==j
            tag=array[n&255]&3;point=Point(array,table,n);point.step(tag);assert point.number(point.read('w10'))==n+1
            actual=[];bound_reads=[];path=[]
            for k in range(lo,hi):
                for kind,x in by_event.get(k,[]):
                    a=int(x['address'],16)
                    if R.FIRST<=a<R.SECOND+256:
                        assert x['size_bytes']==1;actual.append(('read' if kind=='source_reads' else 'write',x['pc'],x['address'],int(x['bytes_hex' if kind=='source_reads' else 'after_hex'],16)))
                    if x['pc']=='0x10058c40c':bound_reads.append(x)
            assert actual==point.accesses,(j,tag,actual,point.accesses)
            assert len(bound_reads)==1 and bound_reads[0]['address']==hex(R.J+0x23) and bound_reads[0]['bytes_hex']=='00'
            assert len([x for x in actual if x[0]=='write'])==[1,1,4,2][tag]
            route_counts[str(tag)]+=1;iterations.append({'iteration':n,'route':tag,'array_accesses':len(actual),'array_writes':len([x for x in actual if x[0]=='write'])})
            counts.update(structured_iterations_checked=1,ordered_array_events_checked=len(actual),bound_byte_reads_checked=1);j+=1
        assert bytes(array)==Prior.GS.raw(state_bytes(row),R.FIRST,256);counts['complete_array_boundary_bytes_checked']+=256
    assert j==2569 and dict(route_counts)=={'0':820,'1':528,'3':612,'2':609}
    final=state_bytes(rows[-1]);assert Prior.GS.raw(final,R.SECOND,256)==table
    for row in R.intervals(e):
        s=state_bytes(row)
        assert Prior.GS.raw(s,R.T,21).hex()=='0641233c4092b2b0a0b9ac9789294bf3578a446d91'
        assert sum(R.S+i in s for i in range(64))==53 and not any(R.U+i in s for i in range(48))
        assert not any(R.S<=int(x['address'],16)<R.U+48 for x in row['source_reads']+row['source_writes'])
        assert not any(R.J+0x68<=int(x['address'],16)<R.J+0x70 for x in row['source_writes'])
        counts['heap_and_publication_preservation_intervals_checked']+=1
    records=[]
    for c in e['handoff_classes']:
        row=R.unpack(c['interval_packed']);b=row['boundary'];s=state_bytes(row);r=int(b['registers31'][0],16)
        assert r==0x6800070db8 and b['registers31'][8]=='0x1004172f4' and b['registers31'][17]=='0xf248'
        assert Prior.GS.raw(s,r+16,8)==Prior.GS.raw(s,r+24,8)==struct.pack('<Q',R.FIRST)
        assert len(row['source_writes'])==5 and not row['source_calls']
        records.append({'representative_parent_index':c['representative_parent_index'],'record_address':hex(r),
                        'defined40_hex':Prior.GS.raw(s,r,40).hex(),'pending_target':b['registers31'][8],
                        'modifier':b['registers31'][17],'members':len(c['member_parent_indices'])})
    return {'verified_counts':dict(counts),'route_counts':dict(route_counts),'structured_iteration_records':iterations,
            'point_programs':{str(k):[[hex(a),hex(b)] for a,b in spans] for k,spans in PROGRAMS.items()},
            'final_array256_hex':bytes(array).hex(),'final_array_sha256':sha256(array).hexdigest(),
            'constant_table_sha256':sha256(table).hexdigest(),'handoff_records':records,'all_checks_pass':True}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));replay=json.loads(read(ROOT/(R.P+'_replay.json')))
    assert e['generator_sha256']==replay['generator_sha256']==sha(R.__file__) and replay['replayer_sha256']==sha(Replay.__file__)
    assert replay['checks_sha256']==sha(ROOT/(R.P+'_checks.json')) and replay['all_checks_pass']
    assert e['dependencies']==replay['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert replay['replayer_dependencies']=={n:sha(ROOT/n) for n in Replay.DEPS}
    p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));parents={x['parent_index']:R.unpack(x['derived_terminal_state_packed']) for x in p['coverage']}
    covered=coverage(e,parents);model=contracts(e);proofs=obligations(e)
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'replayer_sha256':sha(Replay.__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'replay_sha256':sha(ROOT/(R.P+'_replay.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},
            'verified_counts':e['verified_counts'],'independent_totals':replay['independent_totals'],'coverage':covered,'model':model,
            'source_proofs':proofs,'source_queries_unsat':len(proofs),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps({'coverage':e['coverage']['verified_counts'],'model':e['model']['verified_counts'],'queries':e['source_queries_unsat']}),flush=True)
