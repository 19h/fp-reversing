#!/usr/bin/env python3
"""Independent A64 replay, byte-codec oracle and optional-pointer gate audit.

O(replayed prefixes+source visits+byte effects+queries) time/space.
Source initializer lifetimes and conditional caller paths remain separate.
No native API/IPC/PAC, free or daemon-kext transaction executes.
"""
import json
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
from replay_daemon_context_transfer import evaluate
import recover_daemon_return_cache_codec as R
import audit_daemon_return_bank_origins as ParentAudit

def scalar(s):
    assert 'hex' in s
    return int.from_bytes(bytes.fromhex(s['hex']),'little')

class UpstreamReplay(ParentAudit.UpstreamReplay):
    def code(self,u,a,n,d):
        if self.seq==len(self.steps):
            f=int(self.p['frame_base'],16)
            for off,value in R.ROOTS.items():
                assert int.from_bytes(u.mem_read(f+off,8),'little')==value
                self.counts['live_cache_root_cells_checked']+=1
        return super().code(u,a,n,d)

def interface(c,p):
    t=c['trace'];s=int(c['configuration']['caller_SP'],16);rows=t['steps'];b=t['boundary']
    prefix,k=R.prefix(p['trace']);assert k==c['parent_trace_cut_index']==15485
    assert [r['pc'] for r in rows[:23]]==[r['pc'] for r in p['trace']['steps'][k:]]
    assert b['pc']=='0x10080e294' and not b['uncommitted_events'] and rows[-1]['pc']=='0x10080e290'
    assert b['reason']=="('unknown flags', '0x10080e294')"
    assert len(c['additional_cache_contract'])==2
    for m in c['additional_cache_contract']:
        off=int(m['address'],16)-s
        assert off in R.ROOTS and m['size_bytes']==8 and m['bytes_hex']==R.ROOTS[off].to_bytes(8,'little').hex()
        assert m['before']=={'terms':[{'origin':s+off+j-0x640000b520} for j in range(8)]}
    registers=dict(t['initial_registers']);ledger=[];pending=None;cache_reads=[];writes=[];calls=[];origin_copy=[]
    for row in rows:
        pc=int(row['pc'],16);events=row['events']
        if pc==0x100792b28:
            assert len(events)==1 and events[0]['address']=='0x1010c67d4' and events[0]['size_bytes']==4 and scalar(events[0]['value'])==255
        if pc==0x100792b2c:
            assert len(events)==1 and events[0]['address']=='0x1010c8268' and events[0]['size_bytes']==8
            cache_reads.append(events[0])
        if pc==0x100792b40:
            assert len(events)==1 and events[0]['size_bytes']==4
            base=scalar(cache_reads[-1]['value']);assert int(events[0]['address'],16)==base+132
            pending={'address':hex(scalar(registers['x16'])),'raw32':hex(scalar(registers['x14'])),
                     'choice32':hex(scalar(registers['x23'])),'cache_base':hex(base),'cached_word':events[0]}
        if pc==0x100792b5c:pending['encoded_window_mask64']=hex(scalar(events[0]['value']))
        if pc==0x100792b84:pending['encoded_window_base64']=hex(scalar(events[0]['value']))
        if pc in [0x100792bb0,0x100792bb8]:
            key='text0' if pc==0x100792bb0 else 'text1';assert len(events)==1 and events[0]['size_bytes']==1
            pending[key]=events[0]
        if pc==0x100792bc4:
            assert len(events)==1 and events[0]['kind']=='write' and events[0]['size_bytes']==1
            a=int(pending['address'],16);word=scalar(pending['cached_word']['value']);mask=int(pending['encoded_window_mask64'],16)^0xa7a730ec
            base=int(pending['encoded_window_base64'],16)^0x12af5504870a589f
            for key,add in [('text0',0xa96e0c87),('text1',0xa96e0c89)]:
                want=base+(((word+(a&0xffffffff)+add)&0xffffffff)&mask)
                assert int(pending[key]['address'],16)==want and scalar(pending[key]['value'])==IMAGE.read(want,1)[0]
            want=(int(pending['raw32'],16)^(-83*a)^scalar(pending['text0']['value'])^scalar(pending['text1']['value'])^int(pending['choice32'],16))&255
            assert events[0]['address']==hex(a) and scalar(events[0]['value'])==want
            pending['decoded_window_base']=hex(base);pending['decoded_window_mask']=hex(mask);pending['output']=events[0]
            ledger.append(pending);pending=None
        if row['mnemonic'] in ['bl','blraa','blr','blrab','svc']:calls.append(row['pc'])
        for e in events:
            if e['kind']=='write':writes.append({'pc':row['pc'],**e})
            if e['kind']=='write' and 'terms' in e['value']:origin_copy.append({'pc':row['pc'],**e})
        registers.update(row['registers_after'])
    assert len(ledger)==2 and pending is None and not calls
    assert [int(x['address'],16) for x in ledger]==[s+0x3a07,s+0x3a06]
    loop_reads=[{'pc':r['pc'],**e} for r in rows if r['pc']=='0x100792bd0' for e in r['events']]
    assert len(loop_reads)==2
    for generated,readback in zip(ledger,loop_reads):
        assert readback['kind']=='read' and readback['size_bytes']==1
        assert readback['address']==generated['output']['address'] and readback['value']==generated['output']['value']
        assert scalar(readback['value'])!=0
    overwrite=next(w for w in writes if w['pc']=='0x1005ecd40')
    assert overwrite['address']==hex(s+0x3a06) and overwrite['size_bytes']==2
    assert scalar(overwrite['value']) in [18,26] and scalar(overwrite['value'])==scalar(b['registers31'][8])&65535
    expected_origin={'terms':[{'origin':s+0x4a20+j-0x640000b520} for j in range(8)]}
    pointer_read=next(e for r in rows if r['pc']=='0x1005ecd4c' for e in r['events'])
    assert pointer_read['address']==hex(s+0x8ad0) and pointer_read['value']==expected_origin==b['registers31'][27]
    assert len(origin_copy)==1 and origin_copy[0]['address']==hex(s+0x6c48) and origin_copy[0]['value']==expected_origin
    return {'parent_case_index':c['parent_case_index'],'variant':c['variant'],'codec_iterations':ledger,
            'writes':writes,'unknown_copies':origin_copy,'generated_byte_loop_readbacks':loop_reads,'scratch_u16_overwrite':overwrite,
            'next_pointer_read':pointer_read,'next_gate_count_low16':scalar(b['registers31'][8])&65535,
            'next_gate_pointer':b['registers31'][27],'source_visits':len(rows),'overlapping_parent_tail_visits':23,
            'new_post_frontier_visits':len(rows)-23,'initializer_control_join_proved':False,'all_checks_pass':True}

def gate_controls():
    out=[];start=0x10080e290;end=0x10080e2a8;stack=0x6d00000000
    for count in [0,1,18,65536,0xffff0000,0xffffffff]:
        for pointer in [0,1,1<<63,(1<<64)-1]:
            u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX)
            u.mem_map(start&~4095,4096);u.mem_write(start,IMAGE.read(start,end-start));u.mem_map(stack,4096)
            for reg,value in [('SP',stack),('X8',count),('X27',pointer),('X10',0x5c1c)]:u.reg_write(getattr(ar,'UC_ARM64_REG_'+reg),value)
            u.emu_start(start,end,count=6);active=int(bool(count&65535) and pointer!=0)
            assert u.reg_read(ar.UC_ARM64_REG_X12)==active and u.reg_read(ar.UC_ARM64_REG_X10)==(0x5c1c^active^1)
            assert int.from_bytes(u.mem_read(stack+0x808,4),'little')==active
            out.append({'count32':hex(count),'pointer64':hex(pointer),'active':active,'source_visits':6,'all_checks_pass':True})
    return out

def loop_proof():
    from lskd_values_symbolic import mem
    f,p,j=z3.BitVecs('rcc_loop_SP64 rcc_loop_buffer64 rcc_loop_offset64',64)
    left,target,index,shift=z3.BitVecs('rcc_loop_left32 rcc_loop_target32 rcc_loop_index32 rcc_loop_shift32',32)
    byte=z3.BitVec('rcc_loop_byte8',8)
    class Loop(R.Parent.Algebra):
        def __init__(self):super().__init__();self.read_address=None
        def load(self,a,n):
            if self.pc==0x100792bd0:assert n==1;self.read_address=a;return byte
            return super().load(a,n)
    v=Loop();v.seed('sp',f);v.seed('x15',j);v.seed('w22',left);v.seed('w3',target);v.seed('w9',index);v.seed('w8',shift)
    mem(v,f+0x6c48,8,p);v.run_block(0x100792bc8,0x100792bf8)
    remaining=left-z3.If(byte!=0,z3.BitVecVal(1,32),z3.BitVecVal(0,32))
    bad=z3.Or(v.read_address!=p+j,v.read('w22')!=remaining,v.read('w8')!=shift+8,
              v.read('w9')!=(index^z3.If(remaining==target,z3.BitVecVal(0x7d69,32),z3.BitVecVal(0,32))))
    solver=z3.Solver();solver.set(timeout=30000);assert solver.check()==z3.sat;solver.add(z3.simplify(bad));assert solver.check()==z3.unsat
    return {'label':'all_u8_loop_readback_decrement_and_selection','query':solver.to_smt2(),'result':'unsat','premises_nonvacuous':True}

def loop_controls():
    start=0x100792bc8;end=0x100792bf8;stack=0x6d00000000;data=stack+0x9000;out=[]
    for byte in [0,1,127,128,254,255]:
        for left,target in [(0,0),(1,0),(2,0),(0,0xffffffff)]:
            u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX)
            u.mem_map(start&~4095,4096);u.mem_write(start,IMAGE.read(start,end-start));u.mem_map(stack,0x10000)
            u.mem_write(stack+0x6c48,data.to_bytes(8,'little'));u.mem_write(data+7,bytes([byte]))
            for reg,value in [('SP',stack),('X15',7),('X22',left),('X3',target),('X9',0x4321),('X8',0x123)]:u.reg_write(getattr(ar,'UC_ARM64_REG_'+reg),value)
            u.emu_start(start,end,count=12);remaining=(left-int(byte!=0))&0xffffffff
            assert u.reg_read(ar.UC_ARM64_REG_X22)==remaining and u.reg_read(ar.UC_ARM64_REG_X8)==0x12b
            assert u.reg_read(ar.UC_ARM64_REG_X9)==(0x4321^(0x7d69 if remaining==target else 0))
            out.append({'byte':byte,'left32':hex(left),'target32':hex(target),'remaining32':hex(remaining),'source_visits':12,'all_checks_pass':True})
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));parent,error,results,post,inherited=R.inputs()
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['source_regions']==R.source() and e['upstream_field_lifetimes']==R.upstream_fields(parent)
    assert e['next_gate_dispatch']==R.gate_dispatch()
    fresh=R.obligations();assert len(fresh)==len(e['source_proofs'])==6
    assert [q['label'] for q in fresh]==[q['label'] for q in e['source_proofs']]
    for q in e['source_proofs']:
        solver=z3.Solver();solver.set(timeout=30000);solver.from_string(q['query'])
        assert q['premises_nonvacuous'] and q['result']=='unsat' and solver.check()==z3.unsat
    pins,old,ingress,preparations,processing=inherited;replays=[];joins=[];totals=Counter();prefixes=Counter()
    for c,p in zip(e['cases'],parent['cases']):
        assert c['configuration']==p['configuration'] and c['variant']==p['variant'] and c['parent_case_index']==p['parent_case_index']
        cfg=c['configuration'];ix=c['parent_case_index'];variant=c['variant'];joins.append(interface(c,p))
        er=next(x for x in error['cases'] if x['parent_case_index']==ix and x['variant']==variant)
        result=next(x for x in results['cases'] if x['parent_case_index']==ix and x['variant']==variant)
        o=next(x for x in ingress['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['parent_variant'])
        prep=next(x for x in preparations['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['preparation_variant'])
        proc=next(x for x in processing['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['name'])
        prefix,k=R.prefix(p['trace'])
        for pattern in [0,3]:
            check=ParentAudit.A.Check(pins['daemon_callback_revisit_snapshot.json'],old,o,prep,proc,post['cases'][ix],pattern)
            prefixes.update(check.run()['verified_counts'])
            for j,t in enumerate(result['intervals']):
                check.model(result['free_return_premise'] if j else result['API_return_premise']);prefixes.update(check.interval(t)['verified_counts'])
            prefixes.update(check.interval(er['trace'])['verified_counts'])
            for model in p['additional_bank_contract']:
                a=int(model['address'],16);assert bytes(check.u.mem_read(a,8))==evaluate(model['before'],check.backing)
                check.u.mem_write(a,bytes.fromhex(model['bytes_hex']))
            prefixes.update(check.interval(prefix)['verified_counts'])
            for model in c['additional_cache_contract']:
                a=int(model['address'],16);assert bytes(check.u.mem_read(a,8))==evaluate(model['before'],check.backing)
                check.u.mem_write(a,bytes.fromhex(model['bytes_hex']))
            run=check.interval(c['trace']);totals.update(run['verified_counts'])
            replays.append({'parent_case_index':ix,'variant':variant,**run})
        print(json.dumps({'parent':ix,'variant':variant,'patterns_checked':2}),flush=True)
    upstream=[];upstream_totals=Counter()
    for c in parent['upstream_cases']:
        for pattern in [0,3]:
            run=UpstreamReplay(c,pattern).run();upstream_totals.update(run['verified_counts']);upstream.append({'variant':c['variant'],**run})
    gates=gate_controls();loop=loop_proof();loop_cases=loop_controls()
    return {'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'dependencies':e['dependencies'],
            'verified_counts':e['verified_counts'],'source_queries_unsat':6,'interface_joins':joins,
            'independent_replays':replays,'independent_totals':dict(totals),'separately_replayed_prefix_totals':dict(prefixes),
            'upstream_replays':upstream,'upstream_independent_totals':dict(upstream_totals),'gate_controls':gates,
            'additional_loop_source_proof':loop,'loop_controls':loop_cases,
            'initializer_to_caller_control_join_established':False,'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'full_goal_complete':False,'all_checks_pass':True}

if __name__=='__main__':
    a=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
    print(json.dumps({k:a[k] for k in ['verified_counts','independent_totals','separately_replayed_prefix_totals','upstream_independent_totals','all_checks_pass']}),flush=True)
