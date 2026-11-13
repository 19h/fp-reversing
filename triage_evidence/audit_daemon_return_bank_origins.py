#!/usr/bin/env python3
"""Independent initializer replay and conditional post-error bank/counter audit.

O(patterns*cases*(restored bytes+source visits+events)+text words) time/space.
Earlier caller journals restored; selected post-block/error prefixes replayed.
Native API/IPC/PAC and the missing initializer-to-caller control join do not run.
"""
import json
from collections import Counter,defaultdict
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,POOL
from verify_daemon_reader_record_payloads_publication import read,sha
from replay_daemon_context_transfer import evaluate
from replay_daemon_callback_revisit import Replay
import replay_daemon_descriptor_producers as Frozen
import recover_daemon_return_bank_origins as R
import audit_daemon_iokit_result as A

class UpstreamReplay(Frozen.Replay):
    # Archive-transparent initialization; inherited hooks execute original A64.
    def __init__(self,prefix,pattern):
        self.p=prefix; self.t=None; self.pattern=pattern; self.F=0
        self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM); self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX)
        self.pages=set(); self.seq=0; self.counts=Counter(); self.pending=[]; self.current=None; self.rc=self.wc=0
        self.helper=json.loads(read(ROOT/'daemon_descriptor_producers_source.json'))['stack_probe_original_function']
        self.reads=defaultdict(list); self.writes=defaultdict(list); self.events={}; self.evalcache={}; self.fixed=[]
        self.ram=bytes([prefix['configuration']['pattern']&255])*Frozen.SIZE if pattern==0 else bytes((j*73+19)&255 for j in range(Frozen.SIZE))
        self.u.mem_map(Frozen.P,Frozen.SIZE); self.u.mem_write(Frozen.P,self.ram)
        for row in prefix['initial_private_fixtures']+prefix['initial_image_fixtures']:
            a=int(row['address'],16); raw=bytes.fromhex(row['bytes_hex']); self.ensure(a,len(raw)); self.u.mem_write(a,raw)
        self.seed(prefix['entry_registers31']); self.u.reg_write(ar.UC_ARM64_REG_SP,int(prefix['entry_SP'],16))
        self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(prefix['entry_NZCV'],16)); self.u.reg_write(ar.UC_ARM64_REG_TPIDRRO_EL0,int(prefix['entry_TPIDRRO_EL0'],16))
        for j,x in enumerate(prefix['entry_Q_registers32']): self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))
        for key,out in [('source_reads',self.reads),('source_writes',self.writes)]:
            for e in prefix[key]: out[e['source_visit_index']].append(e)
        self.steps=prefix['source_visits'].copy(); self.edges={e['source_visit_index']:e for e in prefix['logical_edges']}; self.boundary=prefix['boundary']
        self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.missing); self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read)
        self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write); self.u.hook_add(uc.UC_HOOK_CODE,self.code)
    def code(self,u,a,n,d):
        if a==0x10061a310:
            regs,sp=self.helper_entry; assert self.reg('sp')==sp
            assert all(self.reg('x'+str(j))==x for j,x in enumerate(regs) if j!=9)
            self.counts['helper_preservation_checks']+=1
        if self.seq==len(self.steps):
            f=int(self.p['frame_base'],16)
            for off,expected in R.ROOTS.items():
                assert int.from_bytes(u.mem_read(f+off,8),'little')==expected
                self.counts['live_bank_cells_checked']+=1
            if self.p['variant']=='unsupported_operation':
                assert self.reg('sp')==int(self.p['entry_SP'],16)
                assert all(self.reg('x'+str(j))==int(self.p['entry_registers31'][j],16) for j in range(19,30))
                assert int.from_bytes(u.mem_read(int(self.p['record_address'],16)+0x18,4),'little')==0x74c29dee
                self.counts['restored_outer_frames_checked']+=1
        return super().code(u,a,n,d)

def caller_join(case):
    s=int(case['configuration']['caller_SP'],16); rows=case['trace']['steps']; ev=[{'pc':r['pc'],**e} for r in rows for e in r['events']]
    def one(pc,kind):
        x=[e for e in ev if e['pc']==hex(pc) and e['kind']==kind]; assert len(x)==1; return x[0]
    left=one(0x1004f6508,'read'); right=one(0x1004f6518,'read')
    for e,off in [(left,0x600),(right,0x5f8)]:
        assert e['address']==hex(s+off) and e['size_bytes']==8 and A.A.scalar(e['value'])==R.ROOTS[off]
    pub=one(0x1004f653c,'write'); counter=one(0x1004f6540,'read'); local=one(0x1004f6564,'read')
    assert pub['address']==hex(s+0x920) and pub['size_bytes']==8 and A.A.scalar(pub['value'])==R.COUNTER
    assert counter['address']==hex(R.COUNTER) and counter['size_bytes']==4
    assert local['address']==hex(s+0x8d0) and local['size_bytes']==8 and 'hex' in local['value']
    b=case['trace']['boundary']; assert b['pc']==hex(R.STOP) and b['SP']==hex(s) and not b['uncommitted_events']
    missing=one(0x100792b24,'read'); assert rows[-1]['pc']=='0x100792b24'
    assert missing['address']==hex(s+0x878) and missing['size_bytes']==8
    assert missing['value']=={'terms':[{'origin':s+0x878+j-0x640000b520} for j in range(8)]}
    assert not any(r['mnemonic'] in ['bl','blr','blrab','svc'] for r in rows)
    assert len(case['additional_bank_contract'])==2
    for model in case['additional_bank_contract']:
        off=int(model['address'],16)-s; assert off in R.ROOTS and model['size_bytes']==8
        assert model['bytes_hex']==R.ROOTS[off].to_bytes(8,'little').hex()
        assert model['before']=={'terms':[{'origin':s+off+j-0x640000b520} for j in range(8)]}
    # Recover initial state from first reads, with per-byte temporal consistency.
    statebase=0x1010c784c; end=statebase+624*4; initial={}; current={}; statewrites=[]; ram={}; regs=dict(case['trace']['initial_registers']); helper=None; less=None
    for row in rows:
        if row['pc']=='0x1004f6610':
            record=A.A.scalar(regs['x0']); assert record==s+0x10cb8
            def get(off,n): return int.from_bytes(bytes(ram[record+off+j] for j in range(n)),'little')
            key=((record^0x4de3a292f9d49974)*0xda51a827)&((1<<64)-1); low=key&0xffffffff
            helper={'record':hex(record),'mode32':(get(0,4)-low)&0xffffffff,'A64':hex((get(8,8)-key)&((1<<64)-1)),
                    'B64':hex(get(0x20,8)^key),'mask32':hex((get(0x14,4)-low)&0xffffffff),
                    'false32':hex((get(0x28,4)+low)&0xffffffff),'true32':hex(get(0x2c,4)^low)}
        if row['pc']=='0x10078703c':
            record=A.A.scalar(regs['x0']); assert record==s+0x10cb8
            def get(off,n): return int.from_bytes(bytes(ram[record+off+j] for j in range(n)),'little')
            key=(((((record<<1)|0x5a2dd95b7f1fcb68)-record+0xd2e9135240701a4c)^0x2c6f16a258bd37d6)*0xba209ef7)&((1<<64)-1); low=key&0xffffffff
            less={'record':hex(record),'mode32':get(8,4)^low,'A64':hex((get(0,8)+key)&((1<<64)-1)),
                  'B64':hex(get(0x18,8)^key),'mask32':hex(get(0x20,4)^low),
                  'false32':hex((get(0x14,4)+low)&0xffffffff),'true32':hex(get(0x10,4)^low)}
        for e in row['events']:
            at=int(e['address'],16)
            if 'hex' in e['value']:
                raw=bytes.fromhex(e['value']['hex'])
                for j,bv in enumerate(raw):
                    a=at+j
                    if statebase<=a<end:
                        if e['kind']=='read':
                            if a in current: assert current[a]==bv
                            else: initial[a]=bv
                        current[a]=bv
                    ram[a]=bv
            if e['kind']=='write' and statebase<=at<end:
                assert e['size_bytes']==4 and at%4==0; statewrites.append({'pc':row['pc'],**e})
        regs.update(row['registers_after'])
    assert set(initial)==set(range(statebase,end)) and len(statewrites)==624
    words=[int.from_bytes(bytes(initial[statebase+4*j+k] for k in range(4)),'little') for j in range(624)]
    for j,w in enumerate(statewrites):
        assert int(w['address'],16)==statebase+4*j
        following=words[(j+1)%624]; y=(words[j]&0x80000000)|(following&0x7fffffff)
        want=words[(j+397)%624]^(y>>1)^(0x9908b0df if following&1 else 0)
        assert A.A.scalar(w['value'])==want,(j,w['pc']); words[j]=want
    before=A.A.scalar(counter['value']); after=one(0x1004dc344,'write')
    assert after['address']==hex(R.COUNTER) and after['size_bytes']==4 and A.A.scalar(after['value'])==(before+1)&0xffffffff
    assert helper and helper['mode32']==0 and int(helper['A64'],16)==before and helper['B64']=='0x0'
    assert less and less['mode32']==0 and less['A64']=='0x13ff' and int(less['B64'],16)==before
    first_result=[e for e in ev if e['kind']=='write' and int(e['address'],16)==s+0x10cb8+0x10 and 0x10041a5e0<=int(e['pc'],16)<0x10041a670]
    assert len(first_result)==1 and A.A.scalar(first_result[0]['value'])==int(helper['mask32'],16)^int(helper['false32'],16)
    less_result=one(0x1004275ac,'write')
    assert less_result['address']==hex(s+0x10cb8+12) and A.A.scalar(less_result['value'])==int(less['mask32'],16)^int(less['false32'],16)
    root_reuse=[e for e in ev if e['kind']=='write' and int(e['address'],16)<s+0x10cc4 and s+0x10cc0<int(e['address'],16)+e['size_bytes']]
    assert root_reuse[0]['pc']=='0x1004f658c' and root_reuse[0]['size_bytes']==8
    calls=[{'pc':r['pc'],'target':r['target'],'modifier16':r['modifier16']} for r in rows if r['mnemonic']=='blraa']
    assert calls==[{'pc':'0x1004f6610','target':'0x10041a5e0','modifier16':'0xec9d'},
                   {'pc':'0x10078703c','target':'0x100427514','modifier16':'0x46a2'}]
    return {'parent_case_index':case['parent_case_index'],'variant':case['variant'],
            'counter_pointer_publication':pub,'counter_read':counter,'counter_increment':after,'comparison_helper':helper,'less_than_helper':less,
            'first_comparison_result':first_result[0],'less_than_result':less_result,'root_result_first_reuse':root_reuse[0],
            'state_words_updated':624,'in_place_MT19937_recurrence_checked':True,'internal_calls':calls,
            'next_unknown':missing,'additional_bank_premises':2,'initializer_control_join_proved':False,'all_checks_pass':True}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['source_regions']==R.source() and e['decoder']==R.decoder() and e['literal_store_census']==R.census()
    assert e['source_fixups']==R.Parent.Parent.Core.verify_fixups({int(a,16) for c in e['cases'] for a in c['trace']['used_fixups']})
    fresh=R.obligations(); assert len(fresh)==len(e['source_proofs'])==9
    assert [{k:v for k,v in q.items() if k!='query'} for q in fresh]==[{k:v for k,v in q.items() if k!='query'} for q in e['source_proofs']]
    for q in e['source_proofs']:
        solver=z3.Solver(); solver.set(timeout=30000); solver.from_string(q['query'])
        assert q['premises_nonvacuous'] and q['result']=='unsat' and solver.check()==z3.unsat
    upstream_runs=[]; upstream_totals=Counter()
    for c in e['upstream_cases']:
        for pattern in [0,3]:
            r=UpstreamReplay(c,pattern).run(); upstream_totals.update(r['verified_counts'])
            upstream_runs.append({'variant':c['variant'],**r})
    pins,old,ingress,preparations,processing=R.Parent.Parent.Parent.inputs()
    parent=json.loads(read(ROOT/'daemon_iokit_error_return_checks.json'))
    results=json.loads(read(ROOT/'daemon_iokit_result_checks.json')); post=json.loads(read(ROOT/'daemon_postblock_dispatch_checks.json'))
    runs=[]; joins=[]; totals=Counter(); prefixes=Counter(); counts=Counter()
    for c in e['cases']:
        cfg=c['configuration']; er=next(x for x in parent['cases'] if x['parent_case_index']==c['parent_case_index'] and x['variant']==c['variant'])
        result=next(x for x in results['cases'] if x['parent_case_index']==c['parent_case_index'] and x['variant']==c['variant'])
        po=post['cases'][c['parent_case_index']]; assert cfg==er['configuration']==result['configuration']==po['configuration']
        original=next(x for x in ingress['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['parent_variant'])
        prep=next(x for x in preparations['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['preparation_variant'])
        proc=next(x for x in processing['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['name'])
        joins.append(caller_join(c)); counts.update(c['counts'])
        for pattern in [0,3]:
            checker=A.Check(pins['daemon_callback_revisit_snapshot.json'],old,original,prep,proc,po,pattern)
            prefixes.update(checker.run()['verified_counts'])
            for j,trace in enumerate(result['intervals']):
                checker.model(result['free_return_premise'] if j else result['API_return_premise'])
                prefixes.update(checker.interval(trace)['verified_counts'])
            prefixes.update(checker.interval(er['trace'])['verified_counts'])
            for model in c['additional_bank_contract']:
                at=int(model['address'],16); assert bytes(checker.u.mem_read(at,8))==evaluate(model['before'],checker.backing)
                checker.u.mem_write(at,bytes.fromhex(model['bytes_hex']))
            r=checker.interval(c['trace']); totals.update(r['verified_counts'])
            runs.append({'parent_case_index':c['parent_case_index'],'variant':c['variant'],'pattern':pattern,**r})
        print(json.dumps({'parent':c['parent_case_index'],'variant':c['variant'],'independent_patterns':2}),flush=True)
    assert e['verified_counts']=={'conditional_caller_cases':len(e['cases']),**counts,
                                 'upstream_cases':len(e['upstream_cases']),'upstream_source_visits':sum(len(c['source_visits']) for c in e['upstream_cases'])}
    return {'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'dependencies':e['dependencies'],
            'verified_counts':e['verified_counts'],'source_queries_unsat':9,'interface_joins':joins,
            'upstream_replays':upstream_runs,'upstream_independent_totals':dict(upstream_totals),
            'conditional_caller_replays':runs,'conditional_caller_independent_totals':dict(totals),
            'separately_replayed_prefix_totals':dict(prefixes),'all_checks_pass':True,
            'initializer_to_caller_control_join_established':False,'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

if __name__=='__main__':
    a=build(); (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
    print(json.dumps({k:a[k] for k in ['verified_counts','upstream_independent_totals','conditional_caller_independent_totals','all_checks_pass']}),flush=True)
