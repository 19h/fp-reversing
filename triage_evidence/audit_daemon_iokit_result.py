#!/usr/bin/env python3
"""Independent A64 effects and channel/lifetime audit of IOKit result paths.

O(patterns*cases*(restored bytes+source visits+events)) time/space. API outputs
and ordinary returns are explicit model inputs. No native API/IPC/PAC runs.
"""
import json
from pathlib import Path
from collections import Counter
import z3
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,FIXUPS,TABLE
from replay_daemon_context_transfer import evaluate
from replay_daemon_callback_revisit import Replay
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_daemon_postblock_dispatch as A
import recover_daemon_iokit_result as R

class Check(A.Check):
    def __init__(self,*args):
        self.newmode=False; self.logical_retired=[]; super().__init__(*args)

    def code(self,u,a,n,d):
        return Replay.code(self,u,a,n,d) if self.newmode else super().code(u,a,n,d)

    def live_new(self,a,n):
        assert not any(a<z and a+n>b for b,z in self.logical_retired), 'source access after logical retirement'

    def read(self,u,access,a,n,value,d):
        if not self.newmode: return super().read(u,access,a,n,value,d)
        self.live_new(a,n); return Replay.read(self,u,access,a,n,value,d)

    def write(self,u,access,a,n,value,d):
        if not self.newmode: return super().write(u,access,a,n,value,d)
        self.live_new(a,n); return Replay.write(self,u,access,a,n,value,d)

    def model(self,m):
        for s in m['register_effects'].values():
            for term in s.get('terms',[]):
                if isinstance(term,dict): self.backing.setdefault(term['origin'],self.unknown_byte(term['origin']))
        for n,s in m['preserved'].items():
            assert self.register(n)==int.from_bytes(evaluate(s,self.backing),'little')
        for n,s in m['preserved_D8_D15'].items():
            assert self.register('q'+n)&((1<<64)-1)==int.from_bytes(evaluate(s,self.backing),'little')
        for n,s in m['register_effects'].items():
            self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+n.upper()),int.from_bytes(evaluate(s,self.backing),'little'))
        self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000 if self.pattern==3 else 0)
        for w in m.get('declared_output_writes',[]): self.u.mem_write(int(w['address'],16),bytes.fromhex(w['bytes_hex']))

    def interval(self,row):
        self.newmode=True; self.trace=row; self.index=0; self.previous=None; self.complete=False; self.counts=Counter()
        self.logical_retired=[(int(s['start'],16),int(s['end'],16)) for s in row['logical_retired_spans']]
        for n,s in row['initial_registers'].items():
            assert self.register(n)==int.from_bytes(evaluate(s,self.backing),'little'),('new initial register',n)
        self.snap={'boundary':{'pc':row['start']}}
        return Replay.run(self)

def interface(case,post):
    rows=[s for t in case['intervals'] for s in t['steps']]; f=int(post['trace']['boundary']['SP'],16)
    b=int(post['api_view']['address'],16); assert b==f+0x6a8
    variant=case['variant']; reads=[{'pc':s['pc'],**e} for s in rows for e in s['events'] if e['kind']=='read' and b<=int(e['address'],16)<b+552]
    writes=[{'pc':s['pc'],**e} for s in rows for e in s['events'] if e['kind']=='write']
    branches=[{'pc':s['pc'],'target':s['target'],'modifier16':s['modifier16']} for s in rows if s['mnemonic']=='braa']
    assert not any(e['kind']=='read' and int(e['address'],16)<f+0x3f8 and int(e['address'],16)+e['size_bytes']>f+0x3f0 for s in rows for e in s['events'])
    first=branches[0]; zero=variant!='API_error'
    assert first=={'pc':'0x100478a54','target':'0x10061ada0' if zero else '0x10062c4bc','modifier16':'0x404c'}
    api=case['API_return_premise']['status32']; expected_result=None; count=None; extended=None
    if variant=='API_error': assert not reads; expected_result=api^0x8b3dc651
    elif variant=='unspecified_protocol_status':
        assert len(reads)==1 and reads[0]['pc']=='0x10061adc4' and reads[0]['address']==hex(b+0x224) and reads[0]['size_bytes']==4
        assert 'terms' in reads[0]['value'] and len(reads[0]['value']['terms'])==4 and all(isinstance(x,dict) for x in reads[0]['value']['terms'])
    elif variant=='provider_error_word':
        assert len(reads)==1 and reads[0]['pc']=='0x10061adc4' and reads[0]['address']==hex(b+0x224) and reads[0]['value']=={'hex':'5e5affff'}
        assert branches[1]=={'pc':'0x10061adf8','target':'0x10062c4bc','modifier16':'0x1a02'}
        expected_result=0xffff5a5e^0x8b3dc651
    else:
        count=16 if variant=='both_zero_count16' else 512
        fields_read=[r for r in reads if int(r['address'],16) in [b+0x224,b+0x220]]
        assert [(r['pc'],r['address'],r['value']) for r in fields_read]==[('0x10061adc4',hex(b+0x224),{'hex':'00000000'}),('0x10061bed8',hex(b+0x220),{'hex':count.to_bytes(4,'little').hex()})]
        extra=[r for r in reads if r not in fields_read]
        if case['configuration']['parent_variant']=='extended':
            assert len(extra)==16 and [int(r['address'],16) for r in extra]==list(range(b+27,b+11,-1)) and all(r['size_bytes']==1 for r in extra)
            copied=[w for w in writes if 0x10047455c<=int(w['pc'],16)<0x1004746f0]
            assert len(copied)==16 and [int(w['address'],16) for w in copied]==list(range(f+0x62f,f+0x61f,-1))
            assert all(bytes.fromhex(r['value']['hex'])[0]^0x98==bytes.fromhex(w['value']['hex'])[0] for r,w in zip(extra,copied))
            extended={'source':hex(b+12),'destination':hex(f+0x620),'size_bytes':16,'XOR8':'0x98','descending_offsets':True}
        else: assert not extra
        assert branches[1]=={'pc':'0x10061adf8','target':'0x1003ec8e8','modifier16':'0x1a02'}
        fields={w['pc']:w for w in writes}
        for pc,off,value in [('0x10061bedc',0x588,count),('0x10061bf04',0x58c,count^0x8b3dc651)]:
            assert fields[pc]['address']==hex(f+off) and fields[pc]['value']=={'hex':value.to_bytes(4,'little').hex()}
        assert fields['0x10061bf10']['value']==fields['0x10061bf14']['value']=={'hex':(f+0x6c8).to_bytes(8,'little').hex()}
    retirement=None
    if expected_result is not None:
        a=int(case['configuration']['allocation'],16)
        overwritten=[w for w in writes if a<=int(w['address'],16)<a+32]
        assert len(overwritten)==32 and [int(w['address'],16) for w in overwritten]==list(range(a+31,a-1,-1)) and all(w['size_bytes']==1 for w in overwritten)
        free=case['intervals'][0]['boundary']; assert free['pc']=='0x1002dc500' and free['modifier16']=='0x46a2' and A.scalar(free['registers31'][0])==a
        assert FIXUPS[0x10109ff30]['target']=='libSystem/_free'
        publications=[w for w in writes if w['pc']=='0x100309cd8']; assert len(publications)==1
        out=publications[0]; assert out['size_bytes']==4 and out['value']=={'hex':expected_result.to_bytes(4,'little').hex()}
        assert int(out['address'],16)==A.scalar(case['intervals'][-1]['boundary']['registers31'][0])+8
        assert int(out['address'],16)==int(case['configuration']['caller_SP'],16)+0x10cb8+8
        assert A.scalar(case['intervals'][-1]['boundary']['registers31'][28])==expected_result
        assert case['intervals'][-1]['boundary']['pc']==hex(R.STOP) and case['free_return_premise']['model_memory_effects']==0
        retirement={'allocation':hex(a),'overwritten_bytes':32,'root_result_address':out['address'],'root_result32':hex(expected_result)}
    assert not any(w for w in writes if b<=int(w['address'],16)<b+552), 'source writes into API buffer after return'
    return {'parent_case_index':case['parent_case_index'],'variant':variant,'API_status32':api,
            'protocol_field_read':bool(reads),'count_read':count,'retirement':retirement,'extended_copyback':extended,
            'first_two_branch_edges':branches[:2],'native_pairing_established':False,'all_checks_pass':True}

def build():
    pins,old,ingress,preparations,previous=R.Parent.inputs()
    e=json.loads(read(ROOT/(R.P+'_checks.json'))); post=json.loads(read(ROOT/'daemon_postblock_dispatch_checks.json'))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['source_regions']==R.source() and e['source_fixups']==R.Core.verify_fixups({int(a,16) for c in e['cases'] for t in c['intervals'] for a in t['used_fixups']})
    fresh=R.obligations(); assert len(fresh)==len(e['source_proofs'])==8
    for q in e['source_proofs']:
        s=z3.Solver(); s.set(timeout=30000); s.from_string(q['query']); assert q['result']=='unsat' and s.check()==z3.unsat
    replays=[]; joins=[]; totals=Counter(); parent_totals=Counter()
    for case in e['cases']:
        p=post['cases'][case['parent_case_index']]; c=p['configuration']
        original=next(x for x in ingress['cases'] if x['configuration']['epoch']==c['epoch'] and x['configuration']['name']==c['parent_variant'])
        prep=next(x for x in preparations['cases'] if x['configuration']['epoch']==c['epoch'] and x['configuration']['name']==c['preparation_variant'])
        processing=next(x for x in previous['cases'] if x['configuration']['epoch']==c['epoch'] and x['configuration']['name']==c['name'])
        joins.append(interface(case,p))
        for pattern in [0,3]:
            checker=Check(pins['daemon_callback_revisit_snapshot.json'],old,original,prep,processing,p,pattern)
            prefix=checker.run(); parent_totals.update(prefix['verified_counts'])
            checker.model(case['API_return_premise']); intervals=[]
            for j,row in enumerate(case['intervals']):
                if j: checker.model(case['free_return_premise'])
                r=checker.interval(row); intervals.append(r); totals.update(r['verified_counts'])
            replays.append({'parent_case_index':case['parent_case_index'],'variant':case['variant'],'pattern':pattern,'intervals':intervals,'all_checks_pass':True})
        print(json.dumps({'parent':case['parent_case_index'],'variant':case['variant'],'independent_patterns':2}),flush=True)
    return {'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
            'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_queries_unsat':len(fresh),
            'interface_joins':joins,'independent_replays':replays,'independent_totals':dict(totals),
            'reproduced_parent_totals':dict(parent_totals),'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'all_checks_pass':True,'full_goal_complete':False}

if __name__=='__main__':
    result=build(); (ROOT/(R.P+'_audit.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'verified_counts':result['verified_counts'],'independent_totals':result['independent_totals'],'all_checks_pass':True}),flush=True)
