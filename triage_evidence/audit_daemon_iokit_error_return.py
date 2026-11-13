#!/usr/bin/env python3
"""Independent original A64 replay and temporal error-return interface audit.

O(patterns*cases*(restored bytes+source visits+events)) time/space, 30 s/query.
Predecessor journals are restored, the post-block/result prefixes replayed.
No native API, Mach transport, free, or pointer authentication executes.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE,TABLE,qword
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_iokit_error_return as R
import audit_daemon_iokit_result as A

def scalar(s): return A.A.scalar(s)

def interface(case,parent,original,prep,processing,post):
    c=case['configuration']; s=int(c['caller_SP'],16); f=s-0x9d0; temp=s-0x50; q=s+0xba18; record=s+0x10cb8
    rows=case['trace']['steps']; regs=dict(case['trace']['initial_registers']); points={}; events=[]
    for j,row in enumerate(rows):
        points[row['pc']]={'visit':j,'registers':regs.copy()}
        events.extend({'visit':j,'pc':row['pc'],**e} for e in row['events']); regs.update(row['registers_after'])
    def event(pc,kind):
        ee=[e for e in events if e['pc']==hex(pc) and e['kind']==kind]; assert len(ee)==1,(hex(pc),len(ee)); return ee[0]
    def value(pc,kind,address,n,expected):
        e=event(pc,kind); assert e['address']==hex(address) and e['size_bytes']==n and scalar(e['value'])==expected; return e
    stages=[('ingress',original['trace']['steps'][:c['parent_entry_source_visits']]),
            ('preparation',prep['trace']['steps']),('processing',processing['trace']['steps']),
            ('postblock',post['trace']['steps'])]+[('result_'+str(j),t['steps']) for j,t in enumerate(parent['intervals'])]+[('return',rows)]
    temp_writers=[]; bank_writers=[]
    for stage,seq in stages:
        for j,row in enumerate(seq):
            assert IMAGE.read(int(row['pc'],16),4).hex()==row['bytes_hex']
            for e in row['events']:
                if e['kind']!='write': continue
                a=int(e['address'],16); z=a+e['size_bytes']
                w={'stage':stage,'visit':j,'pc':row['pc'],**e}
                if a<temp+8 and temp<z: temp_writers.append(w)
                if a<s+0x608 and s+0x600<z: bank_writers.append(w)
    assert [w['pc'] for w in temp_writers]==['0x1004ac9a4','0x10049f4a8'] and not bank_writers
    first,last=temp_writers; seed=scalar(last['value'])
    assert seed==0xc48d2124b50100b9 and scalar(first['value'])==(seed-0xb0)&((1<<64)-1)
    assert first['address']==last['address']==hex(temp) and first['size_bytes']==last['size_bytes']==8
    value(0x1004aca5c,'read',temp,4,seed&0xffffffff); value(0x1004aca68,'write',q,8,0)
    assert scalar(points['0x1004aca5c']['registers']['x21'])&0xffffffff==seed&0xffffffff
    # Compare complete original entry and actual return register states.
    oldregs=dict(original['trace']['initial_registers']); entry={}; models={m['after_source_visits']:m for m in original['API_models']}
    for j,row in enumerate(stages[0][1]):
        if j in models: oldregs.update(models[j]['register_effects'])
        if row['pc'] in ['0x1004ac814','0x10049f358']: entry[row['pc']]=oldregs.copy()
        oldregs.update(row['registers_after'])
    for ep,ret,sp in [('0x10049f358','0x1004aca5c',temp),('0x1004ac814','0x10084cb08',s)]:
        actual=points[ret]['registers']; assert scalar(actual['sp'])==sp
        assert all(actual['x'+str(j)]==entry[ep]['x'+str(j)] for j in range(19,30)),(ep,'callee saved')
    returns=[{'pc':r['pc'],'target':r['target'],'SP_after':r['registers_after'].get('sp')} for r in rows if r['mnemonic']=='retab']
    assert [(r['pc'],r['target']) for r in returns]==[('0x100309d10','0x1004aca5c'),('0x1004aca7c','0x10084cb08')]
    # Source guard equality is private-state evidence, not native PAC execution.
    guard=event(0x100309cdc,'read'); current=event(0x100309ce8,'read'); assert guard['value']==current['value']
    assert rows[points['0x100309cf0']['visit']+1]['pc']=='0x100309cf4'
    expected=0x8b3dc654 if case['variant']=='API_error' else 0x74c29c0f
    value(0x10084cb18,'read',record+8,4,expected)
    assert scalar(points['0x10084cb18']['registers']['sp'])==s
    branches=[{'pc':r['pc'],'target':r['target'],'modifier16':r['modifier16']} for r in rows if r['mnemonic']=='braa']
    expected_edges=[(0x10084cb28,0x1008c1710,0x982),(0x1008c1764,0x1008c26d4,0xa9e),
                    (0x1008c26fc,0x10085ead4,0xa9e),(0x10085eb14,0x10081a7c4,0xadc3),
                    (0x10081acc0,0x10080e250,0xe01c),(0x10080e2bc,0x1007b3210,0x92c2),
                    (0x1007b32a8,0x1008053fc,0xd3b8),(0x100805424,0x1004f6458,0x9225)]
    assert branches==[{'pc':hex(a),'target':hex(b),'modifier16':hex(m)} for a,b,m in expected_edges]
    assert qword(TABLE+0x5d32*8)==0x1008c26d4 and qword(TABLE+0x5d45*8)==0x10085ead4
    value(0x1008c1730,'write',s+0x16d0,8,(-0x480)&((1<<64)-1))
    value(0x1008c26e8,'write',s+0x5c48,8,0xe87f552eb3388cb6)
    copied=event(0x10085ead8,'read'); out=event(0x10085eae0,'write')
    assert copied['address']==hex(s+0x4a20) and out['address']==hex(s+0x8ad0) and copied['size_bytes']==out['size_bytes']==8
    assert copied['value']==out['value']=={'terms':[{'origin':s+0x4a20+j-0x640000b520} for j in range(8)]}
    value(0x10085eae8,'write',s+0x3a06,2,0)
    value(0x10080e26c,'write',s+0x16d0,8,(-0x440)&((1<<64)-1))
    value(0x10080e280,'write',s+0x8e8,8,s+0xbbf0)
    value(0x10080e28c,'write',s+0x6c48,8,s+0x3a06)
    value(0x1004f6468,'write',s+0x4060,8,32)
    state_word=0x83+c['epoch']+(4 if c['parent_variant']=='extended' else 0)
    value(0x1004f64dc,'read',0x1010c67dc,4,state_word)
    value(0x1004f64e4,'write',s+0x4c94,4,state_word)
    bank=event(0x1004f6508,'read'); assert rows[-1]['pc']=='0x1004f6508'
    assert bank['address']==hex(s+0x600) and bank['size_bytes']==8 and bank['value']=={'terms':[{'origin':s+0x600+j-0x640000b520} for j in range(8)]}
    b=case['trace']['boundary']; assert b['pc']=='0x1004f650c' and b['kind']=='before_unresolved_source_effect' and b['SP']==hex(s) and not b['uncommitted_events']
    assert not any(r['mnemonic'] in ['bl','blr','blraa','blrab','svc'] for r in rows)
    assert not any(e['kind']=='write' and int(e['address'],16)<record+12 and record+8<int(e['address'],16)+e['size_bytes'] for e in events)
    return {'parent_case_index':case['parent_case_index'],'variant':case['variant'],'caller_SP':hex(s),'root_SP':hex(f),
            'temp':hex(temp),'delta_cell':hex(q),'root_record':hex(record),'root_status32':hex(expected),
            'temp_seed_u64':hex(seed),'all_temp_writers':temp_writers,'later_temp_writers':0,'delta_u64':0,
            'source_guard_equal':True,'root_and_adapter_saved_GPRs_verified':11,'returns':returns,'branches':branches,
            'error_marker_address':hex(s+0x5c48),'error_marker_u64':'0xe87f552eb3388cb6',
            'unknown_copy':{'read':copied,'write':out},'unknown_bank_root':bank,'source_bank_writers_in_retained_chain':0,
            'caller_bookkeeping_u64':'0xfffffffffffffbc0','selected_state_word_u32':hex(state_word),
            'frontier':b['pc'],'external_calls':0,'native_pairing_established':False,'all_checks_pass':True}

def build():
    pins,old,ingress,preparations,previous=R.Parent.Parent.inputs()
    e=json.loads(read(ROOT/(R.P+'_checks.json'))); parent=json.loads(read(ROOT/'daemon_iokit_result_checks.json')); post=json.loads(read(ROOT/'daemon_postblock_dispatch_checks.json'))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['source_regions']==R.source() and e['parent_checks_sha256']==R.PIN==sha(ROOT/'daemon_iokit_result_checks.json')
    used={int(a,16) for c in e['cases'] for a in c['trace']['used_fixups']}; assert e['source_fixups']==R.Parent.Core.verify_fixups(used)
    fresh=R.obligations(); assert len(fresh)==len(e['source_proofs'])==11
    for q in e['source_proofs']:
        solver=z3.Solver(); solver.set(timeout=30000); solver.from_string(q['query']); assert q['premises_nonvacuous'] and q['result']=='unsat' and solver.check()==z3.unsat
    runs=[]; joins=[]; totals=Counter(); prefix_totals=Counter(); counts=Counter()
    for case in e['cases']:
        p=next(x for x in parent['cases'] if x['parent_case_index']==case['parent_case_index'] and x['variant']==case['variant'])
        po=post['cases'][case['parent_case_index']]; c=case['configuration']; assert c==p['configuration']==po['configuration']
        original=next(x for x in ingress['cases'] if x['configuration']['epoch']==c['epoch'] and x['configuration']['name']==c['parent_variant'])
        prep=next(x for x in preparations['cases'] if x['configuration']['epoch']==c['epoch'] and x['configuration']['name']==c['preparation_variant'])
        processing=next(x for x in previous['cases'] if x['configuration']['epoch']==c['epoch'] and x['configuration']['name']==c['name'])
        joins.append(interface(case,p,original,prep,processing,po)); counts.update(case['counts'])
        for pattern in [0,3]:
            checker=A.Check(pins['daemon_callback_revisit_snapshot.json'],old,original,prep,processing,po,pattern)
            pre=checker.run(); prefix_totals.update(pre['verified_counts'])
            for j,row in enumerate(p['intervals']):
                checker.model(p['free_return_premise'] if j else p['API_return_premise'])
                pre=checker.interval(row); prefix_totals.update(pre['verified_counts'])
            r=checker.interval(case['trace']); totals.update(r['verified_counts'])
            runs.append({'parent_case_index':case['parent_case_index'],'variant':case['variant'],'pattern':pattern,**r})
        print(json.dumps({'parent':case['parent_case_index'],'variant':case['variant'],'independent_patterns':2}),flush=True)
    assert {'cases':len(e['cases']),**counts}==e['verified_counts']
    return {'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'dependencies':e['dependencies'],
            'verified_counts':e['verified_counts'],'source_queries_unsat':11,'interface_joins':joins,
            'independent_replays':runs,'independent_totals':dict(totals),'separately_replayed_prefix_totals':dict(prefix_totals),
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'all_checks_pass':True,'full_goal_complete':False}

if __name__=='__main__':
    a=build(); (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
    print(json.dumps({'verified_counts':a['verified_counts'],'independent_totals':a['independent_totals'],'all_checks_pass':True}),flush=True)
