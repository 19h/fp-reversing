#!/usr/bin/env python3
"""Source-only return of selected IOKit errors through root, adapter and caller.

Exact preceding journals and declared API/free effects are restored. Saved
frames and temporary writers supply provenance; no new native return is
invented. O(receipts+C*(state bytes+V)+I+Q) time/space plus 30 s/query.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE,CS
from daemon_seed_material_symbolic import apply_journal,decode
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_iokit_result as Parent
import recover_daemon_versioned_ingress as Ingress
from lskd_values_symbolic import mem,cell,resize

P='daemon_iokit_error_return'
ENTRY=Parent.STOP
PIN='8602bdf334f6f52a96e4fe5be4528d89b4653369bda02c17b607e64b6f4f1525'

class Run(Parent.Run):
    def one(self,i):
        if i.address in [ENTRY,0x1008c1760]:
            return Parent.Core.Run.one(self,i)
        return super().one(i)

def restore(pins,old,original,prep,processing,post,parent):
    v=Parent.restore(pins,old,original,prep,processing,post)
    for j,t in enumerate(parent['intervals']):
        m=parent['free_return_premise'] if j else parent['API_return_premise']
        for n,s in m['register_effects'].items(): v.regs[v.key(n)]=decode(s,v.F)
        for w in m.get('declared_output_writes',[]):
            for k,b in enumerate(bytes.fromhex(w['bytes_hex'])): Parent.Core.put(v,int(w['address'],16)+k,1,b)
        if j:
            a=int(m['argument_X0'],16); v.retired=[(a,a+32)]
        apply_journal(v,t)
    v.__class__=Run; Parent.reset(v)
    return v

def source():
    ranges=[('root_epilogue',ENTRY,0x100309d18),('adapter_return',0x1004aca5c,0x1004aca80),
            ('caller_return',0x10084cb08,0x10084cb2c),('caller_result_gate',0x1008c1710,0x1008c1768),
            ('error_head',0x1008c26d4,0x1008c2700),('common_head',0x10085ead4,0x10085eb18),
            ('caller_bookkeeping',0x10080e250,0x10080e2c0),
            ('bank_frontier',0x1004f6458,0x1004f6540)]
    return [{'name':n,'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),
             'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
                             for i in CS.disasm(IMAGE.read(a,z-a),a)]} for n,a,z in ranges]

def build(limit=None):
    assert sha(ROOT/'daemon_iokit_result_checks.json')==PIN
    parent=json.loads(read(ROOT/'daemon_iokit_result_checks.json'))
    assert parent['generator_sha256']==sha(Parent.__file__)
    pins,old,ingress,preparations,processing=Parent.Parent.inputs()
    post=json.loads(read(ROOT/'daemon_postblock_dispatch_checks.json'))
    cases=[]; totals=Counter(); used=set()
    selected=[x for x in parent['cases'] if x['free_return_premise']][:limit]
    for p in selected:
        cfg=p['configuration']; c=post['cases'][p['parent_case_index']]
        original=next(x for x in ingress['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['parent_variant'])
        prep=next(x for x in preparations['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['preparation_variant'])
        prior=next(x for x in processing['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['name'])
        v=restore(pins,old,original,prep,prior,c,p)
        initial=Parent.shape_registers(v); b=v.run_revisit(ENTRY,limit=20000)
        trace={'start':hex(ENTRY),'initial_registers':initial,'initial_NZCV_unspecified':False,
               'steps':v.steps,'boundary':b,'source_pool':v.pool,'used_fixups':list(map(hex,sorted(v.fixups))),
               'logical_retired_spans':[{'start':hex(a),'end':hex(z)} for a,z in v.retired]}
        counts={'source_visits':len(v.steps),'read_events':sum(e['kind']=='read' for s in v.steps for e in s['events']),
                'write_events':sum(e['kind']=='write' for s in v.steps for e in s['events'])}
        assert not v.definitions
        assert b['kind']=='before_unresolved_source_effect' and b['pc']=='0x1004f650c' and not b['uncommitted_events']
        assert len(v.steps)==525 and not any(s['mnemonic'] in ['bl','blr','blraa','blrab'] for s in v.steps)
        totals.update(counts); used.update(v.fixups)
        cases.append({'parent_case_index':p['parent_case_index'],'configuration':cfg,'variant':p['variant'],'trace':trace,'counts':counts})
        print(json.dumps({'parent':p['parent_case_index'],'variant':p['variant'],**counts,'boundary_PC':b['pc'],
                          'boundary_kind':b['kind'],'target':b.get('target'),'reason':b.get('reason')}),flush=True)
    deps=[*parent['dependencies'],'recover_daemon_iokit_result.py','audit_daemon_iokit_result.py']
    return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n) for n in deps},
            'parent_checks_sha256':PIN,'source_sha256':parent['source_sha256'],'source_regions':source(),
            'source_fixups':Parent.Core.verify_fixups(used),'source_proofs':obligations(),
            'cases':cases,'verified_counts':{'cases':len(cases),**totals},'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

def obligations():
    S,F,P,Q,T,C,U,D,B=z3.BitVecs('er_SP64 er_frame64 er_FP64 er_output64 er_temp64 er_seed64 er_unknown64 er_delta64 er_bank64',64)
    STATUS,INDEX=z3.BitVecs('er_status32 er_index32',32); qs=[]
    def run(a,z,seeds=(),memory=(),v=None):
        v=Ingress.Algebra() if v is None else v
        for n,x in seeds: v.seed(n,x)
        for at,n,x in memory: mem(v,at,n,x)
        v.run_block(a,z); return v
    def prove(name,bad):
        q=z3.Solver(); q.set(timeout=30000); assert q.check()==z3.sat
        q.add(bad); assert q.check()==z3.unsat,name
        qs.append({'label':name,'query':q.to_smt2(),'result':'unsat','premises_nonvacuous':True})
    saved={j:z3.BitVec('er_root_saved_'+str(j),64) for j in range(19,31)}
    slots={28:0x920,27:0x928,26:0x930,25:0x938,24:0x940,23:0x948,22:0x950,21:0x958,20:0x960,19:0x968,29:0x970,30:0x978}
    v=run(0x100309cf4,0x100309d10,[('sp',F)],[(F+slots[j],8,x) for j,x in saved.items()])
    prove('root_frame_restoration',z3.Or(v.read('sp')!=F+0x980,*[v.read('x'+str(j))!=x for j,x in saved.items()]))
    v=run(0x1004aca5c,0x1004aca6c,[('x20',T),('x19',Q),('w21',resize(C,32))],[(T,4,resize(U,32))])
    delta=z3.ZeroExt(48,z3.Extract(15,0,U-C))<<4
    prove('adapter_delta_from_temp_low16',cell(v,Q,8)!=delta)
    prove('restored_seed_gives_zero_delta',z3.Implies(resize(U,32)==resize(C,32),delta==0)==False)
    saved={j:z3.BitVec('er_adapter_saved_'+str(j),64) for j in [19,20,21,22,29,30]}
    slots={22:-0x20,21:-0x18,20:-0x10,19:-8,29:0,30:8}
    v=run(0x1004aca6c,0x1004aca7c,[('x29',P)],[(P+slots[j],8,x) for j,x in saved.items()])
    prove('adapter_frame_restoration',z3.Or(v.read('sp')!=P+0x10,*[v.read('x'+str(j))!=x for j,x in saved.items()]))
    v=run(0x10084cb08,0x10084cb18,[('sp',S),('x23',Q-0xa18)],[(Q,8,D)])
    prove('caller_applies_u64_delta',v.read('sp')!=S+D)
    v=run(0x10084cb18,0x10084cb1c,[('x22',Q-0xcb8)],[(Q+8,4,STATUS)])
    prove('caller_reads_same_root_result',v.read('w8')!=STATUS)
    v=run(0x1008c1710,0x1008c1758,[('w8',STATUS),('w19',0x5d32),('x11',U),('sp',S)])
    prove('caller_encoded_result_selection',z3.Or(cell(v,S+0x16d0,8)!=U-0x480,
          v.read('w8')!=z3.If(STATUS==0x8b3dc651,z3.BitVecVal(0x5d45,32),z3.BitVecVal(0x5d32,32))))
    v=run(0x1008c26d4,0x1008c26ec,[('w9',0x6cf4),('sp',S)])
    prove('error_marker_and_rejoin_index',z3.Or(v.read('w8')!=0x5d45,cell(v,S+0x5c48,8)!=0xe87f552eb3388cb6))
    v=run(0x10085ead8,0x10085eaec,[('sp',S)],[(S+0x4a20,8,U)])
    prove('common_head_unknown_copy_and_zero',z3.Or(cell(v,S+0x8ad0,8)!=U,cell(v,S+0x3a06,2)!=0))
    v=run(0x10080e258,0x10080e270,[('sp',S)],[(S+0x16d0,8,U)])
    prove('caller_u64_bookkeeping',z3.Or(cell(v,S+0x16d0,8)!=U+0x40,v.read('x14')!=S+0xc070+U))
    v=run(0x1004f650c,0x1004f6510,[('x24',B),('w8',INDEX)])
    prove('unexecuted_bank_address_dependency',v.read('x9')!=B+z3.ZeroExt(56,z3.Extract(7,0,INDEX)))
    return qs

if __name__=='__main__':
    e=build(); (ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps(e['verified_counts']),flush=True)
