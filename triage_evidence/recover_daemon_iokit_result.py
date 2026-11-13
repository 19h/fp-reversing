#!/usr/bin/env python3
"""Source-only selector-21 API/protocol result gates and caller cleanup.

Restore exact pending-call parents. Independently declared API status/output
effects are hypotheses, without native transport or buffer identity. Ordinary
free returns are separate premises; retirement is analysis bookkeeping.
O(restored receipts+C*V+I+Q) time/space plus 30 s/query; 20000 visits/interval.
"""
import copy
import json
from collections import Counter
from pathlib import Path
import z3
from daemon_receive_tools import ROOT, IMAGE, CS, TABLE, FIXUPS
from daemon_seed_material_symbolic import apply_journal
from daemon_callback_revisit_symbolic import ALLOWED_CALLS
from lskd_values_symbolic import mem, cell
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_postblock_dispatch as Parent
import recover_daemon_versioned_root as Core

P = 'daemon_iokit_result'
CALL = 0x100478a04
ENTRY = CALL+4
STOP = 0x100309cdc
PIN = '3cd216630458c65aa34c0f2b1f6155c35a7cfc8206eb97b0fdcc6788e0b401b0'
WRAPPER_PIN = '745b927fe59d20ae447a18c49d99656dc0096a7ab37a7220dbe6126e772d0ae4'
VARIANTS = [('API_error', 5, None, None), ('unspecified_protocol_status', 0, None, None),
            ('provider_error_word', 0, 0xffff5a5e, None),
            ('both_zero_count16', 0, 0, None), ('both_zero_count512', 0, 0, 512)]

class Run(Parent.Run):
    def one(self, ins):
        assert ins.address != STOP, 'declared boundary after root result store'
        return super().one(ins)

    def load(self, address, n):
        a = self.concrete(address, 'unknown-dependent read address')
        assert not any(a < z and a+n > b for b,z in self.retired), 'read intersects logically retired span'
        return super().load(address,n)

    def store(self, address, n, value, pc):
        a = self.concrete(address, 'unknown-dependent write address')
        assert not any(a < z and a+n > b for b,z in self.retired), 'write intersects logically retired span'
        return super().store(address,n,value,pc)

def reset(v):
    v.steps=[]; v.pool={}; v.cache={}; v.fixups=set(); v.zero_reads=[]
    v.changed=set(); v.definitions=[]; v.origins={}; v.unknown_inputs_used={}

def shape_registers(v):
    return {n:v.shape(x,16 if n.startswith('q') else 8) for n,x in v.regs.items()}

def restore(pins, old, original, preparation, processing, post):
    v, cut = Parent.restore(pins['daemon_callback_revisit_snapshot.json'], old, original, preparation, processing)
    apply_journal(v, post['trace'])
    assert v.concrete(v.read('sp'),'SP') == int(post['trace']['boundary']['SP'],16)
    v.__class__ = Run; v.retired=[]; reset(v)
    return v

def return_effects(v, pc, origin, status=None):
    preserved = {n:v.shape(v.read(n),8) for n in ['sp']+['x'+str(j) for j in range(18,30)]}
    d = {str(j):v.shape(z3.Extract(63,0,v.read('q'+str(j))),8) for j in range(8,16)}
    for j in range(18): v.regs['x'+str(j)] = Core.opaque(v,origin+8*j,8)
    if status is not None:
        v.regs['x0'] = z3.Concat(Core.opaque(v,origin+4,4),z3.BitVecVal(status,32))
    for j in range(32):
        v.regs['q'+str(j)] = (z3.Concat(Core.opaque(v,origin+0x100+16*j,8),z3.Extract(63,0,v.read('q'+str(j))))
                              if 8<=j<16 else Core.opaque(v,origin+0x100+16*j,16))
    v.regs['x30'] = z3.BitVecVal(pc+4,64)
    v.n,v.z,v.carry,v.overflow = [z3.Bool('api_result_'+str(pc)+'_'+x) for x in ['N','Z','C','V']]
    assert preserved == {n:v.shape(v.read(n),8) for n in preserved}
    assert d == {str(j):v.shape(z3.Extract(63,0,v.read('q'+str(j))),8) for j in range(8,16)}
    return {'pc':hex(pc),'source_bytes_hex':IMAGE.read(pc,4).hex(),'origin_base':hex(origin),
            'status32':status,'register_effects':shape_registers(v),'preserved':preserved,
            'preserved_D8_D15':d,'NZCV_unspecified':True,'native_API_executed':False}

def interval(v, start):
    reset(v); initial=shape_registers(v); b=v.run_revisit(start,limit=20000)
    assert not v.definitions
    return {'start':hex(start),'initial_registers':initial,'initial_NZCV_unspecified':True,
            'steps':v.steps,'boundary':b,'source_pool':v.pool,'used_fixups':list(map(hex,sorted(v.fixups))),
            'logical_retired_spans':[{'start':hex(a),'end':hex(z)} for a,z in v.retired],
            'new_native_execution':False}

def source():
    specs=[('API_return',ENTRY,0x100478a58),('protocol_status',0x10061ada0,0x10061adfc),
           ('error_merge',0x10062c4bc,0x10062c4f4),('count_consumer',0x10061beac,0x10061bf24),
           ('root_result',0x100309cd8,0x100309d18),('extended_copyback',0x10047455c,0x100474700)]
    return [{'name':n,'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),
             'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
                             for i in CS.disasm(IMAGE.read(a,z-a),a)]} for n,a,z in specs]

def build():
    assert sha(ROOT/'daemon_postblock_dispatch_checks.json') == PIN
    assert sha(ROOT/'versioned_wrapper_error_return_checks.json') == WRAPPER_PIN
    post=json.loads(read(ROOT/'daemon_postblock_dispatch_checks.json'))
    wrapper=json.loads(read(ROOT/'versioned_wrapper_error_return_checks.json'))
    assert all(c['UserClient_result_component']['source_status32']=='0xffff5a5e' for c in wrapper['cases'])
    pins,old,ingress,preparations,previous=Parent.inputs()
    assert post['generator_sha256']==sha(Parent.__file__)
    ALLOWED_CALLS.add(0x100439874)
    cases=[]; totals=Counter(); used=set()
    for ix,p in enumerate(post['cases']):
        c=p['configuration']
        original=next(x for x in ingress['cases'] if x['configuration']['epoch']==c['epoch'] and x['configuration']['name']==c['parent_variant'])
        prep=next(x for x in preparations['cases'] if x['configuration']['epoch']==c['epoch'] and x['configuration']['name']==c['preparation_variant'])
        processing=next(x for x in previous['cases'] if x['configuration']['epoch']==c['epoch'] and x['configuration']['name']==c['name'])
        base=restore(pins,old,original,prep,processing,p)
        for name,api,status,count in VARIANTS:
            v=copy.copy(base); v.bytes=base.bytes.copy(); v.regs=base.regs.copy(); v.retired=[]
            origin=0x6b00000000+ix*0x10000
            model=return_effects(v,CALL,origin,api); writes=[]; buf=int(p['api_view']['address'],16)
            for off,value in [(0x224,status),(0x220,count)]:
                if value is not None:
                    Core.put(v,buf+off,4,value); writes.append({'address':hex(buf+off),'offset_bytes':off,'size_bytes':4,'bytes_hex':value.to_bytes(4,'little').hex()})
            model['declared_output_writes']=writes; model['memory_scope']='only listed u32 output effects; all other modeled memory preserved; native effects unknown'
            rows=[interval(v,ENTRY)]; free=None
            b=rows[-1]['boundary']
            if name in ['API_error','provider_error_word']:
                assert b['kind']=='before_uninspected_call' and b['pc']==hex(Core.FREE), b
                allocation=int(c['allocation'],16); assert v.concrete(v.read('x0'),'free argument')==allocation
                free=return_effects(v,Core.FREE,origin+0x1000)
                free.update(argument_X0=hex(allocation),logical_retirement_only={'start':hex(allocation),'end':hex(allocation+32)},model_memory_effects=0)
                v.retired=[(allocation,allocation+32)]; rows.append(interval(v,Core.FREE+4))
                assert rows[-1]['boundary']['pc']==hex(STOP),rows[-1]['boundary']
            elif name=='unspecified_protocol_status':
                assert b['pc']=='0x10061adc8' and b['kind']=='before_unresolved_source_effect',b
            else:
                assert b['pc']=='0x1004d6d94' and b['target']=='0x100436388',b
            counts={'intervals':len(rows),'source_visits':sum(len(r['steps']) for r in rows),
                    'read_events':sum(e['kind']=='read' for r in rows for s in r['steps'] for e in s['events']),
                    'write_events':sum(e['kind']=='write' for r in rows for s in r['steps'] for e in s['events'])}
            totals.update(counts)
            for r in rows: used.update(int(x,16) for x in r['used_fixups'])
            cases.append({'parent_case_index':ix,'configuration':c,'variant':name,'API_return_premise':model,
                          'free_return_premise':free,'intervals':rows,'counts':counts})
            print(json.dumps({'parent':ix,'variant':name,**counts,'boundary':rows[-1]['boundary']['pc']}),flush=True)
    deps=[*Parent.DEPS,'recover_daemon_postblock_dispatch.py','audit_daemon_postblock_dispatch.py']
    return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n) for n in deps},
            'parent_checks_sha256':PIN,'wrapper_checks_sha256':WRAPPER_PIN,'source_sha256':post['source_sha256'],
            'source_regions':source(),'source_fixups':Core.verify_fixups(used),'source_proofs':obligations(),
            'cases':cases,'verified_counts':{'parent_cases':len(post['cases']),'cases':len(cases),**totals},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

def obligations():
    A=Parent.Parent.Parent.R.Algebra
    API,STATUS,COUNT,RAW=z3.BitVecs('result_API32 result_protocol32 result_count32 result_raw32',32)
    F,R=z3.BitVecs('result_frame64 result_record64',64); qs=[]
    def run(a,z,seeds=(),memory=(),v=None):
        v=A() if v is None else v
        for n,x in seeds: v.seed(n,x)
        for at,n,x in memory: mem(v,at,n,x)
        v.run_block(a,z); return v
    def prove(name,bad):
        s=z3.Solver(); s.set(timeout=30000); assert s.check()==z3.sat
        s.add(bad); result=s.check(); assert result==z3.unsat,(name,str(result))
        qs.append({'label':name,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True})
    v=run(0x100478a0c,0x100478a28,[('w0',API)])
    prove('API_status_XOR_encoding',z3.Or(v.read('w28')!=(API^0x8b3dc651),v.read('w8')!=0x167b8ca2,v.read('w10')!=0x8b3dc651))
    v=run(0x100478a28,0x100478a4c,[('w28',API^0x8b3dc651),('w21',0x2699),('w19',0x871a),('w24',0x92b2)])
    prove('API_zero_gate_index',v.read('w9')!=z3.If(API==0,z3.BitVecVal(0xb464,32),z3.BitVecVal(0x92b2,32)))
    v=run(0x10061adc8,0x10061add4,[('w8',0x167b8ca2),('w10',0x8b3dc651),('w11',STATUS)])
    prove('protocol_status_XOR_encoding',v.read('w28')!=(STATUS^0x8b3dc651))
    v=run(0x10061ada0,0x10061adc4,[('w21',0x2699)])
    v=run(0x10061add4,0x10061adf0,[('w11',STATUS)],v=v)
    prove('protocol_zero_gate_index',v.read('w8')!=z3.If(STATUS==0,z3.BitVecVal(0x31c6,32),z3.BitVecVal(0x2699,32)))
    v=run(0x10061beac,0x10061bee0,[('sp',F),('w12',0x3616),('w22',RAW)],[(F+0x3f8,8,R),(F+0x8c8,4,COUNT)])
    prove('count_and_span_record_setup',z3.Or(cell(v,F+0x588,4)!=COUNT,cell(v,F+0x580,8)!=R,v.read('x21')!=F+0x6c8,v.read('w10')!=0x343a))
    v=run(0x10061bee0,0x10061bf08,[('sp',F),('w20',COUNT),('w10',0x343a)])
    prove('count_XOR_record_field',cell(v,F+0x58c,4)!=(COUNT^0x8b3dc651))
    v=run(0x100309cd8,0x100309cdc,[('x0',R),('w28',RAW)])
    prove('root_result_publication',cell(v,R+8,4)!=RAW)
    data=[z3.BitVec('result_extended_byte_'+str(j),8) for j in range(16)]
    v=run(0x10047455c,0x1004746f0,[('sp',F),('w8',0x53e6)],[(F+0x488,8,R)]+[(F+0x6b4+j,1,b) for j,b in enumerate(data)])
    prove('extended_copyback_XOR98',z3.Or(*[cell(v,R+j,1)!=(b^0x98) for j,b in enumerate(data)]))
    return qs

if __name__=='__main__':
    result=build(); (ROOT/(P+'_checks.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result['verified_counts']),flush=True)
