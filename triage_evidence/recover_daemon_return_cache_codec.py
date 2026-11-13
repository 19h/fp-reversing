#!/usr/bin/env python3
"""Conditional post-error cached-table/self-text byte-codec continuation.

Restore the exact preceding journals before their first cache-root load.
Two additional initializer-compatible cells are explicit premises; the
initializer-to-caller epoch join and native transport remain unproved.
O(receipts+cases*(restored bytes+visits+effects)+queries) time/space.
No native API, IPC, free, hardware or pointer authentication executes.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE,CS,TABLE,qword
from daemon_seed_material_symbolic import apply_journal
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import mem,cell,resize
import recover_daemon_return_bank_origins as Parent

P='daemon_return_cache_codec'; ENTRY=0x1004dc3c8
PIN='9e5d75cb4a1f452a8499a3a917351283e8763335a44f264809024aaaeded3c69'
ROOTS={0x878:0x1010c67d4,0x858:0x1010c8268}

def source():
    spans=[('initializer_cache_pointer',0x1004c2d04,0x1004c2d34),('initializer_mask_pointer',0x1004c2de4,0x1004c2e18),
           ('cache_root_admission',ENTRY,0x1004dc3d8),('byte_codec_and_loop',0x100792adc,0x100792c08),
           ('next_optional_pointer_gate',0x10080e28c,0x10080e2c0)]
    return [{'name':n,'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),
             'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
                             for i in CS.disasm(IMAGE.read(a,z-a),a)]} for n,a,z in spans]

def gate_dispatch():
    rows=[{'active':active,'index':hex(index),'slot':hex(TABLE+8*index),
           'slot_bytes_hex':IMAGE.read(TABLE+8*index,8).hex(),'target':hex(qword(TABLE+8*index))}
          for active,index in [(0,0x5c1d),(1,0x5c1c)]]
    return {'rows':rows,'source_fixups':Parent.Parent.Parent.Core.verify_fixups({int(r['slot'],16) for r in rows}),
            'unexecuted_from_current_unknown_pointer_boundary':True}

def obligations():
    qs=[];s,d,a,encoded_mask,encoded_base=z3.BitVecs('rcc_SP64 rcc_table64 rcc_address64 rcc_mask64 rcc_base64',64)
    m,w,u,c,n=z3.BitVecs('rcc_mask32 rcc_word32 rcc_raw32 rcc_choice32 rcc_count32',32)
    byte0,byte1=z3.BitVecs('rcc_text0_8 rcc_text1_8',8)
    def prove(label,bad):
        solver=z3.Solver();solver.set(timeout=30000);assert solver.check()==z3.sat
        solver.add(z3.simplify(bad));assert solver.check()==z3.unsat,label
        qs.append({'label':label,'query':solver.to_smt2(),'result':'unsat','premises_nonvacuous':True})
    for off,pc,reg in [(0x858,0x1004c2d30,'x9'),(0x878,0x1004c2e14,'x9')]:
        v=Parent.Algebra();v.seed('sp',s);v.seed(reg,ROOTS[off]);v.run_block(pc,pc+4)
        prove('initializer_pointer_store_'+hex(off),cell(v,s+off,8)!=ROOTS[off])
    v=Parent.Algebra();v.seed('x17',0x1010c67d4);v.seed('x19',0x1010c8268)
    mem(v,0x1010c67d4,4,m);mem(v,0x1010c8268,8,d);v.run_block(0x100792b28,0x100792b40)
    offset=z3.SignExt(32,m)&0xffffffffa96e0c84
    prove('all_u32_sign_extended_mask_to_table_address',v.read('x17')!=d+offset)
    prove('mask255_selects_aligned_word_at132',z3.substitute(offset,(m,z3.BitVecVal(255,32)))!=132)
    class Codec(Parent.Algebra):
        def __init__(self):super().__init__();self.data=[]
        def load(self,at,n):
            if self.pc in [0x100792b40,0x100792bb0,0x100792bb8]:
                want,value={0x100792b40:(4,w),0x100792bb0:(1,byte0),0x100792bb8:(1,byte1)}[self.pc]
                assert n==want;self.data.append((at,n));return value
            return super().load(at,n)
    v=Codec();v.seed('x17',d+132);v.seed('x16',a);v.seed('w14',u);v.seed('w23',c)
    mem(v,0x1010c6800,8,encoded_mask);mem(v,0x1010ca2a8,8,encoded_base)
    v.run_block(0x100792b40,0x100792bc8)
    window_mask=encoded_mask^0xa7a730ec;base=encoded_base^0x12af5504870a589f
    # Source W additions wrap before zero extension into address arithmetic.
    expected0=base+(z3.ZeroExt(32,w+resize(a,32)+0xa96e0c87)&window_mask)
    expected1=base+(z3.ZeroExt(32,w+resize(a,32)+0xa96e0c89)&window_mask)
    want=z3.Extract(7,0,u^(-83*resize(a,32))^z3.ZeroExt(24,byte0)^z3.ZeroExt(24,byte1)^c)
    assert len(v.data)==3 and len(v.stores)==1
    prove('complete_byte_codec_data_addresses_and_output',z3.Or(v.data[0][0]!=d+132,v.data[1][0]!=expected0,
          v.data[2][0]!=expected1,v.stores[0]['address']!=a,cell(v,a,1)!=want,v.stores[0]['size_bytes']!=1))
    p=z3.BitVec('rcc_optional_pointer64',64)
    class Gate(Parent.Algebra):
        def __init__(self):super().__init__();self.table_read=None
        def load(self,at,size):
            if self.pc==0x10080e2ac:
                assert size==8;self.table_read=at
                return z3.If(at==TABLE+8*0x5c1c,z3.BitVecVal(qword(TABLE+8*0x5c1c),64),z3.BitVecVal(qword(TABLE+8*0x5c1d),64))
            return super().load(at,size)
    gate=Gate();gate.seed('sp',s);gate.seed('w8',n);gate.seed('x27',p);gate.seed('w10',0x5c1c);mem(gate,s+0x9d8,8,TABLE)
    gate.run_block(0x10080e290,0x10080e2bc)
    active=z3.If(z3.And(n&0xffff!=0,p!=0),z3.BitVecVal(1,32),z3.BitVecVal(0,32))
    index=0x5c1c^active^1
    target=z3.If(active==1,z3.BitVecVal(qword(TABLE+8*0x5c1c),64),z3.BitVecVal(qword(TABLE+8*0x5c1d),64))
    prove('all_u64_optional_pointer_and_low16_count_gate',z3.Or(cell(gate,s+0x808,4)!=active,
          gate.table_read!=TABLE+8*z3.ZeroExt(32,index),gate.read('x10')!=target,gate.read('x17')!=0x92c2))
    return qs

def upstream_fields(parent):
    out=[]
    for c in parent['upstream_cases']:
        f=int(c['frame_base'],16);fields=[]
        for off,value in ROOTS.items():
            writes=[w for w in c['source_writes'] if int(w['address'],16)<f+off+8 and f+off<int(w['address'],16)+w['size_bytes']]
            assert len(writes)==1 and writes[0]['size_bytes']==8 and int.from_bytes(bytes.fromhex(writes[0]['after_hex']),'little')==value
            fields.append({'offset_bytes':off,'value':hex(value),'writer':writes[0],'later_overlapping_writes':0})
        out.append({'configuration':c['configuration'],'variant':c['variant'],'frame_base':c['frame_base'],'boundary':c['boundary']['pc'],'fields':fields})
    return out

def prefix(t):
    k=next(j for j,r in enumerate(t['steps']) if r['pc']==hex(ENTRY))
    registers=dict(t['initial_registers'])
    for row in t['steps'][:k]: registers.update(row['registers_after'])
    assert 'hex' in registers['sp']
    out={**t,'steps':t['steps'][:k],
         'boundary':{'pc':hex(ENTRY),'registers31':[registers['x'+str(j)] for j in range(31)],
                     'SP':hex(int.from_bytes(bytes.fromhex(registers['sp']['hex']),'little'))}}
    return out,k

def inputs():
    assert sha(ROOT/'daemon_return_bank_origins_checks.json')==PIN
    parent=json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'))
    error=json.loads(read(ROOT/'daemon_iokit_error_return_checks.json'))
    results=json.loads(read(ROOT/'daemon_iokit_result_checks.json'))
    post=json.loads(read(ROOT/'daemon_postblock_dispatch_checks.json'))
    inherited=Parent.Parent.Parent.Parent.inputs()
    return parent,error,results,post,inherited

def restore(c,error,results,post,inherited):
    pins,old,ingress,preparations,processing=inherited;cfg=c['configuration'];ix=c['parent_case_index']
    er=next(x for x in error['cases'] if x['parent_case_index']==ix and x['variant']==c['variant'])
    result=next(x for x in results['cases'] if x['parent_case_index']==ix and x['variant']==c['variant'])
    original=next(x for x in ingress['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['parent_variant'])
    prep=next(x for x in preparations['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['preparation_variant'])
    proc=next(x for x in processing['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['name'])
    v=Parent.Parent.restore(pins,old,original,prep,proc,post['cases'][ix],result);apply_journal(v,er['trace'])
    for w in c['additional_bank_contract']:
        Parent.Parent.Parent.Core.put(v,int(w['address'],16),8,int.from_bytes(bytes.fromhex(w['bytes_hex']),'little'))
    t,k=prefix(c['trace']);apply_journal(v,t);v.__class__=Parent.Run
    Parent.Parent.Parent.reset(v)
    return v,k

def run_case(c,error,results,post,inherited):
    v,k=restore(c,error,results,post,inherited);s=int(c['configuration']['caller_SP'],16);models=[]
    for off,ptr in ROOTS.items():
        at=s+off;before=v.shape(z3.Concat(*[v.bytes.get(at+j,z3.BitVec('unknown_'+hex(at+j),8)) for j in range(7,-1,-1)]),8)
        assert 'terms' in before
        Parent.Parent.Parent.Core.put(v,at,8,ptr)
        models.append({'address':hex(at),'size_bytes':8,'before':before,'bytes_hex':ptr.to_bytes(8,'little').hex(),
                       'provenance':'additional initializer-compatible cache-root premise; control/epoch join unproved'})
    initial=Parent.Parent.Parent.shape_registers(v);b=v.run_revisit(ENTRY,limit=100000)
    trace={'start':hex(ENTRY),'initial_registers':initial,'steps':v.steps,'boundary':b,'source_pool':v.pool,
           'used_fixups':list(map(hex,sorted(v.fixups))),'logical_retired_spans':[{'start':hex(a),'end':hex(z)} for a,z in v.retired]}
    return {'parent_case_index':c['parent_case_index'],'configuration':c['configuration'],'variant':c['variant'],
            'parent_trace_cut_index':k,'additional_cache_contract':models,'trace':trace,
            'counts':{'source_visits':len(v.steps),'read_events':sum(e['kind']=='read' for row in v.steps for e in row['events']),
                      'write_events':sum(e['kind']=='write' for row in v.steps for e in row['events'])}}

def build(limit=None):
    parent,error,results,post,inherited=inputs();cases=[];counts=Counter();used=set()
    for c in parent['cases'][:limit]:
        row=run_case(c,error,results,post,inherited);b=row['trace']['boundary']
        assert b['kind']=='before_unresolved_source_effect' and b['pc']=='0x10080e294' and not b['uncommitted_events']
        assert not any(r['mnemonic'] in ['bl','blraa','blr','blrab','svc'] for r in row['trace']['steps'])
        cases.append(row);counts.update(row['counts']);used.update(row['trace']['used_fixups'])
        print(json.dumps({'parent':c['parent_case_index'],'variant':c['variant'],**row['counts'],'frontier':b['pc']}),flush=True)
    dependencies={**parent['dependencies'],'recover_daemon_return_bank_origins.py':sha(Parent.__file__),
                  'daemon_return_bank_origins_checks.json':PIN,'daemon_return_bank_origins_audit.json':sha(ROOT/'daemon_return_bank_origins_audit.json')}
    return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':dependencies,'parent_checks_sha256':PIN,
            'source_sha256':parent['source_sha256'],'source_regions':source(),'source_fixups':Parent.Parent.Parent.Core.verify_fixups({int(x,16) for x in used}),
            'source_proofs':obligations(),'next_gate_dispatch':gate_dispatch(),'upstream_field_lifetimes':upstream_fields(parent),'cases':cases,
            'verified_counts':{'cases':len(cases),**counts},'initializer_to_caller_control_join_established':False,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
