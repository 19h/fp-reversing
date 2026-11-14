#!/usr/bin/env python3
"""Full independent conditional constructor replay and explicit entry joins.
O(visits*(register state+byte effects)+joins) time; O(receipts+largest interval+
byte map) storage. All source frames are checked; no native operation executes.
"""
import json
from collections import Counter
from functools import lru_cache
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_constructor_gate as R
import replay_daemon_table_consumer as Parent
from audit_daemon_environment_outputs import Lift as Numeric,DEC
from lskd_values_symbolic import resize
from capstone.arm64_const import ARM64_OP_REG,ARM64_SFT_ASR,ARM64_SFT_ROR
GS=Parent.GS
DEPS=['replay_daemon_table_consumer.py',*Parent.DEPS,
      'daemon_state_container_construction_checks.json','daemon_state_allocation_cascade_checks.json',
      'daemon_state_emitter_completion_checks.json','daemon_state_table_mixing_checks.json']

@lru_cache(maxsize=None)
def instruction(pc):return next(DEC.disasm(IMAGE.read(pc,4),pc))

def inherited_continuation():
    a=0x6800068da8;slot=0x10103ea90;target=0x1007812e8;value=target.to_bytes(8,'little').hex();counts=Counter();examples=[]
    overlap=lambda w:int(w['address'],16)<a+8 and a<int(w['address'],16)+w['size_bytes']
    def clear(row,after=-1):
        assert not any(overlap(w) and w['source_visit_index']>after for w in row['source_writes'])
        counts['intervening_original_intervals_checked']+=1
    p=json.loads(read(ROOT/'daemon_state_container_construction_checks.json'))
    for j,c in enumerate(p['contexts']):
        row=R.unpack(c['allocation_cases'][1]['interval_packed']);rr=GS.selected(row,0x10083c8b0);ww=GS.selected(row,0x10083c8b8,'source_writes')
        assert len(rr)==len(ww)==1;r,w=rr[0],ww[0]
        assert (r['address'],r['size_bytes'],r['bytes_hex'])==(hex(slot),8,value)
        assert (w['address'],w['size_bytes'],w['after_hex'])==(hex(a),8,value) and r['source_visit_index']<w['source_visit_index']
        clear(row,w['source_visit_index']);examples.append({'parent_index':j,'load':r,'store':w})
    assert len(examples)==76 and FIXUPS[slot]['target']==target
    p=json.loads(read(ROOT/'daemon_state_allocation_cascade_checks.json'))
    for c in p['contexts']:
        for x in [c['allocation21_cases'][1],c['allocation48_cases'][1],c['refill_comparison']]:
            clear(R.unpack(x['interval_packed']))
            if 'API_return_premise' in x:
                for w in x['API_return_premise']['invalidated_spans']:assert not overlap(w)
    p=json.loads(read(ROOT/'daemon_state_emitter_completion_checks.json'))
    for c in p['classes']:
        for x in c['intervals']:clear(R.unpack(x['interval_packed']))
    p=json.loads(read(ROOT/'daemon_state_table_mixing_checks.json'))
    for x in [*p['shared_intervals'],*p['handoff_classes']]:clear(R.unpack(x['interval_packed']))
    p=json.loads(read(ROOT/'daemon_table_consumer_checks.json'))
    from audit_daemon_network_record import state_bytes
    for c in p['classes']:
        for x in c['intervals']:clear(R.unpack(x['interval_packed']))
    for x in p['coverage']:
        memory=state_bytes(R.unpack(x['derived_terminal_state_packed']));assert bytes(memory[a+j] for j in range(8)).hex()==value
    return {'address':hex(a),'slot':hex(slot),'target':hex(target),'examples':examples,'verified_counts':dict(counts),
            'all_checks_pass':True,'native_epoch_join_established':False}

def pointer_origins(row,initial,inherited):
    """Track only exact 64-bit loads, MOVs and stores; kill every other def.

    Origins begin at actual original authenticated-fixup reads. Byte-level
    store tags reject overlapping destruction. No equal-value origin guessing
    or arithmetic propagation is permitted. Full numeric replay checks all
    addresses, values and instruction frames separately.
    """
    regs={'X9':initial};memory={int(inherited['address'],16)+j:(int(inherited['slot'],16),int(inherited['target'],16)) for j in range(8)};written=set();out={};counts=Counter();rr={};ww={}
    for x in row['source_reads']:rr.setdefault(x['source_visit_index'],[]).append(x)
    for x in row['source_writes']:ww.setdefault(x['source_visit_index'],[]).append(x)
    norm=R.Parent.Parent.normalized
    for j,v in enumerate(row['source_visits']):
        i=instruction(int(v['pc'],16));m=i.mnemonic;old=dict(regs)
        if m in ['braa','blraa']:
            name=norm(i.reg_name(i.operands[0].reg));origin=old.get(name)
            assert origin is not None,('missing exact pointer origin',v['pc'],name)
            out[j]=origin;counts['exact_authenticated_pointer_chains_checked']+=1
        if m not in ['pacibsp','paciasp','autibsp','autiasp','paciza']:
            for r in i.regs_access()[1]:regs.pop(norm(i.reg_name(r)),None)
        if m=='mov' and len(i.operands)==2 and i.operands[1].type==1:
            dst=i.reg_name(i.operands[0].reg);src=i.reg_name(i.operands[1].reg)
            if (dst.startswith('x') or dst in ['fp','lr']) and norm(src) in old:regs[norm(dst)]=old[norm(src)]
        if m in ['ldr','ldur','ldp']:
            for k,r in enumerate(rr.get(j,[])):
                name=i.reg_name(i.operands[k].reg);a=int(r['address'],16);n=r['size_bytes'];origin=None
                if n==8 and a in FIXUPS and FIXUPS[a]['kind'].startswith('auth-'):
                    assert not any(a+b in written for b in range(8))
                    origin=(a,FIXUPS[a]['target']);counts['original_fixup_pointer_reads_checked']+=1
                elif n==8:
                    tags=[memory.get(a+b) for b in range(8)]
                    if tags[0] is not None and all(t==tags[0] for t in tags):origin=tags[0];counts['exact_saved_pointer_reloads_checked']+=1
                if origin:
                    assert (name.startswith('x') or name in ['fp','lr']) and int.from_bytes(bytes.fromhex(r['bytes_hex']),'little')==origin[1]
                    regs[norm(name)]=origin
        for k,w in enumerate(ww.get(j,[])):
            a=int(w['address'],16);n=w['size_bytes']
            for b in range(n):memory.pop(a+b,None);written.add(a+b)
            if m in ['str','stur','stp'] and n==8:
                name=i.reg_name(i.operands[k].reg);origin=old.get(norm(name))
                if origin:
                    assert int.from_bytes(bytes.fromhex(w['after_hex']),'little')==origin[1]
                    for b in range(n):memory[a+b]=origin
                    counts['exact_saved_pointer_stores_checked']+=1
    return out,dict(counts)

class Lift(Parent.Lift):
    def operand(self,i,o,n):
        if o.shift.type in [ARM64_SFT_ASR,ARM64_SFT_ROR]:
            assert o.type==ARM64_OP_REG and not o.ext
            value=resize(self.read(i.reg_name(o.reg)),n)
            return value>>o.shift.value if o.shift.type==ARM64_SFT_ASR else z3.RotateRight(value,o.shift.value)
        return super().operand(i,o,n)

    def __init__(self,row,dependencies,origin,inherited):
        super().__init__(row,dependencies)
        reads=GS.selected(origin,0x10057abf0);assert len(reads)==1;r=reads[0]
        assert (r['address'],r['size_bytes'],r['bytes_hex'])==('0x101048b28',8,'94798c0001000000')
        assert FIXUPS[0x101048b28]['target']==0x1008c7994 and row['entry_registers31'][9]=='0x1008c7994'
        for visit in origin['source_visits'][r['source_visit_index']+1:]:
            i=next(R.Parent.Parent.DEC.disasm(IMAGE.read(int(visit['pc'],16),4),int(visit['pc'],16)))
            assert not any(i.reg_name(x) in ['x9','w9'] for x in i.regs_access()[1])
        self.last_authenticated_load=(0x101048b28,0x1008c7994)
        self.counts['cross_interval_target_origins_checked']+=1
        self.origin_journal,ct=pointer_origins(row,self.last_authenticated_load,inherited);self.counts.update(ct)

    def integer(self,x):
        value=Numeric.integer(self,x)
        j=self.counts['source_visits'];origin=self.origin_journal.get(j) if hasattr(self,'origin_journal') else None
        if origin and value==origin[1]:self.last_authenticated_load=origin
        return value

    def one(self,i):
        if i.mnemonic=='sbfx':
            dst=i.reg_name(i.operands[0].reg);width=self.width(dst);lsb=i.operands[2].imm;n=i.operands[3].imm
            value=z3.SignExt(width-n,z3.Extract(lsb+n-1,lsb,self.read(i.reg_name(i.operands[1].reg))))
            self.write(dst,value);return
        if i.mnemonic=='sbfiz':
            dst=i.reg_name(i.operands[0].reg);width=self.width(dst);lsb=i.operands[2].imm;n=i.operands[3].imm
            value=z3.SignExt(width-n,z3.Extract(n-1,0,self.read(i.reg_name(i.operands[1].reg))))<<lsb
            self.write(dst,value);return
        if i.mnemonic=='umull':
            a=z3.ZeroExt(32,resize(self.read(i.reg_name(i.operands[1].reg)),32))
            b=z3.ZeroExt(32,resize(self.read(i.reg_name(i.operands[2].reg)),32))
            self.write(i.reg_name(i.operands[0].reg),a*b);return
        if i.mnemonic=='casal':
            assert i.address==0x1006b7730 and i.op_str=='w13, w10, [x19]'
            a=self.address(i,i.operands[2]);old=self.load(a,4)
            match=self.projected(old)==self.projected(self.read('w13'))
            self.store(a,4,self.read('w10') if match else old,i.address)
            self.write('w13',old);self.counts['CAS_value_transitions_checked']+=1;return
        return super().one(i)

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    parents={x['parent_index']:R.unpack(x['derived_terminal_state_packed']) for x in p['coverage']}
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    inherited=inherited_continuation();cases=[];counts=Counter()
    for ci,c in enumerate(e['classes']):
        before,fx=R.premised(parents[c['representative_parent_index']],e['root_provenance']);assert fx==c['entry_premises']
        row=R.unpack(c['interval_packed']);GS.joined(before,row)
        prior=p['classes'][next(x['class_index'] for x in p['coverage'] if x['parent_index']==c['representative_parent_index'])]
        origin=R.unpack(prior['intervals'][-1]['interval_packed'])
        dependencies={'required':set(),'written':set()};lift=Lift(row,dependencies,origin,inherited).run()
        projection=R.registers([row]);semantic={k:sorted(v) for k,v in dependencies.items()}
        assert set(semantic['required'])<=set(projection['required']) and semantic['written']==projection['written']
        cases.append({'semantic_register_dependencies':semantic,'lift':lift,'all_checks_pass':True});counts.update(lift['verified_counts'])
        print(json.dumps({'class':ci,'source_visits':counts['source_visits']}),flush=True)
    return {'scope':__doc__,'replayer_sha256':sha(__file__),'generator_sha256':sha(R.__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],
            'replayer_dependencies':{n:sha(ROOT/n) for n in DEPS},'verified_counts':e['verified_counts'],
            'cases':cases,'inherited_saved_continuation':inherited,'independent_totals':dict(counts),'all_checks_pass':True,'native_API_executed':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_replay.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['independent_totals']),flush=True)
