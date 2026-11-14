#!/usr/bin/env python3
"""Full independent growth/cleanup replay and pointer custody across ABI returns.
O(visits*(register state+byte effects)+joins) time; O(receipts+largest interval+
byte map) storage. Pointer tags propagate only through exact 64-bit transfers;
ABI clobbers and overlapping invalidations kill tags. No native API/PAC runs.
"""
import json
import z3
from collections import Counter
from functools import lru_cache
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_state_emitter_completion import immutable_byte
from audit_daemon_environment_outputs import Lift as Numeric
import recover_daemon_constructor_buffer as R
import replay_daemon_constructor_gate as Prior
import replay_daemon_table_consumer as Base
GS=Base.GS
DEPS=['replay_daemon_constructor_gate.py','replay_daemon_table_consumer.py',*Prior.DEPS,
      'audit_daemon_state_emitter_completion.py','daemon_table_consumer_checks.json']

def origins(row,initial=None):
    regs,memory=(dict(initial[0]),dict(initial[1])) if initial else ({},{})
    written=set();out={};counts=Counter();rr={};ww={};norm=R.Parent.Parent.Parent.normalized
    for x in row['source_reads']:rr.setdefault(x['source_visit_index'],[]).append(x)
    for x in row['source_writes']:ww.setdefault(x['source_visit_index'],[]).append(x)
    for j,v in enumerate(row['source_visits']):
        i=Prior.instruction(int(v['pc'],16));m=i.mnemonic;old=dict(regs)
        if m in ['braa','blraa']:
            name=norm(i.reg_name(i.operands[0].reg));origin=old.get(name)
            assert origin is not None,('missing pointer custody',v['pc'],name)
            out[j]=origin;counts['exact_authenticated_pointer_chains_checked']+=1
        if m not in ['pacibsp','paciasp','autibsp','autiasp','paciza']:
            for name in R.accesses(i.address)[1]:regs.pop(name,None)
        if m=='mov' and len(i.operands)==2 and i.operands[1].type==1:
            dst=i.reg_name(i.operands[0].reg);src=i.reg_name(i.operands[1].reg)
            if (dst.startswith('x') or dst in ['fp','lr']) and norm(src) in old:regs[norm(dst)]=old[norm(src)]
        if m in ['ldr','ldur','ldp']:
            for k,r in enumerate(rr.get(j,[])):
                name=i.reg_name(i.operands[k].reg);a=int(r['address'],16);n=r['size_bytes'];origin=None
                if n==8 and a in FIXUPS and FIXUPS[a]['kind'].startswith('auth-'):
                    assert not any(a+b in written for b in range(8))
                    target=int.from_bytes(bytes(immutable_byte(a+b) for b in range(8)),'little')
                    origin=(a,target);counts['original_fixup_pointer_reads_checked']+=1
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
    return out,(regs,memory),dict(counts)

def abi_origins(tags,event):
    regs,memory=dict(tags[0]),dict(tags[1])
    regs={n:o for n,o in regs.items() if n.startswith('X') and 18<=int(n[1:])<=29}
    for span in event['invalidated_spans']:
        a=int(span['address'],16);memory={at:o for at,o in memory.items() if not a<=at<a+span['size_bytes']}
    if event.get('allocated_owner_premise'):
        a=int(event['allocated_owner_premise']['address'],16);assert not any(a<=at<a+R.N for at in memory)
    return regs,memory

def parent_origins(parent,ci,inherited):
    c=parent['classes'][ci];row=R.unpack(c['interval_packed']);a=int(inherited['address'],16);o=(int(inherited['slot'],16),int(inherited['target'],16))
    initial=({'X9':(0x101048b28,0x1008c7994)},{a+j:o for j in range(8)})
    journal,tags,counts=origins(row,initial)
    assert len(journal)==4596-12 and tags[0]['X14'][1]==0x1005015e8
    rr=[x for x in row['source_reads'] if x['pc']=='0x1005f1498'];assert len(rr)==1
    r=rr[0];assert tags[0]['X14']==(int(r['address'],16),int.from_bytes(bytes.fromhex(r['bytes_hex']),'little'))
    return tags,{'representative_parent_index':c['representative_parent_index'],'pending_target_read':r,'verified_counts':counts}

class Lift(Prior.Lift):
    def __init__(self,row,dependencies,journal):
        Base.Lift.__init__(self,row,dependencies);self.origin_journal=journal

    def integer(self,value):
        result=Numeric.integer(self,value);o=self.origin_journal.get(self.counts['source_visits']) if hasattr(self,'origin_journal') else None
        if o and result==o[1]:self.last_authenticated_load=o
        return result

    def one(self,i):
        if i.mnemonic=='sdiv':
            dst,a,b=[i.reg_name(o.reg) for o in i.operands]
            left,right=self.read(a),self.read(b)
            self.write(dst,z3.If(right==0,z3.BitVecVal(0,self.width(dst)),left/right));return
        if i.mnemonic=='casal':
            assert i.address==0x1003adb90 and i.op_str=='w13, w10, [x8]'
            a=self.address(i,i.operands[2]);old=self.load(a,4)
            match=self.projected(old)==self.projected(self.read('w13'))
            self.store(a,4,self.read('w10') if match else old,i.address)
            self.write('w13',old);self.counts['CAS_value_transitions_checked']+=1;return
        return super().one(i)

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    parents={x['parent_index']:R.unpack(x['derived_terminal_state_packed']) for x in p['coverage']}
    inherited=Prior.inherited_continuation();prefixes=[];branches=[];counts=Counter();prefix_tags={}
    for ci,c in enumerate(e['prefixes']):
        row=R.unpack(c['interval_packed']);before,fx=R.premised(parents[c['representative_parent_index']]);assert fx==c['entry_premise'];GS.joined(before,row)
        old_ci=next(x['class_index'] for x in p['coverage'] if x['parent_index']==c['representative_parent_index'])
        tags,receipt=parent_origins(p,old_ci,inherited);journal,tags,ct=origins(row,tags);dependencies={'required':set(),'written':set()}
        lift=Lift(row,dependencies,journal).run();counts.update(lift['verified_counts']);pr=R.registers([row])
        assert dependencies['required']<=set(pr['required']) and sorted(dependencies['written'])==pr['written']
        prefixes.append({'lift':lift,'semantic_register_dependencies':{k:sorted(v) for k,v in dependencies.items()},'pointer_counts':ct,'parent_pointer_origin':receipt,'all_checks_pass':True});prefix_tags[ci]=tags
        print(json.dumps({'prefix':ci,'source_visits':counts['source_visits']}),flush=True)
    for bi,c in enumerate(e['branches']):
        before=R.unpack(next(x for x in e['prefix_coverage'] if x['parent_index']==c['representative_parent_index'])['derived_terminal_state_packed'])
        tags=prefix_tags[c['prefix_class_index']];lifts=[]
        for j,x in enumerate(c['intervals']):
            ev=x['API_return_premise'];row=R.unpack(x['interval_packed']);entry=R.fixture_state(before,ev);GS.joined(entry,row)
            journal,tags,ct=origins(row,abi_origins(tags,ev));dependencies={'required':set(),'written':set()}
            lift=Lift(row,dependencies,journal).run();counts.update(lift['verified_counts']);pr=R.registers([row])
            assert dependencies['required']<=set(pr['required']) and sorted(dependencies['written'])==pr['written'],(bi,j,dependencies,pr)
            lifts.append({'lift':lift,'pointer_counts':ct,'semantic_register_dependencies':{k:sorted(v) for k,v in dependencies.items()},'all_checks_pass':True});before=row
        branches.append({'intervals':lifts,'all_checks_pass':True});print(json.dumps({'branch':bi,'source_visits':counts['source_visits']}),flush=True)
    return {'scope':__doc__,'replayer_sha256':sha(__file__),'generator_sha256':sha(R.__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'replayer_dependencies':{n:sha(ROOT/n) for n in DEPS},
            'verified_counts':e['verified_counts'],'prefixes':prefixes,'branches':branches,'independent_totals':dict(counts),
            'inherited_saved_continuation':inherited,'all_checks_pass':True,'native_API_executed':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_replay.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['independent_totals']),flush=True)
