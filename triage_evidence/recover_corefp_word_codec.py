#!/usr/bin/env python3
"""Paired u64 word storage and compensated hash-input decoders.

Typed private caller, control, address and PAC premises remain explicit.
O(C*(B+V*J+P*F+R)) replay time/space; fixed-size scalar contracts;
30 s/SMT query. No native target/API/IPC or IDB operation.
"""
import json
from pathlib import Path
from collections import Counter
import z3
import recover_corefp_scan_entry as E
F=E.P;C=E.C;ROOT=E.ROOT;S=C.Pointers();SHA=E.SHA
MASK=2**64-1;KEY=0xcccccccccccccccc;MULT=0xabdf5fe3f3ef5db9
SPECS=[('first_head',0x1b4900,0x1b4934),('first_tail',0x1b4efc,0x1b4f1c),
 ('second_head',0x1b5738,0x1b57d0),('second_tail',0x1b5d84,0x1b5e1c)]
PINS={**E.PINS,'corefp_scan_entry_checks.json':'05d8c579009d0a2c79705fcd7b491bb548f5173ae8e7a423c176a4316065869e',
 'corefp_scan_entry_audit.json':'b3598b3e866886d404522ff56cc6a394f7ad876d4dde425b258101b76465f383'}


class Lift(F.Lift):
    def execute(self,instructions):
        for i in instructions:
            if i.mnemonic=='madd':
                o=i.operands;n=i.reg_name(o[0].reg);assert n.startswith('x')
                self.put(n,self.value(i,o[1],64)*self.value(i,o[2],64)+self.value(i,o[3],64))
            else:super().execute([i])
        return self


def proofs():
    out=[];word,hashed,ptr,control=[z3.BitVec('codec_'+n,64)for n in ['word','hash','pointer','control']]
    def state(kind,hi=None,normalize=False):
        name,lo,end=SPECS[kind];regs={j:z3.BitVec(name+'_X'+str(j),64)for j in range(31)}
        if kind==0:regs.update({28:word,19:hashed,27:ptr,8:control})
        elif kind==1:regs.update({3:word,19:hashed,2:ptr})
        else:regs.update({3:word,12:hashed,(24 if kind==2 else 8):z3.BitVecVal(0x1912e4b015aaf11f if kind==2 else 0x86aa3caf8765908f,64)})
        machine=Lift(regs,z3.BitVec('codec_SP',64))
        for ins in C.CS.disasm(S.read(lo,(hi or end)-lo),lo):
            if normalize and ins.address in [0x1b57a8,0x1b5df4]:
                # Composed with the separately proved source decode identity.
                machine.put('x3',(word^KEY)+(0x91499b0ece9271b0 if kind==2 else 0x12f88b4c91857f78))
            machine.execute([ins])
        return machine
    a=state(0);assert len(a.stores)==1
    F.P.prove(out,'first_head_general_control_store_hash',z3.And(a.stores[0][0]==ptr,a.stores[0][1]==word^(control+0xcccccccccccc4763),a.rr('x28')==word*MULT,a.rr('x19')==hashed^(word*MULT)))
    F.P.prove(out,'first_head_retained_key',a.stores[0][1]==word^KEY,[control==0x8569])
    b=state(1);assert len(b.stores)==1
    F.P.prove(out,'first_tail_store_hash',z3.And(b.stores[0][0]==ptr,b.stores[0][1]==word^KEY,b.rr('x2')==word*MULT,b.rr('x3')==hashed^(word*MULT)))
    for kind,bias,comp,cut in [(2,0x91499b0ece9271b0,0x5737958f518ee7d0,0x1b57a8),(3,0x12f88b4c91857f78,0x7ff561c46e304a48,0x1b5df4)]:
        name=SPECS[kind][0];pre=state(kind,cut);end=state(kind,normalize=True);assert not end.stores
        F.P.prove(out,name+'_decode_bias',pre.rr('x3')==(word^KEY)+bias)
        F.P.prove(out,name+'_modular_compensation',z3.BitVecVal(bias,64)*MULT+comp==0)
        F.P.prove(out,name+'_source_hash_input',z3.And(end.rr('x3'if kind==2 else'x20')==(word^KEY)*MULT,end.rr('x12')==hashed^((word^KEY)*MULT)))
    F.P.prove(out,'stored_word_round_trip',(word^KEY)^KEY==word)
    h2=z3.BitVec('codec_other_hash',64);term=word*MULT
    F.P.prove(out,'common_hash_input_preserves_hash_xor',((hashed^term)^(h2^term))==hashed^h2)
    return out


class Capture(E.Capture):
    def __init__(self,*args):super().__init__(*args);self.word_components=[];self.active_word=None
    def code(self,u,pc,n,d):
        self.flush()
        for name,lo,hi in SPECS:
            if pc==C.BASE+lo:
                assert self.active_word is None
                self.active_word={'name':name,'entry':F.P.A.capture(self)}
            if pc==C.BASE+hi and self.active_word is not None and self.active_word['name']==name:
                self.active_word['end']=F.P.A.capture(self);self.word_components.append(self.active_word);self.active_word=None
        return super().code(u,pc,n,d)


def epochs(p):
    visits=p['visits']
    raw=[r for r in p['reads']if visits[r['visit']]['pc']in ['0x1b48fc','0x1b4ef8']]
    stored=[w for w in p['writes']if visits[w['visit']]['pc']in ['0x1b4930','0x1b4f00']]
    later=[r for r in p['reads']if visits[r['visit']]['pc']in ['0x1b5734','0x1b5d80']]
    assert len(raw)==len(stored)==len(later)==p['configuration']['length_u32']//8
    out=[]
    for a,w,b in zip(raw,stored,later):
        assert a['address']==w['address']==b['address']and a['size_B']==w['size_B']==b['size_B']==8 and a['visit']<w['visit']<b['visit']
        assert a['bytes_hex']==w['before_hex']and w['after_hex']==b['bytes_hex']
        original=int.from_bytes(bytes.fromhex(a['bytes_hex']),'little');encoded=int.from_bytes(bytes.fromhex(b['bytes_hex']),'little');assert original^encoded==KEY
        at=int(w['address'],16)
        assert not any(w['visit']<v['visit']<b['visit']and int(v['address'],16)<at+8 and at<int(v['address'],16)+v['size_B']for v in p['writes'])
        out.append({'address':w['address'],'size_B':8,'raw_read_PC':visits[a['visit']]['pc'],'store_PC':visits[w['visit']]['pc'],'encoded_read_PC':visits[b['visit']]['pc'],
          'raw_read_visit':a['visit'],'store_visit':w['visit'],'encoded_read_visit':b['visit'],'raw_word_u64':hex(original),'encoded_word_u64':hex(encoded),'no_intervening_overlapping_write':True})
    return out


def main():
    pinned={}
    for name,h in PINS.items():
        raw=F.P.read(ROOT/name).encode();assert SHA(raw)==h;pinned[name]=json.loads(raw)
    parent=pinned['corefp_workspace_checks.json'];blocks=[];joins=[];totals=Counter();counts=Counter()
    for p in parent['profiles']:
        r=Capture(p,parent['source_spans'],S);totals.update(r.run());assert r.active_word is None
        for b in r.word_components:
            lo,hi=b['entry']['source_visit'],b['end']['source_visit'];name,start,end=next(v for v in SPECS if v[0]==b['name']);assert hi-lo==(end-start)//4
            b.update({'label':p['configuration']['label'],'visits':p['visits'][lo:hi],**{k:[v for v in p[k]if lo<=v['visit']<hi]for k in ['reads','writes','PAC_models']}})
            assert not b['reads']and not b['PAC_models'];assert len(b['writes'])==(1 if name.startswith('first')else 0)
            regs=list(map(lambda x:int(x,16),b['entry']['CPU']['X31']))
            if name=='first_head':assert regs[8]==0x8569
            if name=='second_head':assert regs[24]==0x1912e4b015aaf11f
            if name=='second_tail':assert regs[8]==0x86aa3caf8765908f
            counts[name]+=1;blocks.append(b)
        ep=epochs(p);joins.append({'label':p['configuration']['label'],'epochs':ep});print(json.dumps({'captured':p['configuration']['label'],'word_epochs':len(ep)}),flush=True)
    assert dict(counts)=={'first_head':6,'first_tail':10,'second_head':10,'second_tail':6}
    deps=['recover_corefp_scan_entry.py','audit_corefp_scan_entry.py',*pinned['corefp_scan_entry_checks.json']['dependencies']]
    qs=proofs();verified={'profiles':6,'regions':32,'source_instructions':97,'source_B':388,'regional_visits':766,'regional_reads':0,'regional_writes':16,'regional_PAC_models':0,'stable_word_epochs':16,'new_queries_unsat':len(qs),'region_counts':dict(counts)}
    assert sum(len(b['visits'])for b in blocks)==verified['regional_visits']
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':C.THIN_SHA,'parent_pins':PINS,'dependencies':{n:SHA(F.P.read(ROOT/n).encode())for n in deps},
      'source_regions':[{'name':n,'start':hex(lo),'end':hex(hi),'instructions':F.P.source_rows(lo,hi)}for n,lo,hi in SPECS],
      'proofs':qs,'blocks':blocks,'joins':joins,'verified_counts':verified,'replay_totals':dict(totals),'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,
      'new_live_IDA_claim':False,'earlier_arithmetic_passes_universally_reduced':False,'general_raw_preparation_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_word_codec_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(verified),flush=True)


if __name__=='__main__':main()
