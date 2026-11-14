#!/usr/bin/env python3
"""Full independent mixed-table consumer replay, all GP/Q/NZCV frames.
O(visits*(register state+byte effects)+joins) time; O(receipts+largest
interval+byte map) storage. No target native operation or new input premise.
"""
import json,z3
from collections import Counter
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
import recover_daemon_table_consumer as R
import replay_daemon_state_table_mixing as Parent
GS=Parent.GS
DEPS=['replay_daemon_state_table_mixing.py',*Parent.DEPS]
class Lift(Parent.Lift):
    def one(self,i):
        if i.mnemonic=='cneg':
            dst=i.reg_name(i.operands[0].reg);src=self.read(i.reg_name(i.operands[1].reg))
            cc=i.op_str.rsplit(',',1)[1].strip()
            self.write(dst,z3.If(self.condition(cc),-src,src));return
        return super().one(i)
    def __init__(self,row,dependencies,origin=None):
        super().__init__(row,dependencies)
        if row['entry_PC']==hex(R.ENTRY):
            assert origin is not None
            reads=GS.selected(origin,0x1004d5de0);assert len(reads)==1;r=reads[0]
            assert (r['address'],r['size_bytes'],r['bytes_hex'])==('0x1010a09e0',8,'f472410001000000')
            assert FIXUPS[0x1010a09e0]['target']==R.CALLEE and row['entry_registers31'][8]==hex(R.CALLEE)
            for visit in origin['source_visits'][r['source_visit_index']+1:]:
                i=next(R.Parent.DEC.disasm(IMAGE.read(int(visit['pc'],16),4),int(visit['pc'],16)))
                assert not any(i.reg_name(x) in ['x8','w8'] for x in i.regs_access()[1])
            self.last_authenticated_load=(0x1010a09e0,R.CALLEE)
            self.counts['cross_interval_call_target_origins_checked']+=1

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    parents={x['parent_index']:R.unpack(x['derived_terminal_state_packed']) for x in p['coverage']}
    handoffs={x['parent_index']:R.unpack(p['handoff_classes'][x['handoff_class_index']]['interval_packed']) for x in p['coverage']}
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    cases=[];counts=Counter()
    for ci,c in enumerate(e['classes']):
        before=parents[c['representative_parent_index']];dependencies={'required':set(),'written':set()};lifts=[];rows=[]
        for j,x in enumerate(c['intervals']):
            row=R.unpack(x['interval_packed']);GS.joined(before,row);lift=Lift(row,dependencies,handoffs[c['representative_parent_index']] if j==0 else None).run()
            lifts.append(lift);counts.update(lift['verified_counts']);rows.append(row);before=row
            print(json.dumps({'class':ci,'interval':j,'source_visits':counts['source_visits']}),flush=True)
        projection=R.registers(rows);semantic={k:sorted(v) for k,v in dependencies.items()}
        assert set(semantic['required'])<=set(projection['required']) and semantic['written']==projection['written']
        cases.append({'semantic_register_dependencies':semantic,'lifts':lifts,'all_checks_pass':True})
    return {'scope':__doc__,'replayer_sha256':sha(__file__),'generator_sha256':sha(R.__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],
            'replayer_dependencies':{n:sha(ROOT/n) for n in DEPS},'verified_counts':e['verified_counts'],
            'cases':cases,'independent_totals':dict(counts),'all_checks_pass':True,'native_API_executed':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_replay.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['independent_totals']),flush=True)
