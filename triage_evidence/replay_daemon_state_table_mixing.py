#!/usr/bin/env python3
"""Independent complete source replay and semantic register-dependency audit.

Every GP/SP/Q/NZCV frame, byte event and logical authenticated target is
checked. Semantic read/write hooks exclude audit-only frame inspections.
Projection crosses chunk joins; source-local flag conditions are tracked.
O(visits*(register state+byte effects)+joins) time;
O(receipts+largest interval+byte map) space. No native target operations.
"""
import json
from collections import Counter
import z3
from lskd_values_symbolic import resize
from daemon_receive_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_daemon_generated_stream as GS
import recover_daemon_state_table_mixing as R

DEPS=['audit_daemon_generated_stream.py','audit_daemon_readiness_arena.py','audit_daemon_context_state_publish.py',
      'audit_daemon_context_unseal.py','audit_daemon_network_record.py','audit_daemon_environment_outputs.py',
      'recover_daemon_return_bank_origins.py','daemon_context_transfer_symbolic.py','lskd_values_symbolic.py']

class Lift(GS.Lift):
    def __init__(self,row,dependencies):
        self.tracking=False;self.dependencies=dependencies;self.numeric_ready=False;self.projection_cache={}
        super().__init__(row)
        self.numeric={R.normalized(name):self.projected(self.read(name)) for name in
                      ['sp']+['x'+str(j) for j in range(31)]+['q'+str(j) for j in range(32)]}
        self.numeric_ready=True;self.tracking=True

    def projected(self,value):
        assert not self.symbols
        key=value.get_id()
        if key not in self.projection_cache:self.projection_cache[key]=(value,super().projected(value))
        return self.projection_cache[key][1]

    def used(self,name):
        if self.tracking:
            name=R.normalized(name)
            if name is not None and name not in self.dependencies['written']:self.dependencies['required'].add(name)

    def defined(self,name):
        if self.tracking:
            name=R.normalized(name)
            if name is not None:self.dependencies['written'].add(name)

    def read(self,name):self.used(name);return super().read(name)
    def write(self,name,value):
        self.defined(name);result=super().write(name,value)
        if self.numeric_ready and name not in ['xzr','wzr']:
            self.numeric[R.normalized(name)]=self.projected(self.regs[self.key(name)])
        return result
    def flags(self,*args,**kwargs):
        result=super().flags(*args,**kwargs);self.defined('nzcv');return result
    def condition(self,cc):self.used('nzcv');return super().condition(cc)
    def one(self,ins):
        if ins.mnemonic in ['sxtb','sxth']:
            width=8 if ins.mnemonic=='sxtb' else 16;dest=ins.reg_name(ins.operands[0].reg)
            value=z3.SignExt(self.width(dest)-width,resize(self.read(ins.reg_name(ins.operands[1].reg)),width))
            self.write(dest,value);return
        if ins.mnemonic=='smull':
            a=z3.SignExt(32,resize(self.read(ins.reg_name(ins.operands[1].reg)),32))
            b=z3.SignExt(32,resize(self.read(ins.reg_name(ins.operands[2].reg)),32))
            self.write(ins.reg_name(ins.operands[0].reg),a*b);return
        result=super().one(ins)
        if ins.mnemonic=='tst':self.defined('nzcv')
        return result
    def frame(self,row):
        # Values are recomputed from the independent model after every write;
        # unchanged registers reuse their exact value, with no sampled frames.
        for j,x in enumerate(row['registers31']):assert self.numeric['X'+str(j)]==int(x,16),(row['pc'],'X'+str(j))
        assert self.numeric['SP']==int(row['SP'],16)
        for j,x in enumerate(row['Q_registers32']):assert self.numeric['Q'+str(j)]==int(x,16),(row['pc'],'Q'+str(j))
        flags=sum(self.projected(getattr(self,n))<<bit for n,bit in [('n',31),('z',30),('carry',29),('overflow',28)])
        assert flags==int(row['NZCV'],16),(row['pc'],'NZCV')
        self.counts.update(register_values_checked=32,vector_register_values_checked=32,NZCV_values_checked=1)

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    before=R.unpack(next(x for x in p['coverage'] if x['parent_index']==0)['derived_terminal_state_packed'])
    dependencies={'required':set(),'written':set()};lifts=[];counts=Counter();rows=[]
    for j,row in enumerate(R.shared_intervals(e)):
        GS.joined(before,row);lift=Lift(row,dependencies).run();lifts.append(lift);counts.update(lift['verified_counts']);rows.append(row);before=row
        print(json.dumps({'interval':j,'source_visits':counts['source_visits']}),flush=True)
    projection=R.registers(rows)
    semantic={k:sorted(v) for k,v in dependencies.items()}
    assert set(semantic['required'])<=set(projection['required']) and semantic['written']==projection['written'],(semantic,projection)
    assert not any(x.startswith('Q') for x in semantic['required']+semantic['written'])
    parents={x['parent_index']:R.unpack(x['derived_terminal_state_packed']) for x in p['coverage']};handoffs=[]
    for j,c in enumerate(e['handoff_classes']):
        before=R.terminal(parents[c['representative_parent_index']],rows,projection);row=R.unpack(c['interval_packed']);GS.joined(before,row)
        dependencies={'required':set(),'written':set()};lift=Lift(row,dependencies).run();handoffs.append(lift);counts.update(lift['verified_counts'])
        pr=R.registers([row]);assert dependencies['required']<=set(pr['required']) and sorted(dependencies['written'])==pr['written']
        print(json.dumps({'handoff':j,'source_visits':counts['source_visits']}),flush=True)
    return {'scope':__doc__,'replayer_sha256':sha(__file__),'generator_sha256':sha(R.__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],
            'replayer_dependencies':{n:sha(ROOT/n) for n in DEPS},'verified_counts':e['verified_counts'],
            'shared_lifts':lifts,'handoff_lifts':handoffs,'independent_totals':dict(counts),'semantic_register_dependencies':semantic,
            'all_checks_pass':True,'native_API_executed':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_replay.json')).write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps({'replay':e['independent_totals'],'semantic_register_dependencies':e['semantic_register_dependencies']}),flush=True)
