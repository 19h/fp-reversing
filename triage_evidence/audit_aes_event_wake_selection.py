#!/usr/bin/env python3
"""Independent original-instruction wake interpretation over private canvases.

No new generator or Z3 import. Queue/thread bytes, DAIF and CPU context are
declared. PAC is logical identity; locks, mask restoration and scheduler calls
are explicit ABI models with caller-saved clobbers. No target executes.
O(cases*(source visits+canvas bytes)) time; O(code+private bytes) space.
"""
import json
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_SFT_ASR
from audit_startup_dispatch import OrderIntegers, run
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read

Q=0x410000;CURRENT=0x700000;CPU=0x710000;SCRATCH=0xfffffe000cac74e0
STACK=0x60000000;STOP=0x12340000;MASK64=(1<<64)-1
LOCKS={0xfffffe000bd0aecc,0xfffffe000bd0ab18,0xfffffe000bd0bfa4,0xfffffe000bd0c2cc,0xfffffe000be7c458}
MASK=0xfffffe000be81fa8;SCHED=0xfffffe000bd26ba8;AFTER=0xfffffe000bd27054


class WakeIntegers(OrderIntegers):
    def __init__(self,code):
        super().__init__(code);self.daif=0x3c0;self.scheduler_result=0;self.scheduler_calls=[]
        self.boundaries=[];self.scan_calls=0;self.explicit_nzcv=None

    def value(self,i,o):
        if o.shift.type==ARM64_SFT_ASR:
            assert not o.ext;v=self.get(i.reg_name(o.reg));width=self.width(i.reg_name(o.reg))
            return(v-(1<<width)if v&(1<<(width-1))else v)>>o.shift.value
        return super().value(i,o)

    def condition(self,name):
        if self.explicit_nzcv is None:return super().condition(name)
        n,z,c,v=self.explicit_nzcv
        return {'eq':z,'ne':not z,'hs':c,'lo':not c,'hi':c and not z,'ls':not c or z}[name]

    def foreign(self,pc,target):
        args=tuple(self.get('x'+str(j))for j in range(3));self.boundaries.append((pc,target,args))
        result=0
        if target==MASK:
            assert args[0]in [0,1]
            if args[0]:self.daif&=~0x1c0
        elif target==SCHED:
            self.scheduler_calls.append((pc,args[0]));result=self.scheduler_result
        elif target==AFTER:assert args[1]==5
        else:
            assert target in LOCKS,(hex(pc),hex(target))
            if target==0xfffffe000be7c458:assert args[1]==1
        self.clobber(pc);self.put('w0',result);self.flags=(0x123,0x456,32);self.explicit_nzcv=None

    def step(self,pc):
        i=self.code[pc];m,o=i.mnemonic,i.operands
        names=[i.reg_name(x.reg)for x in o if x.type==ARM64_OP_REG]
        if m in ['cmp','cmn','tst','subs','adds','bics']:self.explicit_nzcv=None
        if m=='ccmp':
            self.visits+=1;condition=i.op_str.rsplit(',',1)[1].strip()
            if self.condition(condition):
                self.flags=(self.value(i,o[0]),self.value(i,o[1]),self.width(names[0]));self.explicit_nzcv=None
            else:self.explicit_nzcv=tuple(bool(o[2].imm&(1<<b))for b in [3,2,1,0])
            return pc+4
        if m=='mrs':
            self.visits+=1
            assert i.op_str.endswith(', daif')or i.op_str.endswith(', tpidr_el1')
            self.put(names[0],self.daif if i.op_str.endswith(', daif')else CURRENT);return pc+4
        if m=='msr':
            self.visits+=1;assert i.op_str=='daifset, #7';self.daif|=0x1c0;return pc+4
        if m=='movi':
            self.visits+=1;assert i.op_str=='v0.2d, #0000000000000000';self.put('q0',0);return pc+4
        if m=='mov'and i.op_str=='v0.d[0], v0.d[0]':self.visits+=1;return pc+4
        if m=='bics':
            self.visits+=1;v=self.value(i,o[1])&~self.value(i,o[2]);self.put(names[0],v)
            self.flags=(v&0xffffffff,0,32);return pc+4
        if m=='bl':
            self.visits+=1;target=o[0].imm&MASK64;self.put('lr',pc+4)
            if target in LOCKS|{MASK,SCHED,AFTER}:self.foreign(pc,target);return pc+4
            assert target in [0xfffffe000bd6c660,0xfffffe000bd6ce44,0xfffffe000bd6cbcc,0xfffffe000bd6bad0]
            if target==0xfffffe000bd6ce44:self.scan_calls+=1
            return target
        if m=='b'and o[0].imm&MASK64==MASK:
            self.visits+=1;self.foreign(pc,MASK);return self.get('lr')
        return super().step(pc)


def machine(code,events,states,summary_extra=0,foreign_id=False):
    m=WakeIntegers(code)
    for j in range(31):m.put('x'+str(j),0x100+j)
    m.put('sp',STACK);m.put('lr',STOP)
    for a in range(STACK-4096,STACK+128):m.memory[a]=(a*13+31)&255
    for at,length in [(Q-16,56),(CURRENT,0x220),(CPU,0x100),(SCRATCH,32)]:
        for j in range(length):m.memory[at+j]=0
    for j in range(16):m.memory[Q-16+j]=0xa5;m.memory[Q+24+j]=0x5a
    m.store(Q+4,4,0x144);m.store(CURRENT+0x1c0,8,CPU)
    m.store(0xfffffe0007e66df8,8,Q);m.store(0xfffffe0007e66e00,4,1)
    nodes=[0x500000+j*0x800 for j in range(len(events))];summary=summary_extra
    for j,(t,event,state)in enumerate(zip(nodes,events,states)):
        for k in range(-16,0x610):m.memory[t+k]=(k*17+j*29+43)&255
        identity=Q+0x100 if foreign_id and j==0 else Q
        for a,n,v in [(t,8,nodes[(j+1)%len(nodes)]),(t+8,8,nodes[(j-1)%len(nodes)]),
          (t+0x18,8,event),(t+0x28,8,identity),(t+0x1f8,4,state),(t+0xcb,1,1),(t+0x58e,1,0x2a)]:m.store(a,n,v)
        summary|=(event if identity==Q else identity)&0x7ffffff
    m.store(Q,4,9|(summary_extra<<5))
    for j,event in enumerate(events):
        m.put('x24',Q);m.put('w8',m.load(Q,4))
        m.put('x28',Q+0x100 if foreign_id and j==0 else event)
        m.cut(0xfffffe000bd6bec4,0xfffffe000bd6becc)
    assert m.load(Q,4)==9|(summary<<5)
    m.store(Q+8,8,nodes[0]if nodes else 0)
    m.writes=[];return m,nodes


def ring(m):
    head=m.load(Q+8,8)
    if not head:return []
    out=[];t=head
    while t not in out:
        assert len(out)<64;out.append(t);n=m.load(t,8);p=m.load(t+8,8)
        assert m.load(n+8,8)==t and m.load(p,8)==t;t=n
    assert t==head;return out


def audit():
    e=json.loads(read(ROOT/'aes_event_wake_selection_checks.json'));cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    code={i.address:i for row in e['spans']for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))}
    totals={'complete_wake_cases':0,'selector_limit_cases':0,'summary_miss_cases':0,'summary_false_positive_cases':0,
            'immediate_scheduler_models':0,'deferred_scheduler_models':0,'source_instruction_visits':0,'foreign_identity_cases':0}
    # Count=1 makes every event share the bucket under the previously proved hash.
    event_sets=[(),(1,),(2,),(1,1),(1,2,1),(2,1,2),(1,1+(1<<27)),(1+(1<<40),1),
                (1,2,3,1,2,3),(3,1,2),(0x7ffffff,1,2),(1<<27,1<<40)]
    for events in event_sets:
      for target in [1,2,3,1+(1<<27),1+(1<<40),1<<27]:
       for bit2 in [False,True]:
        for mixed in [False,True]:
         for daif in [0x200,0x3c0]:
          for scheduler_result in [0,1]:
            states=[(5 if bit2 else 1)if not mixed or j%2==0 else(1 if bit2 else 5)for j in range(len(events))]
            m,nodes=machine(code,events,states);m.daif=daif;m.scheduler_result=scheduler_result
            before={t:bytes(m.memory[t+j]for j in range(-16,0x610))for t in nodes}
            queue_before=bytes(m.memory[Q-16+j]for j in range(56))
            old_header=m.load(Q,4);selected=[t for t,event in zip(nodes,events)if event==target]
            m.put('x0',Q);m.put('x1',target);m.put('w2',0);m.put('w3',0);m.put('w4',0xffffffff)
            saved={f'x{j}':m.get(f'x{j}')for j in range(19,30)}
            run(m,0xfffffe000bd6e22c,STOP,30000)
            assert m.get('sp')==STACK and m.get('w0')==len(selected)and m.daif==daif
            assert all(m.get(r)==v for r,v in saved.items())
            assert sorted(t for _,t in m.scheduler_calls)==sorted(selected)
            remaining=[t for t in nodes if t not in selected];assert ring(m)==remaining
            missing=(target&0x7ffffff)&~(old_header>>5)
            assert m.scan_calls==int(not missing)
            if missing:totals['summary_miss_cases']+=1
            elif not selected and nodes:totals['summary_false_positive_cases']+=1
            want_summary=0
            for t,event in zip(nodes,events):
                if t in remaining:want_summary|=event&0x7ffffff
                expected=bytearray(before[t]);off=16
                if t in selected:
                    for at,n,value in [(0,16,0),(0x18,8,0),(0x28,8,0),(0xcb,1,0),(0x58e,1,0),(0x1f8,4,states[nodes.index(t)]|0x100),(0xd8,4,0)]:
                        expected[off+at:off+at+n]=value.to_bytes(n,'little')
                else:
                    j=remaining.index(t);expected[off:off+8]=remaining[(j+1)%len(remaining)].to_bytes(8,'little')
                    expected[off+8:off+16]=remaining[(j-1)%len(remaining)].to_bytes(8,'little')
                assert bytes(m.memory[t+j]for j in range(-16,0x610))==bytes(expected),(events,target,t)
            expected_header=old_header if missing else 9|(want_summary<<5)
            assert m.load(Q,4)==expected_header and m.load(Q+4,4)==0x144
            queue_expected=bytearray(queue_before);queue_expected[16:20]=expected_header.to_bytes(4,'little')
            queue_expected[24:32]=(remaining[0]if remaining else 0).to_bytes(8,'little')
            assert bytes(m.memory[Q-16+j]for j in range(56))==bytes(queue_expected)
            assert m.load(CURRENT+0x1c8,4)==0 and m.load(SCRATCH,8)==0 and m.load(SCRATCH+8,1)==0
            immediate=sum(pc==0xfffffe000bd6cc78 for pc,_ in m.scheduler_calls)
            deferred=sum(pc==0xfffffe000bd6bb84 for pc,_ in m.scheduler_calls)
            assert immediate==sum(bool(states[nodes.index(t)]&4)for t in selected)
            assert deferred==len(selected)-immediate
            assert sum(target_call==AFTER for _,target_call,_ in m.boundaries)==(len(selected)if scheduler_result else 0)
            totals['immediate_scheduler_models']+=immediate;totals['deferred_scheduler_models']+=deferred
            totals['source_instruction_visits']+=m.visits;totals['complete_wake_cases']+=1
    # Call the original selector with a private request. State bit2 is set,
    # so these limited cases use immediate handoff and need no deferred drain.
    for events in [(1,1,2,1),(2,1,2,1),(1,),()]:
      for maximum in [0,1,2,0xffffffff]:
       for flags in [4,4|32]:
        for foreign_id in [False,True]:
            m,nodes=machine(code,events,[5]*len(events),summary_extra=0x7ffffff,foreign_id=foreign_id)
            request=0x720000
            for j in range(48):m.memory[request+j]=0
            for at,n,value in [(request,8,1),(request+0xc,4,flags),(request+0x10,4,maximum)]:m.store(at,n,value)
            old_header=m.load(Q,4)
            eligible=[t for j,(t,event)in enumerate(zip(nodes,events))if event==1 and not(foreign_id and j==0)]
            selected=eligible[:maximum];remaining=[t for t in nodes if t not in selected]
            m.put('x0',Q);m.put('x1',request);run(m,0xfffffe000bd6c660,STOP,10000)
            assert m.get('sp')==STACK and m.load(request+0x18,4)==len(selected)and ring(m)==remaining
            assert [t for _,t in m.scheduler_calls]==selected
            # More is checked only when the scan visits a matching node after
            # the limit; bit5 requests continued scanning after reaching it.
            expected_more=bool(len(eligible)>maximum and(maximum==0 or flags&32))
            assert bool(m.load(request+0x15,1))==expected_more
            if not remaining:want=9
            elif len(selected)>=maximum:want=old_header
            else:
                summary=0
                for j,(t,event)in enumerate(zip(nodes,events)):
                    if t in remaining:summary|=((Q+0x100)if foreign_id and j==0 else event)&0x7ffffff
                want=9|(summary<<5)
            assert m.load(Q,4)==want
            totals['selector_limit_cases']+=1;totals['foreign_identity_cases']+=foreign_id
            totals['source_instruction_visits']+=m.visits
    totals['all_checks_pass']=True;return totals


if __name__=='__main__':print(json.dumps(audit()),flush=True)
