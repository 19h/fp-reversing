#!/usr/bin/env python3
"""Independent private source interpretation of block/wake state handshakes.

No new generator or Z3 import. Single-RMW LDADD/CASP observations, clock/CPU
snapshots, logical PAC and returning helper models are declared. No native
queue, scheduler, switch, atomic, interrupt or IPC operation executes.
O(cases*(source visits+private bytes)) time; O(code+private bytes) space.
"""
import json
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG
from audit_aes_event_wake_selection import WakeIntegers, machine, Q, CURRENT, CPU, STACK, STOP, MASK64, SCHED, AFTER
from audit_startup_dispatch import run
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read

G=0xfffffe000cad06a0;INC=0xfffffe000bd22370;DEC=0xfffffe000bd1e688
OWNER=0xfffffe000bd7e084;TIMER=0xfffffe000be81d4c;U=0xfffffe000cac6e18
D=0x740000;RO=0x750000;PSET=0x760000;T=0x500000


class HandshakeIntegers(WakeIntegers):
    def __init__(self,code):
        super().__init__(code);self.raw_clock=100;self.atomics=[];self.placements=[];self.owner_models=0;self.timer_models=[]

    def foreign(self,pc,target):
        if target in [OWNER,TIMER,AFTER,0xfffffe000bd5e97c,0xfffffe000bd36b70,0xfffffe000bd0af50,0xfffffe000be7c458]:
            args=tuple(self.get('x'+str(j))for j in range(4));result=0
            if target==OWNER:result=RO;self.owner_models+=1
            elif target==AFTER:self.placements.append((pc,args[0],args[1]))
            elif target==TIMER:self.timer_models.append((args[0],args[1],args[2]))
            elif target==0xfffffe000bd36b70:result=3
            elif target==0xfffffe000be7c458:assert args[1]in [1,2]
            self.boundaries.append((pc,target,args));self.clobber(pc);self.put('x0',result)
            self.flags=(0x123,0x456,32);self.explicit_nzcv=None;return
        return super().foreign(pc,target)

    def step(self,pc):
        i=self.code[pc];m,o=i.mnemonic,i.operands
        names=[i.reg_name(x.reg)for x in o if x.type==ARM64_OP_REG]
        if m=='mrs'and i.op_str.endswith(', s3_4_c15_c10_6'):
            self.visits+=1;self.put(names[0],self.raw_clock);return pc+4
        if m=='nop':self.visits+=1;return pc+4
        if m=='subs':
            self.visits+=1;n=self.width(names[0]);mask=(1<<n)-1
            a=self.value(i,o[1])&mask;b=self.value(i,o[2])&mask;v=(a-b)&mask
            self.put(names[0],v);self.flags=(a,b,n)
            self.explicit_nzcv=(bool(v&(1<<(n-1))),v==0,a>=b,bool((a^b)&(a^v)&(1<<(n-1))))
            return pc+4
        if m=='ldadd':
            self.visits+=1;n=self.width(names[0])//8;at=self.address(i,o[2]);old=self.load(at,n)
            desired=(old+self.get(names[0]))&((1<<(n*8))-1);self.store(at,n,desired);self.put(names[1],old)
            self.atomics.append((pc,'ldadd',at,n,old,desired));return pc+4
        if m=='casp':
            self.visits+=1;at=self.address(i,o[4]);old=self.load(at,16)
            expected=self.get(names[0])|(self.get(names[1])<<64);desired=self.get(names[2])|(self.get(names[3])<<64)
            new=desired if expected==old else old;self.store(at,16,new)
            self.put(names[0],old&MASK64);self.put(names[1],old>>64)
            self.atomics.append((pc,'casp',at,16,old,new));return pc+4
        if m=='csinv':
            self.visits+=1;cond=i.op_str.rsplit(',',1)[1].strip()
            self.put(names[0],self.get(names[1])if self.condition(cond)else ~self.get(names[2]));return pc+4
        if m=='movi'and i.op_str=='v0.2d, #0xffffffffffffffff':
            self.visits+=1;self.put('q0',(1<<128)-1);return pc+4
        if m=='ldrsh':
            self.visits+=1;v=self.load(self.address(i,o[1]),2);self.put(names[0],v-65536 if v&0x8000 else v);return pc+4
        if m=='bl':
            target=o[0].imm&MASK64
            if target in [SCHED,INC,DEC]:
                self.visits+=1;self.put('lr',pc+4)
                if target==SCHED:self.scheduler_calls.append((pc,self.get('x0')))
                return target
            if target in [OWNER,TIMER,AFTER,0xfffffe000bd5e97c,0xfffffe000bd36b70,0xfffffe000bd0af50]:
                self.visits+=1;self.put('lr',pc+4);self.foreign(pc,target);return pc+4
        return super().step(pc)


def seed(code,state=0x101,bound=False,count=0,epoch=50,kind=1,category=0):
    old,_=machine(code,[1],[state]);m=HandshakeIntegers(code)
    m.regs=old.regs.copy();m.memory=old.memory.copy();m.writes=[];m.visits=old.visits
    for at,n in [(CURRENT,0x700),(CPU,0x100),(D,0x400),(RO,0x40),(U,0x700)]:
        for j in range(n):m.memory[at+j]=0
    for at,n,value in [
      (CURRENT+0x1c0,8,CPU),(CPU+0x58,8,7),(RO+0x18,8,0x750100),
      (T+0x43a,1,0),(T+0x1fc,4,category),(T+0x2a0,8,U if bound else 0),(T+0x298,8,D),
      (T+0x204,1,kind),(T+0x57,1,255),(T+0x580,8,0),(T+0x558,2,0),
      (T+0x258,4,17),(T+0x2b8,8,99),(T+0xd0,8,0),(T+0x58e,1,0),
      (G,4,9),(0xfffffe000cb62868,8,37),(0xfffffe000cb0c540,4,0),
      (0xfffffe000ca9f260,4,0),(0xfffffe000cb0c4c8,4,0),(0xfffffe000cb5c400,4,0),
      (D+0x80+112*kind,8,count),(D+0x88+112*kind,8,epoch),(D+0xb8+112*kind,8,11)]:m.store(at,n,value)
    m.writes=[];return m


def audit():
    e=json.loads(read(ROOT/'aes_block_wake_handshake_checks.json'));prior=json.loads(read(ROOT/'aes_event_wake_selection_checks.json'))
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    code={i.address:i for r in prior['spans']+e['spans']for i in cs.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))}
    totals={'complete_wake_state_cases':0,'counter_pair_cases':0,'atomic_mismatch_cases':0,'post_switch_wake_order_cases':0,
      'placement_prefix_cases':0,'callback_argument_cases':0,'elapsed_guard_cases':0,
      'source_instruction_visits':0,'atomic_observations':0,'readonly_owner_models':0}
    for state in [0x101,0x109,0x105,0x10d,0x111]:
      for bound in [False,True]:
       for count in [0,1,3]:
        for category in [0,1]:
         for kind in [0,1,3]:
          m=seed(code,state,bound,count,kind=kind,category=category)
          m.put('x0',Q);m.put('x1',1);m.put('w2',0);m.put('w3',0);m.put('w4',0xffffffff)
          before=bytes(m.memory[T+j]for j in range(-16,0x610))
          saved={f'x{j}':m.get(f'x{j}')for j in range(19,30)}
          run(m,0xfffffe000bd6e22c,STOP,30000)
          slow=not bool(state&4);slot=D+0x80+112*kind
          assert m.get('w0')==1 and m.get('sp')==STACK and m.load(T+0x1f8,4)==((state|0x100)&~0x14d)|4
          assert all(m.get(r)==v for r,v in saved.items())
          assert m.load(G,4)==9+slow and m.load(T+0x57,1)==(252 if slow else 255)
          assert m.load(slot,8)==(count+1 if slow and not bound else count)
          assert m.load(slot+8,8)==(MASK64 if slow and not bound and count==0 else 50)
          assert m.load(D+0xb8+112*kind,8)==11+(37 if slow and not bound and count==0 else 0)
          assert m.load(T+0x2b8,8)==0 and m.load(T+0xd0,8)==0 and m.load(T+0x58e,1)==0
          if slow:assert[m.load(T+off,8)for off in [0x270,0x278,0x328]]==[107]*3
          if category==1:assert m.load(T+0x260,8)==124
          assert m.load(T+0x18,8)==m.load(T+0x28,8)==0
          expected=bytearray(before)
          changes=[(0,16,0),(0x18,8,0),(0x28,8,0),(0xcb,1,0),(0x58e,1,0),(0xd8,4,0),
             (0x1f8,4,((state|0x100)&~0x14d)|4),(0x2b8,8,0),(0xd0,8,0)]
          if slow:changes.extend([(0x57,1,252)]+[(off,8,107)for off in [0x270,0x278,0x328]])
          if category==1:changes.append((0x260,8,124))
          for off,n,value in changes:expected[16+off:16+off+n]=value.to_bytes(n,'little')
          assert bytes(m.memory[T+j]for j in range(-16,0x610))==bytes(expected)
          assert m.placements==([(0xfffffe000bd6bb94,T,5)]if slow else [])
          assert len(m.scheduler_calls)==1 and m.owner_models==1
          totals['complete_wake_state_cases']+=1;totals['source_instruction_visits']+=m.visits
          totals['atomic_observations']+=len(m.atomics);totals['readonly_owner_models']+=m.owner_models
    # Both original count helpers, including their CASP paths, on a private epoch.
    for bound in [False,True]:
      for count in [1,2,3,0xffffffffffffffff]:
       for kind in [0,1,3]:
        m=seed(code,bound=bound,count=count,epoch=77,kind=kind);slot=D+0x80+112*kind
        m.put('x0',T);m.put('lr',STOP);run(m,DEC,STOP,200)
        assert m.get('w0')==8 and m.load(G,4)==8
        assert m.load(slot,8)==(count if bound else(count-1)&MASK64)
        assert m.load(slot+8,8)==(107 if not bound and count==1 else 77)
        m.raw_clock=200;m.put('x0',T);m.put('lr',STOP);run(m,INC,STOP,300)
        assert m.get('w0')==9 and m.load(G,4)==9 and m.load(slot,8)==count
        assert m.load(slot+8,8)==(MASK64 if not bound and count==1 else 77)
        assert m.load(D+0xb8+112*kind,8)==11+(37 if not bound and count==1 else 0)
        totals['counter_pair_cases']+=1;totals['source_instruction_visits']+=m.visits;totals['atomic_observations']+=len(m.atomics)
    for epoch in [107,108,MASK64]:
        m=seed(code,count=0,epoch=epoch);m.put('x0',T);m.put('lr',STOP);run(m,INC,STOP,300)
        assert m.load(D+0x80+112,8)==1 and m.load(D+0x88+112,8)==MASK64
        assert m.load(D+0xb8+112,8)==11
        totals['elapsed_guard_cases']+=1;totals['source_instruction_visits']+=m.visits;totals['atomic_observations']+=len(m.atomics)
    for mismatch in ['low','high']:
      for address in [0xfffffe000bd223dc,0xfffffe000bd1e710]:
        m=seed(code);slot=D+0x80;m.store(slot,8,1);m.store(slot+8,8,2)
        m.put('x4',99 if mismatch=='low'else 1);m.put('x5',99 if mismatch=='high'else 2)
        m.put('x6',7);m.put('x7',8);m.put('x2',7);m.put('x3',8);m.put('x10',slot);m.put('x12',slot)
        m.step(address);assert m.load(slot,16)==1|(2<<64)and m.get('x4')==1 and m.get('x5')==2
        totals['atomic_mismatch_cases']+=1;totals['atomic_observations']+=len(m.atomics)
    # Matched private phases, not a native concurrent or context-switch execution.
    for waitmask in [1,9]:
      for early in [False,True]:
       for bound in [False,True]:
        m=seed(code,state=4|waitmask,bound=bound,count=1,epoch=77)
        m.store(U+0x70,8,107);m.store(T+0x328,8,7);m.store(T+0x330,8,13)
        m.store(T+0xca,1,0);m.store(T+0x212,1,0)
        if early:
            m.put('x0',T);m.put('lr',STOP);run(m,SCHED,STOP,1000)
            assert m.get('w0')==0 and m.load(T+0x1f8,4)==4
        m.put('x21',T);m.put('x19',U);m.put('x20',0x780000)
        run(m,0xfffffe000bd2ab7c,0xfffffe000bd2ae14,2000)
        if early:
            assert m.placements==[(0xfffffe000bd2abdc,T,0x25)]and m.load(G,4)==9
            assert m.load(T+0x1f8,4)==4
        else:
            assert not m.placements and m.load(G,4)==8 and m.load(T+0x1f8,4)==waitmask
            assert m.load(T+0x270,16)==(1<<128)-1 and m.load(T+0x2b0,8)==0
            m.raw_clock=200;m.put('x0',T);m.put('lr',STOP);run(m,SCHED,STOP,1000)
            assert m.get('w0')==1 and m.load(T+0x1f8,4)==4 and m.load(G,4)==9
        totals['post_switch_wake_order_cases']+=1;totals['source_instruction_visits']+=m.visits
        totals['atomic_observations']+=len(m.atomics);totals['readonly_owner_models']+=m.owner_models
    # Original placement prefix to the first actual queue-backend call frontier.
    for flags in [5,0x25]:
      for priority in [0,20,96]:
        m=seed(code,state=4,bound=True,count=1)
        for at,n,value in [(0xfffffe000cacb000,8,0x11223344),(0xfffffe000cadd66c,4,7),(T+0x2e0,4,7),
          (CURRENT+0x518,4,0x1234),(PSET+0x10c,4,0x1234),(U+0x20,8,PSET),(T+0x214,2,priority),
          (0xfffffe000cad06a8,8,0),(0xfffffe000cad06b0,8,0),(0xfffffe000caa2238,1,0),
          (U+6,1,0),(U+0x28,4,0)]:m.store(at,n,value)
        m.put('x0',T);m.put('w1',flags)
        run(m,AFTER,0xfffffe000bd27644,1500)
        assert(m.get('x0'),m.get('x1'),m.get('x2'))==(U,T,flags)
        assert m.load(T+0x208,4)==3 and m.load(T+0x2b0,8)==U
        totals['placement_prefix_cases']+=1;totals['source_instruction_visits']+=m.visits
    for a,z,reg,tag in [(0xfffffe000bd2ad18,0xfffffe000bd2ad28,'x21',1),(0xfffffe000bd26ca8,0xfffffe000bd26cb8,'x19',2)]:
        m=seed(code);m.put(reg,T);m.store(T+0x2d8,8,0x12345000);m.cut(a,z)
        assert(m.get('x8'),m.get('x0'),m.get('x1'),m.get('x17'))==(0x12345000,tag,T,0xae56)
        totals['callback_argument_cases']+=1;totals['source_instruction_visits']+=m.visits
    totals['all_checks_pass']=True;return totals


if __name__=='__main__':print(json.dumps(audit()),flush=True)
