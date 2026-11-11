#!/usr/bin/env python3
"""Independent uncached-context source interpretation and byte-canvases.

No new generator or Z3 import. Private policy-off records, stable clock/owner
observations, logical PAC, returning lock assertions and scalar RMWs only.
No native queue, scheduler, atomic, interrupt, device or IPC operation runs.
O(cases*(source visits+canvas bytes)) time; O(code+private bytes) space.
"""
import json
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_EXT_UXTB
from audit_aes_cached_class_queue import CachedIntegers, CONSTRUCT, INIT, MASK64, MASK48
from audit_aes_runqueue_membership import canvas, snapshot, patch, CLASSIFICATION, BACKEND
from audit_aes_block_wake_handshake import seed, T, U, PSET, CURRENT, D
from audit_startup_dispatch import run, STACK, STOP
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read

ARRAY=0x980000;T2=0x510000;STAT=0xfffffe000cad05b0;ACTIVE=0xfffffe000cb62930
SCORE=0xfffffe000bd1ec40;SELECT=0xfffffe000bd1efa8;REKEY=0xfffffe000bd1ea3c
PRIMARY=0xfffffe000c48bb48;PRIORITY=0xfffffe000c48b42c;RAISE=0xfffffe000c48b730


class ContextIntegers(CachedIntegers):
    def value(self,i,o):
        if o.ext==ARM64_EXT_UXTB:
            assert not o.shift.type;return self.get(i.reg_name(o.reg))&255
        return super().value(i,o)

    def step(self,pc):
        i=self.code[pc];o=i.operands;m=i.mnemonic
        if m=='bic':
            self.visits+=1;self.put(i.reg_name(o[0].reg),self.value(i,o[1])&~self.value(i,o[2]));return pc+4
        if m in ['ldrsb','ldrsw','ldurb','sturb','sxth','ldset']:
            self.visits+=1;dest=i.reg_name(o[0].reg)
            if m=='sxth':
                value=self.get(i.reg_name(o[1].reg))&65535;self.put(dest,value-65536 if value&32768 else value)
            elif m=='ldset':
                at=self.address(i,o[2]);old=self.load(at,8);new=old|self.get(dest)
                self.store(at,8,new);self.put(i.reg_name(o[1].reg),old);self.atomics.append((pc,'ldset',at,8,old,new))
            elif m=='sturb':self.store(self.address(i,o[1]),1,self.get(dest))
            else:
                n=4 if m=='ldrsw'else 1;v=self.load(self.address(i,o[1]),n)
                self.put(dest,v-(1<<(8*n))if m in ['ldrsb','ldrsw']and v&(1<<(8*n-1))else v)
            return pc+4
        if m=='bl'and o[0].imm&MASK64 in [SCORE,SELECT,PRIMARY,PRIORITY,RAISE]:
            self.visits+=1;target=o[0].imm&MASK64;self.put('lr',pc+4);self.entered.append((pc,target));return target
        if m=='b'and o[0].imm&MASK64==REKEY:self.entered.append((pc,REKEY))
        return super().step(pc)


def thread(m,t,kind,primary,base,lane):
    canvas(m,t,0x610)
    for j in range(0x610):m.memory[t+j]=0
    for a,n,v in [(t+0x204,1,kind),(t+0x214,2,primary),(t+0x216,2,base),
      (t+0x298,8,D),(t+0x55c,1,255),(t+0x1f8,4,4)]:m.store(a,n,v)
    if lane==0:m.store(t+0x53,1,1)
    elif lane==1:m.store(t+0x54,1,1)


def setup(code,kind,context_class,lane,typ,primary,base,offset,index,classified):
    initial=seed(code,bound=False);m=ContextIntegers(code);m.__dict__.update(initial.__dict__)
    canvas(m,PSET,0x4000);canvas(m,D,0x400)
    for at,n in [(PSET,0x4000),(D,0x400)]:
        for j in range(n):m.memory[at+j]=0
    m.put('d8',0x123456789abcdef0);m.put('d9',0xfedcba9876543210)
    owner=0x920000;m.store(owner,1,index);m.store(owner+1,1,0)
    for j in range(6):m.store(0xfffffe000cb628a0+8*j,8,0);m.store(0xfffffe000cb628d0+8*j,8,1000+j);m.store(ACTIVE+4*j,4,0)
    m.put('x0',PSET+0x858);m.put('x1',owner);m.put('lr',STOP);run(m,CONSTRUCT,STOP,1200)
    x=ARRAY+200*index;canvas(m,x,200)
    for j in range(200):m.memory[x+j]=0
    a=D+0x60+112*kind
    for at,n,value in [(x,8,a),(x+0xb0,8,x+0xb0),(x+0xb8,8,x+0xb0),(x+0xc0,1,context_class),(x+0xc4,1,typ),
      (a+0x38,8,77),(a+0x40,1,offset),(a+0x60,8,ARRAY),(U+0x20,8,PSET),
      (CURRENT+0x518,4,0x1234),(PSET+0x10c,4,0x1234),(STAT,8,0),(STAT+8,8,0),
      (CLASSIFICATION,8,(1<<(primary%64))if classified and primary<64 else 0),
      (CLASSIFICATION+8,8,(1<<(primary%64))if classified and primary>=64 else 0)]:m.store(at,n,value)
    for j in range(3):m.store(x+0x30+40*j,1,255)
    thread(m,T,kind,primary,base,lane);thread(m,T2,kind,primary,base,lane)
    m.writes=[];return m,x,a


def expected_first(m,x,a,kind,context_class,lane,typ,primary,base,offset,flags,classified):
    extents=[(PSET,0x4000),(D,0x400),(x,200),(T,0x610),(T2,0x610)]
    want={at:bytearray(snapshot(m,at,n))for at,n in extents};score=base+offset;node=x+0x18+40*lane
    def put(at,n,value):
        owner=next(b for b,size in extents if b<=at and at+n<=b+size);patch(want[owner],at-owner,n,value)
    h=PSET+0x858;g=PSET+0xaf8+1112*context_class;bucket=PSET+0x878+168*lane+56*typ
    for j in range(kind,6):put(PSET+0xae8+2*j,2,1)
    for at,n,value in [(T+0x20,8,U),(T+0x58,1,lane),(T+0x60,16,0),
      (T+0x70,8,(primary<<8)|((flags&1)^1)),(T+0x78,8,107),(T+0x80,16,0),(T+0x90,8,base<<8),
      (T+0x98,8,x+0xb0),(T+0xa0,8,x+0xb0),(x+0xb0,8,T+0x98),(x+0xb8,8,T+0x98),
      (node,16,0),(node+0x10,8,primary<<8),(node+0x18,1,typ),(node+0x20,8,T+0x60),
      (bucket+8*context_class,8,node),(bucket+0x30,8,1<<context_class),(PSET+0xa70+8*lane,8,1<<typ),
      (x+0x10,8,T+0x80),(PSET+0x85c,2,int(classified)),(D+0x50,2,1),
      (a+0x30,8,1),(a+0x38,8,107),(x+0xc2,2,1),(PSET+0x85a,2,1),(x+0xc1,1,score),
      (h+0x260,8,1<<context_class),(g+8,4,score),(g+0xc,4,1),(g+0x10+8*(score//64),8,1<<(score%64)),
      (g+0x20+8*score,8,x+0xa0),(x+0xa0,8,x+0xa0),(x+0xa8,8,x+0xa0),(x+8,8,h),(h,2,base)]:put(at,n,value)
    if lane<2:put(T+(0x51 if lane==0 else 0x52),1,1)
    if context_class:
        for at,n,value in [(h+0x10,8,x+0x90),(h+0x18,8,x+0x90),(x+0x90,8,h+0x10),(x+0x98,8,h+0x10),
          (g+0x420,16,0),(g+0x430,8,0),(g+0x438,8,1107+context_class),(h+0x280,8,g+0x420)]:put(at,n,value)
    return extents,want


def compare(m,extents,want,label):
    for at,n in extents:
        got=snapshot(m,at,n)
        if got!=bytes(want[at]):
            delta=[(hex(at+j-16),want[at][j],got[j])for j in range(len(got))if got[j]!=want[at][j]]
            raise AssertionError((label,delta[:16]))


def expected_second(m,x,a,kind,context_class,lane,typ,p0,b0,p1,b1,offset,flags):
    extents=[(PSET,0x4000),(D,0x400),(x,200),(T,0x610),(T2,0x610)]
    want={at:bytearray(snapshot(m,at,n))for at,n in extents}
    def put(at,n,value):
        owner=next(b for b,size in extents if b<=at and at+n<=b+size);patch(want[owner],at-owner,n,value)
    def pair(left,right,left_key,right_key,timed):
        # Both supplied nodes are childless. Full existing-child melds are a
        # separate audit obligation; this oracle checks the serialized join.
        take_right=right_key>left_key or(timed and right_key==left_key and left_key&1)
        winner,loser=(right,left)if take_right else(left,right)
        key=right_key if take_right else left_key
        put(loser,8,0);put(loser+8,8,winner)
        put(winner,16,0);put(winner+0x10,8,((loser&MASK48)<<16)|key)
        return winner
    h=PSET+0x858;g=PSET+0xaf8+1112*context_class;node=x+0x18+40*lane
    oldscore=b0+offset;score=max(b0,b1)+offset
    for j in range(kind,6):put(PSET+0xae8+2*j,2,2)
    for at,n,value in [(T2+0x20,8,U),(T2+0x58,1,lane),(T2+0x60,16,0),
      (T2+0x70,8,(p1<<8)|((flags&1)^1)),(T2+0x78,8,207),(T2+0x80,16,0),(T2+0x90,8,b1<<8),
      (T2+0x98,8,x+0xb0),(T2+0xa0,8,T+0x98),(T+0x98,8,T2+0x98),(x+0xb8,8,T2+0x98),
      (D+0x50,2,2),(a+0x30,8,2),(x+0xc2,2,2),(PSET+0x85a,2,2)]:put(at,n,value)
    if lane<2:put(T2+(0x51 if lane==0 else 0x52),1,1)
    root=pair(T+0x60,T2+0x60,(p0<<8)|((flags&1)^1),(p1<<8)|((flags&1)^1),True)
    put(node+0x20,8,root);put(node+0x10,8,max(p0,p1)<<8)
    root=pair(T+0x80,T2+0x80,b0<<8,b1<<8,False);put(x+0x10,8,root)
    if score!=oldscore:
        put(g+0x20+8*oldscore,8,0);put(g+0x20+8*score,8,x+0xa0)
        for bank in range(2):put(g+0x10+8*bank,8,(1<<(score%64))if bank==score//64 else 0)
        put(g+8,4,score);put(x+0xc1,1,score);put(h,2,max(b0,b1))
    return extents,want,int(b1>b0)


def audit():
    e=json.loads(read(ROOT/'aes_uncached_context_queue_checks.json'));prior=json.loads(read(ROOT/'aes_event_wake_selection_checks.json'))
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    code={i.address:i for row in prior['spans']+e['spans']for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))}
    totals={'first_context_canvases':0,'lane_selector_paths':0,'second_thread_canvases':0,
      'context_score_changes':0,'unchanged_score_returns':0,'source_instruction_visits':0,'atomic_observations':0}
    for context_class in range(6):
     for lane in range(3):
      for typ in range(3):
       for primary,base in [(0,0),(64,31),(95,64)]:
        for flags in [0,1,2,5,0x25]:
         for classified in [False,True]:
          kind=(context_class+lane+typ)%6;offset=(lane+typ+flags)&1;index=3*((context_class+typ)&1)
          m,x,a=setup(code,kind,context_class,lane,typ,primary,base,offset,index,classified)
          extents,want=expected_first(m,x,a,kind,context_class,lane,typ,primary,base,offset,flags,classified)
          saved={f'x{j}':m.get(f'x{j}')for j in range(19,30)}
          m.put('x0',U);m.put('x1',T);m.put('x2',flags);m.put('lr',STOP);run(m,BACKEND,STOP,2500)
          assert m.get('w0')==1 and m.get('sp')==STACK and all(m.get(reg)==v for reg,v in saved.items())
          compare(m,extents,want,(context_class,lane,typ,primary,base,flags,classified))
          assert [m.load(STAT+8*j,8)for j in range(2)]==[int(lane==j)for j in range(2)]
          assert[m.load(ACTIVE+4*j,4)for j in range(6)]==[int(j==context_class)for j in range(6)]
          totals['first_context_canvases']+=1;totals['source_instruction_visits']+=m.visits;totals['atomic_observations']+=len(m.atomics)
    # Exhaust every low-bit combination through the original branch graph.
    for bits in range(16):
        m=ContextIntegers(code);m.put('x20',T)
        for j in range(4):m.store(T+0x53+j,1,0xa0|((bits>>j)&1))
        run(m,0xfffffe000bd20af4,0xfffffe000bd20b18,20)
        expected=0 if bits&5 else 1 if bits&10 else 2
        assert m.get('w28')==expected
        totals['lane_selector_paths']+=1;totals['source_instruction_visits']+=m.visits
    pairs=[(31,20,31,20),(31,20,64,40),(64,40,31,20),(0,0,0,0)]
    for context_class in range(6):
     for lane in range(3):
      for p0,b0,p1,b1 in pairs:
       for flags in [0,1,2]:
        typ=(context_class+lane)%3;kind=(context_class+lane+1)%6;offset=lane&1
        m,x,a=setup(code,kind,context_class,lane,typ,p0,b0,offset,0,False)
        extents,want=expected_first(m,x,a,kind,context_class,lane,typ,p0,b0,offset,flags,False)
        m.put('x0',U);m.put('x1',T);m.put('x2',flags);m.put('lr',STOP);run(m,BACKEND,STOP,2500)
        compare(m,extents,want,('second-case-first',context_class,lane,flags))
        thread(m,T2,kind,p1,b1,lane)
        extents,want,result=expected_second(m,x,a,kind,context_class,lane,typ,p0,b0,p1,b1,offset,flags)
        saved={f'x{j}':m.get(f'x{j}')for j in range(19,30)};m.raw_clock=200;entries=len(m.entered)
        m.put('x0',U);m.put('x1',T2);m.put('x2',flags);m.put('lr',STOP);run(m,BACKEND,STOP,2500)
        assert m.get('w0')==result and m.get('sp')==STACK and all(m.get(reg)==v for reg,v in saved.items())
        compare(m,extents,want,('second',context_class,lane,p0,b0,p1,b1,flags))
        assert len([r for r in m.entered[entries:]if r[1]==REKEY])==1
        assert [m.load(STAT+8*j,8)for j in range(2)]==[2*int(lane==j)for j in range(2)]
        assert[m.load(ACTIVE+4*j,4)for j in range(6)]==[int(j==context_class)for j in range(6)]
        totals['second_thread_canvases']+=1;totals['context_score_changes']+=int(b1>b0)
        totals['unchanged_score_returns']+=int(b1<=b0)
        totals['source_instruction_visits']+=m.visits;totals['atomic_observations']+=len(m.atomics)
    totals['all_checks_pass']=True;return totals


if __name__=='__main__':print(json.dumps(audit()),flush=True)
