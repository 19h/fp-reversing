#!/usr/bin/env python3
"""Independent full-source context-score policy and controlled CASP retries.

Private disjoint records, stable scalar globals, logical PAC and scripted
pair observations only. No generator or Z3 import; no native lock, atomic,
clock, scheduler, device or IPC operation. O(cases*(visits+canvas bytes)) time,
O(code+private bytes+bounded observations) space. No retry liveness proof.
"""
from collections import Counter
import json
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from audit_aes_uncached_context_queue import ContextIntegers, setup, expected_first, expected_second, compare, T, T2, U, PSET, D, ACTIVE
from audit_aes_runqueue_membership import canvas, snapshot, patch, BACKEND
from audit_aes_block_wake_handshake import CURRENT, CPU
from audit_startup_dispatch import run, STACK, STOP
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read

MASK=(1<<64)-1;X=0x990000;A=0x9a0000;NODE=0x9b0000
SCORE=0xfffffe000bd1ec40;INC=0xfffffe000bd22370
CONFIG=0xfffffe000bd24c94;CONVERT=0xfffffe000bd21468
LIMIT=0xfffffe000cb62868;SCALE=0xfffffe000cb62870;PERIOD=0xfffffe000cb62900;DIVISOR=0xfffffe000ca9068c
PCS={'period':0xfffffe000bd1ecd4,'account':0xfffffe000bd1ed88,'cache':0xfffffe000bd1edf8}


def divide(a,b):return a//b if b else 0


class PolicyIntegers(ContextIntegers):
    def __init__(self,code):
        super().__init__(code);self.injections={};self.pair_observations=[];self.coverage=Counter();self.configuration_calls=[]

    def step(self,pc):
        i=self.code[pc];o=i.operands;m=i.mnemonic;self.coverage[pc]+=1
        if m in ['smull','umaddl']:
            self.visits+=1;a=self.get(i.reg_name(o[1].reg));b=self.get(i.reg_name(o[2].reg))
            if m=='smull':
                a=a-(1<<32)if a&0x80000000 else a;b=b-(1<<32)if b&0x80000000 else b;v=a*b
            else:v=a*b+self.get(i.reg_name(o[3].reg))
            self.put(i.reg_name(o[0].reg),v);return pc+4
        if m in ['bl','b']and o[0].imm&MASK in [0xfffffe000c5e48a4,0xfffffe000bd26674,CONVERT]:
            self.visits+=1;target=o[0].imm&MASK;args=tuple(self.get('x'+str(j))for j in range(5))
            self.configuration_calls.append((pc,target,args))
            if m=='bl':self.put('lr',pc+4)
            if target==CONVERT:return target
            if target==0xfffffe000c5e48a4:
                assert args[1:]==(0xfffffe000704ec40,DIVISOR,1,0)
                if self.option_status:self.store(DIVISOR,1,self.option_value)
                result=self.option_status
            else:result=0
            self.clobber(pc);self.put('w0',result);return pc+4
        if m in ['udiv','sxtw']:
            self.visits+=1;v=self.get(i.reg_name(o[1].reg));dest=i.reg_name(o[0].reg)
            if m=='sxtw':v=(v&0xffffffff)-(1<<32)if v&0x80000000 else v&0xffffffff
            else:v=divide(v,self.get(i.reg_name(o[2].reg)))
            self.put(dest,v);return pc+4
        if m=='casp':
            self.visits+=1;at=self.address(i,o[4]);regs=[i.reg_name(p.reg)for p in o[:4]]
            if self.injections.get(pc):
                pair=self.injections[pc].pop(0);self.store(at,16,pair[0]|(pair[1]<<64))
            old=self.load(at,16);expected=self.get(regs[0])|(self.get(regs[1])<<64)
            desired=self.get(regs[2])|(self.get(regs[3])<<64);new=desired if old==expected else old
            self.store(at,16,new);self.put(regs[0],old&MASK);self.put(regs[1],old>>64)
            self.pair_observations.append((pc,at,old,expected,desired,new));return pc+4
        return super().step(pc)


def oracle(inputs,injections=None):
    s=dict(inputs);scripts={n:list(v)for n,v in(injections or{}).items()};events=[]
    def pair(name,fields,desired):
        expected=tuple(s[f]for f in fields);observed=tuple(scripts[name].pop(0))if scripts.get(name)else expected
        new=tuple(desired)if observed==expected else observed
        def packed(p):return p[0]|(p[1]<<64)
        offset={'period':0x30,'account':0x50,'cache':0x40}[name]
        events.append((PCS[name],s['aux']+offset,packed(observed),packed(expected),packed(desired),packed(new)))
        for f,v in zip(fields,new):s[f]=v&MASK
        return observed==expected
    b=s['priority'];k=0
    if not s['context_count']:return s,0,events
    if not s['policy']:return s,(b+(s['cached']&255))&255,events
    if s['active']:
        signed=s['active']-(1<<32)if s['active']&0x80000000 else s['active']
        period=(s['period_base']+s['period_scale']*signed)&MASK
        while s['now']>s['epoch']:
            delta=s['now']-s['epoch']
            if delta<period:break
            k=divide(delta,period)&255
            if pair('period',('count','epoch'),(s['count'],(s['epoch']+k*period)&MASK)):break
            k=0
    while k or((s['u']+s['v'])&MASK)>=s['limit']:
        u,v=s['u'],s['v']
        if ((u+v)&MASK)>=s['limit']:u//=10;v//=10
        deduction=divide((v*k)&MASK,s['divisor'])
        adjusted=max(0,u-deduction)
        if v<u:
            product=(v*s['divisor'])&MASK
            adjusted=divide((product*u)&MASK,(u*k+product)&MASK)
        if pair('account',('u','v'),(adjusted,v)):break
    u,v=s['u'],s['v'];d=s['divisor']
    if u==v==0:candidate=s['cached']&255
    elif v>u:candidate=(d+divide(((v-u)*d)&MASK,v))&255
    else:candidate=divide((v*d)&MASK,u)&255
    while s['stamp']<s['now']:
        desired=s['cached']if not s['stamp']else candidate
        if pair('cache',('cached','stamp'),(desired,s['now'])):break
    return s,(b+s['cached'])&255,events


def fields(m,a,s):
    for off,n,key in [(0,1,'policy'),(0x30,8,'count'),(0x38,8,'epoch'),(0x40,8,'cached'),
      (0x48,8,'stamp'),(0x50,8,'u'),(0x58,8,'v')]:m.store(a+off,n,s[key])
    for at,n,key in [(ACTIVE+4*s['policy'],4,'active'),(PERIOD+8*s['policy'],8,'period_base'),
      (SCALE+8*s['policy'],8,'period_scale'),(LIMIT,8,'limit'),(DIVISOR,1,'divisor')]:m.store(at,n,s[key])
    m.store(0xfffffe000cb5c400,4,0)


def private(code,s,injections=None):
    m=PolicyIntegers(code)
    for j in range(31):m.put('x'+str(j),0x100+j)
    m.put('sp',STACK);m.put('lr',STOP)
    for at,n in [(A,112),(X,200),(NODE,32),(STACK-0x80,0x100)]:canvas(m,at,n)
    fields(m,A,s);m.store(X,8,A);m.store(X+0x10,8,NODE);m.store(X+0xc2,2,s['context_count'])
    m.store(NODE+0x11,1,s['priority']);m.store(X+0xc1,1,0x71)
    m.injections={PCS[n]:list(v)for n,v in(injections or{}).items()}
    return m


def case(code,s,injections=None):
    m=private(code,s,injections);want,score,events=oracle(s,injections)
    extents=[(A,112),(X,200),(NODE,32)];expected={at:bytearray(snapshot(m,at,n))for at,n in extents}
    for off,key in [(0x30,'count'),(0x38,'epoch'),(0x40,'cached'),(0x48,'stamp'),(0x50,'u'),(0x58,'v')]:patch(expected[A],off,8,want[key])
    saved={f'x{j}':m.get(f'x{j}')for j in range(19,30)}
    m.put('x0',X);m.put('x1',s['now']);run(m,SCORE,STOP,1200)
    assert m.get('w0')==score and m.get('sp')==STACK and all(m.get(r)==v for r,v in saved.items())
    assert m.pair_observations==events,(s,injections,m.pair_observations,events)
    compare(m,extents,expected,('score',s,injections))
    assert not any(m.injections.values())
    return m


def audit():
    e=json.loads(read(ROOT/'aes_context_score_policy_checks.json'));prior=json.loads(read(ROOT/'aes_uncached_context_queue_checks.json'))
    seed_source=json.loads(read(ROOT/'aes_event_wake_selection_checks.json'))
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    code={i.address:i for row in seed_source['spans']+prior['spans']+e['spans']for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))}
    totals={'full_score_canvases':0,'empty_context_canvases':0,'period_boundary_canvases':0,'controlled_retry_canvases':0,
      'wake_then_score_canvases':0,'policy_backend_compositions':0,'configuration_canvases':0,
      'source_instruction_visits':0,'pair_observations':0}
    covered=set();mismatches=Counter()
    def record(m):
        totals['source_instruction_visits']+=m.visits;totals['pair_observations']+=len(m.pair_observations);covered.update(m.coverage)
        for pc,at,old,expected,desired,new in m.pair_observations:
            if old!=expected:mismatches[hex(pc)]+=1
    accounts=[(0,0),(10,20),(20,10),(10,10),(1,0),(0,1),(9,9),(100,200),(MASK,1),(MASK,MASK),(1<<63,1<<63)]
    for p in [0,1,2,5]:
     for active in [0,1,2,0x80000000,0xffffffff]:
      for div in [0,1,8,255]:
       for j,(u,v)in enumerate(accounts):
        for stamp in [0,499,500,501]:
            period_base,period_scale=[(10,0),(5,2),(0,0),(MASK,1)][j%4]
            s={'aux':A,'context_count':1,'priority':[0,31,95,255][j%4],'policy':p,'active':active,
              'period_base':period_base,'period_scale':period_scale,'now':500,'epoch':[0,1,499,500,501,244][j%6],
              'count':7,'u':u,'v':v,'limit':[0,10,1000,MASK][j%4],'divisor':div,'cached':3 if j&1 else 300,'stamp':stamp}
            m=case(code,s);record(m);totals['full_score_canvases']+=1
    for priority in [0,31,95,255]:
        s={'aux':A,'context_count':0,'priority':priority,'policy':5,'active':1,'period_base':1,'period_scale':0,
          'now':500,'epoch':1,'count':7,'u':10,'v':20,'limit':1000,'divisor':8,'cached':3,'stamp':1}
        m=case(code,s);record(m);totals['empty_context_canvases']+=1
    # One low-lane and one high-lane mismatch at each original CASP. The
    # injected writer is test input; only the target's ensuing retry executes.
    base={'aux':A,'context_count':1,'priority':31,'policy':1,'active':1,'period_base':10,'period_scale':0,
      'now':500,'epoch':10,'count':7,'u':100,'v':200,'limit':1000,'divisor':8,'cached':3,'stamp':1}
    for elapsed in [0,1,254,255,256,257,511,512,65535,MASK-1]:
     for period in [0,1,2,10]:
        s=dict(base);s.update(now=elapsed+1,epoch=1,period_base=period)
        m=case(code,s);record(m);totals['period_boundary_canvases']+=1
    scripts=[{'period':[(9,10)]},{'period':[(7,20)]},{'period':[(7,600)]},
      {'account':[(101,200)]},{'account':[(100,201)]},
      {'cache':[(4,1)]},{'cache':[(3,2)]},{'cache':[(4,500)]},
      {'period':[(9,20)],'account':[(101,201)],'cache':[(4,2)]}]
    for script in scripts:
        m=case(code,base,script);record(m);totals['controlled_retry_canvases']+=1
    # A source-derived wake producer adds bounded stopped time to the very
    # same A+0x58 input subsequently consumed by the score policy.
    for epoch in [50,107,200]:
     for cap in [0,37,1000]:
      for div in [0,8]:
        s=dict(base);s.update(active=0,epoch=107,now=207,limit=cap,divisor=div,u=10,v=20)
        m=private(code,s)
        for at,n in [(T,0x610),(D,0x400),(CURRENT,0x700),(CPU,0x100)]:canvas(m,at,n)
        # Relocate the auxiliary base to D+0x60+112*2 and retain that identity.
        a=D+0x60+224;s['aux']=a;fields(m,a,s);m.store(X,8,a)
        for at,n,v in [(T+0x298,8,D),(T+0x204,1,2),(T+0x2a0,8,0),(a+0x20,8,0),(a+0x28,8,epoch),
          (CURRENT+0x1c0,8,CPU),(CPU+0x58,8,7),(0xfffffe000cad06a0,4,9)]:m.store(at,n,v)
        m.raw_clock=100;m.put('x0',T);m.put('lr',STOP);run(m,INC,STOP,300)
        assert m.load(a+0x20,8)==1 and m.load(a+0x28,8)==MASK and m.get('w0')==10
        added=min(107-epoch,cap)if 107>epoch else 0
        assert m.load(a+0x58,8)==20+added
        s['v']+=added;want,score,events=oracle(s)
        before=bytearray(snapshot(m,a,112))
        for off,key in [(0x30,'count'),(0x38,'epoch'),(0x40,'cached'),(0x48,'stamp'),(0x50,'u'),(0x58,'v')]:patch(before,off,8,want[key])
        m.pair_observations=[];m.put('x0',X);m.put('x1',207);m.put('lr',STOP);run(m,SCORE,STOP,1000)
        assert m.get('w0')==score and snapshot(m,a,112)==bytes(before)and m.pair_observations==events
        record(m);totals['wake_then_score_canvases']+=1
    # The original constructor/backend and tail-rekey execute with policy on;
    # generation observations are equal so that separate refresh is skipped.
    for p in range(1,6):
     for lane in range(3):
      for flags in [0,2]:
       for u,v in [(10,20),(20,10)]:
        kind=p;offset=1;typ=lane
        old,x,a=setup(code,kind,p,lane,typ,31,20,offset,0,False)
        m=PolicyIntegers(code);m.__dict__.update(old.__dict__)
        s=dict(base);s.update(aux=a,policy=p,active=0,now=107,epoch=107,count=1,u=u,v=v,
          limit=10,divisor=8,cached=offset,stamp=0,priority=20,period_base=10,period_scale=0)
        fields(m,a,s);m.store(a+0x30,8,0);m.store(a+0x38,8,77);m.store(a+4,4,0);m.store(0xfffffe000cadd66c,4,0)
        extents,want=expected_first(m,x,a,kind,p,lane,typ,31,20,offset,flags,False)
        first,score,events=oracle(s)
        def expect(at,n,value):
            owner=next(b for b,size in extents if b<=at and at+n<=b+size);patch(want[owner],at-owner,n,value)
        for off,key in [(0x38,'epoch'),(0x40,'cached'),(0x48,'stamp'),(0x50,'u'),(0x58,'v')]:expect(a+off,8,first[key])
        m.put('x0',U);m.put('x1',T);m.put('x2',flags);m.put('lr',STOP);run(m,BACKEND,STOP,2500)
        compare(m,extents,want,('active-policy-first',p,lane,flags,u,v));assert m.get('w0')==1
        from audit_aes_uncached_context_queue import thread
        thread(m,T2,kind,64,40,lane)
        extents,want,result=expected_second(m,x,a,kind,p,lane,typ,31,20,64,40,offset,flags)
        s=dict(first);s.update(active=1,now=207,count=2,priority=40)
        second,score,events=oracle(s);predicted=40+offset;g=PSET+0xaf8+1112*p
        for off,key in [(0x38,'epoch'),(0x40,'cached'),(0x48,'stamp'),(0x50,'u'),(0x58,'v')]:expect(a+off,8,second[key])
        expect(g+0x20+8*predicted,8,0);expect(g+0x20+8*score,8,x+0xa0)
        for bank in range(2):expect(g+0x10+8*bank,8,(1<<(score%64))if bank==score//64 else 0)
        expect(g+8,4,score);expect(x+0xc1,1,score)
        m.raw_clock=200;m.put('x0',U);m.put('x1',T2);m.put('x2',flags);m.put('lr',STOP);run(m,BACKEND,STOP,2500)
        compare(m,extents,want,('active-policy-second',p,lane,flags,u,v));assert m.get('w0')==result==1
        assert m.load(ACTIVE+4*p,4)==1
        record(m);totals['policy_backend_compositions']+=1
    tables=[(0xfffffe000ca90690,0xfffffe000cb628d0),(0xfffffe000ca906a8,0xfffffe000cb628a0),
      (0xfffffe000ca906c0,SCALE),(0xfffffe000ca906d8,PERIOD)]
    observations={int(r['address'],16):bytes.fromhex(r['bytes_hex'])for r in e['file_global_observations']}
    for frequency in [0,1,24000000,1000000000,0xffffffff]:
     for status in [0,1]:
      for value in [0,8,255]:
        m=PolicyIntegers(code)
        for j in range(31):m.put('x'+str(j),0x100+j)
        m.put('sp',STACK);m.put('lr',STOP);canvas(m,STACK-0x80,0x100)
        m.store(0xfffffe0007f8b6e8,8,0x9c0000);m.store(0xfffffe000ca8c000,4,frequency)
        m.option_status=status;m.option_value=value;canvas(m,DIVISOR,1);m.store(DIVISOR,1,0x73)
        output=LIMIT-8;canvas(m,output,0xe0)
        for source,dest in tables:
            raw=observations[source]
            for j,b in enumerate(raw):m.memory[source+j]=b
        expected=bytearray(snapshot(m,output,0xe0));patch(expected,LIMIT-output,8,frequency//2)
        for source,dest in tables:
            raw=observations[source]
            for j in range(6):
                us=int.from_bytes(raw[4*j:4*j+4],'little');ticks=MASK if us==0xffffffff else(us*frequency)//1000000
                patch(expected,dest-output+8*j,8,ticks)
        saved={f'x{j}':m.get(f'x{j}')for j in range(19,30)}
        run(m,CONFIG,STOP,1500)
        assert m.get('sp')==STACK and all(m.get(r)==v for r,v in saved.items())
        assert m.load(DIVISOR,1)==(value if status else 8)and m.load(LIMIT,8)==frequency//2
        actual=snapshot(m,output,0xe0)
        assert actual==bytes(expected),(frequency,status,value,[(hex(output+j-16),expected[j],actual[j])for j in range(len(actual))if expected[j]!=actual[j]][:16])
        for source,dest in tables:assert bytes(m.memory[source+j]for j in range(24))==observations[source]
        assert [target for pc,target,args in m.configuration_calls]==[0xfffffe000c5e48a4,0xfffffe000bd26674]+[CONVERT]*4
        assert [(args[0],args[1])for pc,target,args in m.configuration_calls if target==CONVERT]==tables
        record(m);totals['configuration_canvases']+=1
    totals['score_instructions_visited']=len(covered&set(range(SCORE,SCORE+141*4,4)))
    assert set(range(SCORE,SCORE+141*4,4))-covered==set(range(0xfffffe000bd1ee44,0xfffffe000bd1ee74,4))
    totals['controlled_pair_mismatches']=dict(sorted(mismatches.items()))
    totals['all_checks_pass']=True;return totals


if __name__=='__main__':print(json.dumps(audit()),flush=True)
