#!/usr/bin/env python3
"""Independent initialized queues, cached backend and packed heap interpretation.

No new generator or Z3 import. Private snapshots, logical PAC, stable owner/
clock observations, returning lock assertions and scalar RMWs are declared.
No native scheduling, locking, atomic, IPC or IDB operation executes.
O(cases*(source visits+canvas bytes)) time; O(code+private bytes) space.
"""
import json
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from audit_aes_runqueue_membership import QueueIntegers, canvas, snapshot, patch, Q, CLASSIFICATION, BACKEND
from audit_aes_block_wake_handshake import seed, T, U, PSET, CURRENT, D
from audit_startup_dispatch import run, STACK, STOP
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read

INIT=0xfffffe000bd2d3cc;REFRESH=0xfffffe000bd1ee74;MERGE=0xfffffe000c48b7c0;CONSTRUCT=0xfffffe000bd212b0
MASK64=(1<<64)-1;MASK48=(1<<48)-1


class CachedIntegers(QueueIntegers):
    def __init__(self,code):super().__init__(code);self.entered=[]

    def step(self,pc):
        i=self.code[pc];o=i.operands
        if i.mnemonic=='movi'and i.op_str=='d8, #0x000000ffffffff':
            self.visits+=1;self.put('d8',0xffffffff);return pc+4
        if i.mnemonic=='rbit':
            self.visits+=1;src=self.get(i.reg_name(o[1].reg));n=self.width(i.reg_name(o[1].reg))
            self.put(i.reg_name(o[0].reg),int(f'{src:0{n}b}'[::-1],2));return pc+4
        if i.mnemonic=='bl'and o[0].imm&MASK64 in [INIT,0xfffffe000bd2d5cc,REFRESH,MERGE]:
            self.visits+=1;target=o[0].imm&MASK64;self.put('lr',pc+4);self.entered.append((pc,target));return target
        return super().step(pc)


def plain(code):
    m=CachedIntegers(code)
    for j in range(31):m.put('x'+str(j),0x100+j)
    m.put('d8',0x123456789abcdef0);m.put('d9',0xfedcba9876543210)
    m.put('sp',STACK);m.put('lr',STOP)
    for j in range(-4096,128):m.memory[STACK+j]=(j*13+31)&255
    return m


def cached(code,kind,priority,flags,classified,configuration,skip_deadline):
    initial=seed(code,bound=False);m=CachedIntegers(code);m.__dict__.update(initial.__dict__)
    for j in range(-16,0x620):m.memory.setdefault(T+j,(j*17+43)&255)
    canvas(m,PSET,0x4000)
    for j in range(0x4000):m.memory[PSET+j]=0
    record=PSET+0x2508+1112*kind;queue=record+8;header=PSET+0x858;peer=0x520000
    canvas(m,peer,0x610)
    owner=0x920000;m.store(owner,1,3)
    m.put('d8',0x123456789abcdef0);m.put('d9',0xfedcba9876543210)
    for j in range(6):m.store(0xfffffe000cb628a0+8*j,8,0)
    m.put('x0',header);m.put('x1',owner);m.put('lr',STOP);run(m,CONSTRUCT,STOP,1200)
    oldpriority=(priority+1)%96 if configuration=='other'else priority
    ring=[]if configuration=='empty'else[peer]
    if ring:
        m.store(peer,8,peer);m.store(peer+8,8,peer);m.store(peer+0x214,2,oldpriority)
        m.store(queue,4,oldpriority);m.store(queue+8+8*(oldpriority//64),8,1<<(oldpriority%64))
        m.store(queue+0x18,4,1);m.store(queue+0x1c,4,int(classified and configuration=='one'))
        m.store(queue+0x20+8*oldpriority,8,peer)
    for at,n,value in [(U+0x20,8,PSET),(CURRENT+0x518,4,0x1234),(PSET+0x10c,4,0x1234),
      (T+0x204,1,kind),(T+0x214,2,priority),(T+0x55c,1,3),(PSET+0x85e,1,3),
      (T+0x50,1,0),(T,8,0),(T+8,8,0),(record,1,kind),(record+1,1,1),(record+2,1,skip_deadline),
      (record+0x430,8,0x400+kind),(record+0x438,8,1234),
      (header,2,oldpriority if ring else 65535),(header+0x270,8,(1<<kind)if ring else 0),
      (header+0x288,8,record+0x420 if kind and ring else 0),(PSET+0x85a,2,len(ring)),
      (PSET+0x85c,2,int(classified and configuration=='one')),
      (CLASSIFICATION,8,(1<<(priority%64))if classified and priority<64 else 0),
      (CLASSIFICATION+8,8,(1<<(priority%64))if classified and priority>=64 else 0),
      (0xfffffe000cb628d0+8*kind,8,1000+kind)]:m.store(at,n,value)
    for off in [0x53,0x54,0x55,0x56]:m.store(T+off,1,0)
    m.put('x0',U);m.put('x1',T);m.put('x2',flags);m.put('lr',STOP);m.writes=[]
    return m,record,header,peer,ring,oldpriority


def audit():
    e=json.loads(read(ROOT/'aes_cached_class_queue_checks.json'))
    prior=json.loads(read(ROOT/'aes_event_wake_selection_checks.json'))
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    code={i.address:i for row in prior['spans']+e['spans']for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))}
    totals={'initializer_canvases':0,'paired_constructor_canvases':0,'constructor_cached_backend_cases':0,'deadline_heap_compositions':0,
      'heap_merge_canvases':0,'heap_null_identity_cases':0,'cached_priority_summary_cases':0,'source_instruction_visits':0}
    for base in [Q,0x510000,0xfffffe0000500000]:
      for pattern in [0,0x55,0xff]:
        m=plain(code)
        for j in range(-16,0x440):m.memory[base+j]=pattern
        before=snapshot(m,base,0x420);m.put('x0',base);run(m,INIT,STOP,64)
        expected=bytearray(before);patch(expected,0,4,0xffffffff)
        expected[16+8:16+0x320]=bytes(0x318)
        assert snapshot(m,base,0x420)==bytes(expected)
        totals['initializer_canvases']+=1;totals['source_instruction_visits']+=m.visits
    for base in [Q,0xfffffe0000500000]:
      for pattern in [0,0x55,0xff]:
        m=plain(code);extent=0x36c0
        for j in range(-16,extent+16):m.memory[base+j]=pattern
        owner=0x920000;m.store(owner,1,0x37)
        values=[0x1000+j*0x10 for j in range(6)]
        for j,value in enumerate(values):m.store(0xfffffe000cb628a0+8*j,8,value)
        expected=bytearray(snapshot(m,base,extent))
        for off,n,value in [(0,4,65535),(4,2,0),(6,1,0x37),(8,8,owner),(0x10,8,base+0x10),(0x18,8,base+0x10)]:patch(expected,off,n,value)
        for a,z in [(0x20,0x230),(0x260,0x280),(0x280,0x29c)]:expected[16+a:16+z]=bytes(z-a)
        for j in range(6):
          for cached_type,start in [(False,0x2a0),(True,0x1cb0)]:
            r=start+1112*j
            for off,n,value in [(0,1,j),(1,1,int(cached_type)),(2,1,0),(0x440,8,MASK64),(0x448,8,values[j]),(0x450,8,0)]:patch(expected,r+off,n,value)
            patch(expected,r+8,4 if cached_type else 8,0xffffffff)
            end=0x328 if cached_type else 0x320
            expected[16+r+0x10:16+r+end]=bytes(end-0x10)
            expected[16+r+0x420:16+r+0x440]=bytes(0x20)
        saved={reg:m.get(reg)for reg in [*[f'x{j}'for j in range(19,30)],'d8','d9']}
        m.put('x0',base);m.put('x1',owner);run(m,CONSTRUCT,STOP,1200)
        assert snapshot(m,base,extent)==bytes(expected)
        assert m.get('sp')==STACK and all(m.get(reg)==value for reg,value in saved.items())
        assert len([x for x in m.entered if x[1]==INIT])==6
        totals['paired_constructor_canvases']+=1;totals['source_instruction_visits']+=m.visits
    for kind in range(6):
      for priority in [0,31,64,95]:
       for flags in [0,1,5,0x25]:
        for classified in [False,True]:
         for configuration in ['empty','one','other']:
          for skip in [0,1]:
            m,record,header,peer,ring,oldpriority=cached(code,kind,priority,flags,classified,configuration,skip)
            extents=[(PSET,0x4000),(T,0x610),(peer,0x610)]
            want={a:bytearray(snapshot(m,a,n))for a,n in extents};r=record-PSET;h=header-PSET
            target=ring if configuration=='one'else[];oldmax=oldpriority if ring else-1
            newmax=max(oldmax,priority)
            patch(want[T],0,8,target[0]if target else T);patch(want[T],8,8,target[-1]if target else T)
            if target:patch(want[peer],0,8,T);patch(want[peer],8,8,T)
            patch(want[T],0x20,8,U);patch(want[T],0x50,1,1)
            if not target or not(flags&1):patch(want[PSET],r+0x28+8*priority,8,T)
            if not target:
                patch(want[PSET],r+0x10+8*(priority//64),8,m.load(record+0x10+8*(priority//64),8)|(1<<(priority%64)))
                patch(want[PSET],r+8,4,newmax)
            patch(want[PSET],r+0x20,4,len(ring)+1)
            patch(want[PSET],r+0x24,4,int(classified)*(1+(configuration=='one')))
            patch(want[PSET],0x85a,2,len(ring)+1)
            patch(want[PSET],0x85c,2,int(classified)*(1+(configuration=='one')))
            for j in range(kind,6):patch(want[PSET],0xae8+2*j,2,1)
            patch(want[PSET],h,2,newmax)
            if not ring:
                patch(want[PSET],h+0x270,8,1<<kind)
                if kind:
                    patch(want[PSET],r+0x420,16,0);patch(want[PSET],r+0x430,8,0x400+kind)
                    patch(want[PSET],h+0x288,8,record+0x420)
                    if not skip:patch(want[PSET],r+0x438,8,1107+kind)
            saved={f'x{j}':m.get(f'x{j}')for j in range(19,30)}
            run(m,BACKEND,STOP,1000)
            assert m.get('w0')==int(newmax>oldmax)and m.get('sp')==STACK
            assert all(m.get(reg)==value for reg,value in saved.items())
            for at,n in extents:assert snapshot(m,at,n)==bytes(want[at]),(kind,priority,flags,classified,configuration,skip,hex(at))
            assert len([x for x in m.entered if x[1]==REFRESH])==1
            assert len([x for x in m.entered if x[1]==INIT])==6
            heap_calls=len([x for x in m.entered if x[1]==MERGE]);assert heap_calls==int(not ring and kind!=0)
            totals['constructor_cached_backend_cases']+=1;totals['deadline_heap_compositions']+=heap_calls
            totals['source_instruction_visits']+=m.visits
    deadlines=[0,1,7,(1<<63)-1,1<<63,MASK64]
    for high in [False,True]:
      base=0xfffffe0000800000 if high else 0x800000
      left,right,lc,rc=[base+j*0x1000 for j in range(4)];nodes=[left,right,lc,rc]
      for a in deadlines:
       for b in deadlines:
        for left_child in [False,True]:
         for right_child in [False,True]:
          m=plain(code)
          for at in nodes:canvas(m,at,0x20)
          for at,child,key,time in [(left,lc if left_child else 0,0x1234,a),(right,rc if right_child else 0,0xabcd,b)]:
              m.store(at,16,0);m.store(at+0x10,8,((child&MASK48)<<16)|key);m.store(at+0x18,8,time)
              if child:m.store(child,8,0);m.store(child+8,8,at)
          want={at:bytearray(snapshot(m,at,0x20))for at in nodes}
          winner,loser=(left,right)if a<b else(right,left);child=(lc if left_child else 0)if winner==left else(rc if right_child else 0)
          patch(want[loser],0,8,child);patch(want[loser],8,8,winner)
          if child:patch(want[child],8,8,loser)
          patch(want[winner],0,16,0);patch(want[winner],0x10,8,((loser&MASK48)<<16)|(0x1234 if winner==left else 0xabcd))
          m.put('x0',left);m.put('x1',right);run(m,MERGE,STOP,64)
          assert m.get('x0')==winner
          for at in nodes:assert snapshot(m,at,0x20)==bytes(want[at])
          totals['heap_merge_canvases']+=1;totals['source_instruction_visits']+=m.visits
      for x,y in [(0,left),(left,0),(left,left)]:
          m=plain(code);m.put('x0',x);m.put('x1',y);run(m,MERGE,STOP,16)
          assert m.get('x0')==(y if x==0 else x)and not m.writes
          totals['heap_null_identity_cases']+=1;totals['source_instruction_visits']+=m.visits
    for mask in range(64):
      for p0,p1 in [(0,1),(1,0),(20,20),(95,31)]:
        m=plain(code);canvas(m,Q,0x4000)
        for j in range(0x4000):m.memory[Q+j]=0
        for j in range(6):m.store(Q+0x1cb8+1112*j,4,p0 if j==0 else p1 if j==1 else 10+j)
        m.store(Q+0x270,8,mask);m.store(Q+0x260,8,0);m.put('x0',Q)
        run(m,REFRESH,STOP,128)
        if not mask:expected=-1
        elif mask&1:expected=max(p0,p1)if mask&2 else p0
        else:expected=next(p1 if j==1 else 10+j for j in range(1,6)if mask&(1<<j))
        assert m.load(Q,2)==expected&65535
        totals['cached_priority_summary_cases']+=1;totals['source_instruction_visits']+=m.visits
    totals['all_checks_pass']=True;return totals


if __name__=='__main__':print(json.dumps(audit()),flush=True)
