#!/usr/bin/env python3
"""Independent original-instruction compact runqueue interpretation.

No new generator or Z3 import. Private queue/thread snapshots, logical PAC,
returning lock assertions and single-RMW class counters are declared. No native
scheduler, queue ownership, atomic, interrupt or IPC operation executes.
O(cases*(source visits+canvas bytes)) time; O(code+private bytes) space.
"""
import json
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG
from audit_aes_block_wake_handshake import HandshakeIntegers, seed, T, U, PSET, CURRENT
from audit_startup_dispatch import run, STACK, STOP
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read

Q=0x410000;CLASSIFICATION=0xfffffe000cad06a8
ENQUEUE=0xfffffe000bd2d5cc;BACKEND=0xfffffe000bd207c4


class QueueIntegers(HandshakeIntegers):
    def __init__(self,code):
        super().__init__(code);self.source_entries=[]

    def step(self,pc):
        i=self.code[pc];o=i.operands
        if i.mnemonic=='ands':
            self.visits+=1;value=self.value(i,o[1])&self.value(i,o[2])
            self.put(i.reg_name(o[0].reg),value);self.flags=(value,0,self.width(i.reg_name(o[0].reg)))
            self.explicit_nzcv=None;return pc+4
        if i.mnemonic=='bl'and o[0].imm&((1<<64)-1)in [BACKEND,0xfffffe000bd2173c]:
            self.visits+=1;target=o[0].imm&((1<<64)-1);self.put('lr',pc+4)
            self.source_entries.append((pc,target));return target
        if i.mnemonic=='b'and o[0].imm&((1<<64)-1)==0xfffffe000bd0b348:
            self.visits+=1;assert self.get('x0')==PSET+0x100
            self.boundaries.append((pc,0xfffffe000bd0b348,(self.get('x0'),)))
            self.clobber(pc);self.put('x0',0);return self.get('lr')
        if i.mnemonic=='ldaddh':
            self.visits+=1;names=[i.reg_name(x.reg)for x in o if x.type==ARM64_OP_REG]
            at=self.address(i,o[2]);old=self.load(at,2)
            self.store(at,2,old+self.get(names[0]));self.put(names[1],old)
            return pc+4
        return super().step(pc)


def canvas(m,at,n):
    for j in range(-16,n+16):m.memory[at+j]=(j*17+43)&255


def snapshot(m,at,n):return bytes(m.memory[at+j]for j in range(-16,n+16))


def patch(raw,off,n,value):raw[16+off:16+off+n]=(value&((1<<(8*n))-1)).to_bytes(n,'little')


def private(code,priority,flags,classified,kind):
    m=QueueIntegers(code)
    for j in range(31):m.put('x'+str(j),0x100+j)
    m.put('sp',STACK);m.put('lr',STOP)
    nodes=[0x520000+j*0x1000 for j in range(3)]
    for at,n in [(Q,0x420),(T,0x610)]+[(v,0x610)for v in nodes]:canvas(m,at,n)
    for off in range(0x420):m.memory[Q+off]=0
    m.store(T+0x214,2,priority)
    ring=nodes[:1 if kind in ['other','one']else 3 if kind=='three'else 0]
    other=(priority+1)%128
    old_priority=other if kind=='other'else priority
    for j,node in enumerate(ring):
        m.store(node,8,ring[(j+1)%len(ring)]);m.store(node+8,8,ring[(j-1)%len(ring)])
        m.store(node+0x214,2,old_priority)
    if ring:
        m.store(Q+0x20+8*old_priority,8,ring[0]);m.store(Q+8+8*(old_priority//64),8,1<<(old_priority%64))
    m.store(Q,4,old_priority if ring else 0xffffffff);m.store(Q+0x18,4,len(ring));m.store(Q+0x1c,4,0)
    for bank in range(2):m.store(CLASSIFICATION+8*bank,8,(1<<(priority%64))if classified and bank==priority//64 else 0)
    # The other bucket's priority is distinct, so its members are unclassified.
    if kind in ['one','three']and classified:m.store(Q+0x1c,4,len(ring))
    m.put('x0',Q);m.put('x1',T);m.put('w2',flags);m.writes=[]
    return m,nodes,ring


def audit():
    e=json.loads(read(ROOT/'aes_runqueue_membership_checks.json'))
    prior=json.loads(read(ROOT/'aes_event_wake_selection_checks.json'))
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    code={i.address:i for row in prior['spans']+e['spans']for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))}
    totals={'complete_enqueue_cases':0,'zero_return_insertions':0,'reciprocity_rejections':0,
      'generic_class_suffix_cases':0,'invalid_class_frontiers':0,'record_layout_cases':0,
      'complete_bound_placement_cases':0,'source_instruction_visits':0}
    for priority in range(128):
      for flags in [0,1,5,0x25]:
       for classified in [False,True]:
        for kind in ['empty','other','one','three']:
          m,nodes,ring=private(code,priority,flags,classified,kind)
          extents=[(Q,0x420),(T,0x610)]+[(v,0x610)for v in nodes]
          want={at:bytearray(snapshot(m,at,n))for at,n in extents}
          before_max=m.load(Q,4);oldmax=before_max-(1<<32)if before_max&0x80000000 else before_max
          oldcount=m.load(Q+0x18,4);oldspecial=m.load(Q+0x1c,4)
          target=ring if kind in ['one','three']else []
          patch(want[T],0,8,target[0]if target else T);patch(want[T],8,8,target[-1]if target else T)
          if target:
              patch(want[target[-1]],0,8,T);patch(want[target[0]],8,8,T)
          if not target or not(flags&1):patch(want[Q],0x20+8*priority,8,T)
          if not target:
              patch(want[Q],8+8*(priority//64),8,m.load(Q+8+8*(priority//64),8)|(1<<(priority%64)))
              if priority>oldmax:patch(want[Q],0,4,priority)
          patch(want[Q],0x18,4,oldcount+1);patch(want[Q],0x1c,4,oldspecial+classified)
          saved={f'x{j}':m.get(f'x{j}')for j in range(19,31)}
          run(m,ENQUEUE,STOP,100)
          expected_return=int(not target and priority>oldmax)
          assert m.get('x0')==expected_return and m.get('sp')==STACK
          assert all(m.get(r)==v for r,v in saved.items())
          for at,n in extents:assert snapshot(m,at,n)==bytes(want[at]),(priority,flags,classified,kind,hex(at))
          assert all(any(at<=a and a+n<=at+size for at,size in extents)for a,n,_ in m.writes)
          # Traverse the resulting selected ring, checking both reciprocal links.
          ordered=([T]+target)if not(flags&1)or not target else target+[T]
          cursor=m.load(Q+0x20+8*priority,8)
          for node in ordered:
              assert cursor==node and m.load(m.load(cursor,8)+8,8)==cursor and m.load(m.load(cursor+8,8),8)==cursor
              cursor=m.load(cursor,8)
          assert cursor==ordered[0]
          totals['complete_enqueue_cases']+=1;totals['zero_return_insertions']+=not expected_return
          totals['source_instruction_visits']+=m.visits
    for flags,trap in [(0,0xfffffe000bd2d6a8),(1,0xfffffe000bd2d6ac)]:
        m,_,ring=private(code,64,flags,False,'one');m.store(ring[0],8,0);m.writes=[]
        run(m,ENQUEUE,trap,32);assert not m.writes
        totals['reciprocity_rejections']+=1;totals['source_instruction_visits']+=m.visits
    for kind in range(6):
      for old in [0,65535]:
        initial=seed(code,bound=False);m=QueueIntegers(code);m.__dict__.update(initial.__dict__)
        for at,n,value in [(U+0x20,8,PSET),(CURRENT+0x518,4,0x1234),(PSET+0x10c,4,0x1234),(T+0x204,1,kind)]:m.store(at,n,value)
        for j in range(6):m.store(PSET+0xae8+2*j,2,old)
        m.put('x0',U);m.put('x1',T);m.put('x2',5);m.put('lr',STOP);m.writes=[]
        run(m,BACKEND,0xfffffe000bd20908,150)
        assert m.load(T+0x20,8)==U
        assert[m.load(PSET+0xae8+2*j,2)for j in range(6)]==[(old+(j>=kind))&65535 for j in range(6)]
        totals['generic_class_suffix_cases']+=1;totals['source_instruction_visits']+=m.visits
    for kind in [6,255]:
        m=QueueIntegers(code);m.put('x20',T);m.store(T+0x204,1,kind)
        run(m,0xfffffe000bd20868,0xfffffe000bd208a4,32)
        totals['invalid_class_frontiers']+=1;totals['source_instruction_visits']+=m.visits
    for kind in range(6):
      for index in [0,1,255]:
        m=QueueIntegers(code);m.put('x20',T);m.put('x26',PSET);m.put('sp',STACK)
        m.store(T+0x204,1,kind);m.store(T+0x298,8,0x740000)
        record=0x740000+0x60+112*kind;m.store(record+0x60,8,0x780000);m.store(PSET+0x85e,1,index)
        m.cut(0xfffffe000bd209ac,0xfffffe000bd209c4)
        assert m.get('x23')+8==PSET+0x2510+1112*kind
        m.cut(0xfffffe000bd209e4,0xfffffe000bd209fc);assert m.get('x8')==record
        m.cut(0xfffffe000bd20ac4,0xfffffe000bd20af4);assert m.get('x22')==0x780000+200*index
        totals['record_layout_cases']+=1;totals['source_instruction_visits']+=m.visits
    # Continue the previous placement-prefix cases through the original backend,
    # actual compact enqueue and zero-mask path of the original weight refresh.
    # CPU-context state 0, matched owners/generation and stable bound identity
    # are declared; all lock/optional helper calls remain returning ABI models.
    for flags in [5,0x25]:
      for priority in [0,20,96]:
       for classified in [False,True]:
        initial=seed(code,state=4,bound=True,count=1);m=QueueIntegers(code);m.__dict__.update(initial.__dict__)
        for at,n,value in [(0xfffffe000cacb000,8,0x11223344),(0xfffffe000cadd66c,4,7),(T+0x2e0,4,7),
          (CURRENT+0x518,4,0x1234),(PSET+0x10c,4,0x1234),(U+0x20,8,PSET),(T+0x214,2,priority),
          (CLASSIFICATION,8,(1<<(priority%64))if classified and priority<64 else 0),
          (CLASSIFICATION+8,8,(1<<(priority%64))if classified and priority>=64 else 0),
          (0xfffffe000caa2238,1,0),(U+6,1,0),(U+0x28,4,0),(PSET+0xa0,8,0),(PSET+0xa8,8,0)]:m.store(at,n,value)
        queue=U+0x2a0
        for j in range(0x420):m.memory[queue+j]=0
        m.store(queue,4,0xffffffff);m.put('x0',T);m.put('w1',flags);m.put('lr',STOP)
        saved={f'x{j}':m.get(f'x{j}')for j in range(19,30)}
        run(m,0xfffffe000bd27054,STOP,2000)
        expected=bytearray(0x420);expected[0:4]=priority.to_bytes(4,'little')
        expected[8+8*(priority//64):16+8*(priority//64)]=(1<<(priority%64)).to_bytes(8,'little')
        expected[0x18:0x1c]=(1).to_bytes(4,'little');expected[0x1c:0x20]=int(classified).to_bytes(4,'little')
        expected[0x20+8*priority:0x28+8*priority]=T.to_bytes(8,'little')
        assert bytes(m.memory[queue+j]for j in range(0x420))==bytes(expected)
        assert m.load(T,8)==m.load(T+8,8)==T and m.load(T+0x20,8)==U
        assert m.load(T+0x208,4)==3 and m.load(T+0x2b0,8)==U
        assert m.get('sp')==STACK and all(m.get(r)==v for r,v in saved.items())
        assert m.source_entries==[(0xfffffe000bd27644,BACKEND),(0xfffffe000bd27650,0xfffffe000bd2173c)]
        assert m.boundaries[-1][1]==0xfffffe000bd0b348
        totals['complete_bound_placement_cases']+=1;totals['source_instruction_visits']+=m.visits
    totals['all_checks_pass']=True;return totals


if __name__=='__main__':print(json.dumps(audit()),flush=True)
