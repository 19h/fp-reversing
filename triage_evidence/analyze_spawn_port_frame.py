#!/usr/bin/env python3
"""Finite static frame-origin locator; not execution or a whole-alias proof.
Domain: explicit SP origins, MOV/ADD/SUB/CSEL, monotone 8 B spill candidates.
Unknown inputs/loads and opaque call effects are frontiers, not disjointness facts.
O(W*(D+M)+I) time, O(I*D+M) state storage; W is recorded worklist
visits, I instruction count, D bounded register-domain size, M spill map.
"""
import collections
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_IMM,ARM64_OP_MEM

def analyze(f):
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
 ins=list(cs.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)))
 assert len(ins)*4==len(bytes.fromhex(f['bytes']))
 by={i.address:j for j,i in enumerate(ins)}
 EMPTY=frozenset();WILD=frozenset({None});mem={};unresolved={};calls={};accesses={};stores={};escapes={}
 def reg(i,r):
  n=i.reg_name(r)
  if n=='fp':return 'x29'
  if n=='lr':return 'x30'
  return n
 
 def cap(vals):
  vals=frozenset(vals)
  return WILD if None in vals or len(vals)>16 or any(abs(x)>8192 for x in vals) else vals
 
 def get(st,i,o):
  if o.type!=ARM64_OP_REG:return EMPTY
  n=reg(i,o.reg);return st.get(n,EMPTY)if n=='sp'or n.startswith('x')else EMPTY
 
 def join(a,b):
  c={k:cap(a.get(k,EMPTY)|b.get(k,EMPTY)) for k in a.keys()|b.keys()}
  return {k:v for k,v in c.items()if v}
 
 def span(i,st):
  m=next((o for o in i.operands if o.type==ARM64_OP_MEM),None)
  if m is None:return EMPTY,None
  base=st.get(reg(i,m.mem.base),EMPTY)
  if not base:return EMPTY,m
  if m.mem.index:
   return WILD,m
  return cap(None if x is None else x+m.mem.disp for x in base),m
 
 def width(i):
  mn=i.mnemonic;regs=i.op_str.split('[')[0].strip().rstrip(',').split(', ')
  r=regs[0]
  if mn.endswith(('rb','urb')):w=1
  elif mn.endswith(('rh','urh','rsh','ursh')):w=2
  elif mn in ('ldrsw','ldursw'):w=4
  else:w={'x':8,'w':4,'q':16,'d':8,'s':4,'h':2,'b':1}.get(r[0],8)
  return w*(2 if mn in ('ldp','stp','ldnp','stnp')else 1),w
 
 def succ(j,i):
  mn=i.mnemonic
  if mn.startswith('ret')or mn in ('br','braa','brab'):return []
  if mn=='b':return [by[i.operands[0].imm&((1<<64)-1)]]if i.operands[0].imm&((1<<64)-1) in by else []
  if mn.startswith('b.')or mn in ('cbz','cbnz','tbz','tbnz'):
   target=i.operands[-1].imm&((1<<64)-1)
   if target not in by:
    raise AssertionError(('external conditional',hex(i.address),hex(target)))
   return [j+1,by[target]]
  return [j+1]if j+1<len(ins)else []
 
 states={0:{'sp':frozenset({0x3f0})}};q=collections.deque([0]);queued={0};steps=0;rounds=0
 while True:
  changedmem=False
  while q:
   j=q.popleft();queued.remove(j);i=ins[j];st=states[j];out=dict(st);steps+=1
   if steps>200000:raise RuntimeError('limit')
   reads,writes=i.regs_access()
   for r in writes:out.pop(reg(i,r),None)
   mn=i.mnemonic;ops=i.operands;addr,m=span(i,st)
   if m is not None and addr:
    size,lane=width(i);row={'ea':hex(i.address),'mnemonic':mn,'operands':i.op_str,'frame_offsets':sorted(addr,key=lambda x:(x is None,x or 0)),'size_bytes':size}
    accesses[i.address]=row
    # Monotone spill candidates; never infer an unknown load as a new stack origin.
    if mn in ('str','stur','stp','stnp'):
     for k,o in enumerate(ops):
      if o.type==ARM64_OP_MEM:break
      val=get(st,i,o)
      if val and lane==8:
       for x in addr:
        if x is not None:
         off=x+k*lane;new=cap(mem.get(off,EMPTY)|val)
         if new!=mem.get(off,EMPTY):mem[off]=new;changedmem=True
         stores[i.address]=row
    elif mn.startswith('ld'):
     for k,o in enumerate(ops):
      if o.type==ARM64_OP_MEM:break
      if o.type==ARM64_OP_REG and lane==8:
       val=EMPTY
       for x in addr:
        if x is not None:val=cap(val|mem.get(x+k*lane,EMPTY))
       if val:out[reg(i,o.reg)]=val
   if m is not None and not addr and mn in ('str','stur','stp','stnp'):
    vals={reg(i,o.reg):get(st,i,o)for o in ops if o.type==ARM64_OP_REG and get(st,i,o)}
    if vals:escapes[i.address]={'ea':hex(i.address),'instruction':mn+' '+i.op_str,'stored_frame_offsets':{k:sorted(v,key=lambda x:(x is None,x or 0))for k,v in vals.items()}}
   handled=False
   if mn=='mov'and len(ops)==2 and ops[0].type==ARM64_OP_REG:
    val=get(st,i,ops[1]);n=reg(i,ops[0].reg)
    if val and(n.startswith('x')or n=='sp'):out[n]=val
    handled=True
   elif mn in ('add','sub')and len(ops)==3 and ops[0].type==ARM64_OP_REG:
    val=get(st,i,ops[1]);n=reg(i,ops[0].reg)
    if val:
     out[n]=cap(None if x is None else x+(ops[2].imm*(1 if mn=='add'else -1))for x in val)if ops[2].type==ARM64_OP_IMM else WILD
    elif get(st,i,ops[2]):out[n]=WILD
    handled=True
   elif mn=='csel':
    val=cap(get(st,i,ops[1])|get(st,i,ops[2]));n=reg(i,ops[0].reg)
    if val and n.startswith('x'):out[n]=val
    handled=True
   elif mn in ('bl','blr','blraa','blrab'):
    args={n:sorted(st[n],key=lambda x:(x is None,x or 0))for n in ['x'+str(k)for k in range(8)]if st.get(n)}
    if args:calls[i.address]={'ea':hex(i.address),'instruction':mn+' '+i.op_str,'args':args}
    for k in range(19):out.pop('x'+str(k),None)
    out.pop('x30',None);handled=True
   # SP/FP adjustments, including indexed writeback.
   if m is not None and i.writeback:
    bn=reg(i,m.mem.base);val=st.get(bn,EMPTY)
    if val:
     delta=m.mem.disp if '!'in i.op_str else ops[-1].imm
     out[bn]=cap(None if x is None else x+delta for x in val)
   if not handled and m is None and mn not in ('cmp','ccmp','tst','cbz','cbnz','tbz','tbnz','pacibsp','retab','b')and not mn.startswith('b.'):
    touched={reg(i,r):st[reg(i,r)]for r in reads if st.get(reg(i,r))}
    if touched:
     unresolved[i.address]={'ea':hex(i.address),'instruction':mn+' '+i.op_str,'frame_inputs':{k:sorted(v,key=lambda x:(x is None,x or 0))for k,v in touched.items()}}
     for r in writes:
      n=reg(i,r)
      if n.startswith('x')or n=='sp':out[n]=WILD
   for k in succ(j,i):
    new=join(states.get(k,{}),out)
    if k not in states or new!=states[k]:
     states[k]=new
     if k not in queued:q.append(k);queued.add(k)
  rounds+=1
  if not changedmem:break
  q.extend(states);queued=set(states)
  if rounds>10:raise RuntimeError('roundlimit')
 def rows(d):return [d[k]for k in sorted(d)]
 resolved=[r for r in rows(accesses)if None not in r['frame_offsets']]
 dynamic=[r for r in rows(accesses)if None in r['frame_offsets']]
 overlaps=[r for r in resolved if any(o<0x2e0 and o+r['size_bytes']>0x2d0 for o in r['frame_offsets'])]
 read_overlaps=[r for r in overlaps if r['mnemonic'].startswith('ld')]
 return {'domain':'Explicit frame-origin locator with opaque loads/calls, monotone spill candidates and path-insensitive joins. No arbitrary alias or whole-kernel proof.',
  'entry_SP_from_local_frame_bytes':0x3f0,'frame_pointer_from_local_frame_bytes':0x3e0,
  'descriptor_interval':[0x250,0x2e0],'Conclave_interval':[0x2d0,0x2e0],
  'counts':{'instructions':len(ins),'CFG_reachable_instructions':len(states),'CFG_edges':sum(len(succ(j,i))for j,i in enumerate(ins)),
   'worklist_visits':steps,'spill_rounds':rounds,'memory_access_sites':len(accesses),'resolved_memory_sites':len(resolved),
   'dynamic_memory_sites':len(dynamic),'frame_argument_call_sites':len(calls),'frame_pointer_escape_stores':len(escapes),
   'spill_store_sites':len(stores),'spill_slots':len(mem),'unsupported_frame_operations':len(unresolved),
   'Conclave_overlapping_resolved_stores':len(overlaps)-len(read_overlaps),'Conclave_overlapping_resolved_loads':len(read_overlaps)},
  'accesses':rows(accesses),'dynamic_accesses':dynamic,'Conclave_overlapping_accesses':overlaps,
  'calls':rows(calls),'escapes':rows(escapes),'spill_stores':rows(stores),'unsupported_frame_operations':rows(unresolved),
  'states':{hex(ins[j].address):{k:sorted(v,key=lambda x:(x is None,x or 0))for k,v in sorted(st.items())}for j,st in sorted(states.items())}}
