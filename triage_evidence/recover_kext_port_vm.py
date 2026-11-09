#!/usr/bin/env python3
"""Recover bounded kext port/VM contracts from original code and collection.

No target execution. Native-to-formula translation is manually audited in the
linked report. Bank checks cover all byte inputs; SMT checks full word domains.
O(B+N+D) time/space for input bytes, symbol records, and captured instructions,
plus constant-size exhaustive checks and solver-dependent proof cost.
"""
import subprocess
from kext_port_tools import *
from resolve_kernel_collection_interfaces import CACHE,commands,macho,string


def main():
    live=json.loads((ROOT/'kext_port_vm_live.json').read_text())
    live_checks=[]
    for rec in live['ranges']:
        raw=bytes.fromhex(rec['bytes'])
        assert IMAGE.read(int(rec['start'],16),len(raw))==raw
        live_checks.append({'start':rec['start'],'bytes':len(raw),'matches':True})
    spans=[
      (0xfffffe000a606728,0xfffffe000a606d88,'frame roots and bank saves'),
      (0xfffffe000a607608,0xfffffe000a607704,'constructor initial state and CPU sentinel'),
      (0xfffffe000a60aa8c,0xfffffe000a60ae40,'port acquisition and forwarding'),
      (0xfffffe000a60ae40,0xfffffe000a60b7c8,'name extent, staging allocation/copy and VM copyin'),
      (0xfffffe000a60b7c8,0xfffffe000a60b8bc,'RPC502 selection, inputs and return continuation'),
      (0xfffffe000a60d334,0xfffffe000a60d708,'RPC700, reply guard, VM copyout and null mapping'),
      (0xfffffe000a611700,0xfffffe000a611850,'copyout failure and optional auxiliary discard'),
      (0xfffffe000a61230c,0xfffffe000a6126cc,'reply mapping installation and page wiring'),
      (0xfffffe000a615e44,0xfffffe000a615fd8,'request buffer free and acquired-port release'),
      (0xfffffe000a60ce6c,0xfffffe000a60cf10,'earlier unresolved release candidate'),
      (0xfffffe000a508e04,0xfffffe000a508e54,'named kernel VM adapters'),
    ]
    native=[]
    for a,z,label in spans:
        raw=IMAGE.read(a,z-a)
        native.append({'start':hex(a),'end':hex(z),'label':label,'bytes':raw.hex(),
          'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}
                          for i in CS.disasm(raw,a)]})
    cases=[
      ('kernel_map cell',0xfffffe0007949dd0,0xfffffe000792fbc0,0x3e,0x10e,POOL,-4,0xfffffe0007f860a8),
      ('ipc_kernel_map cell',0xfffffe0007941f60,0xfffffe000794a0d0,0x6d,0x77,POOL,-4,0xfffffe0007efa630),
      ('PAGE_SHIFT cell',0xfffffe0007949dd0,0xfffffe000792fbc0,0xd8,0x163,POOL,0,0xfffffe0007e6d9c0),
      ('strlen',0xfffffe000792fcc0,0xfffffe00079391f0,0x47,0xf03,TABLE,0,0xfffffe000bc9db70),
      ('name memcpy/memmove',0xfffffe0007949dd0,0xfffffe000792fbc0,0xd8,0xf37,TABLE,0,0xfffffe000c647f10),
      ('kmem_alloc adapter',0xfffffe0007949dd0,0xfffffe000792fbc0,0x16,0xea7,TABLE,0,0xfffffe000a508e04),
      ('request copyin adapter',0xfffffe0007949dd0,0xfffffe000792fbc0,0xd8,0xf7c,TABLE,0,0xfffffe000a508e2c),
      ('reply copyout adapter',0xfffffe000792fcc0,0xfffffe00079391f0,0x47,0xef9,TABLE,0,0xfffffe000a508e34),
      ('reply-copy discard adapter',0xfffffe000792fcc0,0xfffffe00079391f0,0x87,0xe45,TABLE,0,0xfffffe000a508e24),
      ('alternate discard selector',0xfffffe0007941f60,0xfffffe000794a0d0,5,0xef7,TABLE,0,0xfffffe000a508e24),
      ('reply wire adapter',0xfffffe000792fdc0,0xfffffe00079392f0,0x93,0xecb,TABLE,0,0xfffffe000a508e0c),
      ('request free adapter',0xfffffe000792fcc0,0xfffffe00079391f0,0x87,0xe8a,TABLE,0,0xfffffe000a508e4c),
      ('acquired-port release',0xfffffe0007941f60,0xfffffe000794a0d0,0x6d,0xefe,TABLE,0,0xfffffe000bcd0448),
    ]
    banks=[]
    for label,l,r,k,a,b,bias,want in cases:
        row=selected(l,r,k,a,b,bias);assert row['target']==hex(want)
        row['label']=label;banks.append(row)
    # Saved bank pointers are established in the captured dispatcher prefix.
    assert qword(POOL+0x458)-8==0xfffffe000792fcc0
    assert qword(POOL+0x638)-12==0xfffffe00079391f0
    assert qword(POOL+0xf50)-4==0xfffffe000792fdc0
    assert qword(POOL+0xf20)-4==0xfffffe00079392f0
    assert qword(POOL+0x2b08-0x1f00)-8==0xfffffe0007941f60
    assert qword(POOL+0x2058-0x1f00)-4==0xfffffe000794a0d0
    # Bind each named adapter's native tail stub through the original map.
    adapters=[]
    for a in [0xfffffe000a508e04,0xfffffe000a508e0c,0xfffffe000a508e24,
              0xfffffe000a508e2c,0xfffffe000a508e34,0xfffffe000a508e4c]:
        body=block(a,0x20);stub=int(body['instructions'][-1]['operands'][1:],16)
        sb=block(stub,0x30);ins=sb['instructions']
        page=int(ins[0]['operands'].split('#')[-1],16)
        delta=int(ins[1]['operands'].split('#')[-1],16)
        slot=page+delta;target=qword(slot)
        symbol=next(x for x in SYMBOLS if x['address']==hex(target))
        adapters.append({'adapter':hex(a),'stub':sb,'slot':hex(slot),
          'target':hex(target),'exact_symbols':symbol['exact_symbols'],
          'original_slot_provenance':[x for x in symbol['slot_provenance'] if x['slot']==hex(slot)]})
    data=CACHE.read_bytes()
    assert hashlib.sha256(data).hexdigest()=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
    root=macho(data,0,'collection')
    def collection_range(a,z,label):
        s=next(s for s in root['segments'] if s['address']<=a and z<=s['address']+s['file_size'])
        off=s['file_offset']+a-s['address'];raw=data[off:off+z-a]
        return {'start':hex(a),'end':hex(z),'label':label,'file_offset':off,'bytes':raw.hex(),
          'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}
                          for i in CS.disasm(raw,a)]}
    transport=[collection_range(0xfffffe000bcf5f18,0xfffffe000bcf5f24,'mig_get_reply_port returns NULL'),
               collection_range(0xfffffe000bcf5e28,0xfffffe000bcf5e3c,'kext RPC wrapper delegates to common transport')]
    wanted={0xfffffe0007f860a8,0xfffffe0007efa630};globals_found=[]
    for at,c,n in commands(data,0):
        if c!=0x80000035:continue
        va,off,ident,res=struct.unpack_from('<QQII',data,at+8)
        e=macho(data,off,string(data,at+ident))
        if 'symtab' not in e:continue
        so,ns,st,ss=e['symtab']
        for j in range(ns):
            sx,ty,se,ds,v=struct.unpack_from('<IBBHQ',data,so+16*j)
            if v in wanted and sx and sx<ss:
                original=next(x for x in SYMBOLS if int(x['address'],16)==v+4)
                globals_found.append({'address':hex(v),'exact_symbol':string(data,st+sx),
                  'entry':e['name'],'stored_biased_address':hex(v+4),
                  'native_adjustment':-4,'original_slot_provenance':original['slot_provenance']})
    assert {x['exact_symbol'] for x in globals_found}=={'_kernel_map','_ipc_kernel_map'}
    queries={
      'filename_extent':'''(declare-fun n () (_ BitVec 32))
(define-fun w () (_ BitVec 32) (bvadd n #x4c6734f9))
(define-fun widened () (_ BitVec 64)
 (bvor ((_ zero_extend 32) w)
  (ite (bvult w #x4c6734f8) #x0000000100000000 #x0000000000000000)))
(define-fun decoded () (_ BitVec 64)
 (bvadd widened #x3332e64213b7c9a8 #xcccd19bd9fe10160))
(assert (not (= decoded ((_ zero_extend 32) (bvadd n #x00000001)))))''',
      'copyin_status':'''(declare-fun r () (_ BitVec 32))
(define-fun folded () (_ BitVec 32)
 (bvadd (bvxor r #xdb9cfadf) (bvand (bvshl r #x00000001) #xb739f5be)))
(assert (not (= (= folded #xdb9cfadf) (= r #x00000000))))''',
      'rpc_status':'''(declare-fun r () (_ BitVec 32))
(define-fun folded () (_ BitVec 32)
 (bvsub (bvadd r #x31ae0066) (bvand (bvshl r #x00000001) #x635c00cc)))
(assert (not (= (= folded #x31ae0066) (= r #x00000000))))''',
    }
    proofs=[]
    for name,body in queries.items():
        p=ROOT/f'kext_port_vm_{name}.smt2';p.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        answer=subprocess.run(['z3','-smt2',str(p)],check=True,text=True,capture_output=True).stdout.strip()
        assert answer=='unsat',(name,answer);proofs.append({'name':name,'file':p.name,'result':answer})
    # One complete local post-RPC rejection route; aliases are conditional on
    # the inherited frame/records and ordinary callee preservation.
    s=0x3e784ff5
    assert (0xc187b00c+s)&MASK32==1
    branch_expect={0x206:0xfffffe000a60d3d0,0x267:0xfffffe000a60d420,
      0x977:0xfffffe000a60d51c,0x207:0xfffffe000a615e44,
      0x163:0xfffffe000a60d588,0xcff:0xfffffe000a611700,
      0xd14:0xfffffe000a60d648,0x258:0xfffffe000a615e44,
      0x264:0xfffffe000a6117cc,0x26d:0xfffffe000a615e44,
      0xbaa:0xfffffe000a60d684,0xe53:0xfffffe000a615e44}
    for ix,target in branch_expect.items():assert qword(TABLE+8*ix)==target
    assert (0x958^0x83b)==0x163
    assert ((0x163+0x7ffb5e92)&MASK32)&0xbe7cefff==s
    assert (0x163+0x101000+0xb9c)&MASK32==0x101cff
    assert (s^((0x3e784247+0xa4a)&MASK32))^0x163==0x207
    # Page wiring is reached after mapping address and count are installed.
    assert (((0xe51-0xc187bb5e)-0x2fe)&MASK32)==s
    assert (((0xc187b00c+s+0x20f)&MASK32)|8)==0x218
    assert (0x218-0x219)&MASK32==MASK32
    out={'image':str(SOURCE),'sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
      'scope':__doc__,'native_ranges':native,'live_ida_original_checks':live_checks,
      'bank_proofs':banks,'adapters':adapters,
      'collection_transport_ranges':transport,'biased_global_bindings':globals_found,
      'direct_exact_symbol_count':sum(bool(x['exact_symbols']) for x in SYMBOLS),
      'external_values':len(SYMBOLS),'remaining_without_symbol_or_native_bias_binding':[],
      'proofs':proofs,'branch_slots':[{'index':hex(ix),'target':hex(t)} for ix,t in branch_expect.items()],
      'filename_extent':'zero_extend_64((low32(strlen(name))+1) mod 2^32)',
      'release_site':'0xfffffe000a615f2c',
      'release_route_guards':['RPC status==0','CPU field !=0xabcd','reply record0 word0 !=0xbeefed02'],
      'unknowns':['all predecessor paths to host lookup and RPC','total request allocation extent',
        'all side effects and aliases of protected callees','complete normal publication/close lifetime',
        'whether the earlier 0xfffffe000a60ced8 candidate is a port release in its actual frame',
        'runtime map/port pointer values, reference balance and native round trip'],
      'target_executed':False}
    (ROOT/'kext_port_vm_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'native_ranges':len(native),'live_byte_checks':len(live_checks),'bank_proofs':len(banks),
      'adapter_bindings':len(adapters),'biased_globals':len(globals_found),
      'smt_unsat':len(proofs),'direct_symbols':out['direct_exact_symbol_count'],
      'external_values':len(SYMBOLS)}))


if __name__=='__main__':main()
