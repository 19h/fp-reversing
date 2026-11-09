#!/usr/bin/env python3
"""Original MIG61471 path/record/XPC and kernel producer contracts.

Extraction O(B+F+I), parsing O(P*D) with nesting depth D<=8; retained bytes B,
fixups F,instructions I,packet bytes P. SMT cost is separate. No target execution
or host IPC/file/framework/loader calls. Analyst reads and compiler only.
"""
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,TABLE,POOL,FIXUPS,selected
from daemon_import_bindings import binding
from bootpolicy_cache_reader import uleb,Cache,Dylib
from kernel_native_reader import Kernel
from resolve_kernel_collection_interfaces import commands
from probe_arcade_subscription import RANGES


def decode_wire(data,depth=0):
    if depth>8:return None
    out=[];p=0
    while p<len(data):
        if p+10>len(data):return None
        key,tag,n=struct.unpack_from('>IHI',data,p)
        if tag not in (0x9777,0x8485,0x50db) or p+10+n>len(data):return None
        raw=data[p+10:p+10+n];r={'offset_bytes':p,'key':hex(key),'tag':hex(tag),'payload_size_bytes':n,'payload_hex':raw.hex()}
        if tag==0x9777:
            if n!=4:return None
            r.update({'raw_be_u32':hex(int.from_bytes(raw,'big')),'decoded_u32':hex(int.from_bytes(raw,'big')^0x8b3dc651)})
        elif tag==0x8485:
            if n!=8:return None
            r.update({'raw_be_u64':hex(int.from_bytes(raw,'big')),'decoded_u64':hex(int.from_bytes(raw,'big')^0x2c220a381b62f9ab)})
        elif raw:
            nested=decode_wire(raw,depth+1)
            if nested:r['nested_records']=nested
        out.append(r);p+=10+n
    return out


def length_query():
    """Direct straight-line instruction lift, SSA definitions keep size linear."""
    declarations=['(declare-fun length () (_ BitVec 32))','(declare-fun stack () (_ BitVec 64))']
    regs={'x0':'((_ zero_extend 32) length)','x22':'#x0000000000006f21','sp':'stack'};defs=[]
    def val(s,w):
        if s.startswith('#'):return f'(_ bv{int(s[1:],0)%(1<<w)} {w})'
        if s in ('wzr','xzr'):return f'(_ bv0 {w})'
        a=regs['x'+s[1:] if s.startswith('w') else s]
        return f'((_ extract 31 0) {a})' if w==32 else a
    for i in CS.disasm(IMAGE.read(0x1007cd09c,0x1d8),0x1007cd09c):
        m=i.mnemonic;ops=i.op_str.split(', ');dst=ops[0];w=32 if dst.startswith('w') else 64
        def shifted(s,modifier):
            a=val(s,w)
            if modifier:
                kind,n=modifier.split(' ');assert kind in ('lsl','lsr')
                a=f'({"bvshl" if kind=="lsl" else "bvlshr"} {a} {val(n,w)})'
            return a
        if m=='mov':expr=val(ops[1],w)
        elif m=='movk':
            shift=int(ops[2].split('#')[1],0) if len(ops)>2 else 0;mask=((1<<w)-1)^(0xffff<<shift)
            expr=f'(bvor (bvand {val(dst,w)} (_ bv{mask} {w})) (_ bv{int(ops[1][1:],0)<<shift} {w}))'
        elif m in ('add','sub','and','orr','eor'):
            op={'add':'bvadd','sub':'bvsub','and':'bvand','orr':'bvor','eor':'bvxor'}[m]
            expr=f'({op} {val(ops[1],w)} {shifted(ops[2],ops[3] if len(ops)>3 else None)})'
        elif m in ('lsl','lsr'):
            shift=val(ops[2],w)
            if not ops[2].startswith('#'):shift=f'(bvand {shift} (_ bv{w-1} {w}))'
            expr=f'({"bvshl" if m=="lsl" else "bvlshr"} {val(ops[1],w)} {shift})'
        else:raise AssertionError((hex(i.address),m,i.op_str))
        name=f'v_{i.address:x}';defs.append(f'(define-fun {name} () (_ BitVec {w}) {expr})')
        regs['x'+dst[1:] if dst.startswith('w') else dst]=f'((_ zero_extend 32) {name})' if w==32 else name
    return '\n'.join(declarations+defs+[f'(assert (not (= ((_ extract 31 0) {regs["x8"]}) (bvxor (bvadd length #x00000001) #x8b3dc651))))'])


def main():
    starts=[]
    for at,cmd,n in commands(IMAGE.data,0):
        if cmd!=0x26:continue
        off,n=struct.unpack_from('<II',IMAGE.data,at+8);raw=IMAGE.data[off:off+n];p=0;a=0x100000000
        while p<len(raw):
            d,p=uleb(raw,p)
            if not d:break
            a+=d;starts.append(a)
    extra=[(0x1003b41fc,0x1003b5724),(0x10040ebd4,0x10040fef4),(0x100460008,0x1004601d0),
        (0x10077e48c,0x10077e61c)]
    ranges=[]
    for a,z in RANGES+extra:
        raw=IMAGE.read(a,z-a);ins=list(CS.disasm(raw,a));assert len(ins)*4==z-a
        ix=bisect.bisect_right(starts,a)-1;end=starts[ix+1] if ix+1<len(starts) else None
        ranges.append({'start':hex(a),'end':hex(z),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':raw.hex(),
            'compiler_start':hex(starts[ix]),'next_compiler_start':None if end is None else hex(end),
            'complete_compiler_range':a==starts[ix] and z==end,
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]})
    branchless=next(r for r in ranges if r['start']=='0x100444dfc')
    assert len(branchless['instructions'])==5497
    assert not any(i['mnemonic'].startswith(('bl','cb','tb')) or i['mnemonic']=='b' or i['mnemonic'].startswith('b.') or i['mnemonic'] in ('svc','hvc','smc') for i in branchless['instructions'])
    A=(0x100fc4230,0x101031fa0);B=(0x100fc4130,0x101031ea0);C=(0x101031da0,0x100e99900);D=(0x100e99a00,0x100f4e390)
    banks=[]
    for label,pair,key,add,want in [('wrapper',D,0x6d,0xcc19,0x10065ffd8),
        ('logging',A,0xe4,0xcc54,'libSystem/_os_log_type_enabled'),
        ('checked path copy',D,0x9c,0xce54,'libSystem/___strcpy_chk'),
        ('anonymous CF name',D,0x9c,0xccd5,'CoreFoundation/_CFMachPortGetPort'),
        ('source path length',A,0xf3,0xcc4d,'libSystem/_strnlen'),
        ('128-byte allocation',C,0x9a,0xcb28,'libSystem/_malloc'),
        ('112-byte allocation',B,0x4e,0xcb0e,'libSystem/_malloc'),
        ('mutable byte-state helper',B,0xa3,0xcbe6,0x100444dfc),
        ('XPC connection',D,0xd7,0xcda7,'libSystem/_xpc_connection_create')]:
        r=selected(*pair,key,add);assert r['target']==(hex(want) if isinstance(want,int) else want),(label,r)
        r['label']=label;banks.append(r)
    queries={'length_including_nul':length_query(),
      'path_pointer_identity':'''(declare-fun p () (_ BitVec 64))
(assert (not (= (bvadd (bvxor p #xffdcefdcfbfbf6a5) #x002310230404095b (bvand (bvshl p #x0000000000000001) #xffb9dfb9f7f7ed4a)) p)))''',
      'service_name_equality':'''(declare-fun s () (_ BitVec 32)) (declare-fun p () (_ BitVec 32))
(assert (not (= (= (bvsub (bvadd s (bvxor p #x58a30122)) (bvand (bvshl p #x00000001) #x4eb9fdba)) #x58a30122) (= s p))))'''}
    proofs=[]
    for name,query in queries.items():
        p=ROOT/f'arcade_subscription_{name}.smt2';p.write_text('(set-logic QF_BV)\n'+query+'\n(check-sat)\n')
        result=subprocess.run(['z3','-smt2',str(p)],capture_output=True,text=True,check=True,timeout=60).stdout.strip()
        assert result=='unsat',(name,result);proofs.append({'name':name,'file':p.name,'result':result,'scope':'lifted local arithmetic only'})
    checks=[]
    for a,m,o,meaning in [(0x100005984,'str','x1, [sp, #8]','path argument'),(0x100005988,'str','w2, [sp, #0x10]','count argument'),
        (0x10000598c,'stp','x3, x4, [sp, #0x18]','opaque and decision pointer'),
        (0x10051e4f4,'str','w11, [x9]','decision initialized1 before checked copy'),
        (0x10051e558,'mov','w2, #0x400','checked-copy capacity1024'),(0x10051e560,'blraa','x8, x17','checked-copy call'),
        (0x10051e5a8,'blraa','x8, x17','CF name query after copy'),(0x1007cd098,'blraa','x8, x17','strnlen call'),
        (0x1007cd2f4,'stp','x25, x9, [x23, #0x30]','path pointer at record+56'),
        (0x1007cd30c,'stp','w8, w24, [x23, #0x48]','encoded inclusive length and mode2'),
        (0x1003b42d4,'str','x0, [x23]','publish58-byte buffer'),(0x1003b43c4,'str','x0, [x28]','publish101-byte buffer'),
        (0x10040fcf8,'blraa','x8, x17','xpc_add_bundle'),(0x10040fdb0,'blraa','x12, x17','xpc_connection_create'),
        (0x10077e5c4,'blraa','x9, x17','set dictionary data'),(0x10077e614,'blraa','x8, x17','synchronous XPC send call')]:
        raw=IMAGE.read(a,4);i=next(CS.disasm(raw,a));assert (i.mnemonic,i.op_str)==(m,o),(hex(a),i.mnemonic,i.op_str)
        checks.append({'address':hex(a),'bytes':raw.hex(),'mnemonic':m,'operands':o,'meaning':meaning})
    live=json.loads((ROOT/'arcade_subscription_live_ida_bytes.json').read_text())
    for r in live['results']:assert bytes.fromhex(r['bytes'])==IMAGE.read(int(r['address'],16),r['size_read'])
    imports=[]
    wanted={'libSystem/___strcpy_chk','libSystem/_strnlen','libSystem/_malloc','libSystem/_free','libSystem/_xpc_add_bundle',
        'libSystem/_xpc_connection_create','libSystem/_xpc_connection_set_event_handler','libSystem/_xpc_connection_resume',
        'libSystem/_xpc_dictionary_create','libSystem/_xpc_dictionary_set_data','libSystem/_xpc_connection_send_message_with_reply_sync',
        'libSystem/__dispatch_main_q','libSystem/__NSConcreteGlobalBlock'}
    for a,r in FIXUPS.items():
        if r['target'] in wanted:imports.append(binding(a))
    k=Kernel();kf=[k.function(a) for a in [0xfffffe000bce1a64,0xfffffe000c36e108,0xfffffe000bd7e084,0xfffffe000bd3ee28]]
    strings=[]
    for a in [0xfffffe00070bee64,0xfffffe000711b8c1,0xfffffe000711b8f2,0xfffffe000711b922]:
        b=k.read(a,180).split(b'\0')[0];strings.append({'address':hex(a),'text':b.decode(),'bytes':b.hex()})
    kc_checks=[]
    for a,m,o,meaning in [(0xfffffe000bce1d34,'bl','#0xfffffe000bd7e084','current thread read-only view'),
        (0xfffffe000bce1d38,'ldr','x27, [x0, #0x18]','process-like pointer'),
        (0xfffffe000bce1d6c,'bl','#0xfffffe000c36e108','path producer result not checked before VM copy'),
        (0xfffffe000bce1da0,'ldr','x3, [x27, #0x5a0]','opaque u64 source field'),
        (0xfffffe000bce1ed8,'cmp','w8, #1','word1 selects task action on status0'),
        (0xfffffe000bce1eac,'bl','#0xfffffe000bd3ee28','task teardown action'),
        (0xfffffe000bd3ef4c,'strb','wzr, [x20, #0x14]','task action clears active-like byte')]:
        b=k.read(a,4);i=next(k.cs.disasm(b,a));assert (i.mnemonic,i.op_str)==(m,o),(hex(a),i.mnemonic,i.op_str)
        kc_checks.append({'address':hex(a),'bytes':b.hex(),'mnemonic':m,'operands':o,'meaning':meaning})
    source={'path':str(SOURCE),'sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest()}
    out={'scope':__doc__,'source':source,'ranges':ranges,'banks_256':banks,'proofs':proofs,'native_instruction_checks':checks,
        'original_import_bindings':imports,'live_ida_ranges_matched':len(live['results']),
        'kernel':{'sha256':k.sha256,'ranges':kf,'native_instruction_checks':kc_checks,'strings':strings,
            'exact_symbols':k.symbols({0xfffffe000bf41098,0xfffffe000bf3aa1c,0xfffffe000bf3f7d0,0xfffffe000bf76b80})},
        'xpc':{'bundle':IMAGE.read(0x101027868,256).split(b'\0')[0].decode(),'connection_name':IMAGE.read(0x100f5db60,128).split(b'\0')[0].decode(),
            'event_block_address':'0x101039d50','event_block_original_bytes':IMAGE.read(0x101039d50,32).hex(),'event_callback':'0x100460008',
            'request_key':'data','wire_schema_semantic_key_names':'unknown'},
        'native_target_executed':False,'target_host_operations_executed':False,'full_goal_complete':False}
    (ROOT/'arcade_subscription_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'daemon_ranges':len(ranges),'kernel_ranges':len(kf),'banks_256':len(banks),'proofs_unsat':len(proofs),'fresh_ida_ranges':len(live['results'])}))


if __name__=='__main__':main()
