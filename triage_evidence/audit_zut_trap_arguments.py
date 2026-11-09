#!/usr/bin/env python3
"""Reconcile recorded mach_msg2 register packets with original printed hex.

Read-only supplied trace. Does not run RAX, daemon, IPC or IDA. O(T+M) time
and O(T+M) retained storage for trace bytes T and parsed message evidence M.
Unprinted message bodies are unknown, not reconstructed from register fields.
"""
import collections
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

ROOT=Path(__file__).resolve().parent
TRACE=Path('/Users/___/Downloads/zut/annotated-strace-rax-user.txt')


def main():
    data=TRACE.read_bytes();digest=hashlib.sha256(data).hexdigest()
    assert digest=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
    old=json.loads((ROOT/'zut_trace_decoded.json').read_text());assert old['trace_sha256']==digest
    lines=data.decode().splitlines();events={e['line']:e for e in old['events']}
    hd=re.compile(r'\]\s+([0-9a-f]{4,})\s+((?:[0-9a-f]{2}\s+)+)\|')
    trap=re.compile(r'pc=(0x[0-9a-f]+)\s+mach_msg2_trap\(([^)]+)\)\s*=\s*(0x[0-9a-f]+|\d+)')
    active={};packets=[];matched=[];unmatched=[];last_by_thread={};resume_pairs=[]
    for i,line in enumerate(lines,1):
        tid=re.match(r'^\[([^]]+)\]',line)
        tid=tid[1] if tid else None
        if i in events:
            e=events[i];raw=bytearray();j=i
            while j<len(lines):
                m=hd.search(lines[j])
                if not m:break
                assert int(m[1],16)==len(raw)
                raw.extend(bytes.fromhex(m[2]));j+=1
            assert bytes(raw[:e['size_bytes']]).hex()==e['message_hex']
            if e['direction']=='send':
                assert tid not in active,(i,tid)
                active[tid]=e
        m=trap.search(line)
        if not m:continue
        args=[int(x.strip(),0) for x in m[2].split(',')]
        assert len(args)==8 and all(0<=x<1<<64 for x in args)
        bits=args[2]&0xffffffff;size=args[2]>>32;mid=args[4]>>32
        row={'line':i,'thread':tid,'recorded_pc':m[1],'args_hex':[hex(x) for x in args],
             'return_bits':hex(int(m[3],0)),'message_id_bits':mid,
             'remote_name':hex(args[3]&0xffffffff),'local_name':hex(args[3]>>32),
             'voucher_name':hex(args[4]&0xffffffff),'descriptor_count':args[5]&0xffffffff,
             'receive_name':hex(args[5]>>32),'receive_size_or_vector_count':args[6]&0xffffffff,
             'priority_bits':hex(args[6]>>32),'timeout_bits':hex(args[7]),
             'vector_mode':bool(args[1]&(1<<32)),'call_class_bits':hex(args[1]&0x1e00000000)}
        if tid in active:
            e=active.pop(tid);raw=bytes.fromhex(e['message_hex'])
            hbits,hsize,remote,local,voucher,hmid=struct.unpack_from('<6I',raw)
            assert (bits,args[3]&0xffffffff,args[3]>>32,args[4]&0xffffffff,mid)==(hbits,remote,local,voucher,hmid),(i,e['line'])
            count=struct.unpack_from('<I',raw,24)[0] if hbits&0x80000000 and args[1]&1 else 0
            assert args[5]&0xffffffff==count
            if not row['vector_mode']:assert size==hsize
            row['printed_send_line']=e['line'];row['header_and_descriptor_fields_match']=True
            row['recorded_receive_name_equals_header_local']=args[5]>>32==local
            matched.append(row)
        else:
            row['printed_message_body']='not newly printed; current buffer bytes unknown at this record'
            previous=last_by_thread[tid]
            assert previous['args_hex']==row['args_hex'] and previous['return_bits']=='0x80000001' and row['return_bits']=='0x0'
            row['same_packet_as_line']=previous['line'];row['associated_printed_send_line']=previous['printed_send_line']
            between=list(enumerate(lines[previous['line']:i-1],previous['line']+1))
            receives=[n for n,s in between if 'rax-user: bridge: received id ' in s]
            sends=[n for n,s in between if 'rax-user: bridge: sent id ' in s]
            assert len(receives)==1 and not sends
            resume_pairs.append({'first_trap_line':previous['line'],'second_trap_line':i,
                'printed_send_line':previous['printed_send_line'],'arguments_identical':True,
                'first_return_bits':'0x80000001','second_return_bits':'0x0',
                'intervening_bridge_receive_lines':receives,'intervening_bridge_send_lines':sends})
            unmatched.append(row)
        packets.append(row)
        last_by_thread[tid]=row
    assert not active and len(packets)==27 and len(matched)==22 and len(unmatched)==5
    rax=Path('/Users/___/dev/rax')
    source=[]
    slices=[('src/user/darwin/syscall/mach/mod.rs',37,91),('src/user/darwin/syscall/mach/msg.rs',293,356),
            ('src/user/darwin/arch.rs',518,534),('src/user/darwin/syscall/trace.rs',60,85)]
    for rel,start,end in slices:
        raw=(rax/rel).read_bytes();text=raw.decode().splitlines()
        source.append({'path':str(rax/rel),'sha256':hashlib.sha256(raw).hexdigest(),
                       'start_line':start,'end_line':end,'snippet':'\n'.join(text[start-1:end])})
    mod=(rax/'src/user/darwin/syscall/mach/mod.rs').read_text()
    msg=(rax/'src/user/darwin/syscall/mach/msg.rs').read_text()
    arch=(rax/'src/user/darwin/arch.rs').read_text()
    assert 'pub const RESTART: KernReturn = i32::MIN + 1;' in mod
    assert mod.index('super::trace::print(ctx.thread.tid')<mod.index('match r {\n        JUST_RETURN')
    assert 'RESTART => ctx.thread.cpu.restart_syscall()' in mod
    assert 'send.as_ref().filter(|_| step == 0)' in msg and 'Err(w) => park(ctx, w, 1)' in msg
    assert 'self.set_pc(pc.wrapping_sub(len))' in arch and 'DarwinCpu::Arm64(_) => 4' in arch
    head=subprocess.run(['git','-C',str(rax),'rev-parse','HEAD'],check=True,capture_output=True,text=True).stdout.strip()
    status=subprocess.run(['git','-C',str(rax),'status','--short','--',*[x[0] for x in slices]],check=True,capture_output=True,text=True).stdout
    out={'scope':__doc__,'trace_path':str(TRACE),'trace_sha256':digest,
         'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'prior_hex_decoder_sha256':hashlib.sha256((ROOT/'analyze_zut_trace.py').read_bytes()).hexdigest(),
         'raw_svc_records':len(packets),'printed_hex_headers_rechecked':len(events),'matched_sends':len(matched),
         'unprinted_body_packets':unmatched,'packets':packets,
         'identical_packet_resume_pairs':resume_pairs,
         'candidate_rax_source':{'head':head,'selected_path_status':status,'files':source,
             'restart_i32_bits':'0x80000001','source_mutated':False,'historical_producer_match_attested':False},
         'call_classes':dict(collections.Counter(p['call_class_bits'] for p in packets)),
         'recorded_pc_counts':dict(collections.Counter(p['recorded_pc'] for p in packets)),
         'native_target_executed':False,'trace_producer_version':'unknown',
         'historical_library_uuid_attested':False}
    (ROOT/'zut_trap_argument_audit.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'raw_trap_records':len(packets),'matched_hex_sends':len(matched),
        'unprinted_ids':[p['message_id_bits'] for p in unmatched],'classes':out['call_classes'],
        'recorded_pcs':out['recorded_pc_counts']}))


if __name__=='__main__':main()
