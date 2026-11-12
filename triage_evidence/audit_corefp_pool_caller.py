#!/usr/bin/env python3
"""Independent caller replay, address-key proofs and paired arena oracle.

Does not import the new producer. O(C*(B+P*F+V*J+R)+256*K) conservative
time/space; 60000 visits/profile, SMT 30 s/query. No native target/API/IPC,
IDB operation, source-PC substitution or child-record substitution.
"""
import copy,json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
from audit_corefp_lookup_initialization import Replay as Frozen,initial_page,declared_inputs,frame,restore,unpack,ret,CS
from audit_corefp_pool_allocator import source_checks as pool_source,sdk_checks
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE,BIND
from verify_daemon_reader_record_payloads_publication import read
SHA=lambda b:sha256(b).hexdigest();M=(1<<64)-1
ENTRY=0x1af6b8;REC=0x63000100;OUT=0x63000300;HEAP=0x64000000;ARENA=0x64002000;DONE=0x65000000;SP=0x62018000
CHILD=0x62017f78;PAIR=0x62017ef8;TOKEN=0x1d33108;SELECTOR=0x1d44409;HOLDER=0x1d32dd0
POINTS={0x1af928:'entry_dispatch',0x1afe90:'length_gate',0x1affb0:'first_allocation_call',0x1bc12c:'allocation_entry',
 0x1b0080:'second_allocation_call',0x1b008c:'allocation_pair_store',0x1b0168:'first_cleanup_call',0x1b01e8:'second_cleanup_call',
 0x5c87d4:'cleanup_entry',0x5c8938:'cleanup_operation_dispatch',0x1b0234:'outer_marker_store'}
ATOMICS={0x1bc344:('X27','W15','W12'),0x5c8974:('X9','W17','W6')}


def expected_config(label):
    rows={'length_0':{'length_u32':0},'length_1':{'length_u32':1},'length_15':{'length_u32':15},'length_16':{},'length_32':{'length_u32':32},
      'selector_two':{'selector_u8':2},'selector_255':{'selector_u8':255},'malloc_null_16':{'empty_holder':True},
      'malloc_null_32':{'empty_holder':True,'length_u32':32},'backed_16':{'empty_holder':True,'malloc_success':True},
      'backed_32':{'empty_holder':True,'malloc_success':True,'length_u32':32},
      'backed_clobber':{'empty_holder':True,'malloc_success':True,'clobber_callers':True},
      'forward_16':{'layout':'forward'},'overlap_reverse_16':{'layout':'overlap_reverse'},'overlap_forward_16':{'layout':'overlap_forward'},'busy_token':{'selector_u8':1,'token_u32':0xa94ef},'raw_holder_frontier':{'selector_u8':1}}
    v=rows[label];return {'label':label,'length_u32':16,'selector_u8':1 if v.get('empty_holder')else 0,'malloc_success':False,**v}


def addresses(c):
    offsets={'reverse':[256,512],'forward':[512,256],'overlap_reverse':[256,264],'overlap_forward':[264,256]}[c.get('layout','reverse')]
    return tuple(HEAP+j for j in offsets)


def overlay(c):
    src,dst=addresses(c)
    lo=REC&0xffffffff;k=((~(lo^0x2a38f3cc)^0x81e8b3a8)*0x4386951d)&0xffffffff
    b=bytearray([165]*48);struct.pack_into('<Q',b,0,HEAP+128);struct.pack_into('<I',b,12,0x7f48^k)
    struct.pack_into('<QQQ',b,16,HEAP+256,(dst+0x1bef9457ac319362)&M,src)
    struct.pack_into('<I',b,40,((c['length_u32']-0xf3d07647)&0xffffffff)^k)
    rows=[(REC,bytes(b)),(OUT,bytes(8)),(BASE+SELECTOR,bytes([c['selector_u8']])),(HEAP+128,b'B'*16),
      (dst,bytes([165])*64),(src,bytes(range(64)))]
    if 'token_u32'in c:rows.append((BASE+TOKEN,struct.pack('<I',c['token_u32'])))
    if c.get('empty_holder'):rows.extend((BASE+HOLDER+j,struct.pack('<Q',BASE+HOLDER+48))for j in [72,80])
    return rows


def snapshot(r,label):
    return {'label':label,'CPU':frame(r.u),'record48_hex':r.ram(REC,48).hex(),'child32_hex':r.ram(CHILD,32).hex(),
      'pair16_hex':r.ram(PAIR,16).hex(),'cursor8_hex':r.ram(OUT,8).hex(),'transformed64_hex':r.ram(addresses(r.p['configuration'])[1],64).hex(),
      'holder88_hex':r.ram(BASE+HOLDER,88).hex(),'selector_u8':r.ram(BASE+SELECTOR,1)[0],'token_u32':int.from_bytes(r.ram(BASE+TOKEN,4),'little')}


class Replay(Frozen):
    def __init__(self,*args):super().__init__(*args);self.attempts=0;self.allocations=[];self.entries=[]
    def stop(self,reason,**extra):
        assert self.p['frontier']=={'reason':reason,'CPU':frame(self.u),**extra};self.done=True;self.u.emu_stop()
    def code(self,u,pc,n,d):
        self.flush();at=pc-BASE;c=self.p['configuration']
        if pc==DONE:return self.stop('ordinary_return')
        if at==0x1b0270:return self.stop('before_transform_body',source_pc=hex(at),successful_processing_established=False)
        if at in [0x1bc12c,0x5c87d4]:self.attempts=0;self.entries.append(hex(at))
        if at in ATOMICS:
            if self.attempts:return self.stop('before_second_CASAL',source_pc=hex(at),concurrent_ordering_validated=False)
            ptr,cmpreg,newreg=ATOMICS[at];a=u.reg_read(getattr(A,'UC_ARM64_REG_'+ptr));old=int.from_bytes(self.ram(a,4),'little')
            compare=u.reg_read(getattr(A,'UC_ARM64_REG_'+cmpreg));new=u.reg_read(getattr(A,'UC_ARM64_REG_'+newreg));assert (a,compare,new)==(BASE+TOKEN,0x5d96,0xa94ef)
            raw=self.ram(pc,4);i=next(CS.disasm(raw,at));assert i.mnemonic=='casal'
            assert self.p['visits'][self.v]=={'pc':hex(at),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str};self.v+=1;self.attempts+=1;e=self.event()
            assert {k:e[k]for k in ['kind','visit','pointer','old_u32','compare_u32','replacement_u32','concurrent_ordering_validated']}=={
              'kind':'declared_sequential_CASAL','visit':self.v-1,'pointer':hex(a),'old_u32':old,'compare_u32':compare,'replacement_u32':new,'concurrent_ordering_validated':False}
            self.effects(e,[(a,struct.pack('<I',new))]if old==compare else [])
            f=copy.deepcopy(e['before']);f['X31'][int(cmpreg[1:])]=hex(old);f['PC']=hex(pc+4);assert e['after']==f;restore(u,f);return
        pointer=u.reg_read(A.UC_ARM64_REG_X9)
        if at==0x1bca38 and not(c['malloc_success']and self.allocations and ARENA<=pointer<ARENA+5000):
            return self.stop('before_unbacked_node_read',source_pc=hex(at),pointer=hex(pointer),access_offset_B=8,access_size_B=8,native_read_executed=False)
        if at in POINTS:self.point(snapshot(self,POINTS[at]))
        if pc in self.imports:
            name=self.imports[pc];call=u.reg_read(A.UC_ARM64_REG_LR)-4-BASE;args=[u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))for j in range(8)]
            assert name=='_malloc'and call==0x1bcf5c and args[0]==5000 and len(self.allocations)<2
            value=ARENA if c['malloc_success']else 0;assert not value or not self.allocations;e=self.event()
            assert e['kind']=='declared_API'and e['name']==name and e['callsite']==hex(call)and e['args_x0_x7']==list(map(hex,args))and e['return_u64']==hex(value)
            self.effects(e,[(ARENA,bytes([165])*5000)]if value else []);self.allocations.append({'pointer':hex(value),'size_B':5000})
            f=ret(e['before'],value,c.get('clobber_callers',False));assert e['after']==f;restore(u,f);return
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=60001);self.flush();assert self.done
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi]==[len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points']]
        assert self.entries==self.p['child_entries']and self.allocations==self.p['allocations']and snapshot(self,'frontier')==self.p['final_state']
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==unpack(row['payload'])
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,
          'points_checked':self.pi,'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def oracle(p,r,s):
    c=p['configuration'];n=c['length_u32'];label=c['label'];busy=label=='busy_token';raw=label=='raw_holder_frontier';backed=c['malloc_success'];early=n in [0,1,15]
    reason='before_second_CASAL'if busy else 'before_unbacked_node_read'if raw else 'before_transform_body'if backed else 'ordinary_return'
    assert p['frontier']['reason']==reason
    pages={int(v['address'],16):unpack(v['payload'])for v in p['initial_RAM']};fetch=lambda a,k:pages[a&~4095][a%4096:a%4096+k]
    record=bytearray(fetch(REC,48));root=bytearray(fetch(BASE+HOLDER,88));returns=reason=='ordinary_return'
    if returns:struct.pack_into('<I',record,8,0x45e2a203)
    assert r.ram(REC,48)==record and r.ram(OUT,8)==bytes(8)
    mask=bytes.fromhex('064c76251492cc1a6593e6d6c53d5042')
    src,dst=addresses(c);before_src=fetch(src,64);expected_out=bytearray(fetch(dst,64))
    expected_out[:n]=bytes(v^mask[j%16]for j,v in enumerate(before_src[:n]));assert r.ram(dst,64)==expected_out
    out_writes=[w for w in p['writes']if dst<=int(w['address'],16)<dst+n]
    assert len(out_writes)==n and all(w['size_B']==1 for w in out_writes)
    assert [int(w['address'],16)for w in out_writes]==([dst+j for j in range(n)]if src>dst else [dst+j for j in range(n-1,-1,-1)])
    entries=[v for v in p['points']if v['label']=='allocation_entry'];cleans=[v for v in p['points']if v['label']=='cleanup_entry']
    assert len(entries)==(0 if early else 1 if busy or raw else 2)and len(cleans)==(2 if returns and not early else 0)
    requests=[];parent_calls=[]
    k=((CHILD^0xcf834db9ae8c9498)*0x9e8a2055)&M
    for j,v in enumerate(entries):
        b=bytes.fromhex(v['child32_hex']);assert int(v['CPU']['X31'][0],16)==CHILD
        assert (int.from_bytes(b[16:20],'little')+k)&0xffffffff==0x2b9b
        size=(int.from_bytes(b[8:16],'little')+k+0xb055c0a249dc0450)&M;assert size==[1027,1031][j];requests.append(size)
        call=[0x1affb0,0x1b0080][j];assert int(v['CPU']['X31'][30],16)==BASE+call+4 and v['CPU']['SP']=='0x62017ad0'
        edge=next(e for e in p['PAC_models']if e['pc']==hex(call));assert edge['pointer_row']==s.decoded[0x1d037d0]
        parent_calls.append(hex(call))
    for j,v in enumerate(cleans):
        b=bytes.fromhex(v['child32_hex']);assert int.from_bytes(b[:8],'little')==0 and int(v['CPU']['X31'][0],16)==CHILD
        free_key=((CHILD^0x309487ae)*0x87cfdb29)&0xffffffff
        assert (int.from_bytes(b[8:12],'little')-free_key)&0xffffffff==0x88cd
        call=[0x1b0168,0x1b01e8][j];edge=next(e for e in p['PAC_models']if e['pc']==hex(call));assert edge['pointer_row']==s.decoded[0x1d036a8]
    for v in p['points']:
        if v['label']=='entry_dispatch':assert int(v['CPU']['X31'][9],16)==0x7f48
        if v['label']=='length_gate':assert int(v['CPU']['X31'][13],16)==n^0x458e3e59
        if v['label']=='cleanup_operation_dispatch':assert int(v['CPU']['X31'][1],16)==0x88cd
    pair=None;arena_B=0
    if backed:
        C=0x2fecaf1f3ee407fa;S=BASE+HOLDER+48;b=bytearray([165]*5000);struct.pack_into('<QQ',b,0,C,C+4976);struct.pack_into('<QQ',b,24,S,S)
        struct.pack_into('<QQ',b,4976,C+4976,0xafecaf1f3ee407fa)
        end=4976;nodes=[];fill_counts=[]
        for packet in [1052,1056]:
            node=end-packet-12;count=packet+76;start=end-count
            seq=bytes((((0x62017a48+j)^0xba)*(0x62017a48+j+17))&255 for j in range(count));b[start:end]=seq[::-1]
            struct.pack_into('<QQQ',b,node,C+node,C-packet-12,0x0fd0175a3240227d);struct.pack_into('<Q',b,8,C+node);struct.pack_into('<Q',b,end,C)
            nodes.append(node);fill_counts.append(count);end=node
        pair=[ARENA+v+24 for v in nodes];assert pair==[ARENA+3936,ARENA+2868]
        assert r.ram(ARENA,8192)==b+bytes(8192-5000);arena_B=8192
        assert pair[1]+1031<=pair[0]and pair[0]+1027<=ARENA+5000
        struct.pack_into('<Q',root,40,(int.from_bytes(root[40:48],'little')+2132)&M);struct.pack_into('<QQ',root,72,ARENA,ARENA)
        assert r.ram(PAIR,16)==struct.pack('<QQ',*pair)and len(p['allocations'])==1
        fill=[w for w in p['writes']if p['visits'][w['visit']]['pc']=='0x1bcd74'];assert len(fill)==sum(fill_counts)==2260 and all(w['size_B']==1 for w in fill)
        assert not any(v['pc']=='0x1b0270'for v in p['visits'])
    elif not early and not busy and not raw:pair=[0,0];assert r.ram(PAIR,16)==bytes(16)
    assert r.ram(BASE+HOLDER,88)==root and r.ram(BASE+SELECTOR,1)==bytes([c['selector_u8']])
    assert int.from_bytes(r.ram(BASE+TOKEN,4),'little')==(0xa94ef if busy or raw else 0x5d96)
    assert len(p['allocations'])==(1 if backed else 2 if c.get('empty_holder')else 0)
    assert not any(w['address']==hex(BASE+SELECTOR)for w in p['writes'])
    if returns:assert p['frontier']['CPU']['SP']==hex(SP)and p['frontier']['CPU']['X31'][19:]==p['initial_CPU']['X31'][19:]
    if raw:assert p['frontier']['pointer']=='0x176cb4e3'and not any(v['pc']=='0x1bca38'for v in p['visits'])
    return {'label':label,'entry_operation_u32':'0x7f48','length_u32':n,'source_transformed_B':n,'source_pointer':hex(src),'output_pointer':hex(dst),'direction':'forward'if src>dst else 'reverse','diagnostic_OUT_unchanged':True,'frontier':reason,
      'allocation_operation_u32':'0x2b9b','source_child_requests_B':requests,'allocation_calls':parent_calls,'cleanup_operation_u32':'0x88cd',
      'null_cleanup_calls':len(cleans),'allocation_pair_u64':list(map(hex,pair))if pair is not None else None,'arena_oracle_B':arena_B,
      'outer_marker_u32':'0x45e2a203'if returns else None,'child_record_source_produced':True,'native_ownership_established':False,'successful_processing_established':False}


def source_checks(s):
    x=z3.BitVec('R32',32);r=z3.BitVec('R64',64);n=z3.BitVec('n32',32);proofs=[]
    pairs=[('caller_entry_key_pre_multiply',(((x&0x2a38f3cc)<<1)-x+0xd5c70c33)^0x81e8b3a8,x^0x542fbf9b),
      ('first_allocation_key_pre_multiply',((0xef8c7038c0ffa580|(r<<1))-r+0x8839c7e39f802d40)^0xb84575a5cef34658,r^0xcf834db9ae8c9498),
      ('second_allocation_key_pre_multiply',(-2-((r|0x95a4aad27551005a)+(0x6a5b552d8aaeffa5|~r)))^0xa5d8189424226b3d,r^0xcf834db9ae8c9498),
      ('first_cleanup_key_pre_multiply',((x+0x567ff1a9)-((x&0x567ff1a9)<<1))^0x66eb7607,x^0x309487ae),
      ('second_cleanup_key_pre_multiply',((x+0x94e34aca)-((x&0x94e34aca)<<1))^0xa477cd64,x^0x309487ae),
      ('cleanup_reader_key_pre_multiply',((x|0x682b0cc2)+0x97d4f33d-(x|0x97d4f33d))^0x58bf8b6c,x^0x309487ae),
      ('length_counter_encoding',n+0x49e1df96-((n<<1)&0x93c3bf2c),n^0x49e1df96),
      ('length_gate_partition',z3.And((n^0x458e3e59)!=0x458e3e59,((n^0x458e3e59)&15)==9),z3.And(n!=0,(n&15)==0))]
    for name,left,right in pairs:
        q=z3.Solver();q.set(timeout=30000);q.add(left!=right);assert q.check()==z3.unsat;proofs.append({'label':name,'query':q.to_smt2(),'result':'unsat'})
    pool=0x1d05fa0;specs=[('caller_dispatch_base',0x1ac19c0,0x1c78040,0x27,0x1511,pool,0x1c81944),
      ('allocation_first',0x18ac070,0x1ac18c0,0x89,0x102ed+0x6e,0x1c81940,0x1bc12c),
      ('allocation_second',0x174f220,0x18ac170,0x37,0x102ed+0x58,0x1c81940,0x1bc12c),
      ('cleanup_first',0x18ac070,0x1ac18c0,0xc5,0x102ed+0xbe,0x1c81940,0x5c87d4),
      ('cleanup_second',0x18ac270,0x1ac1ac0,0xc8,0x102ed,0x1c81940,0x5c87d4),
      ('cleanup_token',0x18ac270,0x1ac1ac0,0xc8,6,pool,TOKEN),
      ('cleanup_selector',0x174f220,0x18ac170,11,0x13d2,pool,SELECTOR),
      ('cleanup_count',0x174f220,0x18ac170,11,0xba6,pool,0x1d36090),
      ('mask_first',0x18ac270,0x1ac1ac0,0xc8,0x1be0,pool,0x1a28d08),
      ('mask_second',0x1ac19c0,0x1c78040,0x78,0x1416,pool,0x1b2afd8),
      ('mask_third',0x174f320,0x18ac370,0xe5,0x13ea,pool,0x1687b38),
      ('reverse_mask_first',0x174f220,0x18ac170,0xa5,0x1628,pool,0x1beab48),
      ('reverse_mask_second',0x18ac070,0x1ac18c0,0x58,0xadc,pool,0x1abf4f4),
      ('reverse_mask_third',0x1ac19c0,0x1c78040,0x78,0x9fc,pool,0x1abf718)]
    banks=[]
    for label,a,b,c,bias,base,target in specs:
        aa=s.read(a,256);bb=s.read(b,256);out=[v^bb[aa[v]^c]for v in range(256)];assert len(set(out))==1
        row=base+8*(bias+out[0]);fix=s.decoded[row];assert not fix['bind']and fix['target']==hex(target)
        banks.append({'label':label,'A':hex(a),'B':hex(b),'A256_hex':aa.hex(),'B256_hex':bb.hex(),'xor_u8':hex(c),'bias':hex(bias),'base':hex(base),
          'constant_u8':hex(out[0]),'enumerated_inputs':256,'pointer_row':fix})
    tables=[s.read(0x1a28d00,16),s.read(0x1b2afd1,16),s.read(0x1687b31,16)]
    mask=bytes(((-23*j)^tables[0][j]^tables[1][j]^tables[2][j]^0xd7)&255 for j in range(16))
    assert mask.hex()=='064c76251492cc1a6593e6d6c53d5042'
    reverse_tables=[s.read(0x1beab40,16),s.read(0x1abf4f0,16),s.read(0x1abf711,16)]
    reverse_mask=bytes((69*j^reverse_tables[0][j]^reverse_tables[1][j]^reverse_tables[2][j]^0x30)&255 for j in range(16));assert reverse_mask==mask
    for j in range(16):
        for byte in range(256):
            assert ((byte^(69*j)^reverse_tables[0][j]^reverse_tables[1][j]^reverse_tables[2][j]^0x30)&255)==byte^mask[j]
            assert ((byte^((-23*j)&0xffffffff)^tables[0][j]^tables[1][j]^tables[2][j]^0xd7)&255)==byte^mask[j]
    exact={0x1af814:'ldr w9, [x0, #0xc]',0x1af820:'ldr w14, [x0, #0x28]',0x1af81c:'ldp x1, x10, [x0, #0x18]',
      0x1af858:'stur x1, [x29, #-0xd0]',0x1af85c:'add x25, x1, x14',0x1af980:'ldrb w16, [x10, x13]',0x1af984:'and x17, x13, #0xf',
      0x1afa20:'ldurb w2, [x2, #-8]',0x1afa34:'ldurb w3, [x3, #-8]',0x1afa3c:'ldurb w1, [x1, #-8]',
      0x1afa44:'mul w17, w17, w4',0x1afa48:'eor w16, w16, w17',0x1afa4c:'eor w16, w16, w2',
      0x1afa50:'eor w16, w16, w3',0x1afa58:'eor w17, w1, w17',0x1afa5c:'eor w16, w16, w17',
      0x1afbdc:'strb w17, [x2, x11]',0x1afb14:'subs x11, x11, #1',0x1afbc0:'mul w4, w7, w16',0x1afbc4:'eor w17, w17, w4',
      0x1afbc8:'eor w17, w17, w5',0x1afbcc:'eor w2, w3, w2',0x1afbd0:'eor w17, w17, w2',0x1afbd4:'eor w17, w17, #0x30',
      0x1afa68:'strb w16, [x25, x13]',0x1afa6c:'add x13, x13, #1',
      0x1afa70:'eor x15, x13, x12',0x1afa7c:'cmp x15, x16',0x1afe68:'cmp w13, w12',0x1afe6c:'ccmp w10, w11, #0, ne',
      0x1aff24:'stur w9, [x29, #-0x68]',0x1aff40:'stur x9, [x29, #-0x70]',0x1affb0:'blraa x8, x17',0x1b001c:'stur w9, [x29, #-0x68]',
      0x1b0028:'stur x8, [x29, #-0x70]',0x1b0064:'ldur x19, [x29, #-0x78]',0x1b0080:'blraa x8, x17',0x1b008c:'stp x19, x8, [x29, #-0xf8]',
      0x1b0090:'cmp x19, #0',0x1b0094:'ccmp x8, #0, #4, ne',0x1b0168:'blraa x8, x17',0x1b01e8:'blraa x8, x17',
      0x1b0234:'str w8, [x0, #8]',0x5c88b8:'ldr w17, [x0, #8]',0x5c88bc:'msub w1, w8, w9, w17',
      0x5c8974:'casal w17, w6, [x9]',0x5c8a54:'ldr x16, [x0]',0x5c8a64:'cmp x16, #0',0x5c9354:'str w8, [x9]'}
    sites=[]
    for pc,want in exact.items():
        raw=s.read(pc,4);i=next(CS.disasm(raw,pc));assert i.mnemonic+' '+i.op_str==want;sites.append({'pc':hex(pc),'bytes_hex':raw.hex(),'instruction':want})
    return {'byte_mask16_hex':mask.hex(),'mask_table16_hex':[b.hex()for b in tables],'reverse_mask_table16_hex':[b.hex()for b in reverse_tables],'byte_cases_checked':8192,'proofs':proofs,'banks':banks,'bank_inputs_checked':len(banks)*256,'exact_instructions':sites,
      'new_established_callers':['0x1affb0','0x1b0080'],'new_established_cleanup_calls':['0x1b0168','0x1b01e8'],
      'unresolved_literal_candidates_after_this_increment':533,'whole_transform_algorithm':'unknown'}


def main():
    e=json.loads(read(ROOT/'corefp_pool_caller_checks.json'));s=Pointers();assert e['generator_sha256']==SHA((ROOT/'recover_corefp_pool_caller.py').read_bytes())and e['thin_sha256']==THIN_SHA
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['base_declared_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()]
    for span in e['source_spans']:assert span==s.function(int(span['start'],16))
    totals=Counter();oracles=[]
    for p in e['profiles']:
        c=p['configuration'];assert c==expected_config(c['label']);ov=overlay(c);assert p['declared_overlay']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in ov]
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':hex(SP),'PC':hex(BASE+ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(REC);cpu['X31'][1]=hex(OUT);cpu['X31'][30]=hex(DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(4096)if a in [ARENA,ARENA+4096]else bytearray(initial_page(s,a))
            for addr,raw in ov:
                lo=max(a,addr);hi=min(a+4096,addr+len(raw))
                if lo<hi:b[lo-a:hi-a]=raw[lo-addr:hi-addr]
            assert unpack(row['payload'])==b;totals['initial_RAM_B_checked']+=4096
        r=Replay(p,e['source_spans'],s);totals.update(r.run());oracles.append(oracle(p,r,s))
    source=source_checks(s);frozen=pool_source(s);sdk=sdk_checks()
    counts={'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points','allocations','child_entries']}}
    assert counts==e['verified_counts']and len(e['source_spans'])==3
    result={'verified_counts':counts,'independent_replay':dict(totals),'compact_oracle_profiles':len(oracles),
      'source_B_checked':sum(len(bytes.fromhex(v['bytes']))for v in e['source_spans']),'source_spans':3,
      'new_source_queries_unsat':len(source['proofs']),'frozen_pool_queries_unsat':len(frozen['proofs']),
      'bank_inputs_checked':source['bank_inputs_checked']+frozen['bank_inputs_checked'],
      'exact_instructions_checked':len(source['exact_instructions'])+len(frozen['exact_instructions']),'arena_oracle_B':sum(v['arena_oracle_B']for v in oracles),
      'SDK_compile_exit':0,'all_checks_pass':True,'native_target_executed':False}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_pool_caller_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':e['dependencies'],'frozen_auditor_dependencies':{n:SHA(read(ROOT/n).encode())for n in ['audit_corefp_pool_allocator.py','audit_corefp_lookup_initialization.py','audit_fpsd1201_predicates.py']},
      'oracles':oracles,'source_checks':source,'frozen_pool_source_checks':frozen,'SDK_assertions':sdk,'fresh_replay_completed':True,'process_exit_code':0,
      'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'full_goal_complete':False}
    (ROOT/'corefp_pool_caller_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
