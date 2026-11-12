#!/usr/bin/env python3
"""Independent whole caller replay, seven-round ARX and pool-retirement oracles.

Does not import the new producer. Context remains a declared initial fixture.
O(C*(B+P*F+V*J+R)+256*K) time/space; 150000 visits/profile and 30 s/SMT query.
No target/API/IPC, IDB operation or implicit native object construction.
"""
import json,struct,copy
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
import audit_corefp_pool_caller as C
from verify_daemon_reader_record_payloads_publication import read
ROOT=C.ROOT;SHA=lambda b:sha256(b).hexdigest();CTX=0x64004000;BASEPTR=0x1d45f60;OFFSET=0x1d44440;M=(1<<64)-1
EXTRA={0x1b0270:'transform_body_entry',0x1baf60:'context_index_input',0x1bafd8:'context_word_first',0x1bb0dc:'seven_round_ARX_end',
 0x1bb2a4:'context_second_index_input',0x1bb2b8:'context_word_second',0x1bb4f8:'context_third_index_input',0x1bb50c:'context_word_third',
 0x1b016c:'first_cleanup_return',0x1b01ec:'second_cleanup_return'}
KEYS=[0x91c8addf2d0476cf,0xced7f5beeac60162,0x9ba725ad6478ec0e,0x69ad135e9d6c5483,0x2c093d6838485baf,0x8023744e17595bd3,0x2a187c9d9de4a9c0]


def config(label):
    cases={'original_context_zero':{'context_kind':'absent'},'context_ramp_16':{},'context_ramp_32':{'length_u32':32},
      'context_clobber':{'clobber_callers':True},'context_zero_bytes':{'context_kind':'zero'},'context_changed_byte':{'context_kind':'changed'},
      'context_offset8':{'context_offset_u32':8},'context_offset16':{'context_offset_u32':16}}
    return {'label':label,'length_u32':16,'selector_u8':1,'empty_holder':True,'malloc_success':True,'context_kind':'ramp','context_offset_u32':0,**cases[label]}


def context(c):
    b=bytearray(4096)if c['context_kind']=='zero'else bytearray(j%256 for j in range(4096))
    if c['context_kind']=='changed':b[0]=128
    return bytes(b)


def overlay(c):
    rows=C.overlay(c)+[(CTX,context(c))]
    if c['context_kind']!='absent':rows.extend([(C.BASE+BASEPTR,struct.pack('<Q',CTX)),(C.BASE+OFFSET,struct.pack('<I',c['context_offset_u32']))])
    return rows


def snapshot(r,label):
    return {**C.snapshot(r,label),'arena8192_hex':r.ram(C.ARENA,8192).hex(),
      'context_pointer_u64':hex(int.from_bytes(r.ram(C.BASE+BASEPTR,8),'little')),'context_offset_u32':int.from_bytes(r.ram(C.BASE+OFFSET,4),'little')}


class Replay(C.Replay):
    def __init__(self,*args):super().__init__(*args);self.fill_seen=set()
    def point(self,row):
        row={**row,'arena8192_hex':self.ram(C.ARENA,8192).hex(),'context_pointer_u64':hex(int.from_bytes(self.ram(C.BASE+BASEPTR,8),'little')),
          'context_offset_u32':int.from_bytes(self.ram(C.BASE+OFFSET,4),'little')}
        return super().point(row)
    def code(self,u,pc,n,d):
        self.flush();at=pc-C.BASE
        if at==0x5c87d4:self.fill_seen=set()
        if at in [0x5c8cd8,0x5c9254]and at not in self.fill_seen:
            self.fill_seen.add(at);self.point(snapshot(self,'cleanup_fill_entry_'+hex(at)))
        if at==0x1bafd8 and self.p['configuration']['context_kind']=='absent':
            assert u.reg_read(A.UC_ARM64_REG_X19)==u.reg_read(A.UC_ARM64_REG_W8)==0
            return self.stop('before_uninitialized_context_read',source_pc=hex(at),base_u64='0x0',offset_u32=0,access_size_B=8,native_read_executed=False)
        if at in EXTRA:self.point(snapshot(self,EXTRA[at]))
        if at==0x1b0270:return C.Frozen.code(self,u,pc,n,d)
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(C.BASE+C.ENTRY,0,count=150001);self.flush();assert self.done
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi]==[len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points']]
        assert self.entries==self.p['child_entries']and self.allocations==self.p['allocations']and snapshot(self,'frontier')==self.p['final_state']
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==C.unpack(row['payload'])
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,
          'points_checked':self.pi,'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def arena_before_body():
    k=0x2fecaf1f3ee407fa;sent=C.BASE+C.HOLDER+48;b=bytearray([165]*5000)
    struct.pack_into('<QQ',b,0,k,k+4976);struct.pack_into('<QQ',b,24,sent,sent);struct.pack_into('<QQ',b,4976,k+4976,k+(1<<63))
    end=4976
    for packet in [1052,1056]:
        node=end-packet-12;n=packet+76
        fill=bytes((((0x62017a48+j)^0xba)*(0x62017a48+j+17))%256 for j in range(n));b[end-n:end]=fill[::-1]
        struct.pack_into('<QQQ',b,node,k+node,k-packet-12,0x0fd0175a3240227d);struct.pack_into('<Q',b,8,k+node);struct.pack_into('<Q',b,end,k);end=node
    return bytes(b)+bytes(3192)


def reg(p,j):return int(p['CPU']['X31'][j],16)
def ror(v,n):return ((v>>n)|(v<<(64-n)))&M


def oracle(p,r):
    c=p['configuration'];n=c['length_u32'];absent=c['context_kind']=='absent';pts=p['points'];by=lambda label:[x for x in pts if x['label']==label]
    pages={int(x['address'],16):C.unpack(x['payload'])for x in p['initial_RAM']};fetch=lambda a,n:pages[a&~4095][a%4096:a%4096+n]
    rec=bytearray(fetch(C.REC,48));root=bytearray(fetch(C.BASE+C.HOLDER,88));entry=by('transform_body_entry');assert len(entry)==1
    assert bytes.fromhex(entry[0]['arena8192_hex'])==arena_before_body()
    assert bytes.fromhex(entry[0]['pair16_hex'])==struct.pack('<QQ',C.ARENA+3936,C.ARENA+2868)
    assert by('allocation_entry')and len(by('allocation_entry'))==2 and len(p['allocations'])==1 and p['allocations'][0]=={'pointer':hex(C.ARENA),'size_B':5000}
    assert not any(x.get('name')not in [None,'_malloc']for x in p['models'])
    requests=[]
    key=((C.CHILD^0xcf834db9ae8c9498)*0x9e8a2055)&M
    for x in by('allocation_entry'):
        b=bytes.fromhex(x['child32_hex']);assert (int.from_bytes(b[16:20],'little')+key)&0xffffffff==0x2b9b
        requests.append((int.from_bytes(b[8:16],'little')+key+0xb055c0a249dc0450)&M)
    assert requests==[1027,1031]
    context_reads=[x for x in p['reads']if CTX<=int(x['address'],16)<CTX+4096]
    assert len(context_reads)==(0 if absent else 3*n//16)and all(x['size_B']==8 for x in context_reads)
    for x in context_reads:assert x['bytes_hex']==context(c)[int(x['address'],16)-CTX:int(x['address'],16)-CTX+8].hex()
    assert r.ram(CTX,4096)==context(c)
    assert not any(CTX<=int(w['address'],16)<CTX+4096 for w in p['writes'])
    first,second,third=by('context_word_first'),by('context_word_second'),by('context_word_third')
    assert len(first)==len(second)==len(third)==(0 if absent else n//16)
    for inputs,reads,kind in [(by('context_index_input'),first,0),(by('context_second_index_input'),second,1),(by('context_third_index_input'),third,2)]:
        if absent:continue
        assert len(inputs)==len(reads)
        for x,y in zip(inputs,reads):
            u=c['context_offset_u32'];w=(reg(x,0)if kind==0 else reg(x,8))&0xffffffff
            offset=u&0xfffffff8&(w^0xf694e362)if kind==0 else u&((w&0xfffffff8)^[0,0xebc72a90,0xfa751e48][kind])
            assert reg(y,8)==offset and reg(y,19)==CTX
    arx=0
    for start,end in zip(first,by('seven_round_ARX_end')):
        rot=reg(start,16);word=int.from_bytes(context(c)[reg(start,8):reg(start,8)+8],'little')
        for k in KEYS:a=((rot+word)&M)^k;word=a^ror(word,61);rot=ror(a,8);arx+=1
        assert reg(end,16)==a and reg(end,8)==word and reg(end,0)==rot and reg(end,26)==(rot+word)&M
    bodywrites=[w for w in p['writes']if p['visits'][w['visit']]['pc']in ['0x1b6a38','0x1b6a50']]
    assert len(bodywrites)==512 and all(w['size_B']==4 for w in bodywrites)
    for pc,base in [('0x1b6a38',C.ARENA+3936),('0x1b6a50',C.ARENA+2868)]:
        assert sorted(int(w['address'],16)for w in bodywrites if p['visits'][w['visit']]['pc']==pc)==list(range(base,base+1024,4))
    clean=by('cleanup_entry');fills1=by('cleanup_fill_entry_0x5c8cd8');fills2=by('cleanup_fill_entry_0x5c9254');returns=by('first_cleanup_return')+by('second_cleanup_return')
    arena_B=8192;fill_B=0
    if absent:
        assert p['frontier']['reason']=='before_uninitialized_context_read'and not any(x['pc']=='0x1bafd8'for x in p['visits'])
        struct.pack_into('<Q',root,40,(int.from_bytes(root[40:48],'little')+2132)&M);struct.pack_into('<QQ',root,72,C.ARENA,C.ARENA)
        assert not clean and not fills1 and not fills2 and not returns
    else:
        assert p['frontier']['reason']=='ordinary_return'and len(clean)==len(fills1)==len(fills2)==len(returns)==2
        struct.pack_into('<I',rec,8,0xba1df9db);struct.pack_into('<QQ',root,72,C.ARENA,C.ARENA)
        for j,(before,after,f1,f2)in enumerate(zip(clean,returns,fills1,fills2)):
            ptr=[C.ARENA+2868,C.ARENA+3936][j];assert int.from_bytes(bytes.fromhex(before['child32_hex'])[:8],'little')==ptr
            kf=((C.CHILD^0x309487ae)*0x87cfdb29)&0xffffffff;assert (int.from_bytes(bytes.fromhex(before['child32_hex'])[8:12],'little')-kf)&0xffffffff==0x88cd
            b=bytearray.fromhex(before['arena8192_hex'])
            count=reg(f1,5)-reg(f1,3);assert count==250 and (reg(f1,1)+reg(f1,7))&M==1 and reg(f1,6)==0x62017aa0
            assert reg(f1,4)&255==0xba
            for z in range(count):
                a=reg(f1,16)+reg(f1,5)-1-z;seed=0x62017aa0+z;assert C.ARENA<=a<C.ARENA+5000;b[a-C.ARENA]=((seed^0xba)*(seed+17))%256
            assert reg(f2,15)==166 and reg(f2,11)==0x62017a90 and reg(f2,12)==0xba
            for z in range(166):
                a=reg(f2,10)+165-z;seed=0x62017a90+z;assert C.ARENA<=a<C.ARENA+5000;b[a-C.ARENA]=((seed^0xba)*(seed+17))%256
            end=[3912,4976][j];value=0x2fecaf1f3ee407fa+end;struct.pack_into('<Q',b,8,value);struct.pack_into('<Q',b,end,value)
            assert bytes.fromhex(after['arena8192_hex'])==b;arena_B+=8192;fill_B+=416
        assert r.ram(C.ARENA,8192)==bytes.fromhex(returns[-1]['arena8192_hex'])
        assert p['frontier']['CPU']['SP']==hex(C.SP)and p['frontier']['CPU']['X31'][19:]==p['initial_CPU']['X31'][19:]
    assert r.ram(C.REC,48)==rec and r.ram(C.OUT,8)==bytes(8)and r.ram(C.BASE+C.HOLDER,88)==root
    assert r.ram(C.BASE+C.TOKEN,4)==struct.pack('<I',0x5d96)and r.ram(C.BASE+C.SELECTOR,1)==b'\1'
    src,dst=C.addresses(c);assert r.ram(dst+n,64-n)==fetch(dst+n,64-n)
    return {'label':c['label'],'frontier':p['frontier']['reason'],'requests_B':requests,'backing_B':5000,'workspace_words':512,
      'context_read_addresses':[x['address']for x in context_reads],'context_read_source_PCs':[p['visits'][x['visit']]['pc']for x in context_reads],
      'context_reads':len(context_reads),'context_fixture':c['context_kind'],'ARX_rounds_checked':arx,'arena_oracle_B':arena_B,'cleanup_fill_B_checked':fill_B,
      'retirement_order_u64':[hex(C.ARENA+2868),hex(C.ARENA+3936)]if not absent else [],'output_hex':r.ram(dst,n).hex(),
      'outer_marker_u32':None if absent else '0xba1df9db','native_context_initialization_established':False,'whole_transform_algorithm':'unknown'}


def source_checks(s):
    u,w=z3.BitVecs('offset_u32 phase_u32',32);a,b,k=z3.BitVecs('a64 b64 k64',64)
    raw=(((u&0xfffffff8)^0xe4c60ad8)&(w^0xf694e362))^(w&0xe4c60ad8)^0xe4840240;reduced=(u&0xfffffff8)&(w^0xf694e362)
    indices=[reduced,u&((w&0xfffffff8)^0xebc72a90),u&((w&0xfffffff8)^0xfa751e48)]
    ap=(z3.RotateRight(a,8)+b)^k;bp=z3.RotateLeft(b,3)^ap;bi=z3.RotateRight(bp^ap,3);ai=z3.RotateLeft((ap^k)-bi,8)
    claims=[('first_context_index_reduction',raw==reduced),('all_context_indices_aligned_subsets',z3.And(*[z3.And((x&7)==0,(x&~u)==0)for x in indices])),
      ('ARX_round_inverse64',z3.And(ai==a,bi==b))];proofs=[]
    for label,claim in claims:
        q=z3.Solver();q.set(timeout=30000);q.add(z3.Not(claim));assert q.check()==z3.unsat;proofs.append({'label':label,'query':q.to_smt2(),'result':'unsat'})
    constants=[]
    for pc,r,k in zip([0x1bafe0,0x1bb000,0x1bb020,0x1bb040,0x1bb060,0x1bb080,0x1bb0a0],['x23','x12','x24','x13','x28','x10','x11'],KEYS):
        rows=list(C.CS.disasm(s.read(pc,16),pc));value=0
        for j,i in enumerate(rows):
            assert i.mnemonic==('mov'if j==0 else 'movk');assert i.op_str.split(', ')[0]==r
            value|=int(i.op_str.split('#')[1].split(',')[0],0)<<(16*j)
            if j:assert i.op_str.endswith('lsl #'+str(16*j))
        assert value==k;constants.append({'source_pc':hex(pc),'register':r,'constant_u64':hex(k),'bytes_hex':s.read(pc,16).hex()})
    exact={0x1bafd0:'ldr x19, [x0]',0x1bafd8:'ldr x8, [x19, w8, uxtw]',0x1bb2b8:'ldr x8, [x19, w8, uxtw]',0x1bb50c:'ldr x8, [x19, w8, uxtw]',
      0x1b6a38:'str w2, [x7, x17]',0x1b6a50:'str w2, [x6, x17]',0x5c8ce8:'strb w17, [x16, x5]',0x5c9264:'strb w16, [x10, x15]'}
    for pc,want in [(0x1bafdc,'add x16, x8, x16'),(0x1baffc,'add x16, x16, x8'),(0x1bb01c,'add x16, x16, x8'),
      (0x1bb03c,'add x16, x16, x8'),(0x1bb05c,'add x16, x8, x0'),(0x1bb07c,'add x16, x8, x16'),(0x1bb09c,'add x16, x8, x16'),
      (0x1bb0d8,'add x26, x8, x0')]:exact[pc]=want
    for pc,r in zip([0x1baff0,0x1bb010,0x1bb030,0x1bb050,0x1bb070,0x1bb090,0x1bb0b0],['x23','x12','x24','x13','x28','x10','x11']):exact[pc]='eor x16, x16, '+r
    for pc in [0x1baff4,0x1bb014,0x1bb034,0x1bb058,0x1bb074,0x1bb094,0x1bb0b4]:exact[pc]='eor x8, x16, x8, ror #61'
    for pc,r in [(0x1baff8,'x16'),(0x1bb018,'x16'),(0x1bb038,'x16'),(0x1bb054,'x0'),(0x1bb078,'x16'),(0x1bb098,'x16'),(0x1bb0b8,'x0')]:exact[pc]='ror '+r+', x16, #8'
    sites=[]
    for pc,want in exact.items():
        i=next(C.CS.disasm(s.read(pc,4),pc));assert i.mnemonic+' '+i.op_str==want,(hex(pc),i.mnemonic+' '+i.op_str)
        sites.append({'pc':hex(pc),'bytes_hex':s.read(pc,4).hex(),'instruction':want})
    assert s.decoded[0x1d09288]['target']=='0x1d45f60'and s.decoded[0x1d0fea0]['target']=='0x1d44440'
    return {'proofs':proofs,'seven_ARX_constants':constants,'exact_instructions':sites,'context_base_row':s.decoded[0x1d09288],'context_offset_row':s.decoded[0x1d0fea0],
      'whole_transform_algorithm':'unknown','new_source_context_initializer_established':False}


def main():
    e=json.loads(read(ROOT/'corefp_pool_transform_checks.json'));s=C.Pointers();assert e['generator_sha256']==SHA((ROOT/'recover_corefp_pool_transform.py').read_bytes())and e['thin_sha256']==C.THIN_SHA
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['base_declared_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in C.declared_inputs()]
    for span in e['source_spans']:assert span==s.function(int(span['start'],16))
    totals=Counter();oracles=[]
    for p in e['profiles']:
        c=p['configuration'];assert c==config(c['label']);ov=overlay(c);assert p['declared_overlay']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in ov]
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':hex(C.SP),'PC':hex(C.BASE+C.ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(C.REC);cpu['X31'][1]=hex(C.OUT);cpu['X31'][30]=hex(C.DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(4096)if a in [C.ARENA,C.ARENA+4096,CTX]else bytearray(C.initial_page(s,a))
            for addr,raw in ov:
                lo=max(a,addr);hi=min(a+4096,addr+len(raw))
                if lo<hi:b[lo-a:hi-a]=raw[lo-addr:hi-addr]
            assert C.unpack(row['payload'])==b;totals['initial_RAM_B_checked']+=4096
        r=Replay(p,e['source_spans'],s);totals.update(r.run());oracles.append(oracle(p,r));print(json.dumps({'checked':c['label']}),flush=True)
    source=source_checks(s);frozen=C.source_checks(s);pool=C.pool_source(s);sdk=C.sdk_checks()
    counts={'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points','allocations','child_entries']}}
    assert counts==e['verified_counts'];by={o['label']:o for o in oracles};assert by['context_ramp_16']['output_hex']==by['context_clobber']['output_hex']
    assert len({by[n]['output_hex']for n in ['context_ramp_16','context_zero_bytes','context_changed_byte']})==3
    result={'verified_counts':counts,'independent_replay':dict(totals),'source_B_checked':59120,'source_spans':3,'compact_oracle_profiles':len(oracles),
      'new_queries_unsat':len(source['proofs']),'frozen_queries_unsat':len(frozen['proofs'])+len(pool['proofs']),'ARX_rounds_checked':sum(o['ARX_rounds_checked']for o in oracles),
      'arena_oracle_B':sum(o['arena_oracle_B']for o in oracles),'cleanup_fill_B_checked':sum(o['cleanup_fill_B_checked']for o in oracles),
      'bank_inputs_checked':frozen['bank_inputs_checked']+pool['bank_inputs_checked'],'SDK_compile_exit':sdk['exit_code'],'all_checks_pass':True,'native_target_executed':False}
    deps=['audit_corefp_pool_caller.py','audit_corefp_pool_allocator.py','audit_corefp_lookup_initialization.py','audit_fpsd1201_predicates.py']
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_pool_transform_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':e['dependencies'],'frozen_auditor_dependencies':{n:SHA(read(ROOT/n).encode())for n in deps},'oracles':oracles,'source_checks':source,
      'frozen_caller_source_checks':frozen,'frozen_pool_source_checks':pool,'SDK_assertions':sdk,'fresh_replay_completed':True,'process_exit_code':0,
      'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'source_context_initializer_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_pool_transform_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
