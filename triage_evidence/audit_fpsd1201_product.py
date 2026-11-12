#!/usr/bin/env python3
"""Independent product replay, fixture reconstruction and integer oracles.

Never imports the new producer. Prefix execution is receipt-pinned. New CPU,
RAM, journal, PAC, alias and complete-call arithmetic checks are independent.
O(I+C*(B+F+V+P*J+R)) time, O(I+B+F+C*(V+J+P+R)) space; SMT separate.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import unicorn as uc
from unicorn import arm64_const as A
import z3
from audit_fpsd1201_record import Replay as Core,unpack,ROOT,RAM,CS,RECORD,OUT,OWNER,FP,SP,HALT
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();MASK=(1<<32)-1;MASK64=(1<<64)-1;BASE=0x4b0cf050;K=0x1ac70ef2
WRAP=0x74fd0c;CHILD=0x74eb08;IR=FP+0x100;AD=OWNER+0x800;BD=OWNER+0xa00;ND=OWNER+0xc00;Q=OWNER+0xd00;OD=OWNER+0xe00;CELL=OWNER+0xf00
ENTRIES=[WRAP,CHILD,0x649430,0x33abec,0x5a600c,0x5e8158]
EXITS={0x74ff34:WRAP,0x74f7e0:CHILD,0x6496b4:0x649430,0x33b118:0x33abec,0x5a650c:0x5a600c,0x5e8638:0x5e8158}
PRIOR_AUDIT_SHA='fb318e7c9c39e3943b58ca281ca7975d9a545e83cc1029c4f636f2645e1a7e71'


def numeric(d):
    raw=bytes.fromhex(d['descriptor16_hex']);n=(int.from_bytes(raw[4:8],'little')-BASE)&MASK;n=n-(1<<32)if n>>31 else n
    assert abs(n)<=256;b=bytes.fromhex(d['payload1024_hex']);v=sum((int.from_bytes(b[j*4:j*4+4],'little')^K)<<(32*j)for j in range(abs(n)))
    return -v if n<0 else v


def active(d):
    raw=bytes.fromhex(d['descriptor16_hex']);n=(int.from_bytes(raw[4:8],'little')-BASE)&MASK;n=n-(1<<32)if n>>31 else n
    return raw,bytes.fromhex(d['payload1024_hex'])[:4*abs(n)]


class Replay(Core):
    def __init__(self,p,prior,record,code,banks,D):
        self.p=p;self.c=p['configuration'];self.D=D;self.v=self.r=self.w=self.pi=self.ci=0;self.point_index=self.caller_index=0
        self.pending=[];self.stats=Counter();self.used=set();self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.call_stack=[];self.outcome=None
        mode=self.c['product_mode'];self.mode=mode;self.phase='product_'+mode
        self.ranges=[(int(r['start'],16),int(r['start'],16)+len(bytes.fromhex(r['bytes_hex'])))for r in code];pages=set()
        for a,b in self.ranges+[(a,a+len(b))for a,b in banks.items()]+[(a,a+n)for a,n in RAM]+[(0x1c80000,0x1d20000),(HALT,HALT+4096)]:pages.update(range(a&~4095,(b+4095)&~4095,4096))
        for page in sorted(pages):self.u.mem_map(page,4096)
        for r in code:self.u.mem_write(int(r['start'],16),bytes.fromhex(r['bytes_hex']))
        for a,b in banks.items():self.u.mem_write(a,b)
        for a,row in D.items():
            if 0x1c80000<=a<a+8<=0x1d20000 and not row['bind']:self.u.mem_write(a,int(row['target'],16).to_bytes(8,'little'))
        self.u.mem_write(0x1d1c578,(0x1d43300).to_bytes(8,'little'));self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        baseline=record['profiles'][0]if mode=='direct'else prior
        fixture=baseline['initial_RAM']if mode=='direct'else baseline['final_RAM'];f=baseline['initial']if mode=='direct'else baseline['terminal']
        assert len(fixture)==3
        for row,(a,n)in zip(fixture,RAM):
            b=unpack(row['payload']);assert row['address']==hex(a)and len(b)==n;self.u.mem_write(a,b);self.stats['restored_RAM_bytes_checked']+=n
        for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
        for name,key in [('SP','sp'),('PC','pc'),('NZCV','NZCV')]:self.u.reg_write(getattr(A,'UC_ARM64_REG_'+name),int(f[key],16))
        for j,v in enumerate(f['Q32']):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int(v,16))
        controls=[]
        def patch(a,b):controls.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
        if mode=='direct':
            d=p['direct_configuration'];n,a,b=(int(d[k],16)for k in ['n_hex','a_hex','b_hex']);assert n>0 and n&1 and 0<=a<n and 0<=b<n
            for desc,ptr,v in [(AD,OWNER+0x1000,a),(BD,OWNER+0x1800,b),(ND,OWNER+0x2000,n),(OD,OWNER+0x2800,0)]:
                count=(v.bit_length()+31)//32;patch(desc,struct.pack('<IIQ',130,BASE+count,ptr))
                for j in range(count):patch(ptr+4*j,(((v>>(32*j))&MASK)^K).to_bytes(4,'little'))
            destination={'distinct':OD,'first':AD,'second':BD}[d['alias']]
            patch(Q,struct.pack('<QQII',AD,BD,(-pow(n,-1,1<<32))&MASK,0xa5a5a5a5));mask=(((IR^0x7043a3fa)*0x4ecee2ad)&MASK)
            patch(IR,struct.pack('<QIIQQQQ',AD,mask^0xd7f4,0xa5a5a5a5,ND,Q,destination,BD));patch(CELL,b'\0'*8)
            self.setreg(0,IR);self.setreg(1,CELL);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,SP);self.u.reg_write(A.UC_ARM64_REG_PC,WRAP);self.entry=WRAP
            assert p['prior_profile_index']is None and p['checkpoint_pointer_load']is None
        else:
            assert mode in ['nested_retained','nested_canonical']and prior['terminal']['pc']=='0x114245c'
            assert self.c=={**prior['configuration'],'product_mode':mode}and p['direct_configuration']is None
            if mode=='nested_canonical':
                arg=self.reg(0);desc=int.from_bytes(self.ram(arg+40,8),'little');ptr=int.from_bytes(self.ram(desc+8,8),'little');b=min(0x12345678,self.c['operand_u32']-1)
                patch(desc+4,(BASE+(b!=0)).to_bytes(4,'little'));patch(ptr,(b^K).to_bytes(4,'little'))
            j=p['checkpoint_pointer_load']['prior_read_index'];r=prior['source_reads'][j];visit=prior['source_visits'][r['visit']]
            assert p['checkpoint_pointer_load']=={'prior_read_index':j,'read':r,'source_visit':visit}
            assert(r['address'],r['size_B'],r['bytes_hex'])==('0x1d03d18',8,WRAP.to_bytes(8,'little').hex())
            assert self.ram(int(visit['pc'],16),4).hex()==visit['bytes_hex'];self.entry=0x114245c;self.stats['checkpoint_reaching_pointer_loads_checked']+=1
        assert controls==p['operand_controls'];self.frame(p['initial'])
        for row,(a,n)in zip(p['initial_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['initial_RAM_bytes_checked']+=n
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.readhook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.writehook)
    def desc(self,a):
        d=self.ram(a,16);ptr=int.from_bytes(d[8:],'little');assert any(lo<=ptr<ptr+1024<=lo+n for lo,n in RAM)
        return {'address':hex(a),'descriptor16_hex':d.hex(),'payload1024_hex':self.ram(ptr,1024).hex()}
    def view(self,pc,entry,r,cursor):
        raw=self.ram(r,48);ptr=lambda j:int.from_bytes(raw[j:j+8],'little');extra={}
        if entry in [WRAP,CHILD]:
            q=ptr(24);views={name:self.desc(ptr(off))for name,off in [('first',0),('modulus',16),('output',32),('second',40)]}
            extra={'pair_pointer':hex(q),'pair24_hex':self.ram(q,24).hex(),'cursor_pointer':hex(cursor),'cursor_u64':hex(int.from_bytes(self.ram(cursor,8),'little'))}
        elif entry in [0x649430,0x33abec]:views={'first':self.desc(ptr(0)),'second':self.desc(ptr(16))}
        elif entry==0x5e8158:views={'first':self.desc(ptr(8)),'second':self.desc(ptr(16))}
        else:views={'operand':self.desc(ptr(8))}
        return {'pc':hex(pc),'entry':hex(entry),'record_pointer':hex(r),'record48_hex':raw.hex(),'views':views,**extra}
    def observe(self,pc):
        if pc in ENTRIES:
            item=(pc,self.reg(0),self.reg(1));before=None
        else:
            entry,r,cursor,before=self.call_stack.pop();assert EXITS[pc]==entry;item=(entry,r,cursor)
        e=self.p['product_points'][self.point_index];self.point_index+=1;self.frame(e['CPU']);actual=self.view(pc,*item)
        assert actual=={k:v for k,v in e.items()if k!='CPU'}
        if pc in ENTRIES:
            self.call_stack.append((*item,e));r=item[1];raw=bytes.fromhex(e['record48_hex']);word=lambda j:int.from_bytes(raw[j:j+4],'little');m=(((r^0x309487ae)*0x87cfdb29)&MASK)
            if pc==WRAP:self.product_signature=item
            if pc in [WRAP,CHILD]:
                assert word(8)^(((r^0x7043a3fa)*0x4ecee2ad)&MASK)==0xd7f4
                if pc==CHILD:
                    w=self.call_stack[0][3];s=int(w['cursor_u64'],16);pad=16*((((s*0x2ea5+1)&MASK64)>>60)+1)
                    assert int(e['CPU']['sp'],16)==int(w['CPU']['sp'],16)-64-pad and int(e['cursor_u64'],16)==(s-112)&MASK64
                    self.stats['product_frame_geometries_checked']+=1
            if pc==0x649430:assert(word(8)+m)&MASK==0x2f63
            if pc==0x33abec:assert(word(24)+(((r^0x302a1e77)*0xcae5b081)&MASK))&MASK==0x69d6
            if pc==0x5a600c:assert(word(4)-m)&MASK==0xc215
            if pc==0x5e8158:assert word(0)^(((r^0x7043a3fa)*0x4ecee2ad)&MASK)==0xf136
        else:self.return_contract(item[0],before,e)
        self.stats['product_family_points_checked']+=1
    def return_contract(self,entry,before,after):
        a=before['views'];b=after['views'];raw=bytes.fromhex(before['record48_hex'])
        if entry in [WRAP,CHILD]:
            n=numeric(a['modulus']);x=numeric(a['first']);y=numeric(a['second']);out=numeric(b['output']);nd=bytes.fromhex(a['modulus']['descriptor16_hex']);k=(int.from_bytes(nd[4:8],'little')-BASE)&MASK
            coefficient=int.from_bytes(bytes.fromhex(before['pair24_hex'])[16:20],'little');assert n>0 and k>0 and x>=0 and y>=0 and active(b['modulus'])==active(a['modulus'])
            expected=x*y*pow(1<<(32*k),-1,n)%n if n&1 else None
            if self.mode!='nested_retained'and n&1:
                assert x<n and y<n and out==expected
                if entry==CHILD:self.stats['canonical_Montgomery_product_oracles_checked']+=1
            elif self.mode=='nested_retained'and n&1:
                if entry==CHILD:self.stats['retained_odd_matches'if out==expected else'retained_odd_counterexamples']+=1
            elif self.mode=='nested_canonical':
                assert k==1;t=x*y;t=(t+(((t&MASK)*coefficient)&MASK)*n)>>32;t=t-n if t>=n else t;assert out==t
                if entry==CHILD:self.stats['canonical_even_literal_REDC_controls_checked']+=1
            elif entry==CHILD:self.stats['retained_even_controls_checked']+=1
            if n&1:assert coefficient==(-pow(n,-1,1<<32))&MASK
            od=bytes.fromhex(a['output']['descriptor16_hex']);end=bytes.fromhex(b['output']['descriptor16_hex']);count=(int.from_bytes(end[4:8],'little')-BASE)&MASK
            assert od[:4]==end[:4]and od[8:]==end[8:]
            for key in ['first','second']:
                if a[key]['address']!=a['output']['address']:assert active(a[key])==active(b[key])
            assert before['pair24_hex']==after['pair24_hex']
            if entry==CHILD:
                assert int(after['cursor_u64'],16)==(int(before['cursor_u64'],16)+112)&MASK64;self.stats['complete_product_child_returns_checked']+=1
                self.outcome={'modulus_hex':hex(n),'first_hex':hex(x),'second_hex':hex(y),'result_hex':hex(out),'modular_oracle_hex':hex(expected)if expected is not None else None,'modular_oracle_matches':out==expected if expected is not None else None,'modulus_width_limbs':k,'mode':self.mode}
            else:assert after['cursor_u64']=='0x0';self.stats['complete_product_wrapper_returns_checked']+=1
        elif entry==0x649430:
            s=bytes.fromhex(a['first']['descriptor16_hex']);d=bytes.fromhex(a['second']['descriptor16_hex']);o=bytes.fromhex(b['second']['descriptor16_hex']);count=(int.from_bytes(s[4:8],'little')-BASE)&MASK;count=count-(1<<32)if count>>31 else count;count=abs(count)
            assert active(b['first'])==active(a['first'])and o==d[:4]+s[4:8]+d[8:]
            assert bytes.fromhex(b['second']['payload1024_hex'])[:4*count]==bytes.fromhex(a['first']['payload1024_hex'])[:4*count]
            self.stats['copy_oracles_checked']+=1
        elif entry==0x33abec:
            x,y=numeric(a['first']),numeric(a['second']);assert all(active(a[k])==active(b[k])for k in a)
            assert int.from_bytes(bytes.fromhex(after['record48_hex'])[8:12],'little')==0x312bc2c1+(y>x)-(y<x);self.stats['comparison_oracles_checked']+=1
        elif entry==0x5a600c:
            r=int(before['record_pointer'],16);m=(((r^0x309487ae)*0x87cfdb29)&MASK);shift=(int.from_bytes(raw[:4],'little')-m+0xa2eae272)&MASK;shift=shift-(1<<32)if shift>>31 else shift
            v=numeric(a['operand']);out=(abs(v)<<shift)if shift>=0 else(abs(v)>>(-shift));out=-out if v<0 else out;assert numeric(b['operand'])==out;self.stats['shift_oracles_checked']+=1
        else:assert numeric(b['second'])==numeric(a['second'])-numeric(a['first']);self.stats['subtraction_oracles_checked']+=1
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in ENTRIES or pc in EXITS:self.observe(pc)
        if pc in [0x74ec38,0x74ff14,0x1142460]:
            e=self.p['caller_points'][self.caller_index];self.caller_index+=1;self.frame(e['CPU']);item=self.call_stack[0][:3]if self.call_stack else self.product_signature
            assert self.view(pc,*item)=={k:v for k,v in e.items()if k!='CPU'};self.stats['caller_points_checked']+=1
            if pc==0x74ec38:
                child=self.call_stack[-1][3];assert int.from_bytes(self.ram(int(child['cursor_pointer'],16),8),'little')==(int(child['cursor_u64'],16)+112)&MASK64
                self.stats['early_child_cursor_restores_checked']+=1
        if pc==0x11425bc:
            self.frame(self.p['terminal']);slot=0x1d037a8;row=self.D[slot];assert(self.reg(8),self.reg(17))==(0x59f4e8,0x7c9f)
            assert(row['target'],row['diversity'],row['key'],row['address_diversity'])==('0x59f4e8','0x7c9f','IA',0)
            assert any(r['address']==hex(slot)and r['size_B']==8 and r['bytes_hex']==(0x59f4e8).to_bytes(8,'little').hex()for r in self.p['source_reads'][:self.r])
            assert self.p['frontier']=={'pc':hex(pc),'target':'0x59f4e8','modifier':'0x7c9f','original_slot':hex(slot),'instruction':'blraa x8, x17','instruction_executed':False,'argument_record80_hex':self.ram(self.reg(0),80).hex()}
            self.used.add(slot);self.stop='unretained_callee';u.emu_stop();return
        if pc==0x114245c and self.v==0:
            assert self.p['source_visits'][0]=={'phase':self.phase,'pc':hex(pc),'bytes_hex':self.ram(pc,4).hex(),'instruction':'blraa x8, x17'};self.v+=1
            e=self.p['PAC_models'][self.pi];self.pi+=1;self.frame(e['before']);assert e=={'pc':hex(pc),'kind':'blraa','before':self.p['initial'],'target':hex(WRAP),'modifier':'0xca9b','original_slot':'0x1d03d18'}
            row=self.D[0x1d03d18];assert(row['target'],row['diversity'],row['key'],row['address_diversity'])==(hex(WRAP),'0xca9b','IA',0)
            assert(self.reg(8),self.reg(17))==(WRAP,0xca9b);self.used.add(0x1d03d18);self.setreg(30,pc+4);u.reg_write(A.UC_ARM64_REG_PC,WRAP);return
        Core.hook(self,u,pc,n,data)
    def run(self):
        self.u.emu_start(self.entry,0,count=500000);self.flush();assert self.stop==self.p['stop_reason']==('returned'if self.mode=='direct'else'unretained_callee')
        assert(self.v,self.r,self.w,self.pi,self.ci)==tuple(len(self.p[k])for k in ['source_visits','source_reads','source_writes','PAC_models','CPU_points'])
        assert self.point_index==len(self.p['product_points'])and self.caller_index==len(self.p['caller_points'])and not self.call_stack and self.outcome is not None
        assert self.p['used_original_pointer_rows']==[self.D[a]for a in sorted(self.used)]
        for row in self.p['used_original_pointer_rows']:
            if row['bind']:assert row['import']['name']=='___stack_chk_guard';continue
            word=int(row['word'],16);decoded=word&MASK if word>>63 else(word&((1<<43)-1))|(((word>>43)&255)<<56)
            assert decoded==int(row['target'],16)
            if word>>63:assert word>>49&3==0 and word>>32&65535==int(row['diversity'],16)and word>>48&1==row['address_diversity']
            self.stats['original_pointer_profile_associations_checked']+=1
        assert len(self.p['final_RAM'])==3
        for row,(a,n)in zip(self.p['final_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['final_RAM_bytes_checked']+=n
        assert not self.p['native_effects']
        if self.mode!='direct':
            assert int.from_bytes(self.ram(OUT,8),'little')==self.c['seed_u64']and int.from_bytes(self.ram(RECORD+0x30,4),'little')==0xa5a5a5a5
            for name in ['source_reads','source_writes']:assert not any(int(r['address'],16)<OWNER+0x900 and OWNER+0x880<int(r['address'],16)+r['size_B']for r in self.p[name])
            assert self.ram(OWNER+0x880,128)==b'\xa5'*128
        self.stats.update({'original_visits_checked':self.v,'original_reads_checked':self.r,'original_writes_checked':self.w,'PAC_models_checked':self.pi})
        return self.stats,self.outcome


def sources(e,old):
    assert e['code_spans'][:21]==old['code_spans'];a=json.loads(read(ROOT/'fpsd1201_product_ida_readback.json'));assert not a['IDB_mutated']and not a['native_target_executed']
    raw=(ROOT.parent/'CoreFP').read_bytes();assert SHA(raw)==a['input_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    slices=[struct.unpack_from('>5I',raw,8+20*j)for j in range(struct.unpack_from('>I',raw,4)[0])];_,_,offset,length,_=next(s for s in slices if s[:2]==(0x100000c,0x80000002));thin=raw[offset:offset+length]
    assert SHA(thin)=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c';at=32;segments=[]
    for j in range(struct.unpack_from('<I',thin,16)[0]):
        cmd,n=struct.unpack_from('<II',thin,at)
        if cmd==0x19:
            _,vm,vs,fo,fs=struct.unpack_from('<16s4Q',thin,at+8);segments.append((vm,fo,fs))
        if cmd==0x26:fo,fs=struct.unpack_from('<II',thin,at+8);blob=thin[fo:fo+fs]
        at+=n
    def get(address,n):
        vm,fo,fs=next(s for s in segments if s[0]<=address<address+n<=s[0]+s[2]);return thin[fo+address-vm:fo+address-vm+n]
    starts=[];v=shift=pc=0
    for byte in blob:
        v|=(byte&127)<<shift
        if byte&128:shift+=7;continue
        if not v:break
        pc+=v;starts.append(hex(pc));v=shift=0
    assert starts==json.loads(read(ROOT/'corefp_library_inventory.json'))['compiler_function_starts']
    for r in e['code_spans']:assert get(int(r['start'],16),len(bytes.fromhex(r['bytes_hex'])))==bytes.fromhex(r['bytes_hex'])
    expected=[('0x74fd0c','0x74ff38',556,'6b163c894400902eb94c1d004abc16867bffa53164326bb39f1f8fd522f09005'),('0x74eb08','0x74fd0c',4612,'736e0190a0a23d3ef98abb1a64c5801ce7034883cf8b9f59d07597e52a95b9af')]
    for j,(start,end,n,h)in enumerate(expected):
        r=a['spans'][j];b=bytes.fromhex(r['bytes_hex']);assert(r['start'],r['end_exclusive'],r['size_B'])==(start,end,n)
        assert SHA(b)==r['sha256']==r['original_sha256']==h and r['current_equals_IDA_original_bytes']and len(b)==n and starts[starts.index(start)+1]==end
        assert e['code_spans'][21+j]=={**r,'role':['product_cursor_wrapper','montgomery_product'][j]}
    assert len(a['spans'])==2
    banks={}
    for row in json.loads(read(ROOT/'corefp_lookup_contracts.json'))['banks']:
        for ak,bk in [('first_address','first_bytes'),('second_address','second_bytes')]:
            address=int(row[ak],16);b=bytes.fromhex(row[bk]);assert address not in banks or banks[address]==b;banks[address]=b
    for address,b in banks.items():assert get(address,len(b))==b
    D={int(r['address'],16):r for r in json.loads(read(ROOT/'corefp_fixups_inventory.json'))['fixups']}
    for address,r in D.items():assert int.from_bytes(get(address,8),'little')==int(r['word'],16)
    parent=next(r for r in json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'))['spans']if r['role']=='parent');b=bytes.fromhex(parent['bytes_hex']);assert get(int(parent['start'],16),len(b))==b
    assert e['reference_file_check']=={**old['reference_file_check'],'code_bytes_checked':39500}
    ins={i.address:i for r in e['code_spans']for i in CS.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))}
    exact={0x74fe04:('mov','w16, #0x2ea5'),0x74fe54:('madd','x16, x21, x16, x3'),0x74fe78:('sub','x16, x21, #0x70'),
      0x74ff10:('blraa','x8, x17'),0x74ff20:('str','x8, [x19]'),0x74ec30:('add','x8, x8, #0x70'),0x74ec34:('str','x8, [x1]'),
      0x74ec64:('ldr','w12, [x0, #8]'),0x74ec6c:('ldr','x1, [x0]'),0x74ec70:('ldr','x8, [x0, #0x10]'),0x74eca8:('ldp','x25, x12, [x0, #0x20]'),
      0x74ecdc:('cmp','w3, w5'),0x74ede4:('cmp','w3, #0x83'),0x74eebc:('ldr','x11, [x0, #0x18]'),0x74ef48:('ldr','w12, [x12, #0x10]'),
      0x74f074:('umaddl','x10, w14, w30, x10'),0x74f07c:('mul','w20, w10, w14'),0x74f094:('umaddl','x14, w20, w17, x14'),
      0x74f38c:('mul','w25, w16, w12'),0x74f3a4:('umaddl','x16, w1, w25, x16'),0x74f7e0:('retab',''),0x11425bc:('blraa','x8, x17')}
    for pc,want in exact.items():assert(ins[pc].mnemonic,ins[pc].op_str)==want,(hex(pc),ins[pc].mnemonic,ins[pc].op_str)
    p=z3.BitVec('audit_product_record',32);a,b=z3.BitVecs('audit_first_count audit_second_count',32);seed=z3.BitVec('audit_product_seed',64);c=z3.BitVecVal(0x77e48841,32);top=z3.LShR(seed*11941+1,60);pad=((top<<4)+31)&0x1f0
    claims=[(((p&c)|~(p|c))^0xf858d444)*0x4ecee2ad==(p^0x7043a3fa)*0x4ecee2ad,
      b*0x57f4924c+(a+0x5cfe7d64)*(b+0xb4f30fb0)==(a-BASE)*(b-BASE)+0xe524f7c0,
      seed-0x70+0x70==seed,pad==16*(top+1),z3.And(z3.UGE(pad,16),z3.ULE(pad,256)),z3.Extract(15,0,seed-0x70+0x70-seed)==0]
    assert len(e['proofs'])==len(claims)==6
    for proof,claim in zip(e['proofs'],claims):
        q=z3.Solver();q.set(timeout=60000);q.add(z3.parse_smt2_string(proof['query']));assert q.check()==z3.unsat and proof['result']=='unsat'
        normalized=z3.simplify(claim,som=True);q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(normalized));assert q.check()==z3.unsat
        names={'product_record':z3.BitVec('product_record',32),'product_first_raw_count':z3.BitVec('product_first_raw_count',32),'product_second_raw_count':z3.BitVec('product_second_raw_count',32),'product_seed':z3.BitVec('product_seed',64)}
        retained=z3.parse_smt2_string('(assert '+proof['original_claim_smt2']+')',decls=names)[0]
        assert z3.simplify(retained,som=True).sexpr()==proof['normalized_claim_smt2']
        q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(z3.simplify(retained,som=True)));assert q.check()==z3.unsat
    return banks,D,{'fresh_IDA_spans':2,'fresh_IDA_bytes':5168,'compiler_bounded_bodies':2,'total_selected_code_bytes':39500,
      'original_fixup_words_checked':len(D),'compiler_starts_checked':len(starts),'retained_queries_unsat':6,'independent_queries_unsat':6,
      'exact_source_instructions_checked':len(exact),'complete_algorithm_universally_proved':False}


def main():
    e=json.loads(read(ROOT/'fpsd1201_product_checks.json'));old=json.loads(read(ROOT/'fpsd1201_consumer_checks.json'));record=json.loads(read(ROOT/'fpsd1201_record_checks.json'))
    prior=json.loads(read(ROOT/'fpsd1201_consumer_audit.json'));assert SHA(read(ROOT/'fpsd1201_consumer_audit.json').encode())==PRIOR_AUDIT_SHA and prior['fresh_replay_completed']and prior['result']['all_checks_pass']
    assert prior['checks_sha256']==SHA(read(ROOT/'fpsd1201_consumer_checks.json').encode())and prior['auditor_sha256']==SHA((ROOT/'audit_fpsd1201_consumer.py').read_bytes())
    assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_product.py').read_bytes())and e['IDA_readback_sha256']==SHA(read(ROOT/'fpsd1201_product_ida_readback.json').encode())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    banks,D,source=sources(e,old);total=Counter();summaries=[];direct=[]
    for n in [3,7,0xffffffff,0x80000001]:
        for j,(a,b)in enumerate([(0,n-1),(n-1,n-1),(n//2,n//3)]):
            for alias in ['distinct','first','second']:direct.append({'mode':'direct','label':f'word_{n}_{j}_{alias}','n_hex':hex(n),'a_hex':hex(a),'b_hex':hex(b),'alias':alias})
    for width in [2,4,8,16,32,64]:
        n=(1<<(32*width))-159
        for j,(a,b)in enumerate([(n-1,n-2),(1,n-1)]):
            for alias in ['distinct','first','second']:direct.append({'mode':'direct','label':f'wide_{width}_{j}_{alias}','n_hex':hex(n),'a_hex':hex(a),'b_hex':hex(b),'alias':alias})
    assert len(e['profiles'])==96
    for j,p in enumerate(e['profiles']):
        mode='nested_retained'if j<12 else'nested_canonical'if j<24 else'direct';assert p['configuration']['product_mode']==mode
        if j<24:assert p['prior_profile_index']==j%12;baseline=old['profiles'][j%12]
        else:assert p['direct_configuration']==direct[j-24];baseline=old['profiles'][0]
        replay=Replay(p,baseline,record,e['code_spans'],banks,D);stats,outcome=replay.run();total.update(stats);summaries.append(outcome)
        print(json.dumps({'profile':j,'mode':mode,'visits':stats['original_visits_checked'],'matches':outcome['modular_oracle_matches']}),flush=True)
    assert(total['canonical_Montgomery_product_oracles_checked'],total['retained_odd_matches'],total['retained_odd_counterexamples'],total['canonical_even_literal_REDC_controls_checked'],total['retained_even_controls_checked'])==(81,3,6,3,3)
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    result={'source':source,'fresh_replay':dict(total),'profiles':96,'retained_checkpoint_profiles':12,'canonicalized_checkpoint_profiles':12,'isolated_product_profiles':72,
      'profile_summaries':summaries,'next_callee_targets':['0x59f4e8'],'prefix_instructions_rerun':0,'prior_replay_receipt_sha256':PRIOR_AUDIT_SHA,
      'nested_candidate_inline128_reads_or_writes':0,'complete_consumer_return_established':False,'whole_parent_replayed':False,'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    receipt={'result':result,'dependencies':e['dependencies'],'checks_sha256':SHA(read(ROOT/'fpsd1201_product_checks.json').encode()),'IDA_readback_sha256':e['IDA_readback_sha256'],
      'auditor_sha256':SHA(Path(__file__).read_bytes()),'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_product_audit.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({**result,'profile_summaries':'retained in receipt'}),flush=True)


if __name__=='__main__':main()
