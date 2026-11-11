#!/usr/bin/env python3
"""Independent CoreFP1201 byte replay, wire oracle and daemon failure join.

Never imports the new producer. Reconstructs entry and external ABI effects,
checks full CPU/read/write/RAM evidence, source-lifts transport classification,
and freshly replays the original zero-input daemon profile. No native effects.
O(C*(V+J+R)+server replay) time/space; SMT costs separate.
"""
import base64,json,struct,zlib,subprocess
from collections import Counter
from hashlib import sha256
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as A
import z3
from daemon_receive_tools import ROOT,CS,IMAGE,SOURCE,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from replay_daemon_descriptor_source import decode
from verify_daemon_reader_record_payloads_publication import read

BASE=0x500000000;STACK=0x71000000;INPUT=0x72000000;BIND=0x76000000;HALT=BASE+0x1fff000
REGIONS=[(STACK,65536),(INPUT,4096),(BIND,8192),(BASE+0x1d1c000,4096),(BASE+0x15d6000,4096)]
SHA=lambda b:sha256(b).hexdigest()


class Replay:
    def __init__(self,p,body,stubs,literal):
        self.p=p;self.c=p['configuration'];self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        self.vi=self.ri=self.wi=self.mi=self.pi=0;self.pending=[];self.counts=Counter();self.imports={};self.stubrows=stubs
        for a,n in [(BASE+0x8000,4096),(BASE+0x15d1000,4096),(HALT,4096)]+REGIONS:self.u.mem_map(a,n)
        self.u.mem_write(BASE+0x8d40,bytes.fromhex(body['bytes']));self.u.mem_write(STACK,b'\xa5'*65536)
        self.u.mem_write(INPUT,bytes.fromhex(self.c['inline128_hex']));self.u.mem_write(BASE+0x15d6978,literal)
        self.u.mem_write(BIND+0x100,bytes.fromhex('0000000001000000'));self.u.mem_write(BIND+0x200,bytes.fromhex('b39a4e0cf582617d'))
        for off,value in [(0x1d1c570,BIND+0x100),(0x1d1c578,BIND+0x200),(0x1d1c5d0,0 if self.c['voucher']=='absent'else BIND+0x300)]:self.u.mem_write(BASE+off,struct.pack('<Q',value))
        for j,r in enumerate(stubs):
            at=int(r['address'],16);target=BIND+0x300 if at==0x15d1a14 else BIND+0x1000+32*j
            self.u.mem_write(BASE+at,bytes.fromhex(r['bytes']));self.u.mem_write(BASE+int(r['pointer']['address'],16),struct.pack('<Q',target));self.imports[target]=r
        for j in range(31):self.u.reg_write(self.rid(j),((j+1)*0x13579bdf)&((1<<64)-1))
        for j,v in [(0,self.c['destination_u32']),(1,self.c['word_u32']),(2,INPUT),(30,HALT)]:self.u.reg_write(self.rid(j),v)
        for j in range(32):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int.from_bytes(bytes([j])*16,'little'))
        self.u.reg_write(A.UC_ARM64_REG_SP,STACK+0x8000);self.u.reg_write(A.UC_ARM64_REG_PC,BASE+0x8d40)
        self.u.reg_write(A.UC_ARM64_REG_NZCV,0);self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        assert p['initial_regions']==[{'address':hex(a),'size_B':n,'sha256':SHA(self.ram(a,n))}for a,n in REGIONS]
        self.frame(p['entry'])
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.readhook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.writehook)
    @staticmethod
    def rid(j):return A.UC_ARM64_REG_X0+j if j<29 else [A.UC_ARM64_REG_X29,A.UC_ARM64_REG_X30][j-29]
    def reg(self,j):return self.u.reg_read(self.rid(j))
    def ram(self,a,n):return bytes(self.u.mem_read(a,n))
    def frame(self,f):
        assert f=={'pc':hex(self.u.reg_read(A.UC_ARM64_REG_PC)),'sp':hex(self.u.reg_read(A.UC_ARM64_REG_SP)),
          'registers31':[hex(self.reg(j))for j in range(31)],'NZCV':hex(self.u.reg_read(A.UC_ARM64_REG_NZCV)),
          'Q32':[hex(self.u.reg_read(A.UC_ARM64_REG_Q0+j))for j in range(32)]};self.counts['complete_CPU_frames_checked']+=1
    def flush(self):
        for w in self.pending:assert w['after_hex']==self.ram(int(w['address'],16),w['size_B']).hex()
        self.pending=[]
    def readhook(self,u,ac,a,n,v,d):
        assert self.p['source_reads'][self.ri]=={'visit':self.vi-1,'address':hex(a),'size_B':n,'bytes_hex':self.ram(a,n).hex()};self.ri+=1
    def writehook(self,u,ac,a,n,v,d):
        assert STACK<=a<a+n<=STACK+65536
        e=self.p['source_writes'][self.wi];self.wi+=1
        assert {k:e[k]for k in('visit','address','size_B','before_hex')}=={'visit':self.vi-1,'address':hex(a),'size_B':n,'before_hex':self.ram(a,n).hex()};self.pending.append(e)
    def external(self,a):
        row=self.imports[a];name=row['pointer']['import']['name'];args=[self.reg(j)for j in range(8)];c=self.c;e=self.p['imports'][self.mi];self.mi+=1
        assert e['stub']==row['address']and e['name']==name and e['args8']==[hex(v)for v in args];self.frame(e['before']);patches=[];result=0
        if name=='_mig_get_reply_port':result=c['reply_name_u32']
        elif name=='_voucher_mach_msg_set':
            assert c['voucher']!='absent'
            if c['voucher']=='header_write':patches=[(args[0]+16,struct.pack('<I',0x8844))]
        elif name=='_mach_msg':
            assert args[1:7]==[3,164,44,c['reply_name_u32'],0,0]
            self.msg=args[0];assert e['request164_hex']==self.p['request164_hex']==self.ram(args[0],164).hex()
            result=c['transport_u32']
            if result==0:
                reply=struct.pack('<6I',c['reply_bits'],c['reply_size_B'],c['reply_remote'],c['reply_local'],c['reply_reserved'],c['reply_id'])
                reply+=bytes.fromhex(c['reply_NDR_hex'])+struct.pack('<I',c['reply_status_u32'])+b'\xa5'*8
                patches=[(args[0],reply)]
        else:
            assert name in ['_mach_msg_destroy','_mig_put_reply_port','_mig_dealloc_reply_port']
            assert args[0]==(self.msg if name=='_mach_msg_destroy'else c['reply_name_u32'])
        assert len(patches)==len(e['patches'])
        for(at,b),saved in zip(patches,e['patches']):
            assert saved=={'address':hex(at),'before_hex':self.ram(at,len(b)).hex(),'after_hex':b.hex()};self.u.mem_write(at,b)
        assert e['result_u64']==hex(result);target=self.reg(30)
        for j in range(18):self.u.reg_write(self.rid(j),(((j+1)*0x123456789abcdef)^0x8b3dc651)&((1<<64)-1))
        self.u.reg_write(A.UC_ARM64_REG_X0,result);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000);self.u.reg_write(A.UC_ARM64_REG_PC,target);self.frame(e['after'])
    def hook(self,u,a,n,d):
        self.flush()
        if a==HALT:self.frame(self.p['terminal']);self.done=True;u.emu_stop();return
        if a in self.imports:return self.external(a)
        off=a-BASE;row=self.p['source_visits'][self.vi]
        assert row=={'pc':hex(off),'bytes_hex':self.ram(a,4).hex()};self.vi+=1
        op=next(CS.disasm(self.ram(a,4),off)).mnemonic
        if op in ['pacibsp','retab','braa']:
            expected={'visit':self.vi-1,'operation':{'pacibsp':'PACIBSP_private_noop','retab':'RETAB_declared_caller','braa':'BRAA_declared_import_pointer'}[op]}
            if op=='braa':
                stub=next(r for r in self.stubrows if int(r['address'],16)+12==off)
                assert self.reg(17)==BASE+int(stub['pointer']['address'],16)and self.reg(16)in self.imports
                target=self.reg(16);expected.update(target=hex(target),modifier=hex(self.reg(17)))
            elif op=='retab':assert self.reg(30)==HALT;target=HALT
            else:target=a+4
            assert expected==self.p['PAC_models'][self.pi];self.pi+=1;u.reg_write(A.UC_ARM64_REG_PC,target)
    def run(self):
        self.u.emu_start(BASE+0x8d40,0,count=2000);self.flush();assert self.done
        assert (self.vi,self.ri,self.wi,self.mi,self.pi)==tuple(len(self.p[k])for k in ['source_visits','source_reads','source_writes','imports','PAC_models'])
        assert self.p['return_u32']==self.reg(0)&0xffffffff and self.p['return_u64']==hex(self.reg(0))
        for (a,n),r in zip(REGIONS,self.p['final_regions']):assert r['address']==hex(a)and decode(r)==self.ram(a,n)
        self.counts.update(original_visits_checked=self.vi,original_reads_checked=self.ri,original_writes_checked=self.wi,
          external_contracts_checked=self.mi,PAC_models_checked=self.pi,complete_final_RAM_bytes_checked=sum(n for a,n in REGIONS))
        return self.counts


def oracle(p):
    c=p['configuration'];b=bytes.fromhex(p['request164_hex'])
    assert len(b)==164 and struct.unpack_from('<6I',b)==(0x1513,0xa5a5a5a5,c['destination_u32'],c['reply_name_u32'],0x8844 if c['voucher']=='header_write'else 0,1201)
    assert b[24:32]==bytes.fromhex('0000000001000000')and struct.unpack_from('<I',b,32)[0]==c['word_u32']
    assert b[36:]==bytes.fromhex(c['inline128_hex'])
    msg=int(next(m['args8'][0]for m in p['imports']if m['name']=='_mach_msg'),16)
    assert not any(int(w['address'],16)<msg+8 and msg+4<int(w['address'],16)+w['size_B']for w in p['source_writes'])
    footprint=set()
    for q in p['source_reads']:
        at=int(q['address'],16)
        if INPUT<=at<INPUT+4096:footprint.update(range(at-INPUT,at-INPUT+q['size_B']))
    assert footprint==set(range(128))
    send=next(j for j,v in enumerate(p['source_visits'])if v['pc']=='0x8e04')
    if c['transport_u32']==0:
        assert not any(q['visit']>send and int(q['address'],16)<msg+32 and msg+24<int(q['address'],16)+q['size_B']for q in p['source_reads'])
    r=c['transport_u32'];cleanup=[]
    if r:cleanup=['_mig_put_reply_port'if r in(0x10000002,0x10000003,0x10000010)else'_mig_dealloc_reply_port']
    else:
        if c['reply_id']==71:r=(-308)&0xffffffff
        elif c['reply_id']!=1301:r=(-301)&0xffffffff
        elif c['reply_bits']&0x80000000 or c['reply_size_B']!=36 or c['reply_remote']!=0:r=(-300)&0xffffffff
        else:r=c['reply_status_u32']
        if r:cleanup=['_mach_msg_destroy']
    actual=[e['name']for e in p['imports']if e['name']in ['_mig_put_reply_port','_mig_dealloc_reply_port','_mach_msg_destroy']]
    assert p['return_u32']==r and actual==cleanup
    assert [e['name']for e in p['imports']]==['_mig_get_reply_port']+([]if c['voucher']=='absent'else['_voucher_mach_msg_set'])+['_mach_msg']+cleanup
    return {'case':c['label'],'visits':len(p['source_visits']),'return_u32':hex(r),'cleanup':cleanup,
      'voucher_model':c['voucher'],'native_effects':False}


def source_lift(e):
    body=e['source_body'];b=bytes.fromhex(body['bytes']);r=z3.BitVec('fresh_transport32',32);w={'w0':r};cmp=None;test=None
    for i in CS.disasm(b[0x8e0c-0x8d40:0x8e34-0x8d40],0x8e0c):
        q=[x.strip()for x in i.op_str.split(',')]
        if i.mnemonic=='mov':w[q[0]]=z3.BitVecVal(int(q[1][1:],0)&0xffffffff,32)
        elif i.mnemonic=='movk':assert q==['w8','#0xefff','lsl #16'];w['w8']=(w['w8']&0xffff)|0xefff0000
        elif i.mnemonic=='add':w[q[0]]=w[q[1]]+w[q[2]]
        elif i.mnemonic=='cmp':cmp=z3.ULE(w[q[0]],int(q[1][1:],0))
        elif i.mnemonic=='b.hi':assert q==['#0x8e40']
        elif i.mnemonic=='lsl':w[q[0]]=w[q[1]]<<(w[q[2]]&31)
        elif i.mnemonic=='tst':test=(w[q[0]]&w[q[1]])!=0
        elif i.mnemonic=='b.eq':assert q==['#0x8e40']
        else:raise AssertionError(i.mnemonic)
    s=z3.Solver();s.set(timeout=20000);s.add(z3.And(cmp,test)!=z3.Or(r==0x10000002,r==0x10000003,r==0x10000010));assert s.check()==z3.unsat
    s=z3.Solver();s.set(timeout=20000);s.from_string(e['proof']['query']);assert s.check()==z3.unsat
    return {'retained_queries_unsat':1,'independently_source_lifted_queries_unsat':1,'put_reply_port_results':['0x10000002','0x10000003','0x10000010']}


def server_join(e,client):
    from audit_fpsd1201_session import Replay as Server
    from recover_fpsd1200_process import inputs
    old,session,mask,_=inputs();allserver=json.loads(read(ROOT/'fpsd1201_session_checks.json'))
    packed=next(r for r in allserver['profiles']if r['label']=='matching_zero')
    raw=zlib.decompress(base64.b64decode(packed['payload_zlib_base64']));assert SHA(raw)==e['frozen_server_payload_sha256'];p=json.loads(raw)
    receipt=json.loads(read(ROOT/'fpsd1201_session_audit.json'));assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0
    assert receipt['checks_sha256']==SHA(read(ROOT/'fpsd1201_session_checks.json').encode())and receipt['IDA_SDK_readback_sha256']==SHA(read(ROOT/'fpsd1201_session_ida_readback.json').encode())
    assert SHA(SOURCE.read_bytes())==allserver['daemon_sha256']
    att=json.loads(read(ROOT/'fpsd1201_session_ida_readback.json'))
    for span in allserver['spans']:
        a,z=int(span['start'],16),int(span['end'],16);b=IMAGE.read(a,z-a);assert b.hex()==span['bytes_hex']and SHA(b)==span['sha256']
    assert att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in allserver['spans']]
    wire=bytearray.fromhex(client['request164_hex']);c=client['configuration']
    struct.pack_into('<6I',wire,0,0x1212,164,c['reply_name_u32'],c['destination_u32'],0,1201)
    assert wire.hex()==p['mig_patches'][0]['after_hex']and wire.hex()==p['request164_hex']
    counts=Server(p,old['setup_cases'][0],session,mask).run()
    accesses={int(r['address'],16)for r in p['source_reads']if int(r['address'],16)in FIXUPS}
    binds=sorted(a for a in accesses if FIXUPS[a]['kind'].endswith('bind'));fix=verify_original_fixups(sorted(accesses-set(binds)))
    binding_records=[binding(a)for a in binds]
    original=bytearray.fromhex(p['reply36_hex']);assert original.hex()==e['frozen_server_reply36_hex']
    assert struct.unpack_from('<6I',original)==(0x12,36,0x6400,0,0,1301)
    struct.pack_into('<6I',original,0,0,36,0,0x6400,0,1301)
    assert original.hex()==next(m['patches'][0]['after_hex']for m in client['imports']if m['name']=='_mach_msg')[:72]
    assert client['return_u32']==0xffff5b37
    return {'fresh_original_server_replay':counts,'source_spans_compared_with_retained_IDA':len(allserver['spans']),
      'original_rebases_checked':len(fix['records']),'original_bindings_checked':len(binding_records),
      'client_to_server_body_bytes_equal':140,'full_received_request_bytes_compared':164,
      'server_to_client_reply_bytes_compared':36,'application_return_u32':'0xffff5b37',
      'receive_header_conversion_is_declared':True,'native_temporal_or_endpoint_identity_established':False,
      'session_prefix_freshly_replayed':False}


def audit():
    e=json.loads(read(ROOT/'fpsd1201_client_checks.json'));assert SHA(read(ROOT/'recover_fpsd1201_client.py').encode())==e['generator_sha256']
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    prior=json.loads(read(ROOT/'corefp_mach_request_profiles.json'));body=next(r for r in prior['original_functions']if r['start']=='0x8d40');assert body==e['source_body']
    imp=json.loads(read(ROOT/'corefp_import_calls.json'));stubs=[r for r in imp['stubs']if r['address']in [x['address']for x in e['source_stubs']]];assert stubs==e['source_stubs']and len(stubs)==7
    att=json.loads(read(ROOT/'fpsd1201_client_ida_readback.json'));assert not att['IDB_mutated']and att['input_sha256']==e['reference_universal_sha256']
    expected=[(0x8d40,bytes.fromhex(body['bytes']))]+[(int(r['address'],16),bytes.fromhex(r['bytes']))for r in stubs]+[(0x15d6978,bytes.fromhex(e['literal8_hex']))]
    assert sorted(att['spans'],key=lambda r:int(r['start'],16))==sorted([{'start':hex(a),'size_B':len(b),'bytes_hex':b.hex(),'sha256':SHA(b)}for a,b in expected],key=lambda r:int(r['start'],16))
    inventory=json.loads(read(ROOT/'corefp_fixups_inventory.json'));assert e['source_pointer_records']==[r for r in inventory['fixups']if r['address']in ['0x1d03f08','0x1d1c570','0x1d1c578','0x1d1c5d0']]
    assert att['builder_xrefs']==[{'from':'0x1d03f08','type':1,'code':False}]
    records=e['source_pointer_records']+[r['pointer']for r in stubs]
    assert len({r['address']for r in records})==11
    for r in records:
        word=int(r['word'],16);auth=word>>63;bind=(word>>62)&1
        assert bool(auth)==r['authenticated']and bool(bind)==r['bind']and r['pointer_format']==12
        if bind:
            ordinal=word&0xffffff;assert ordinal==r['import']['ordinal']
            assert inventory['imports'][ordinal]==r['import']and r['pointer_addend']==0
        else:assert auth and hex(word&0xffffffff)==r['target']=='0x8d40'
        if auth:
            assert hex((word>>32)&65535)==r['diversity']and (word>>48)&1==r['address_diversity']and (word>>49)&3==0 and r['key']=='IA'
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    for h in att['SDK_context']['headers']:assert SHA((sdk/h['SDK_relative_path']).read_bytes())==h['sha256']
    abi=att['SDK_context']['compile_only'];r=subprocess.run([str(sdk)if x=='installed SDK'else x for x in abi['logical_command']],input=abi['source'],text=True,capture_output=True)
    assert r.returncode==abi['exit_code']==0 and r.stdout==abi['stdout']==''and r.stderr==abi['stderr']==''
    counts=Counter();rows=[]
    for p in e['profiles']:counts.update(Replay(p,body,stubs,bytes.fromhex('00000000b1040000')).run());rows.append(oracle(p))
    assert len(rows)==len({r['case']for r in rows})==27
    assert e['verified_counts']=={'profiles':27,'original_visits':counts['original_visits_checked'],
      'source_reads':counts['original_reads_checked'],'source_writes':counts['original_writes_checked'],
      'imports':counts['external_contracts_checked'],'PAC_models':counts['PAC_models_checked'],
      'source_body_bytes':404,'stub_bytes':112,'literal_bytes':8,'local_proofs':1}
    joined=server_join(e,e['profiles'][0]);proof=source_lift(e)
    return {'profiles':27,'client_fresh_replay':dict(counts),'cases':rows,'source_lift':proof,'joined_server':joined,
      'original_CoreFP_pointer_words_decoded':11,'fresh_CoreFP_IDA_spans':9,'fresh_CoreFP_IDA_bytes':524,'SDK_headers_checked':4,
      'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}


if __name__=='__main__':print(json.dumps({'audit_result':audit()}))
