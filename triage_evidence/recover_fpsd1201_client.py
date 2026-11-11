#!/usr/bin/env python3
"""Reference CoreFP1201 serializer, reply parser and source-produced failure join.

Original small bodies only; no full changed installed image is loaded. Reply
names, NDR, weak voucher, Mach transport, cleanup and PAC are declared private
models. Parser-only status fixtures do not supply protected-core results.
O(C*(V+J+R)+B) time/space; local SMT cost separate. No native IPC executes.
"""
import base64,json,struct,zlib
from hashlib import sha256
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as A
import z3
from daemon_receive_tools import ROOT,CS
from probe_daemon_descriptor_source import zipbytes
from verify_daemon_reader_record_payloads_publication import read

BASE=0x500000000;STACK=0x71000000;INPUT=0x72000000;BIND=0x76000000;HALT=BASE+0x1fff000
ENTRY=0x8d40;END=0x8ed4;STUBS=[0x15d1894,0x15d18e4,0x15d18f4,0x15d1924,0x15d1934,0x15d1944,0x15d1a14]
REGIONS=[(STACK,65536),(INPUT,4096),(BIND,8192),(BASE+0x1d1c000,4096),(BASE+0x15d6000,4096)]
DEPS=['corefp_mach_request_profiles.json','corefp_import_calls.json','corefp_fixups_inventory.json',
 'fpsd1201_session_checks.json','fpsd1201_session_audit.json','audit_fpsd1201_session.py',
 'recover_fpsd1200_process.py','audit_fpsd1200_process.py','fpsd1200_lifetime_checks.json',
 'fpsd1200_lifetime_audit.json','daemon_descriptor_source_profiles.json',
 'fpsd1201_session_ida_readback.json','recover_fpsd1201_session.py','audit_fpsd1200_lifetime.py',
 'daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py',
 'probe_daemon_descriptor_source.py','replay_daemon_descriptor_source.py']


def digest(b):return sha256(b).hexdigest()


def sources():
    old=json.loads(read(ROOT/'corefp_mach_request_profiles.json'))
    body=next(r for r in old['original_functions']if r['start']==hex(ENTRY))
    imports=json.loads(read(ROOT/'corefp_import_calls.json'))
    stubs=[r for r in imports['stubs']if int(r['address'],16)in STUBS]
    inventory=json.loads(read(ROOT/'corefp_fixups_inventory.json'))
    ptrs=[r for r in inventory['fixups']if r['address']in ['0x1d03f08','0x1d1c570','0x1d1c578','0x1d1c5d0']]
    p=next(r for r in old['profiles']if r['fixture']['entry']==ENTRY)
    literal=bytes.fromhex(p['records'][-1]['message_bytes'])[16:24]
    assert literal==bytes.fromhex('00000000b1040000')
    server=json.loads(read(ROOT/'fpsd1201_session_checks.json'))
    packed=next(p for p in server['profiles']if p['label']=='matching_zero')
    payload=zlib.decompress(base64.b64decode(packed['payload_zlib_base64']));s=json.loads(payload)
    return body,stubs,ptrs,literal,s,digest(payload)


def configurations():
    base={'label':'source_failure_join','transport_u32':0,'reply_status_u32':0xffff5b37,
      'reply_id':1301,'reply_size_B':36,'reply_bits':0,'reply_remote':0,'reply_local':0x6400,
      'reply_reserved':0,'reply_NDR_hex':'0000000001000000','destination_u32':0x6800,
      'reply_name_u32':0x6400,'word_u32':1,'inline128_hex':'00'*128,'voucher':'absent'}
    yield base
    for label,extra in [('parser_status0',{'reply_status_u32':0}),('parser_status8',{'reply_status_u32':8}),
      ('parser_status_ffffffff',{'reply_status_u32':0xffffffff}),('parser_status_80000000',{'reply_status_u32':0x80000000}),
      ('parser_status_7fffffff',{'reply_status_u32':0x7fffffff}),('complex_reply',{'reply_bits':0x80000000}),
      ('short_size',{'reply_size_B':35}),('long_size',{'reply_size_B':40}),
      ('nonzero_remote',{'reply_remote':0x1234}),('server_died_id',{'reply_id':71}),
      ('wrong_reply_id',{'reply_id':1300}),('NDR_changed',{'reply_NDR_hex':'f0e1d2c3b4a59687'}),
      ('local_reserved_changed',{'reply_local':0x9911,'reply_reserved':0x11223344}),
      ('wire_scalar_bytes',{'word_u32':0x11223344,'inline128_hex':bytes(range(128)).hex(),'destination_u32':0x3141,'reply_name_u32':0x5173}),
      ('zero_reply_name',{'reply_name_u32':0}),('max_names',{'destination_u32':0xffffffff,'reply_name_u32':0xffffffff}),
      ('voucher_noop',{'voucher':'noop'}),('voucher_header_write',{'voucher':'header_write'})]:
        yield {**base,'label':label,**extra}
    for n in [0x10000002,0x10000003,0x10000010,1,4,0x10000001,0x10000004,0x10004003]:
        yield {**base,'label':'transport_'+hex(n),'transport_u32':n}


def response(c):
    b=bytearray(b'\xa5'*44)
    struct.pack_into('<6I',b,0,c['reply_bits'],c['reply_size_B'],c['reply_remote'],c['reply_local'],c['reply_reserved'],c['reply_id'])
    b[24:32]=bytes.fromhex(c['reply_NDR_hex']);struct.pack_into('<I',b,32,c['reply_status_u32']);return bytes(b)


class Client:
    def __init__(self,c,body,stubs,literal):
        self.c=c;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.calls=[];self.pac=[]
        self.stub_rows={int(r['address'],16):r for r in stubs};self.imports={}
        for a,n in [(BASE+0x8000,4096),(BASE+0x15d1000,4096),(HALT,4096)]+REGIONS:self.u.mem_map(a,n)
        self.u.mem_write(BASE+ENTRY,bytes.fromhex(body['bytes']))
        self.u.mem_write(STACK,b'\xa5'*65536);self.u.mem_write(INPUT,bytes.fromhex(c['inline128_hex']))
        self.u.mem_write(BASE+0x15d6978,literal)
        self.u.mem_write(BIND+0x100,bytes.fromhex('0000000001000000'));self.u.mem_write(BIND+0x200,bytes.fromhex('b39a4e0cf582617d'))
        for cell,value in [(0x1d1c570,BIND+0x100),(0x1d1c578,BIND+0x200),(0x1d1c5d0,0 if c['voucher']=='absent'else BIND+0x300)]:self.u.mem_write(BASE+cell,struct.pack('<Q',value))
        for j,r in enumerate(stubs):
            a=int(r['address'],16);target=BIND+0x1000+32*j
            if a==0x15d1a14:target=BIND+0x300
            self.u.mem_write(BASE+a,bytes.fromhex(r['bytes']));self.u.mem_write(BASE+int(r['pointer']['address'],16),struct.pack('<Q',target));self.imports[target]=r
        for j in range(31):self.setreg(j,((j+1)*0x13579bdf)&((1<<64)-1))
        for j,v in [(0,c['destination_u32']),(1,c['word_u32']),(2,INPUT),(30,HALT)]:self.setreg(j,v)
        for j in range(32):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int.from_bytes(bytes([j])*16,'little'))
        self.u.reg_write(A.UC_ARM64_REG_SP,STACK+0x8000);self.u.reg_write(A.UC_ARM64_REG_PC,BASE+ENTRY)
        self.u.reg_write(A.UC_ARM64_REG_NZCV,0);self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        self.initial=[{'address':hex(a),'size_B':n,'sha256':digest(self.ram(a,n))}for a,n in REGIONS];self.entry=self.frame()
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read_hook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write_hook)

    def reg(self,j):return self.u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))
    def setreg(self,j,v):self.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v&((1<<64)-1))
    def ram(self,a,n):return bytes(self.u.mem_read(a,n))
    def frame(self):return {'pc':hex(self.u.reg_read(A.UC_ARM64_REG_PC)),'sp':hex(self.u.reg_read(A.UC_ARM64_REG_SP)),
      'registers31':[hex(self.reg(j))for j in range(31)],'NZCV':hex(self.u.reg_read(A.UC_ARM64_REG_NZCV)),
      'Q32':[hex(self.u.reg_read(A.UC_ARM64_REG_Q0+j))for j in range(32)]}
    def flush(self):
        for w in self.pending:w['after_hex']=self.ram(int(w['address'],16),w['size_B']).hex()
        self.pending=[]
    def read_hook(self,u,ac,a,n,v,d):self.reads.append({'visit':len(self.visits)-1,'address':hex(a),'size_B':n,'bytes_hex':self.ram(a,n).hex()})
    def write_hook(self,u,ac,a,n,v,d):
        assert STACK<=a<a+n<=STACK+65536
        w={'visit':len(self.visits)-1,'address':hex(a),'size_B':n,'before_hex':self.ram(a,n).hex()};self.writes.append(w);self.pending.append(w)
    def model(self,a):
        row=self.imports[a];name=row['pointer']['import']['name'];args=[self.reg(j)for j in range(8)]
        e={'stub':row['address'],'name':name,'args8':[hex(v)for v in args],'before':self.frame(),'patches':[]};result=0
        def patch(at,b):
            e['patches'].append({'address':hex(at),'before_hex':self.ram(at,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
        if name=='_mig_get_reply_port':result=self.c['reply_name_u32']
        elif name=='_voucher_mach_msg_set':
            assert self.c['voucher']!='absent'
            if self.c['voucher']=='header_write':patch(args[0]+16,struct.pack('<I',0x8844))
        elif name=='_mach_msg':
            assert args[1:7]==[3,164,44,self.c['reply_name_u32'],0,0]
            e['request164_hex']=self.ram(args[0],164).hex();self.message=args[0]
            if not self.c['transport_u32']:patch(args[0],response(self.c))
            result=self.c['transport_u32']
        else:assert name in ['_mig_put_reply_port','_mig_dealloc_reply_port','_mach_msg_destroy']
        target=self.reg(30)
        for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
        self.setreg(0,result);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000);self.u.reg_write(A.UC_ARM64_REG_PC,target)
        e.update(result_u64=hex(result),after=self.frame());self.calls.append(e)
    def hook(self,u,a,n,d):
        self.flush()
        if a==HALT:self.terminal=self.frame();u.emu_stop();return
        if a in self.imports:return self.model(a)
        off=a-BASE;stub=next((r for k,r in self.stub_rows.items()if k<=off<k+16),None)
        assert ENTRY<=off<END or stub,(hex(a),len(self.visits))
        b=self.ram(a,4);i=next(CS.disasm(b,off));self.visits.append({'pc':hex(off),'bytes_hex':b.hex()})
        if i.mnemonic=='pacibsp':self.pac.append({'visit':len(self.visits)-1,'operation':'PACIBSP_private_noop'});u.reg_write(A.UC_ARM64_REG_PC,a+4)
        elif i.mnemonic=='retab':
            assert self.reg(30)==HALT;self.pac.append({'visit':len(self.visits)-1,'operation':'RETAB_declared_caller'});u.reg_write(A.UC_ARM64_REG_PC,HALT)
        elif i.mnemonic=='braa':
            assert stub and self.reg(17)==BASE+int(stub['pointer']['address'],16)
            assert self.reg(16)in self.imports
            self.pac.append({'visit':len(self.visits)-1,'operation':'BRAA_declared_import_pointer','target':hex(self.reg(16)),'modifier':hex(self.reg(17))});u.reg_write(A.UC_ARM64_REG_PC,self.reg(16))
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=2000);self.flush();assert hasattr(self,'terminal')
        return {'configuration':self.c,'initial_regions':self.initial,'entry':self.entry,'source_visits':self.visits,
          'source_reads':self.reads,'source_writes':self.writes,'imports':self.calls,'PAC_models':self.pac,
          'terminal':self.terminal,'return_u32':self.reg(0)&0xffffffff,'return_u64':hex(self.reg(0)),
          'request164_hex':next(e['request164_hex']for e in self.calls if e['name']=='_mach_msg'),
          'final_regions':[{'address':hex(a),**zipbytes(self.ram(a,n))}for a,n in REGIONS]}


def proof():
    r=z3.BitVec('transport_return32',32);d=r-0x10000002
    actual=z3.And(z3.ULE(d,14),((z3.BitVecVal(1,32)<<(d&31))&0x4003)!=0)
    expected=z3.Or(*[r==v for v in [0x10000002,0x10000003,0x10000010]])
    s=z3.Solver();s.set(timeout=20000);s.add(actual!=expected);q=s.to_smt2();assert s.check()==z3.unsat
    return {'query':q,'result':'unsat','scope':'All u32 transport results at original parser classifier; native return feasibility and cleanup effects unknown.'}


def main():
    body,stubs,pointers,literal,s,payload_sha=sources();profiles=[]
    for c in configurations():
        p=Client(c,body,stubs,literal).run();profiles.append(p)
        print(json.dumps({'case':c['label'],'visits':len(p['source_visits']),'return':hex(p['return_u32'])}),flush=True)
    counts={'profiles':len(profiles),'original_visits':sum(len(p['source_visits'])for p in profiles),
      'source_reads':sum(len(p['source_reads'])for p in profiles),'source_writes':sum(len(p['source_writes'])for p in profiles),
      'imports':sum(len(p['imports'])for p in profiles),'PAC_models':sum(len(p['PAC_models'])for p in profiles),
      'source_body_bytes':404,'stub_bytes':112,'literal_bytes':8,'local_proofs':1}
    out={'scope':__doc__,'generator_sha256':digest(Path(__file__).read_bytes()),'dependencies':{n:digest(read(ROOT/n).encode())for n in DEPS},
      'reference_universal_sha256':'68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f',
      'reference_thin_sha256':'8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c',
      'source_body':body,'source_stubs':stubs,'source_pointer_records':pointers,'literal8_hex':literal.hex(),
      'profiles':profiles,'proof':proof(),'frozen_server_payload_sha256':payload_sha,
      'frozen_server_reply36_hex':s['reply36_hex'],'verified_counts':counts,'native_target_executed':False,
      'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_client_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
