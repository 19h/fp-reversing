#!/usr/bin/env python3
"""FPSD1200: original daemon wrapper and retained CoreFP parser, private only.

Original instructions execute in isolated Unicorn pages. The protected core,
Mach receive conversion and deallocation imports are explicit fixtures, never
native authentication, certificate processing, ownership or IPC observations.
O(C*(B+F+K)+256*N) time; O(B+F+C*K) space for image bytes, fixups, bounded
visits and N byte-bank selectors. Read-only live IDA attestation is retained.
"""
import hashlib
import json
from pathlib import Path
import struct
import unicorn as uc
from unicorn import arm64_const as A
from daemon_receive_tools import IMAGE,SOURCE,CS,FIXUPS,ROOT,POOL,TABLE,MASK64,qword,selected,verify_original_fixups
from daemon_rpc502_probe import Probe,STACK,HALT
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:hashlib.sha256(b).hexdigest()
RANGES=[(0x100004530,0x100004720),(0x100004b80,0x100004c10),
 (0x100007b28,0x100007fac),(0x10046f89c,0x10046faf8),(0x100e2ab40,0x100e2ab50)]
CLIENT_BASE=0x500000000;CLIENT_STACK=0x71000000;CLIENT_OUT=0x72000000


def sources():
    att=json.loads(read(ROOT/'fpsd1200_ida_readback.json'))
    daemon,core=att['images'];assert daemon['image_base']=='0x100000000' and core['image_base']=='0x0'
    assert core['input_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    for s in daemon['spans']:
        b=bytes.fromhex(s['bytes_hex']);assert len(b)==s['size_B'] and SHA(b)==s['sha256']
        assert IMAGE.read(int(s['start'],16),len(b))==b
    retained=json.loads(read(ROOT/'corefp_mach_request_profiles.json'))
    f=next(f for f in retained['original_functions']if f['start']=='0x8ae0')
    assert len(bytes.fromhex(f['bytes']))==608 and SHA(bytes.fromhex(f['bytes']))==f['sha256']
    imports=json.loads(read(ROOT/'corefp_import_calls.json'))['stubs']
    stubs={int(s['address'],16):s for s in imports if int(s['address'],16)in [0x15d18f4,0x15d1924,0x15d1944]}
    for s in core['spans']:
        a=int(s['start'],16);expected=f if a==0x8ae0 else stubs[a]
        assert s['bytes_hex']==expected['bytes'] and s['sha256']==expected['sha256']
    wire=bytes.fromhex(retained['profiles'][0]['records'][-1]['message_bytes'])
    assert len(wire)==64 and struct.unpack_from('<I',wire,20)[0]==1200
    return att,f,stubs,wire


def selectors():
    rows={}
    specs=[('state1',0x100e99700,0x100f4e190,0x81,0x768,POOL,0xffffffffb2c74fbe),
      ('state2',(qword(POOL+0x6640)+0xffffffffdaeb98b6)&MASK64,(qword(POOL+0x4048)+0xffffffffb971d649)&MASK64,0x61,0x7b,POOL,0xffffffffec9e1772),
      ('table',0x100fc4130,0x101031ea0,0x4e,0x81b,POOL,0xffffffffd0c4d1ee),
      ('copy',(qword(POOL+0x6188)+0xffffffffdc8ddf91)&MASK64,(qword(POOL+0x3030)+0xffffffffc6a5784a)&MASK64,0x56,0xcb9f,TABLE,0),
      ('nested_seed',(qword(POOL+0x2b50)+0xfffffffff02ce87e)&MASK64,(qword(POOL+0x30f8)-0xd45667)&MASK64,0x86,0xd33,POOL,0xffffffffc7024c75),
      ('dispatcher',(qword(POOL+0x29c8)+0xffffffffaa591739)&MASK64,(qword(POOL+0x4c18)+0xffffffff8af86dcd)&MASK64,0xbb,0xcc2e,TABLE,0)]
    for n,l,r,k,add,base,bias in specs:rows[n]=selected(l,r,k,add,base,bias)
    assert [rows[n]['target']for n in rows]==['0x1010b8078','0x1010c4670','0x101039ef0','0x10046f89c','0x1010c4d68','0x10065ffd8']
    addresses={int(s['slot'],16)for s in rows.values()}|{POOL+d for d in [0x6640,0x4048,0x6188,0x3030,0x2b50,0x30f8,0x29c8,0x4c18]}|{0x1010b1d38}
    return rows,verify_original_fixups(addresses)


class Server(Probe):
    def __init__(self,wire,fixture):
        super().__init__();self.fixture=fixture;self.visited=[];self.application=None;self.carrier=None;self.dealloc=[]
        self.req=STACK+0x1000;self.reply=STACK+0x2000;self.ool=STACK+0x6000
        self.u.mem_write(STACK,b'\xa5'*0x80000)
        received=bytearray(wire)+bytearray(64)
        struct.pack_into('<6I',received,0,0x80001212,64,0x6400,0x1400,0,1200)
        struct.pack_into('<Q',received,28,self.ool)
        struct.pack_into('<II',received,64,0,52)
        received[84:116]=bytes(range(32))
        for offset,value,width in fixture.get('request_changes',[]):received[offset:offset+width]=int(value).to_bytes(width,'little')
        self.received=bytes(received);self.u.mem_write(self.req,self.received)
        self.u.mem_write(self.ool,bytes(range(128)))
        self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        for a,v in zip([0x1010b8078,0x1010c4670],fixture.get('states',[0,0])):self.u.mem_write(a,struct.pack('<Q',v))

    def hook(self,u,pc,n,data):
        if pc==HALT:return super().hook(u,pc,n,data)
        if self.steps>3000:return self.stop('instruction_budget_guard')
        if pc==0x100007b28:
            sp=u.reg_read(A.UC_ARM64_REG_SP)
            self.application=[self.reg(i)for i in range(8)]+list(struct.unpack('<6Q',u.mem_read(sp,48)))
        if pc==0x10065ffd8:
            p=self.reg(0);delta=self.reg(1);payload=struct.unpack('<Q',u.mem_read(p+16,8))[0]
            nested=struct.unpack('<Q',u.mem_read(p,8))[0]^0x1c0b9f7ce10f2255
            self.carrier={'address':hex(p),'delta_cell':hex(delta),'nested':hex(nested),'payload':hex(payload),
              'carrier28_before':bytes(u.mem_read(p,28)).hex(),'nested24_before':bytes(u.mem_read(nested,24)).hex(),
              'payload104_before':bytes(u.mem_read(payload,104)).hex()}
            # Declared protected-core result fixture. Original protected code is
            # not executed; these output bytes do not prove actual acceptance.
            status=self.fixture.get('core_status',0)
            u.mem_write(delta,struct.pack('<Q',0));u.mem_write(p+24,struct.pack('<I',status^0x8b3dc651))
            inline=struct.unpack('<Q',u.mem_read(payload+64,8))[0]
            u.mem_write(inline,bytes((i^0x5a)for i in range(128)))
            u.mem_write(payload+72,struct.pack('<Q',0x33445000))
            u.mem_write(payload+80,struct.pack('<6I',13,1,0x11223344,0x55667788,0x99aabbcc,0x8844))
            self.carrier['payload104_after']=bytes(u.mem_read(payload,104)).hex()
            self.return_model(0);return
        if pc in self.imports:
            name=self.imports[pc]
            if name=='libSystem/_mig_deallocate':
                self.dealloc.append({'args_x0_x1':[hex(self.reg(0)),hex(self.reg(1))],
                  'request_ool_before':bytes(u.mem_read(self.req+28,16)).hex(),'modeled':True})
                return self.return_model(0)
            return self.stop('unmodeled_import_guard',name=name)
        if not any(a<=pc<z for a,z in RANGES):return self.stop('unreviewed_continuation_guard',pc=hex(pc))
        self.visited.append(pc);return super().hook(u,pc,n,data)

    def run_case(self):
        self.setreg(0,self.req);self.setreg(1,self.reply);self.setreg(30,HALT)
        self.u.reg_write(A.UC_ARM64_REG_SP,STACK+0x78000)
        try:self.u.emu_start(0x100004b80,0,count=3001)
        except uc.UcError as e:self.stop_reason='private_engine_error:'+str(e)
        reply=bytes(self.u.mem_read(self.reply,212))
        return {'fixture':self.fixture,'request_received128':self.received.hex(),'reply212':reply.hex(),
          'reply_size_B':struct.unpack_from('<I',reply,4)[0],'recognized':self.reg(0),'stop_reason':self.stop_reason,
          'application_args14':None if self.application is None else [hex(x)for x in self.application],
          'protected_core_boundary':self.carrier,'modeled_deallocation':self.dealloc,
          'request_ool_after16':bytes(self.u.mem_read(self.req+28,16)).hex(),
          'states_after':[hex(struct.unpack('<Q',self.u.mem_read(a,8))[0])for a in [0x1010b8078,0x1010c4670]],
          'visited':[hex(a)for a in self.visited],'PAC_bypasses':self.pac}


class Client:
    def __init__(self,function,stubs,reply,fixture):
        self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.visited=[];self.cleanup=[];self.stop_reason=None
        self.function=function;self.stubs=stubs;self.fixture=fixture;self.steps=0
        self.u.mem_map(CLIENT_BASE,0x1600000);self.u.mem_write(CLIENT_BASE+0x8ae0,bytes.fromhex(function['bytes']))
        self.u.mem_map(CLIENT_STACK,0x10000);self.u.mem_map(CLIENT_OUT,0x10000)
        self.u.mem_write(CLIENT_STACK,b'\xa5'*0x10000);self.u.mem_write(CLIENT_OUT,b'\xa5'*0x10000)
        self.sp=CLIENT_STACK+0x8000;self.message=self.sp+12;self.outs=[CLIENT_OUT+i*0x100 for i in range(9)]
        b=bytearray.fromhex(reply)
        # Explicit private receive conversion. The outgoing COPY_SEND type19
        # becomes received send-right type17 only when this fixture requests it.
        struct.pack_into('<I',b,0,struct.unpack_from('<I',b)[0]&0x80000000)
        struct.pack_into('<II',b,8,0,0x5173)
        if fixture.get('normalize_port_disposition',True)and struct.unpack_from('<I',b,4)[0]==212:b[54]=17
        for off,val,width in fixture.get('reply_changes',[]):b[off:off+width]=int(val).to_bytes(width,'little')
        self.received=bytes(b);self.u.mem_write(self.message,self.received)
        self.u.reg_write(A.UC_ARM64_REG_SP,self.sp);self.u.reg_write(A.UC_ARM64_REG_X29,self.sp+0x120)
        # Parser continuation state supplied by the original builder prologue.
        for n,v in [(19,self.outs[3]),(20,self.outs[2]),(21,self.outs[1]),(23,self.outs[0]),(0,fixture.get('transport_status',0))]:self.u.reg_write(A.UC_ARM64_REG_X0+n,v)
        self.u.mem_write(self.sp+0x130,struct.pack('<4Q',*self.outs[4:8]))
        self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20);self.u.hook_add(uc.UC_HOOK_CODE,self.hook)

    def hook(self,u,pc,n,data):
        a=pc-CLIENT_BASE;self.steps+=1
        if a==0x8d08:self.stop_reason='original_parser_reached_epilogue';u.emu_stop();return
        if a in self.stubs:
            self.cleanup.append({'stub':hex(a),'name':self.stubs[a]['pointer']['import']['name'],
              'arg_x0':hex(u.reg_read(A.UC_ARM64_REG_X0)),'native_cleanup_executed':False})
            u.reg_write(A.UC_ARM64_REG_PC,u.reg_read(A.UC_ARM64_REG_LR));return
        if not 0x8bac<=a<0x8d08:self.stop_reason='unreviewed_client_guard';u.emu_stop();return
        self.visited.append(a)

    def run_case(self):
        try:self.u.emu_start(CLIENT_BASE+0x8bac,0,count=501)
        except uc.UcError as e:self.stop_reason='private_engine_error:'+str(e)
        return {'fixture':self.fixture,'received212':self.received.hex(),'stop_reason':self.stop_reason,
          'status_u32':self.u.reg_read(A.UC_ARM64_REG_X22)&0xffffffff,'cleanup':self.cleanup,
          'outputs':[bytes(self.u.mem_read(p,144 if i==1 else 16)).hex()for i,p in enumerate(self.outs[:8])],
          'visited':[hex(a)for a in self.visited]}


def main():
    att,f,stubs,wire=sources();banks,fixups=selectors();rows=[]
    fixtures=[{'label':'accepted_zero_state'}, {'label':'accepted_nonzero_state','states':[0x1020304050607080,0xfedcba9876543210]},
      {'label':'application_error','core_status':0x1234},
      {'label':'trailer_minimum32','request_changes':[[68,32,4]]}]
    fixtures += [{'label':name,'request_changes':[change]}for name,change in [
      ('simple_request',[0,0x1212,4]),('descriptor_count0',[24,0,4]),('request_size60',[4,60,4]),
      ('wrong_descriptor_type',[39,0,1]),('length_disagreement',[60,9,4]),
      ('wrong_trailer_type',[64,1,4]),('short_trailer31',[68,31,4])]]
    fixtures += [{'label':'accepted_max_state','states':[MASK64,MASK64]},
      {'label':'application_error_all_ones','core_status':0xffffffff}]
    for fixture in fixtures:
        r=Server(wire,fixture).run_case();assert r['stop_reason']=='returned_to_fixture' and r['recognized']==1,r
        rows.append(r)
    successful=rows[0];client_fixtures=[{'label':'matching_received_reply'},
      {'label':'outgoing_disposition_without_conversion','normalize_port_disposition':False}]
    client_fixtures += [{'label':name,'reply_changes':[change]}for name,change in [
      ('id71',[20,71,4]),('wrong_id',[20,1301,4]),('descriptor_count1',[24,1,4]),
      ('reply_size208',[4,208,4]),('nonnull_received_remote',[8,0x4444,4]),
      ('wrong_ool_type',[39,0,1]),('wrong_port_type',[55,1,1]),('unequal_ool_count',[196,14,4])]]
    client_fixtures += [{'label':'transport_'+hex(status),'transport_status':status}for status in [0x10000001,0x10000002,0x10000003,0x10000010]]
    clients=[Client(f,stubs,successful['reply212'],case).run_case()for case in client_fixtures]
    clients += [Client(f,stubs,rows[i]['reply212'],{'label':'server_'+rows[i]['fixture']['label']}).run_case()for i in [2,4,7,9,12]]
    clients += [Client(f,stubs,rows[2]['reply212'],case).run_case()for case in [
      {'label':'simple_error_nonnull_remote','reply_changes':[[8,0x4444,4]]},
      {'label':'simple_zero_status','reply_changes':[[32,0,4]]},
      {'label':'simple_wrong_size','reply_changes':[[4,40,4]]}]]
    assert all(r['stop_reason']=='original_parser_reached_epilogue'for r in clients),clients
    spans=[]
    for a,z in RANGES:
        raw=IMAGE.read(a,z-a);spans.append({'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':SHA(raw),
          'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]})
    out={'scope':__doc__,'daemon_slice_sha256':SHA(SOURCE.read_bytes()),'CoreFP_reference_slice_sha256':'8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c',
      'source_attestation':{'daemon_live_ranges_match_original':7,'CoreFP_live_ranges_match_retained_original':4,
       'installed_CoreFP_sha256_observed':SHA(Path('/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP').read_bytes()),
       'installed_CoreFP_matches_reference':SHA(Path('/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP').read_bytes())==att['images'][1]['input_sha256']},
      'selectors':banks,'fixups':fixups,'daemon_source_spans':spans,'CoreFP_function':f,'CoreFP_cleanup_stubs':list(stubs.values()),
      'source_request_wire64':wire.hex(),'server_cases':rows,'client_cases':clients,
      'verified_counts':{'bank_uses':6,'bank_inputs':1536,'format12_words':len(fixups['records']),'server_cases':len(rows),'client_cases':len(clients),
       'server_source_visits':sum(len(r['visited'])for r in rows),'client_source_visits':sum(len(r['visited'])for r in clients)},
      'generator_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in ['daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_rpc502_probe.py','corefp_mach_request_profiles.json','corefp_import_calls.json','fpsd1200_ida_readback.json']},
      'new_IDA_access':True,'new_IDB_mutations':False,'new_native_execution':False,'protected_core_executed':False,'full_goal_complete':False}
    (ROOT/'fpsd1200_contract_checks.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out['verified_counts']))
    for r in rows:print(r['fixture']['label'],r['reply_size_B'],len(r['modeled_deallocation']),None if r['protected_core_boundary']is None else 'core_fixture')
    for r in clients:print(r['fixture']['label'],hex(r['status_u32']),[c['name']for c in r['cleanup']])


if __name__=='__main__':main()
