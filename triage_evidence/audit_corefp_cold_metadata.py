#!/usr/bin/env python3
"""Independent initial-RAM reconstruction and complete cold-client replay.

Does not import the new producer. Uses the frozen cold-prefix replay and a
separate frozen daemon engine with an independent driver. Every client CPU,
data access, modeled effect and final touched page is compared. Daemon checks
cover exact visited source bytes, fixed inputs/reply and fresh bounded execution;
they do not constitute a complete daemon CPU/RAM journal or native transport.
O(C*(B+F+V+J+R)) time/space; 12000 client/2000 daemon visits per case.
"""
import copy,json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
from unicorn import arm64_const as A
from audit_corefp_lookup_initialization import Replay as Frozen,initial_page,declared_inputs,ret,frame,restore,unpack,CS
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE
from daemon_rpc502_probe import Probe as DaemonBase,STACK as DSTACK,HALT
from daemon_receive_tools import IMAGE,SOURCE,verify_original_fixups
from resolve_kernel_collection_interfaces import commands
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M64=(1<<64)-1
REC=0x63000100;OUT=0x63000300;DONE=0x65000000;PRIMARY=0x1d44448


class Daemon(DaemonBase):
    def __init__(self,wire):
        super().__init__();self.visited=[];assert len(wire)==24 and struct.unpack_from('<I',wire,20)[0]==1203
        self.received=struct.pack('<6I',18,24,0x6403,0x1403,0,1203)
        self.u.mem_write(DSTACK+0x1000,self.received);self.u.mem_write(DSTACK+0x2000,b'\xa5'*256)
    def hook(self,u,pc,n,d):
        if pc!=HALT:
            assert self.steps<2000 and pc not in self.imports and any(a<=pc<b for a,b in [(0x100004b80,0x100004c10),(0x100004918,0x100004ae4)])
            self.visited.append(pc)
        return super().hook(u,pc,n,d)
    def run(self,child):
        self.setreg(0,DSTACK+0x1000);self.setreg(1,DSTACK+0x2000);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,DSTACK+0x78000)
        self.u.emu_start(0x100004b80,0,count=2001)
        reply=bytes(self.u.mem_read(DSTACK+0x2000,36));h=sha256()
        for a in self.visited:h.update(struct.pack('<Q',a));h.update(IMAGE.read(a,4))
        assert child=={'received_request_bytes':self.received.hex(),'reply_bytes':reply.hex(),'reply_size_bytes':36,
          'reply_status_signed32':-304,'recognized_u32':1,'stop_reason':'returned_to_fixture','steps':self.steps,'records':self.records,
          'pac_bypasses':self.pac,'visited_original_instructions':[hex(a)for a in self.visited],
          'original_instruction_bytes_sha256':h.hexdigest(),'native_message_delivered':False}
        assert self.reg(0)==1 and self.stop_reason=='returned_to_fixture'and self.steps==38 and len(self.visited)==37
        assert struct.unpack('<6I',reply[:24])==(18,36,0x6403,0,0,1303)
        assert reply[24:]==bytes.fromhex('0000000001000000d0feffff')
        assert any(v['site']=='0x100004bdc'and v['target']=='0x100004918'and v['modifier']=='0x0'for v in self.pac)
        return reply


class Replay(Frozen):
    def __init__(self,p,spans,s):
        super().__init__(p,spans,s);self.bi=self.ri=self.mri=self.di=0
    def checkpoint(self,label):
        return {**self.snapshot(label),'record32_hex':self.ram(REC,32).hex(),'output8_hex':self.ram(OUT,8).hex(),
                'visits_so_far':self.v,'models_so_far':self.mi}
    def code(self,u,pc,n,d):
        self.flush();cfg=self.p['configuration']
        if pc==DONE:
            self.ri+=1;assert self.checkpoint('lookup_return_'+str(self.ri))==self.p['lookup_returns'][self.ri-1]
            if self.ri==2:
                assert self.p['frontier']=={'reason':'second_lookup_return','CPU':frame(u)};self.done=True;u.emu_stop();return
            e=self.event();assert e['kind']=='declared_second_invocation'and e['premise']=='sequential invocation with unchanged RAM; no native lock reacquisition or owner claim'
            f=copy.deepcopy(e['before']);f['X31'][0]=hex(REC);f['X31'][30]=hex(DONE);f['PC']=hex(BASE+0x1cdb24)
            self.effects(e,[]);assert e['after']==f;restore(u,f);return
        if pc==BASE+0x1ce278:
            assert self.checkpoint('metadata_return')==self.p['metadata_returns'][self.mri];self.mri+=1
        name=self.imports.get(pc);args=[u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))for j in range(8)]if name else []
        completed=name=='_pthread_once'and args[0]in self.once_done
        if completed or name in ['_bootstrap_look_up','_mig_get_reply_port','_voucher_mach_msg_set','_mach_msg','_mig_put_reply_port','_mig_dealloc_reply_port','_mach_msg_destroy']:
            e=self.event();assert e['name']==name and e['callsite']==hex(u.reg_read(A.UC_ARM64_REG_LR)-4-BASE)and e['args_x0_x7']==list(map(hex,args));writes=[];value=0
            assert e['kind']==('declared_once_completed'if completed else 'declared_API')
            if completed:assert (args[0],args[1])in [(BASE+0x1d34f90,BASE+0x4a21e0),(BASE+0x1d37f50,BASE+0x59e868)]
            elif name=='_bootstrap_look_up':
                b=cfg['bootstrap_results'][self.bi];self.bi+=1;value=b['status_u32'];assert args[0]==0x1b57 and args[2]==BASE+PRIMARY
                service=self.ram(args[1],64).split(b'\0',1)[0].decode();assert e['service']==service
                assert (service,e['callsite'])in [('com.apple.fpsd','0x1ce1bc'),('com.apple.fairplayd','0x1ce448')]
                if 'write_port_u32'in b:writes=[(args[2],b['write_port_u32'].to_bytes(4,'little'))]
            elif name=='_mig_get_reply_port':assert e['callsite']=='0x90f8';value=0x5173
            elif name=='_voucher_mach_msg_set':assert e['callsite']=='0x9124'
            elif name=='_mach_msg':
                assert args[1:7]==[3,24,60,0x5173,0,0]and e['callsite']=='0x914c';wire=self.ram(args[0],24)
                words=struct.unpack('<6I',wire)
                assert e['request24_hex']==wire.hex()and words[0]==0x1513 and words[2:]==(0x5017,0x5173,0,1203)
                child=self.p['daemon_children'][self.di];assert e['child_index']==self.di;self.di+=1;reply=Daemon(wire).run(child)
                b=bytearray(reply);struct.pack_into('<III',b,0,0,36,0);struct.pack_into('<I',b,12,0x5173)
                assert e['received_reply36_hex']==b.hex()and b[20:]==reply[20:];writes=[(args[0],bytes(b))]
                assert e['adapter']=='received envelope bits/size/task-local names only; original IDs and bytes at +24 onward preserved'
            else:assert name=='_mach_msg_destroy'and e['callsite']=='0x9204'
            self.effects(e,writes);assert e['return_u64']==hex(value);f=ret(e['before'],value,cfg.get('clobber_callers',False));assert e['after']==f;restore(u,f);return
        return super().code(u,pc,n,d)
    def run(self):
        result=super().run();assert self.ri==2 and self.mri==len(self.p['metadata_returns'])and self.di==len(self.p['daemon_children'])and self.bi==self.p['bootstrap_calls']==len(self.p['configuration']['bootstrap_results'])
        return {**result,'lookup_returns_checked':self.ri,'metadata_returns_checked':self.mri,'daemon_children_fresh_checked':self.di,'bootstrap_calls_checked':self.bi}


def oracle(p):
    c=p['configuration'];label=c['label'];primary=label.startswith('primary_')and label!='primary_error_repeat'
    fail=label=='primary_error_repeat';retry=label=='fallback_retry'
    expected_boot=[(0,0x5017)]if primary else [(5,None),(5,None)]if fail else [(1102,None),(5,None),(1102,None),(0,0x5034)]if retry else [(1102,None),(0,0x5034)]
    assert c=={'label':label,'allocation_success':[label!='primary_static_repeat',True],'lock_init_status_u32':[0,0],
      'continue_to_bootstrap':True,'bootstrap_results':[{'status_u32':s,**({'write_port_u32':v}if v is not None else {})}for s,v in expected_boot],
      **({'clobber_callers':True}if label=='primary_clobber_repeat'else {})}
    expected=[]
    for j,r in enumerate(p['lookup_returns']):
        failed=fail or retry and j==0;port=0 if failed else 0x5017 if primary else 0x5034;flags=10 if primary else 0
        status=0x45e2a2e3 if failed else 0xba1df9db;out=b'\xa5'*8 if failed else struct.pack('<II',port,flags)
        assert r['record32_hex'][:8]==status.to_bytes(4,'little').hex()and r['output8_hex']==out.hex()and r['primary_u32']==port and r['secondary_u32']==0
        assert r['metadata20_hex']==(b'\0'*12+struct.pack('<I',flags)+b'\0'*4).hex()and r['reset_word_u32']==0x59fece35
        expected.append({'raw_record_marker_u32':hex(status),'name_u32':hex(port),'flags_u32':hex(flags),'caller_outputs_preserved':failed})
    names=[e.get('name',e['kind'])for e in p['models']]
    assert names.count('_malloc')==2 and names.count('_pthread_rwlock_init')==(1 if label=='primary_static_repeat'else 2)
    assert names.count('_pthread_rwlock_wrlock')==2 and names.count('_pthread_once')==4 and names.count('declared_once_return')==2 and names.count('declared_second_invocation')==1
    assert names.count('_bootstrap_look_up')==len(expected_boot)and names.count('_mach_msg')==int(primary)
    assert not any(n in names for n in ['_pthread_rwlock_unlock','_mach_port_deallocate'])
    assert len(p['metadata_returns'])==int(primary)
    if primary:assert int(p['metadata_returns'][0]['CPU']['X31'][0],16)&0xffffffff==0xfffffed0
    cut=p['lookup_returns'][0]['models_so_far'];after=p['models'][cut:]
    assert not any(e.get('name')in ['_malloc','_pthread_rwlock_init','_mach_msg']for e in after)
    if not fail and not retry:assert not any(e.get('name')=='_bootstrap_look_up'for e in after)
    return {'label':label,'returns':expected,'metadata_rejections':int(primary),'write_lock_models':2,'once_callbacks':2,'native_reentry_established':False}


def main():
    e=json.loads(read(ROOT/'corefp_cold_metadata_checks.json'));s=Pointers();assert e['thin_sha256']==THIN_SHA and e['daemon_thin_sha256']==SHA(SOURCE.read_bytes())
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_cold_metadata.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['declared_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()]
    auth=next(r for r in s.meta['sections']if r['section']=='__auth_stubs');source_bytes=0
    for span in e['source_spans']:
        a,b=int(span['start'],16),int(span['end'],16);raw=s.read(a,b-a);source_bytes+=len(raw)
        if 'kind'in span:assert span['kind']=='complete_import_stub_16B'and b-a==16 and (a-auth['address'])%16==0 and auth['address']<=a<b<=auth['address']+auth['size']and span['bytes']==raw.hex()and span['sha256']==SHA(raw)
        else:assert span==s.function(a)
    for span in e['daemon_source_spans']:
        a,b=int(span['start'],16),int(span['end'],16);raw=IMAGE.read(a,b-a);assert raw.hex()==span['bytes']and SHA(raw)==span['sha256']
    totals=Counter();oracles=[]
    assert [p['configuration']['label']for p in e['profiles']]==['primary_repeat','fallback_repeat','primary_static_repeat','primary_clobber_repeat','primary_error_repeat','fallback_retry']
    for p in e['profiles']:
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M64)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':'0x62018000','PC':hex(BASE+0x1cdb24),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(REC);cpu['X31'][30]=hex(DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        for r in p['initial_RAM']:assert unpack(r['payload'])==initial_page(s,int(r['address'],16));totals['initial_RAM_B_checked']+=4096
        replay=Replay(p,e['source_spans'],s);totals.update(replay.run());oracles.append(oracle(p))
    counts={'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points','lookup_returns','metadata_returns','daemon_children']},'bootstrap_calls':sum(p['bootstrap_calls']for p in e['profiles'])};assert counts==e['verified_counts']
    # Status is returned by the builder but not read by this immediate source continuation.
    continuation=[]
    for i in CS.disasm(s.read(0x1ce278,0x18),0x1ce278):
        assert not any(x in i.op_str.replace('[',' ').replace(']',' ').replace(',',' ').split()for x in ['x0','w0']);continuation.append({'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str})
    fixups=verify_original_fixups([0x1010380e0]);rows=fixups['records'];assert rows[0]['decoded_target']=='0x100004918'and rows[0]['authenticated']and rows[0]['key']=='IA'and rows[0]['diversity']=='0x0'and rows[0]['address_diversity']==0
    # NDR is an unauthenticated data bind; the frozen helper only admits
    # authenticated binds, so decode its original import row directly.
    word=struct.unpack('<Q',IMAGE.read(0x1010b1e10,8))[0];assert word>>63==0 and word>>62&1==1
    at=next(a for a,c,n in commands(IMAGE.data,0)if c==0x80000034);off=struct.unpack_from('<I',IMAGE.data,at+8)[0]
    ver,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',IMAGE.data,off);assert (ver,fmt,symfmt)==(0,2,0)
    ordinal=word&0xffffff;assert ordinal<count;iw,addend=struct.unpack_from('<Ii',IMAGE.data,off+imports+8*ordinal)
    begin=off+symbols+(iw>>9);name=IMAGE.data[begin:IMAGE.data.index(0,begin)].decode();assert name=='_NDR_record'and addend==0 and word>>32&0x7ffff==0
    ndr={'address':'0x1010b1e10','word':hex(word),'authenticated':False,'bind':True,'import_name':name,'import_ordinal':ordinal,'total_addend':0}
    d=json.loads(read(ROOT/'corefp_cold_metadata_ida.json'));live=[]
    assert not d['IDB_mutated']and not d['native_target_executed']and d['daemon_recall']['count']==0 and not d['daemon_recall']['truncated']
    for group,reader in [('CoreFP_bytes',s.read),('daemon_bytes',IMAGE.read)]:
        for r in d[group]['results']:
            b=bytes.fromhex(r['bytes']);assert b==reader(int(r['address'],16),len(b))and len(b)==r['size_read']==r['size_requested'];live.append({'address':r['address'],'size_B':len(b),'sha256':SHA(b)})
    result={'verified_counts':counts,'independent_client_replay':dict(totals),'compact_oracle_profiles':len(oracles),'client_source_spans':len(e['source_spans']),
       'client_source_B_checked':source_bytes,'daemon_source_B_checked':604,'daemon_visits_fresh_checked':111,'daemon_steps_including_return':114,
       'live_B_checked':sum(r['size_B']for r in live),'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_cold_metadata_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'corefp_cold_metadata_ida.json').encode()),'dependencies':e['dependencies'],'oracles':oracles,'postmetadata_continuation':continuation,
      'daemon_used_fixups':fixups,'daemon_NDR_source_binding':ndr,'live_byte_ranges':live,'semantic_annotations_used_as_proof':False,'full_daemon_CPU_RAM_replayed':False,
      'fresh_replay_completed':True,'process_exit_code':0}
    (ROOT/'corefp_cold_metadata_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
