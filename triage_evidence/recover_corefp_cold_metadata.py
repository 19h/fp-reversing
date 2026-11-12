#!/usr/bin/env python3
"""Cold lookup, unchanged-ID daemon rejection, and sequential cache re-entry.

Original client instructions and original daemon rejection instructions execute
in private engines. Once/API/PAC, envelope translation and a second invocation
are explicit models. No native target, IPC, lock ownership or IDB mutation.
O(C*(B+F+V+J+R)) time/space; 12000 client and 2000 daemon visit bounds.
"""
import bisect,json,struct
from pathlib import Path
from hashlib import sha256
from unicorn import arm64_const as A
from recover_corefp_lookup_initialization import Run as Frozen,frame,pack,inputs,ROOT,BASE,BIND,REC,OUT,DONE,PRIMARY,SECONDARY
from corefp_fixups_reader import Pointers,THIN_SHA
from daemon_receive_tools import CS,IMAGE,SOURCE
from probe_corefp_protocol_pair import DaemonMetadata
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest()
DEPS=['recover_corefp_lookup_initialization.py','recover_fpsd1201_predicates.py','corefp_library_reader.py','corefp_fixups_reader.py',
      'corefp_fixups_inventory.json','probe_corefp_protocol_pair.py','probe_corefp_lookup.py','probe_corefp_mach_requests.py',
      'probe_corefp_exports.py','daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_receive_fixups.txt']


def configurations():
    def boot(status,port=None):return {'status_u32':status,**({'write_port_u32':port}if port is not None else {})}
    rows=[]
    for label,seq,extra in [('primary_repeat',[boot(0,0x5017)],{}),
      ('fallback_repeat',[boot(1102),boot(0,0x5034)],{}),
      ('primary_static_repeat',[boot(0,0x5017)],{'allocation_success':[False,True]}),
      ('primary_clobber_repeat',[boot(0,0x5017)],{'clobber_callers':True}),
      ('primary_error_repeat',[boot(5),boot(5)],{}),
      ('fallback_retry',[boot(1102),boot(5),boot(1102),boot(0,0x5034)],{})]:
        rows.append({'label':label,'allocation_success':[True,True],'lock_init_status_u32':[0,0],
                     'continue_to_bootstrap':True,'bootstrap_results':seq,**extra})
    return rows


class Run(Frozen):
    def __init__(self,s,c):
        super().__init__(s,c);self.boots=0;self.returns=[];self.metadata_returns=[];self.children=[]
        self.auth=next(r for r in s.meta['sections']if r['section']=='__auth_stubs')
    def checkpoint(self,label):
        return {**self.snapshot(label),'record32_hex':bytes(self.u.mem_read(REC,32)).hex(),
                'output8_hex':bytes(self.u.mem_read(OUT,8)).hex(),'visits_so_far':len(self.visits),'models_so_far':len(self.models)}
    def effect(self,e,a,b):
        self.touch(a,len(b));e['memory'].append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
    def code(self,u,pc,n,d):
        self.flush()
        if pc==DONE:
            self.returns.append(self.checkpoint('lookup_return_'+str(len(self.returns)+1)))
            if len(self.returns)==2:
                self.frontier={'reason':'second_lookup_return','CPU':frame(u)};u.emu_stop();return
            e={'kind':'declared_second_invocation','before':frame(u),'memory':[],
               'premise':'sequential invocation with unchanged RAM; no native lock reacquisition or owner claim'}
            u.reg_write(A.UC_ARM64_REG_X0,REC);u.reg_write(A.UC_ARM64_REG_LR,DONE);u.reg_write(A.UC_ARM64_REG_PC,BASE+0x1cdb24)
            e['after']=frame(u);self.models.append(e);return
        if pc==BASE+0x1ce278:self.metadata_returns.append(self.checkpoint('metadata_return'))
        name=self.imports.get(pc)
        args=[self.reg('x'+str(j))for j in range(8)]if name else []
        handled=name in ['_bootstrap_look_up','_mig_get_reply_port','_voucher_mach_msg_set','_mach_msg','_mig_put_reply_port','_mig_dealloc_reply_port','_mach_msg_destroy']
        completed=name=='_pthread_once'and args[0]in self.once_done
        if handled or completed:
            e={'kind':'declared_once_completed'if completed else 'declared_API','name':name,'before':frame(u),
               'args_x0_x7':[hex(v)for v in args],'callsite':hex(self.reg('lr')-4-BASE),'memory':[]};self.models.append(e);v=0
            if completed:assert args[1]in [BASE+0x4a21e0,BASE+0x59e868]
            elif name=='_bootstrap_look_up':
                assert self.boots<len(self.c['bootstrap_results']);b=self.c['bootstrap_results'][self.boots];self.boots+=1
                assert args[0]==0x1b57 and args[2]==BASE+PRIMARY
                service=bytes(u.mem_read(args[1],64)).split(b'\0',1)[0].decode();assert service in ['com.apple.fpsd','com.apple.fairplayd'];e['service']=service
                v=b['status_u32']
                if 'write_port_u32'in b:self.effect(e,args[2],b['write_port_u32'].to_bytes(4,'little'))
            elif name=='_mig_get_reply_port':v=0x5173
            elif name=='_mach_msg':
                assert args[1:7]==[3,24,60,0x5173,0,0];wire=bytes(u.mem_read(args[0],24));assert struct.unpack_from('<I',wire,20)[0]==1203
                child=DaemonMetadata(wire,1203).run_server();self.children.append(child)
                assert child['stop_reason']=='returned_to_fixture'and child['recognized_u32']==1 and child['reply_size_bytes']==36 and child['reply_status_signed32']==-304
                body=bytearray.fromhex(child['reply_bytes']);assert struct.unpack_from('<I',body,20)[0]==1303
                struct.pack_into('<III',body,0,0,len(body),0);struct.pack_into('<I',body,12,0x5173)
                e.update({'request24_hex':wire.hex(),'child_index':len(self.children)-1,'received_reply36_hex':body.hex(),
                          'adapter':'received envelope bits/size/task-local names only; original IDs and bytes at +24 onward preserved'})
                self.effect(e,args[0],bytes(body))
            e['return_u64']=hex(v);self.returned(v);e['after']=frame(u);return
        at=pc-BASE
        # Compiler function starts terminate before authenticated import stubs.
        if self.auth['address']<=at<self.auth['address']+self.auth['size']:
            stub=self.auth['address']+((at-self.auth['address'])//16)*16;raw=bytes(u.mem_read(pc,4));i=next(CS.disasm(raw,at))
            if stub not in self.functions:
                b=self.s.read(stub,16);self.functions[stub]={'start':hex(stub),'end':hex(stub+16),'bytes':b.hex(),'sha256':SHA(b),'kind':'complete_import_stub_16B'}
            self.visits.append({'pc':hex(at),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str})
            if i.mnemonic=='braa':
                rn,mn=i.op_str.split(', ');target=self.reg(rn);mod=self.reg(mn)
                ix=next(j for j in range(len(self.reads)-1,-1,-1)if self.reads[j]['size_B']==8 and int.from_bytes(bytes.fromhex(self.reads[j]['bytes_hex']),'little')==target)
                slot=int(self.reads[ix]['address'],16)-BASE;row=self.s.decoded[slot]
                assert row['authenticated']and row['key']=='IA'and mod==(BASE+slot if row['address_diversity']else int(row['diversity'],16))
                self.pacs.append({'visit':len(self.visits)-1,'pc':hex(at),'target':hex(target),'modifier':hex(mod),'load_index':ix,'pointer_row':row,'CPU':frame(u)});u.reg_write(A.UC_ARM64_REG_PC,target)
            return
        return super().code(u,pc,n,d)
    def run(self):
        p=super().run();p.update({'lookup_returns':self.returns,'metadata_returns':self.metadata_returns,'daemon_children':self.children,'bootstrap_calls':self.boots})
        assert self.boots==len(self.c['bootstrap_results'])and len(self.returns)==2;return p


def main():
    s=Pointers();rows=[];spans={}
    for c in configurations():
        run=Run(s,c);p=run.run();rows.append(p);spans.update(run.functions)
    counts={'profiles':len(rows),**{k:sum(len(p[k])for p in rows)for k in ['visits','reads','writes','PAC_models','models','points','lookup_returns','metadata_returns','daemon_children']},'bootstrap_calls':sum(p['bootstrap_calls']for p in rows)}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,'daemon_thin_sha256':SHA(SOURCE.read_bytes()),
         'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'source_spans':list(spans.values()),
         'daemon_source_spans':[{'start':hex(a),'end':hex(b),'bytes':IMAGE.read(a,b-a).hex(),'sha256':SHA(IMAGE.read(a,b-a))}for a,b in [(0x100004b80,0x100004c10),(0x100004918,0x100004ae4)]],
         'declared_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()], 'profiles':rows,'verified_counts':counts,
         'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'corefp_cold_metadata_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
