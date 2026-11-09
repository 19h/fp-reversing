#!/usr/bin/env python3
"""Private MIG41471 -> protected handler -> new CF port -> MIG51471 fixtures.

No host IPC, framework, callback or target process executes. Original mappings
are private, code is nonwritable, PAC is bypassed explicitly. Only named APIs
are modeled; unreviewed continuations/imports/system instructions stop.
"""
import hashlib
import json
from pathlib import Path
import struct
import unicorn as uc
from daemon_rpc502_probe import Probe as Base,STACK,HALT,ar
from daemon_receive_tools import IMAGE,SOURCE,CS,ROOT
from resolve_kernel_collection_interfaces import commands

REQUEST=STACK+0x1000;REPLY=STACK+0x2000;CFPORT=0x5000000000;CFSOURCE=CFPORT+0x1000
RANGES=[(0x1000053c8,0x1000054b8),(0x100006944,0x100006c6c),
    (0x10065ffd8,0x100660254),(0x10061a2d0,0x10061a990),
    (0x1004c244c,0x1004c3638),(0x100610388,0x1006103d8),
    (0x1005283ac,0x1005283f8),(0x1005757cc,0x100575870),
    (0x100503b90,0x100503d14),(0x100547800,0x100547834),
    (0x10050a6a0,0x10050a73c),(0x1000043b4,0x1000044fc),
    (0x100001f50,0x100001f9c),(0x100e2a8e0,0x100e2a8f0),
    (0x100e2ab00,0x100e2ab20),(0x100e2ab30,0x100e2ab70)]
RANGES += [(0x100544124,0x10054416c),(0x1005a8588,0x1005a8644)]
RANGES += [(0x100482dbc,0x100482e14)]
RANGES += [(0x100525f80,0x10052604c)]
RANGES += [(0x100546204,0x100546250)]
RANGES += [(0x1004a93d0,0x1004a9534),(0x100528dd8,0x100528e24),
    (0x100800aa8,0x100800b90)]
RANGES += [(0x1004942a8,0x100494324)]
RANGES += [(0x1004ace0c,0x1004ace8c)]


class CreatedPortProbe(Base):
    def __init__(self,label,*,null_cf=False,null_source=False,insert_status=0,
                 transport_status=0,reply_status=0,reply_id=51571,reply_size=36,
                 reply_complex=False,reply_remote=0,port_name=0x5107,
                 incoming_name=0x32f,arcade_name=0x32f,old_created=False):
        super().__init__();self.label=label;self.null_cf=null_cf;self.null_source=null_source
        self.insert_status=insert_status;self.transport_status=transport_status
        self.reply_status=reply_status;self.reply_id=reply_id;self.reply_size=reply_size
        self.reply_complex=reply_complex;self.reply_remote=reply_remote;self.port_name=port_name
        self.incoming_name=incoming_name;self.arcade_name=arcade_name;self.old_created=old_created
        self.visited=set();self.calls=[];self.u.mem_map(CFPORT,0x10000)
        self.u.mem_write(0x1010c4d08,struct.pack('<Q',CFPORT+0x2000))
        if old_created:self.u.mem_write(0x1010c4d10,struct.pack('<Q',CFPORT+0x3000))
        for at,cmd,size in commands(IMAGE.data,0):
            if cmd!=0x19:continue
            va,vm,off,n=struct.unpack_from('<4Q',IMAGE.data,at+24)
            prot=struct.unpack_from('<I',IMAGE.data,at+60)[0]
            if va and vm:self.u.mem_protect(va&~4095,((va+vm+4095)&~4095)-(va&~4095),prot)
        for name,value in [('libSystem/_mach_task_self_',0x103),
            ('CoreFoundation/_kCFRunLoopDefaultMode',CFPORT+0xe000),
            ('CoreFoundation/_kCFRunLoopCommonModes',CFPORT+0xe100)]:
            if name in self.import_addresses:
                self.u.mem_write(self.import_addresses[name],struct.pack('<Q',value))
                self.data_import_values.append({'name':name,'value':hex(value),'model':'private runtime cell'})

    def hook(self,u,address,size,user):
        if address==HALT:return super().hook(u,address,size,user)
        if address in self.imports:
            name=self.imports[address]
            if name=='libSystem/___chkstk_darwin':return super().hook(u,address,size,user)
            self.steps+=1;args=[self.reg(i) for i in range(8)]
            e={'kind':'private_import','name':name,'return_pc':hex(self.reg(30)),'args':[hex(x) for x in args]}
            self.calls.append(e);self.records.append(e)
            if name=='libSystem/_os_log_type_enabled':
                e['model']='logging disabled';self.return_model(0);return
            if name=='CoreFoundation/_CFMachPortCreate':
                e.update({'context_40_bytes':bytes(u.mem_read(args[2],40)).hex(),'callback':hex(args[1]),
                    'result':hex(0 if self.null_cf else CFPORT)})
                self.return_model(0 if self.null_cf else CFPORT);return
            if name=='CoreFoundation/_CFMachPortGetPort':
                assert args[0] in (CFPORT,CFPORT+0x2000)
                value=self.arcade_name if args[0]==CFPORT+0x2000 else self.port_name
                e['result']=hex(value);self.return_model(value);return
            if name=='libSystem/_mach_port_insert_right':
                e['result']=self.insert_status;self.return_model(self.insert_status);return
            if name=='CoreFoundation/_CFMachPortCreateRunLoopSource':
                e['result']=hex(0 if self.null_source else CFSOURCE);self.return_model(0 if self.null_source else CFSOURCE);return
            if name in ('CoreFoundation/_CFRunLoopGetMain','CoreFoundation/_CFRunLoopGetCurrent'):
                self.return_model(CFPORT+0xf000);return
            if name in ('CoreFoundation/_CFRunLoopAddSource','CoreFoundation/_CFRelease',
                'CoreFoundation/_CFMachPortInvalidate','libSystem/_mach_port_deallocate',
                'libSystem/_mig_put_reply_port','libSystem/_mig_dealloc_reply_port'):
                self.return_model(0);return
            if name=='libSystem/_mig_get_reply_port':self.return_model(0xb03);return
            if name=='libSystem/_mach_msg2_internal':
                assert args[0] and args[6]==44
                e['request_40_bytes']=bytes(u.mem_read(args[0],40)).hex();e['transport_status']=self.transport_status
                if self.transport_status==0:
                    raw=bytearray(44);struct.pack_into('<6I',raw,0,0x80000000 if self.reply_complex else 0,
                        self.reply_size,self.reply_remote,0xb03,0,self.reply_id)
                    raw[24:32]=bytes.fromhex('0000000001000000')
                    struct.pack_into('<I',raw,32,self.reply_status&0xffffffff);struct.pack_into('<II',raw,36,0,8)
                    u.mem_write(args[0],bytes(raw));e['modeled_reply_44_bytes']=raw.hex()
                self.return_model(self.transport_status);return
            if name=='libSystem/_mach_msg_destroy':
                e['message_prefix_40']=bytes(u.mem_read(args[0],40)).hex();self.return_model(0);return
            self.stop('unmodeled_created_port_import',name=name,args=e['args']);return
        if not any(a<=address<z for a,z in RANGES):
            self.stop('unreviewed_native_continuation',pc=hex(address),sp=hex(u.reg_read(ar.UC_ARM64_REG_SP)),
                registers={f'x{i}':hex(self.reg(i)) for i in range(29)});return
        self.visited.add(address);i=next(CS.disasm(bytes(u.mem_read(address,4)),address))
        if i.mnemonic in ('paciza','pacia','pacda','autia','autiza','xpaci'):
            self.steps+=1;self.pac.append({'site':hex(address),'instruction':i.mnemonic,'authentication':'explicit private bypass'})
            u.reg_write(ar.UC_ARM64_REG_PC,address+4);return
        return super().hook(u,address,size,user)

    def run_created(self):
        raw=bytearray(40);struct.pack_into('<7I',raw,0,0x80000000,40,0,self.incoming_name,0,41471,1)
        struct.pack_into('<I',raw,28,0x2203);raw[38]=17;raw[39]=0
        self.u.mem_write(REQUEST,bytes(raw));self.setreg(0,REQUEST);self.setreg(1,REPLY)
        self.setreg(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0x78000)
        try:self.u.emu_start(0x1000053c8,0,count=50000)
        except uc.UcError as e:
            self.stop_reason='engine_error';self.records.append({'kind':'engine_error','message':str(e),
                'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC))})
        if self.stop_reason is None:self.stop_reason='instruction_budget'
        for a in self.visited:assert bytes(self.u.mem_read(a,4))==IMAGE.read(a,4),hex(a)
        h=hashlib.sha256();pages=sorted({a&~4095 for a in self.visited})
        for a in pages:h.update(struct.pack('<Q',a));h.update(IMAGE.read(a,4096))
        return {'scope':__doc__,'label':self.label,'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'base_probe_sha256':hashlib.sha256((ROOT/'daemon_rpc502_probe.py').read_bytes()).hexdigest(),
            'seed':{'null_cf':self.null_cf,'null_source':self.null_source,'insert_status':self.insert_status,
                'transport_status':self.transport_status,'reply_status':self.reply_status,'reply_id':self.reply_id,
                'reply_size':self.reply_size,'reply_complex':self.reply_complex,'reply_remote':self.reply_remote,'port_name':self.port_name},
            'registration_seed':{'incoming_service_name':hex(self.incoming_name),'arcade_service_name':hex(self.arcade_name),
                'arcade_cf_field':'0x1010c4d08','old_created':self.old_created},
            'stop_reason':self.stop_reason,'steps':self.steps,'calls':self.calls,'records':self.records,
            'pac_bypasses':self.pac,'image_writes':self.writes,'visited_instruction_addresses':[hex(a) for a in sorted(self.visited)],
            'original_instruction_bytes_verified':len(self.visited),
            'visited_original_code_pages':[hex(a) for a in pages],'visited_original_code_pages_sha256':h.hexdigest(),
            'final_outer_reply_44_bytes':bytes(self.u.mem_read(REPLY,44)).hex(),
            'final_created_cf_field':hex(int.from_bytes(self.u.mem_read(0x1010c4d10,8),'little')),
            'native_target_executed':False,'target_host_operations_executed':False,'full_goal_complete':False}


def main():
    rows=[]
    cases=[('created_success',{}),('created_null_cf',{'null_cf':True}),('created_null_source',{'null_source':True}),
        ('existing_replaced',{'old_created':True}),('existing_then_null_cf',{'old_created':True,'null_cf':True}),
        ('service_mismatch',{'incoming_name':0x42f}),('insert_error_ignored',{'insert_status':5}),
        ('insert_negative_ignored',{'insert_status':-1}),('zero_created_name',{'port_name':0}),
        ('max_created_name',{'port_name':0xffffffff}),('reply_status5',{'reply_status':5}),
        ('reply_status_negative',{'reply_status':-308}),('reply_wrong_id',{'reply_id':51572}),
        ('reply_notify71',{'reply_id':71}),('reply_complex',{'reply_complex':True}),
        ('reply_size35',{'reply_size':35}),('reply_size40',{'reply_size':40}),
        ('reply_remote_nonzero',{'reply_remote':0x222}),
        ('old_nested_error',{'old_created':True,'reply_status':5})]
    cases += [('old_service_mismatch',{'old_created':True,'incoming_name':0x42f})]
    cases += [(f'transport_{s:08x}',{'transport_status':s}) for s in
        [1,0xffffffff,0x10000001,0x10000002,0x10000003,0x10000004,0x1000000f,0x10000010,0x10000011,0x10004003]]
    for label,kw in cases:
        r=CreatedPortProbe(label,**kw).run_created();rows.append(r)
        print(json.dumps({'label':label,'steps':r['steps'],'stop':r['stop_reason'],'last':r['records'][-1],
            'calls':r['calls']}),flush=True)
    (ROOT/'created_port_profiles.json').write_text(json.dumps({'scope':__doc__,'profiles':rows},indent=2)+'\n')


if __name__=='__main__':main()
