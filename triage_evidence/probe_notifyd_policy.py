#!/usr/bin/env python3
"""Original notifyd configuration parser and controlled-name policy guest.

Extends frozen initialized provider engine with explicit stat/FILE/fgets/number/
string/reallocf models. Captured reference bytes or declared fixtures are input;
no daemon/file/sandbox/Mach operation executes. O(B+P+V+W+A) bounded time/space.
"""
import json
from pathlib import Path
import re
import struct
from probe_notifyd_admission import Session,HEAP
from notifyd_ipc_reader import Notifyd,ROOT,sha
from bootpolicy_cache_reader import Dylib
from unicorn import arm64_const as A

STREAM=HEAP+0x900

class Policy(Session):
    def __init__(self,d,f):
        super().__init__(d,f);self.config=bytes.fromhex(f.get('config_hex',''));self.config_position=0;self.config_line=0;path='/usr/lib/libbsm.0.dylib';self.audit_lib=Dylib(self.cache.cache,path);self.cache.libs[path]=self.audit_lib;self.audit_exports={n:r['address'] for n,r in self.audit_lib.exports.items() if n.startswith('_audit_token_to_')}
    def number(self,text,bits):
        m=re.match(r'^[\t\n\v\f\r ]*([+-]?)([0-9]+)',text);value=int(m[2])*(-1 if m[1]=='-' else 1) if m else 0;assert -(1<<(bits-1))<=value<(1<<(bits-1));return value
    def api(self,im):
        name=im['name'];x=[self.reg('x'+str(j)) for j in range(8)];f=self.fixture
        if name in self.audit_exports:
            target=self.audit_exports[name];self.records.append({'kind':'original_audit_function_transfer','name':name,'callsite':hex(getattr(self,'last_source_branch',self.reg('lr')-4)),'original_cache_target':hex(target),'library_uuid':self.audit_lib.uuid,'native_API_executed':False});self.u.reg_write(A.UC_ARM64_REG_PC,target);return
        if name not in ['_stat','_fopen','_fgets','_fclose','_strcasecmp','_atoi','_atoll','_reallocf']:return super().api(im)
        e={'kind':'explicit_config_API_model','name':name,'callsite':hex(getattr(self,'last_source_branch',self.reg('lr')-4)),'args_x0_x7':[hex(v) for v in x],'native_API_executed':False};self.records.append(e)
        if name=='_stat':
            path=self.string(x[0]);e['path']=path
            if path!='/etc/notify.conf' or not f.get('config_present',True):e['result_signed32']=-1;return self.finish_api(-1)
            raw=bytearray(144);struct.pack_into('<H',raw,4,f.get('config_mode_u16',0o100644));struct.pack_into('<II',raw,16,f.get('config_uid',0),f.get('config_gid',0));struct.pack_into('<q',raw,96,len(self.config));self.api_write(x[1],bytes(raw),e);e.update(result_signed32=0,scope='declared stat144 fixture;identity/TOCTOU not native-validated');return self.finish_api(0)
        if name=='_fopen':
            path=self.string(x[0]);mode=self.string(x[1]);e.update(path=path,mode=mode)
            if path=='/etc/notify.conf' and f.get('config_open_success',True):self.config_position=0;e['result']=hex(STREAM);return self.finish_api(STREAM)
            e['result']='NULL explicit file-boundary fixture';return self.finish_api(0)
        if name=='_fgets':
            assert x[2]==STREAM and 2<=x[1]<=1024;left=self.config[self.config_position:];n=min(len(left),x[1]-1);newline=left.find(b'\n',0,n)
            if newline>=0:n=newline+1
            e.update(input_offset_bytes=self.config_position,bound_bytes=x[1])
            if not n:e['result']='NULL EOF';return self.finish_api(0)
            raw=left[:n];self.config_position+=n;self.config_line+=1;self.api_write(x[0],raw+b'\0',e);e.update(read_chunk_hex=raw.hex(),result=hex(x[0]),chunk_ordinal=self.config_line);return self.finish_api(x[0])
        if name=='_fclose':assert x[0]==STREAM;return self.finish_api(0)
        if name=='_strcasecmp':
            a=self.string(x[0]).encode();b=self.string(x[1]).encode();e.update(left_hex=a.hex(),right_hex=b.hex());return self.finish_api((a.lower()>b.lower())-(a.lower()<b.lower()))
        if name in ['_atoi','_atoll']:
            text=self.string(x[0]);bits=32 if name=='_atoi' else 64;value=self.number(text,bits);e.update(input=text,width_bits=bits,result_signed=value);return self.finish_api(value)
        if name=='_reallocf':
            ptr=self.allocate(x[1],False);e.update(result=hex(ptr),requested_size_bytes=x[1]);old=self.allocations.get(x[0])
            if x[0]:assert old and not old['freed'];self.api_write(ptr,bytes(self.u.mem_read(x[0],min(old['size_bytes'],x[1]))),e);old['freed']=True
            return self.finish_api(ptr)
    def code(self,u,pc,n,data):
        if pc==0x100005a10:
            p=self.reg('x26');tokens=[]
            for j in range(64):
                value=int.from_bytes(self.u.mem_read(p+8*j,8),'little')
                if not value:break
                tokens.append(self.string(value))
            else:return self.stop('bounded_config_token_vector')
            self.records.append({'kind':'original_config_token_vector','pc':hex(pc),'pointer':hex(p),'tokens':tokens,'count_u64':self.reg('x20'),'source_chunk_ordinal':self.config_line})
        old=self.collection_lib
        if any(sec['name']=='__text' and sec['address']<=pc<sec['address']+sec['size'] for sec in self.audit_lib.sections):self.collection_lib=self.audit_lib
        try:return super().code(u,pc,n,data)
        finally:self.collection_lib=old
    def invoke(self,label,entry,args):
        r=super().invoke(label,entry,args);base=int.from_bytes(self.u.mem_read(0x100014210,8),'little');count=int.from_bytes(self.u.mem_read(0x100014224,4),'little');assert count<=64;rows=[]
        for j in range(count):
            ptr=int.from_bytes(self.u.mem_read(base+8*j,8),'little');nameptr=int.from_bytes(self.u.mem_read(ptr+8,8),'little');raw=bytes(self.u.mem_read(ptr,72));uid,gid,access=struct.unpack_from('<III',raw,40);rows.append({'index':j,'record_pointer':hex(ptr),'record72_hex':raw.hex(),'name':self.string(nameptr),'uid_u32':uid,'gid_u32':gid,'access_u32':access})
        r.update(controlled_name_array_pointer=hex(base),controlled_names_after=rows,config_position_bytes=self.config_position);return r


def main():
    f={'model_port_constructor':True,'model_port_request_notification':True,'config_hex':(ROOT/'notifyd_policy_reference.conf').read_bytes().hex()};q=Policy(Notifyd(),f);r=q.invoke('reference_config_startup',q.provider.entry,[q.argc,HEAP+0x1800]);Path('/tmp/notifyd-policy-first.json').write_text(json.dumps(r));print(json.dumps({'stop':r['stop_reason'],'steps':r['steps'],'last':r['records'][-1],'controlled':r['controlled_names_after']}),flush=True)

if __name__=='__main__':main()
