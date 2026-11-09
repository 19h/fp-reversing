#!/usr/bin/env python3
"""Read original CoreFP dylib container, export trie and selected function.

No dlopen/dlsym or target call. Original-file metadata and instruction bytes
only. O(B+E+F) for bytes, exports and function starts; no symbol-name semantics
are inferred beyond exact export identity.
"""
import bisect
import json
from pathlib import Path
import struct
from resolve_kernel_collection_interfaces import commands,macho,string
from bootpolicy_cache_reader import uleb
from appstore_agent_reader import ROOT,CS,sha

SOURCE=Path('/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP')
SHA='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
THIN_SHA='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'


class Library:
    def __init__(self):
        raw=SOURCE.read_bytes();assert sha(raw)==SHA and raw[:4]==bytes.fromhex('cafebabe');self.slices=[]
        for j in range(struct.unpack_from('>I',raw,4)[0]):
            cpu,sub,off,n,al=struct.unpack_from('>5I',raw,8+j*20)
            self.slices.append({'cpu':hex(cpu),'subtype':hex(sub),'offset':off,'size_bytes':n,'sha256':sha(raw[off:off+n])})
        sel=next(x for x in self.slices if x['cpu']=='0x100000c' and x['subtype']=='0x80000002');self.data=raw[sel['offset']:sel['offset']+sel['size_bytes']];assert sha(self.data)==THIN_SHA
        self.meta=macho(self.data,0,'CoreFP original arm64e');self.base=next(x['address'] for x in self.meta['segments'] if x['name']=='__TEXT');self.exports={};self.starts=[];self.loads=[]
        for at,c,n in commands(self.data,0):
            if c in (0xc,0x80000018,0x8000001f,0x80000023,0x20):self.loads.append(string(self.data,at+struct.unpack_from('<I',self.data,at+8)[0]))
            if c==0x80000033:
                off,size=struct.unpack_from('<II',self.data,at+8);buf=self.data[off:off+size];self.export_trie={'file_offset':off,'size_bytes':size,'sha256':sha(buf)}
                def visit(a,prefix,ancestors):
                    assert a not in ancestors;term,pos=uleb(buf,a);end=pos+term
                    if term:
                        flags,pos=uleb(buf,pos)
                        if flags&8:
                            ordinal,pos=uleb(buf,pos);name=buf[pos:buf.index(0,pos)].decode();self.exports[prefix]={'flags':flags,'reexport_ordinal':ordinal,'reexport_name':name}
                        else:
                            offset,pos=uleb(buf,pos);self.exports[prefix]={'flags':flags,'address':self.base+offset,'terminal_bytes':buf[a:end].hex()}
                    count=buf[end];pos=end+1
                    for j in range(count):
                        z=buf.index(0,pos);suffix=buf[pos:z].decode();child,pos=uleb(buf,z+1);visit(child,prefix+suffix,ancestors|{a})
                visit(0,'',set())
            if c==0x26:
                off,size=struct.unpack_from('<II',self.data,at+8);buf=self.data[off:off+size];p=0;value=self.base
                while p<len(buf):
                    d,p=uleb(buf,p)
                    if not d:break
                    value+=d;self.starts.append(value)
    def read(self,a,n):
        for seg in self.meta['segments']:
            if seg['address']<=a and a+n<=seg['address']+seg['file_size']:
                off=seg['file_offset']+a-seg['address'];return self.data[off:off+n]
        raise ValueError('original CoreFP file-backed extent:'+hex(a))
    def function(self,a):
        ix=self.starts.index(a);z=self.starts[ix+1];raw=self.read(a,z-a);ins=list(CS.disasm(raw,a));assert len(ins)*4==len(raw)
        return {'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':sha(raw),
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]}


def main():
    l=Library();export=l.exports['_WIn9UJ86JKdV4dM'];f=l.function(export['address'])
    out={'scope':__doc__,'source':str(SOURCE),'resolved_source':str(SOURCE.resolve()),'source_sha256':SHA,'thin_sha256':THIN_SHA,
        'uuid':l.meta['uuid'],'slices':l.slices,'preferred_base':hex(l.base),'segments':l.meta['segments'],'sections':l.meta['sections'],
        'loads':l.loads,'exports':l.exports,'export_trie':l.export_trie,'compiler_function_starts':[hex(x) for x in l.starts],
        'selected_export':{'name':'_WIn9UJ86JKdV4dM',**export},'selected_original_function':f,
        'export_original_functions':[{'export':n,**l.function(x['address'])} for n,x in l.exports.items() if 'address' in x],
        'native_dlopen_executed':False,'native_dlsym_executed':False,'target_export_executed':False,'full_goal_complete':False,
        'generator_sha256':sha(Path(__file__).read_bytes())}
    (ROOT/'corefp_library_inventory.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'uuid':l.meta['uuid'],'exports':len(l.exports),'functions':len(l.starts),'selected_export':hex(export['address']),
        'selected_function_instructions':len(f['instructions'])}))


if __name__=='__main__':main()
