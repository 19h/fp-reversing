#!/usr/bin/env python3
"""Original AMS v5 chain-page and protected-core pointer inventories.

No native loading/calls. Chain pages are independently walked once; selected
members are cross-checked with the frozen cache reader. O(B+P+E) extraction for
bytes, pointer members and export names. Exact bindings are capabilities, not
proof that a protected caller invokes them.
"""
import bisect
import json
from pathlib import Path
import struct
from bootpolicy_cache_reader import Cache,Dylib,file_read
from appstore_agent_reader import ROOT,CS,sha

AMS='/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices'


class Core:
    def __init__(self):
        self.cache=Cache();assert self.cache.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a'
        self.ams=Dylib(self.cache,AMS);assert self.ams.uuid=='1b464993-f0e2-3804-b412-a6cc8091798c'
        self.page_cache={};self.headers={}
    def page_chains(self,address):
        c=self.cache;m=c.mapping(address)
        if not m['slide_off']:return {}
        key=(m['path'],m['va'])
        if key not in self.headers:
            h=file_read(Path(m['path']),m['slide_off'],24);ver,page_size,count,pad,add=struct.unpack('<4IQ',h)
            assert ver==5 and page_size in (4096,16384)
            starts=struct.unpack('<'+'H'*count,file_read(Path(m['path']),m['slide_off']+24,count*2));self.headers[key]=(page_size,starts,add)
        size,starts,add=self.headers[key];ix=(address-m['va'])//size;assert ix<len(starts)
        base=m['va']+ix*size
        if base in self.page_cache:return self.page_cache[base]
        raw=c.read(base,size);out={};at=starts[ix]
        if at!=0xffff:
            while True:
                assert at%8==0 and at+8<=size and base+at not in out
                word=struct.unpack_from('<Q',raw,at)[0];auth=bool(word>>63);target=add+(word&0x3ffffffff)
                if not auth:target|=((word>>34)&255)<<56
                a=base+at;out[a]={'address':hex(a),'raw_word':hex(word),'target':hex(target),'slide_version':5,
                    'value_add':hex(add),'authenticated':auth,'chain_membership_verified':True,'path':m['path'],
                    'file_offset':hex(m['off']+a-m['va'])}
                delta=((word>>52)&0x7ff)*8
                if not delta:break
                at+=delta
        self.page_cache[base]=out;return out
    def pointer(self,a):
        r=self.page_chains(a)[a];assert r==self.cache.pointer(a)
        return r
    def section_chains(self,sec):
        a=sec['address'];z=a+sec['size'];out={}
        while a<z:
            m=self.cache.mapping(a);self.page_chains(a);size=self.headers[(m['path'],m['va'])][0]
            out.update({p:r for p,r in self.page_chains(a).items() if sec['address']<=p<z})
            a=m['va']+((a-m['va'])//size+1)*size
        return out


def main():
    core=Core();cache=core.cache;lib=core.ams;sections=[x for x in lib.sections if x['name']=='__const' and x['segment'] in ('__DATA_CONST','__AUTH_CONST')]
    pointers={}
    for sec in sections:pointers.update(core.section_chains(sec))
    images=sorted((x['address'],x['path']) for x in cache.images);starts=[a for a,p in images];libs={AMS:lib};targets={}
    for p in pointers.values():
        t=int(p['target'],16)
        try:m=cache.mapping(t)
        except AssertionError:continue
        if not m['initprot']&4:continue
        if any(s['address']<=t<s['address']+s['size'] for s in lib.segments if s['name']=='__TEXT'):continue
        if t in targets:continue
        path=images[bisect.bisect_right(starts,t)-1][1]
        if path not in libs:libs[path]=Dylib(cache,path)
        other=libs[path];targets[t]={'address':hex(t),'library':path,'library_uuid':other.uuid,
            'exact_exports':[n for n,r in other.exports.items() if r['address']==t],
            'compiler_function_start':t in other.functions,
            'target_sections':[{'segment':x['segment'],'section':x['name']} for x in other.sections if x['address']<=t<x['address']+x['size']]}
    out={'scope':__doc__,'cache_uuid':cache.uuid,'ams_uuid':lib.uuid,'ams_path':AMS,'sections':sections,
        'original_pointer_members':list(pointers.values()),'external_executable_targets':list(targets.values()),
        'external_pointer_occurrences':[{'pointer_address':p['address'],'target':p['target']} for p in pointers.values() if int(p['target'],16) in targets],
        'reader_sha256':sha(Path(__file__).read_bytes()),'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'ams_core_pointer_inventory.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'pointer_members':len(pointers),'external_executable_targets':len(targets),
        'exact_bound_external_targets':sum(bool(x['exact_exports']) for x in targets.values()),'external_occurrences':len(out['external_pointer_occurrences'])}))
    for r in targets.values():print(json.dumps(r))


if __name__=='__main__':main()
