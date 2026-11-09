#!/usr/bin/env python3
"""Decode original companion Objective-C class/method metadata, no runtime use.

Time/space O(classes+methods+strings), counts bounded by source section extents.
Relative method entries and chained name slots retain separate provenance.
"""
import json
import struct
from arcade_service_reader import Service,ROOT,THIN_SHA,sha


def recover(s):
    classes=[];methods=[]
    def method_list(a,cls,kind):
        if not a:return []
        flags,count=struct.unpack('<II',s.read(a,8));small=bool(flags&0x80000000);direct=bool(flags&0x40000000)
        stride=flags&0xffff;assert stride==(12 if small else 24) and count<=256,(hex(a),hex(flags),count)
        out=[]
        for j in range(count):
            p=a+8+j*stride;entry=s.read(p,stride)
            if small:
                n,t,i=struct.unpack('<3i',entry);ns=p+n;ts=p+4+t;imp=p+8+i
                np=ns if direct else s.qword(ns)
            else:np,ts,imp=[s.qword(p+k*8) for k in range(3)];ns=p
            r={'class':cls,'kind':kind,'list':hex(a),'flags':hex(flags),'entry':hex(p),'entry_bytes':entry.hex(),
                'selector':s.cstring(np),'selector_address':hex(np),'type_encoding':s.cstring(ts),
                'type_encoding_address':hex(ts),'implementation':hex(imp),'relative':small,'direct_selector':direct,
                'name_reference_address':hex(ns),'name_fixup':s.decoded_fixups.get(ns),
                'implementation_is_compiler_function_start':imp in s.starts}
            out.append(r);methods.append(r)
        return out
    sec=next(r for r in s.sections if r['section']=='__objc_classlist');assert sec['size']%8==0
    for slot in range(sec['address'],sec['address']+sec['size'],8):
        c=s.qword(slot);ro=s.qword(c+32)&~7;name=s.cstring(s.qword(ro+24));meta=s.qword(c);mro=s.qword(meta+32)&~7
        instance=method_list(s.qword(ro+32),name,'instance');cm=method_list(s.qword(mro+32),name,'class')
        classes.append({'name':name,'class_list_slot':hex(slot),'class_address':hex(c),'class_ro':hex(ro),'metaclass':hex(meta),
            'metaclass_ro':hex(mro),'instance_methods':len(instance),'class_methods':len(cm)})
    return {'source_sha256':THIN_SHA,'classes':classes,'methods':methods,
        'category_sections':[r for r in s.sections if r['section'] in ('__objc_catlist','__objc_nlcatlist')],
        'runtime_class_registration_executed':False}


def main():
    r=recover(Service());(ROOT/'arcade_service_objc_metadata.json').write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({'classes':len(r['classes']),'methods':len(r['methods']),
        'compiler_entry_matches':sum(m['implementation_is_compiler_function_start'] for m in r['methods'])}))


if __name__=='__main__':main()
