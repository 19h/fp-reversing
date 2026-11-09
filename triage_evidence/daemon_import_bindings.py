#!/usr/bin/env python3
"""Original format12 bind/import-addend decoder for selected daemon slots."""
from daemon_receive_tools import IMAGE,FIXUPS,struct
from resolve_kernel_collection_interfaces import commands


def binding(address):
    data=IMAGE.data
    loads=[]
    for at,cmd,size in commands(data,0):
        if cmd in (0xc,0x80000018,0x8000001f,0x80000023,0x20):
            n=struct.unpack_from('<I',data,at+8)[0]
            start=at+n
            loads.append(data[start:data.index(0,start)].decode())
    at=next(at for at,cmd,size in commands(data,0) if cmd==0x80000034)
    off,n=struct.unpack_from('<II',data,at+8)
    version,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',data,off)
    assert (version,fmt,symfmt)==(0,2,0)
    word=struct.unpack('<Q',IMAGE.read(address,8))[0]
    auth,bind=word>>63,(word>>62)&1
    assert bind and FIXUPS[address]['kind'].endswith('bind')
    ordinal=word&0xffffff
    assert ordinal<count
    iw,import_addend=struct.unpack_from('<Ii',data,off+imports+8*ordinal)
    lib=iw&255
    if lib&128:lib-=256
    so=off+symbols+(iw>>9)
    name=data[so:data.index(0,so)].decode()
    assert FIXUPS[address]['target'].split('/',1)[1]==name
    pointer_addend=0 if auth else (word>>32)&0x7ffff
    if pointer_addend&(1<<18):pointer_addend-=1<<19
    return {'slot':hex(address),'word':hex(word),'pointer_format':12,
      'import_format':fmt,'import_ordinal':ordinal,'symbol':name,
      'library_ordinal':lib,'library_path':loads[lib-1] if 0<lib<=len(loads) else 'special ordinal',
      'weak_import':bool(iw&256),'authenticated':bool(auth),
      'import_table_addend':import_addend,'pointer_addend':pointer_addend,
      'total_addend':import_addend+pointer_addend,
      'dyld_info_line':FIXUPS[address]['line']}
