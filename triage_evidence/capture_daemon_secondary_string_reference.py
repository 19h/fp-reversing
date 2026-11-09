#!/usr/bin/env python3
"""Measure only the host C library's pure strtol function on owned fixed
ASCII buffers. This is a reference vector source, not target daemon/library
execution or a runtime-version match. No FairPlay/framework/IPC API is called.
O(total test-string bytes) time, O(largest string + result rows) space.
"""
import ctypes as C,json,os,platform
from pathlib import Path
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
CASES={'empty':'','zero':'0','positive':'17','negative':'-1','trailing':'17x','leading_space':' +17','outside_i32':'2147483648','outside_u32':'4294967296','long_max':'9223372036854775807','long_overflow':'9223372036854775808','not_numeric':'abc'}
def capture():
 libc=C.CDLL(None,use_errno=True);fn=libc.strtol;fn.argtypes=[C.c_void_p,C.POINTER(C.c_void_p),C.c_int];fn.restype=C.c_long;assert C.sizeof(C.c_long)==8 and C.sizeof(C.c_void_p)==8;rows=[]
 for name,s in CASES.items():
  raw=s.encode('ascii')+bytes(1);assert len(raw)<=32;b=C.create_string_buffer(raw,32);end=C.c_void_p(0);C.set_errno(0);value=fn(C.addressof(b),C.byref(end),10);error=C.get_errno();offset=end.value-C.addressof(b);assert 0<=offset<len(raw);rows.append({'name':name,'ASCII':s,'NUL_inclusive_hex':raw.hex(),'return_signed64':value,'return_bits64':hex(value&((1<<64)-1)),'end_offset_bytes':offset,'end_byte':raw[offset],'errno':error,'buffer_bytes':32})
 class DlInfo(C.Structure):_fields_=[('fname',C.c_char_p),('base',C.c_void_p),('sname',C.c_char_p),('addr',C.c_void_p)]
 info=DlInfo();dl=libc.dladdr;dl.argtypes=[C.c_void_p,C.POINTER(DlInfo)];dl.restype=C.c_int;assert dl(C.cast(fn,C.c_void_p),C.byref(info))!=0
 sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.2.sdk');man=sdk/'usr/share/man/man3/strtol.3';return {'scope':__doc__,'generator_sha256':sha(__file__),'host':{'system':platform.system(),'machine':platform.machine(),'release':os.uname().release,'version':os.uname().version,'libc_image':info.fname.decode(),'symbol':info.sname.decode(),'sizeof_long_bytes':8,'sizeof_pointer_bytes':8},'primary_manual':{'path':str(man),'sha256':sha(man)},'cases':rows,'host_libc_strtol_executed':True,'target_daemon_executed':False,'target_framework_API_executed':False,'matching_daemon_runtime_established':False,'full_goal_complete':False}
if __name__=='__main__':
 r=capture();(ROOT/'daemon_secondary_string_reference.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'reference_vectors':len(r['cases']),'host_libc_image':r['host']['libc_image'],'target_daemon_executed':False}),flush=True)
