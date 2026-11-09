"""Run inside IDA to refresh read-only triage snapshots. Does not mutate the IDB.

Usage in IDA's Python console:
    exec(compile(open('/Users/___/dev/dylex/extracted/fairplay_capture_ida.py').read(),
                 'fairplay_capture_ida.py', 'exec'))
"""
import json
from pathlib import Path
import ida_bytes
import ida_funcs
import ida_name
import ida_nalt
import ida_segment
import idautils
import idc

OUT=Path(ida_nalt.get_input_file_path()).parent/'triage_evidence'
OUT.mkdir(exist_ok=True)
def write(name,obj):
    (OUT/name).write_text(json.dumps(obj,indent=2)+'\n')
def instructions(a,b,limit=None):
    rows=[]
    for ea in idautils.Heads(a,b):
        if limit is not None and len(rows)>=limit:break
        rows.append({'ea':hex(ea),'line':idc.generate_disasm_line(ea,0)})
    return rows

layout={'functions':[],'names':[],'segments':[]}
for ea in idautils.Functions():
    f=ida_funcs.get_func(ea)
    layout['functions'].append({'start':hex(ea),'end':hex(f.end_ea),
        'name':ida_funcs.get_func_name(ea),'chunks':[(hex(a),hex(b)) for a,b in idautils.Chunks(ea)]})
layout['names']=[{'ea':hex(ea),'name':n} for ea,n in idautils.Names()]
for ea in idautils.Segments():
    s=ida_segment.getseg(ea);layout['segments'].append({'start':hex(s.start_ea),
        'end':hex(s.end_ea),'name':ida_segment.get_segm_name(s),'perm':s.perm})
write('native_function_layout.json',layout)

details={'simple_functions':[],'vtable':[],'rpc_native':[]}
for ea in [0xfffffe000a505804,0xfffffe000a50581c,0xfffffe000a505aa4,
           0xfffffe000a505ab0,0xfffffe000a505abc,0xfffffe000a50602c,
           0xfffffe000a504868,0xfffffe000a50487c,0xfffffe000a561058,0xfffffe000a687ecc]:
    f=ida_funcs.get_func(ea);details['simple_functions'].append({'ea':hex(ea),
        'end':hex(f.end_ea) if f else None,'instructions':instructions(ea,min(f.end_ea,ea+48)) if f else []})
base=ida_name.get_name_ea(0,'__ZTV30com_apple_driver_FairPlayIOKit')+16
for off in range(0x8a0,0xa30,8):
    p=ida_bytes.get_qword(base+off);details['vtable'].append({'offset':hex(off),
        'slot':hex(base+off),'value':hex(p),'name':ida_name.get_name(p)})
for a,b in [(0xfffffe000a5a2064,0xfffffe000a5a22d4),(0xfffffe000a5a22d4,0xfffffe000a5a2544)]:
    details['rpc_native'].append({'start':hex(a),'end':hex(b),'instructions':instructions(a,b)})
write('native_detail.json',details)
life={}
for a,b,label in [(0xfffffe000a504320,0xfffffe000a5043e0,'userclient_start'),
    (0xfffffe000a5043e0,0xfffffe000a50445c,'userclient_stop'),
    (0xfffffe000a508030,0xfffffe000a508104,'aes_init_timeout')]:
    life[label]=instructions(a,b)
write('lifecycle_native.json',{'contexts':life})
write('capture_identity.json',{'input':ida_nalt.get_input_file_path(),
    'input_sha256':ida_nalt.retrieve_input_file_sha256().hex(),
    'functions':len(layout['functions']),'method':'Read-only IDA function/name/segment/byte/instruction reads; evidence files written alongside input.'})
print('Wrote read-only triage snapshots to',OUT)
