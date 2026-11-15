#!/usr/bin/env python3
"""Alternative header/publication source and retained coordinate-copy custody.
O(parent receipt bytes + selected state bytes + source words) time/space.
No alternative execution, guest bytes, owner definition or API-return premise.
"""
import json
from daemon_receive_tools import ROOT, SOURCE, IMAGE, TABLE, FIXUPS, verify_original_fixups
from audit_daemon_environment_outputs import DEC
from audit_daemon_network_record import state_bytes
from recover_daemon_append_fields import custody
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_alternative_fill as Parent

P = 'daemon_alternative_header'
SP, unpack = Parent.SP, Parent.unpack
PINS = {**Parent.PINS,
        'daemon_alternative_fill_checks.json': '83ec71770a279faee2fa7016756b2449354a0e9722c03233b412a7d157cba662',
        'daemon_alternative_fill_audit.json': '62a06536904a4b39ecb2c9242e25919c9463c98752699d4409e39df73316938c',
        'daemon_constructor_gate_checks.json': '9c4ad519628142f228742dd3a011a6b10f94aa106783bd6ba30caffad70af6ff',
        'daemon_constructor_gate_audit.json': 'd95e9e56e1fef1cd3f2fcf610670abcaa98e03159995d478d166e572d97d5b34'}
DEPS = ['recover_daemon_alternative_fill.py', 'recover_daemon_append_fields.py', 'daemon_receive_tools.py',
        'daemon_receive_fixups.txt', 'audit_daemon_environment_outputs.py', 'audit_daemon_network_record.py']
SPANS = {'coordinate_copy': (0x10070a320, 0x10070a324),
         'type_literal': (0x100596008, 0x100596010),
         'entry_saves': (0x10083c8b8, 0x10083c8c4),
         'first_word_setup': (0x1007d39f0, 0x1007d3a3c),
         'key_setup': (0x1005c5b70, 0x1005c5c64),
         'word_writer': (0x10047c6a4, 0x10047cd38),
         'second_word_setup': (0x1005189b4, 0x100518b48),
         'repeat_bridge': (0x10057c168, 0x10057c17c),
         'third_word_setup': (0x10050a808, 0x10050a864),
         'zero_arena_field': (0x100817c94, 0x100817cbc),
         'publish': (0x100825880, 0x1008258fc),
         'saved_return': (0x10068ae70, 0x10068ae88),
         'caller_result_gate': (0x1007812e8, 0x100781330),
         'caller_parent_decode': (0x1006b2200, 0x1006b2240),
         'caller_child_reload': (0x1006bdb90, 0x1006bdbe8)}
CONTEXT = {'w12': 0x1cecdea9, 'x3': 0xaf23f2ffdad73887, 'x23': 0x71ef41f1f2e87b90,
           'x19': 0x04ee7ccde7e80569, 'x11': 0x99cd4c92d6ccbdc5,
           'x2': 0xc0fdc551d2c935a8, 'x16': 0x3d107423d6820c5f, 'w1': 0x133f5a80,
           'x5': 0xaa694589eeb843c4, 'x6': 0x2acb5d3b08a3de1e, 'x7': 0x920827fe15375b5a,
           'x24': 0x59896f33c7af9f88, 'x0': 0x533b48661c28303c,
           'x26': 0x91d4c3ba3555c39b, 'w27': 0xb3, 'x4': 0x8f0490db2637da4e}
NORMALIZERS = [(0x10047c6f0,0x10047c730,'x8',0), (0x10047c73c,0x10047c77c,'x8',1),
    (0x10047c7c8,0x10047c7fc,'x13',4), (0x10047c808,0x10047c848,'x13',5),
    (0x10047c854,0x10047c894,'x13',6), (0x10047c8f8,0x10047c92c,'x8',0),
    (0x10047c958,0x10047c98c,'x8',3), (0x10047c998,0x10047c9ec,'x13',4),
    (0x10047c9f8,0x10047ca2c,'x13',5), (0x10047caa4,0x10047cae4,'x8',0),
    (0x10047cb10,0x10047cb50,'x8',3), (0x10047cb7c,0x10047cbbc,'x8',5),
    (0x10047cbc8,0x10047cc08,'x8',6), (0x10047cc80,0x10047cc90,'x9',0),
    (0x10047ccfc,0x10047cd0c,'x13',6)]
ROUTES = [(0x17fb,0x1005c5b70,0x423d), (0x5054,0x10047c6a4,0x8241),
          (0xcaa,0x1005189b4,0x1ac9), (0x3a28,0x10057c168,0x4f3e),
          (0xcac,0x10050a808,0x1ac9), (0xc91,0x100817c94,0x1ac9),
          (0x93e6,0x100825880,0xdc2a), (0x6a14,0x10068ae70,0xff01),
          (0x64d7,0x1006b2200,0x63a3), (0x6504,0x1006ad0a8,0x63a3),
          (0x602e,0x1006bdb90,0x5c3f), (0x1a3,0x10072c448,0x9325),
          (0x9344,0x100762e48,0x0e3b), (0x92f1,0x1008c25f4,0x0e3b)]
PROGRAM = ['first_word_setup','key_setup','word_writer','second_word_setup','repeat_bridge','word_writer',
           'third_word_setup','repeat_bridge','word_writer','zero_arena_field','publish','saved_return']


def extract():
    for name,digest in PINS.items():
        assert sha(ROOT/name)==digest,name
    cc=json.loads(read(ROOT/'daemon_state_container_construction_checks.json'))
    snapshots,slices=[],[]
    cells={0xb24:(4,0x867a282a),0x3608:(4,0x76d8ea81),0x36e8:(8,0x6600040000),
           0x16d0:(8,0x480),0x8ca8:(8,0x1007812e8),
           0x26e0:(8,(0x6600040000+0x4aba552460e435c6)&((1<<64)-1))}
    for ci,c in enumerate(cc['contexts']):
        row=unpack(c['allocation_cases'][1]['interval_packed']);m=state_bytes(row)
        for off,(n,value) in cells.items():
            assert int.from_bytes(bytes(m[SP+off+j] for j in range(n)),'little')==value
        lo=next(j for j,v in enumerate(row['source_visits']) if v['pc']=='0x10070a320')
        assert row['source_frames'][lo]['registers31'][22]=='0x76d8ea81'
        assert row['boundary']['registers31'][22]=='0x76d8ea81'
        assert not any(any(i.reg_name(x) in ['x22','w22'] for x in i.regs_access()[1])
            for v in row['source_visits'][lo+1:] for i in DEC.disasm(bytes.fromhex(v['bytes_hex']),int(v['pc'],16)))
        request={'address':hex(SP+0x3608),'size_bytes':4,'source_visit_index':len(row['source_visits'])}
        chain=custody(row,request)
        assert all(b['last_writer_in_this_interval']['pc']=='0x10070a320' for b in chain)
        saved_custody={}
        for off,n,pc in [(0xb24,4,'0x10083c8bc'),(0x8ca8,8,'0x10083c8b8'),(0x36e8,8,'0x10083c8c0')]:
            ch=custody(row,{'address':hex(SP+off),'size_bytes':n,'source_visit_index':len(row['source_visits'])})
            assert all(b['last_writer_in_this_interval']['pc']==pc for b in ch)
            saved_custody[hex(off)]=ch
        snapshots.append({'parent_index':ci,'boundary':row['boundary']['pc'],
            'saved_cells':{hex(off):{'size_bytes':n,'value':hex(value)} for off,(n,value) in cells.items()},
            'coordinate_custody':chain,'entry_saved_custody':saved_custody,'W22_equals_saved_coordinate_at_pending_allocation':True,
            'decoded_coordinate_bytes':1,'allocation_extent_bytes':21,'derived_second_word32':'0x7365616e',
            'scope':'Retained clear-route snapshot; no alternative result or execution.'})
        slices.append({'group':'constructor','class_index':ci,'kind':'coordinate_copy','start_visit':lo,
            'end_visit_exclusive':lo+1,'entry':row['source_frames'][lo],'exit':row['source_frames'][lo+1],
            'reads':[r for r in row['source_reads'] if r['source_visit_index']==lo],
            'writes':[w for w in row['source_writes'] if w['source_visit_index']==lo]})
        for kind in ['type_literal','entry_saves']:
            a,b=SPANS[kind];start=next(j for j,v in enumerate(row['source_visits']) if v['pc']==hex(a));end=start+(b-a)//4
            assert [v['pc'] for v in row['source_visits'][start:end]]==[hex(pc) for pc in range(a,b,4)]
            slices.append({'group':'constructor','class_index':ci,'kind':kind,'start_visit':start,'end_visit_exclusive':end,
                'entry':row['source_frames'][start],'exit':row['source_frames'][end],
                'reads':[r for r in row['source_reads'] if start<=r['source_visit_index']<end],
                'writes':[w for w in row['source_writes'] if start<=w['source_visit_index']<end]})
        lit_end=next(j for j,v in enumerate(row['source_visits']) if v['pc']=='0x10059600c')+1
        save=next(j for j,v in enumerate(row['source_visits']) if v['pc']=='0x10083c8bc')
        assert not any(any(i.reg_name(x) in ['x11','w11'] for x in i.regs_access()[1])
            for v in row['source_visits'][lit_end:save] for i in DEC.disasm(bytes.fromhex(v['bytes_hex']),int(v['pc'],16)))
    source=[]
    for name,(a,b) in SPANS.items():
        ii=list(DEC.disasm(IMAGE.read(a,b-a),a));assert len(ii)*4==b-a
        source.append({'name':name,'start':hex(a),'end_exclusive':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
                       'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
    routes=[]
    for idx,target,modifier in ROUTES:
        slot=TABLE+8*idx;raw=IMAGE.read(slot,8);w=int.from_bytes(raw,'little')
        assert FIXUPS[slot]['target']==target and (w>>32)&65535==modifier and not((w>>48)&7)
        routes.append({'index32':hex(idx),'target':hex(target),'IA_modifier':hex(modifier),'slot':hex(slot),'word_hex':raw.hex()})
    gate=json.loads(read(ROOT/'daemon_constructor_gate_checks.json'));clear_views=[]
    for ci,c in enumerate(gate['classes']):
        m=state_bytes(unpack(c['interval_packed']));u=0x6600060000
        fields={hex(off):hex(int.from_bytes(bytes(m[u+off+j] for j in range(n)),'little'))
                for off,n in [(0,8),(8,8),(0x10,4),(0x14,4),(0x18,4),(0x20,8),(0x28,4)]}
        assert fields['0x0']=='0x0' and fields['0x20']=='0x650011519c' and fields['0x28']=='0xd299e642'
        clear_views.append({'class_index':ci,'U_fields':fields,'scope':'Existing separate conditional clear initializer export.'})
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'parent_pins':PINS,
        'dependencies':{p:sha(ROOT/p) for p in DEPS},'source_spans':source,'routes':routes,
        'original_fixups':verify_original_fixups(int(r['slot'],16) for r in routes),
        'retained_clear_snapshots':snapshots,'slices':slices,'clear_U_views':clear_views,
        'verified_counts':{'source_instructions':sum((b-a)//4 for a,b in SPANS.values()),'source_spans':len(SPANS),
            'dispatch_routes':len(routes),'retained_clear_snapshots':len(snapshots),'saved_cells_checked':len(cells)*len(snapshots),
            'coordinate_copy_slices':len(snapshots),'selected_replay_slices':len(slices),'clear_U_views':len(clear_views),
            'composed_source_visits':sum((SPANS[k][1]-SPANS[k][0])//4 for k in PROGRAM),
            'caller_followup_source_instructions':sum((SPANS[k][1]-SPANS[k][0])//4 for k in
                ['caller_result_gate','caller_parent_decode','caller_child_reload'])},
        'prior_admissions_rerun':False,'new_target_intervals':0,'new_guest_input_bytes':0,'new_API_return_premises':0,
        'native_target_executed':False,'alternative_branch_executed':False,'full_goal_complete':False}


if __name__=='__main__':
    e=extract();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps(e['verified_counts']),flush=True)
