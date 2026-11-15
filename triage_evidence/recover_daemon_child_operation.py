#!/usr/bin/env python3
"""Child-operation prelude, raw token, U guards and saved result continuation.
O(parent receipt bytes + selected frames + source words) time/space.
No new target interval, root definition, guest input or API-return premise.
"""
import json
from daemon_receive_tools import ROOT, SOURCE, IMAGE, TABLE, FIXUPS, verify_original_fixups
from audit_daemon_environment_outputs import DEC
from audit_daemon_network_record import state_bytes
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_alternative_header import unpack, SP

P = 'daemon_child_operation'
PINS = {
 'daemon_alternative_header_checks.json':'bc940ef031d5713c79d7cb4142e35463b72a0db2725a393aac339a1d3c7001e5',
 'daemon_alternative_header_audit.json':'fb3011f32a7a663b209de9cf2765b430dd4713edc470017a94691a9870cbdc8b',
 'daemon_constructor_gate_checks.json':'9c4ad519628142f228742dd3a011a6b10f94aa106783bd6ba30caffad70af6ff',
 'daemon_constructor_gate_audit.json':'d95e9e56e1fef1cd3f2fcf610670abcaa98e03159995d478d166e572d97d5b34'}
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','audit_daemon_environment_outputs.py',
      'audit_daemon_network_record.py','recover_daemon_alternative_header.py']
SPANS={
 'entry':(0x100762e48,0x100762e8c), 'token_context':(0x1009679f0,0x100967a50),
 'token_writer':(0x10077b08c,0x10077b128), 'child_reload':(0x1007948e4,0x100794948),
 'frame_setup':(0x100746474,0x100746504), 'base_gate':(0x100532e14,0x100532e64),
 'clear_base_gate':(0x1005280e4,0x100528130), 'flag0_gate':(0x1004e384c,0x1004e3898),
 'flag1_gate':(0x10058c6e8,0x10058c738), 'validation_bridge':(0x1005f1484,0x1005f149c),
 'frame_return':(0x100924854,0x100924878), 'outer_return':(0x1008c25f4,0x1008c2600),
 'result_gate':(0x10072c448,0x10072c4b4)}
SELECTED=list(SPANS)[:9]
ROUTES=[(0x192e,0x1009679f0,0xbe0b),(0x7a4e,0x10077b08c,0xe70e),
 (0x155f,0x1007948e4,0x6878),(0x291c,0x100746474,0x7da4),
 (0xf29,0x1008c25f4,0x8eb3),(0x403e,0x100532e14,0x5469),
 (0x4045,0x100924854,0x5469),(0x2a9e,0x1004e384c,0x696a),
 (0xae23,0x1005280e4,0x696a),(0x2a1b,0x100924854,0x696a),(0x571e,0x100924854,0xc161),
 (0xbc27,0x10058c6e8,0xc161),(0x5727,0x1005f1484,0xc161),
 (0x2a7d,0x1005015e8,0x0f65),(0x8e61,0x1006ad0a8,0xb0c4),
 (0x8eff,0x1008a2610,0xb0c4)]


def extract():
    for name,digest in PINS.items():assert sha(ROOT/name)==digest,name
    source=[]
    for name,(a,b) in SPANS.items():
        ii=list(DEC.disasm(IMAGE.read(a,b-a),a));assert len(ii)*4==b-a
        source.append({'name':name,'start':hex(a),'end_exclusive':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
            'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
    routes=[]
    for idx,target,modifier in ROUTES:
        slot=TABLE+8*idx;raw=IMAGE.read(slot,8);word=int.from_bytes(raw,'little')
        assert FIXUPS[slot]['target']==target and (word>>32)&65535==modifier and not((word>>48)&7)
        routes.append({'index32':hex(idx),'target':hex(target),'IA_modifier':hex(modifier),'slot':hex(slot),'word_hex':raw.hex()})
    parent=json.loads(read(ROOT/'daemon_constructor_gate_checks.json'));slices=[];views=[]
    for ci,c in enumerate(parent['classes']):
        row=unpack(c['interval_packed']);m=state_bytes(row)
        for name in SELECTED:
            a,b=SPANS[name];starts=[j for j,v in enumerate(row['source_visits']) if v['pc']==hex(a)]
            assert len(starts)==1;lo=starts[0];hi=lo+(b-a)//4
            assert [v['pc'] for v in row['source_visits'][lo:hi]]==[hex(pc) for pc in range(a,b,4)]
            slices.append({'group':'initializer','class_index':ci,'kind':name,'start_visit':lo,'end_visit_exclusive':hi,
                'entry':row['source_frames'][lo],'exit':row['source_frames'][hi],
                'reads':[r for r in row['source_reads'] if lo<=r['source_visit_index']<hi],
                'writes':[w for w in row['source_writes'] if lo<=w['source_visit_index']<hi]})
        expected={0x5378:(4,0x99989998),0x4450:(8,SP+0x5378),0x42e0:(8,0x6600060000),
                  0xd80:(8,SP+0xd98),0x2d64:(4,0x76d8ea80),0x2090:(4,0x76657273),
                  0x2690:(4,0x8b3dc655),0x8b90:(8,0x1008c25f4)}
        for off,(n,value) in expected.items():
            assert int.from_bytes(bytes(m[SP+off+j] for j in range(n)),'little')==value,(hex(off),ci)
        assert row['boundary']['pc']=='0x1005f149c'
        assert all(SP+0x260+j not in m for j in range(8))
        views.append({'class_index':ci,'boundary':row['boundary']['pc'],'root_260_defined_bytes':0,
            'saved_cells':{hex(off):{'size_bytes':n,'value':hex(value)} for off,(n,value) in expected.items()},
            'scope':'Earlier conditional clear-route state; no alternative execution.'})
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'parent_pins':PINS,
        'dependencies':{p:sha(ROOT/p) for p in DEPS},'source_spans':source,'routes':routes,
        'original_fixups':verify_original_fixups(int(r['slot'],16) for r in routes),'slices':slices,'retained_views':views,
        'verified_counts':{'source_spans':len(source),'source_instructions':sum((b-a)//4 for a,b in SPANS.values()),
            'dispatch_routes':len(routes),'selected_replay_slices':len(slices),'retained_clear_views':len(views),
            'saved_cells_checked':len(views)*8},
        'prior_admissions_rerun':False,'new_target_intervals':0,'new_guest_input_bytes':0,
        'new_API_return_premises':0,'native_target_executed':False,'full_goal_complete':False}


if __name__=='__main__':
    e=extract();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps(e['verified_counts']),flush=True)
