#!/usr/bin/env python3
"""Tag-selected scalar loop, optional coordinate output and raw-status handoff.
O(parent bytes + retained events + custody scans) time/space. No new target
interval, guest input, owner/root definition or API-return premise is added.
"""
import json
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS,verify_original_fixups
from audit_daemon_environment_outputs import DEC
from recover_daemon_alternative_header import unpack,SP
from recover_daemon_append_fields import custody
from verify_daemon_reader_record_payloads_publication import read,sha

P='daemon_child_loop'
PINS={
 'daemon_child_payload_checks.json':'0eb0ad5e810073cd6558eb47d67cda7badc8049857cd4f01ee8d83bacdc0ace8',
 'daemon_child_payload_audit.json':'124989a6cc4c4befcb97738b78bc5745abbd18918a0df9a19d0314890528f3ef',
 'daemon_child_operation_checks.json':'7d7029404ffe048fff50a8ea402b9f07eb6b27bd0874ce9c5ca45f6358cbc383',
 'daemon_child_operation_audit.json':'c6012aa59d69647d190356f3825e99a72e09a9b1abc579a30cb6c594aac4182a',
 'daemon_constructor_buffer_checks.json':'fe29b3d2d39daecdd79d1d00057229f0f583b8b0ead9c4eb9bd4fd5aa7cafa07',
 'daemon_constructor_buffer_audit.json':'47108bdf5bedbb6a9aec1397ae777d6317a689cdea625638da5fb94a3c86e252'}
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','audit_daemon_environment_outputs.py',
      'recover_daemon_alternative_header.py','recover_daemon_append_fields.py']
SPANS={
 'tag_partition':(0x1008ef9f4,0x1008efa34),
 'tag_exact':(0x100a3811c,0x100a38160),
 'loop_gate':(0x1009a1574,0x1009a15bc),
 'loop_backedge':(0x100957a58,0x100957aa0),
 'optional_output':(0x1008d3490,0x1008d34d8),
 'output_store':(0x10076d5d8,0x10076d5f4),
 'postprocess':(0x1006d140c,0x1006d1474),
 'status_save':(0x100751f2c,0x100751f30),
 'coordinate_save':(0x10069e92c,0x10069e930),
 'frame_return':(0x100924854,0x100924878),
 'outer_return':(0x1008c25f4,0x1008c2600),
 'outer_gate':(0x10072c448,0x10072c4b4)}
ROUTES=[(0x82e2,0x100a3811c,0xd40d),(0x82f6,0x100753528,0xd40d),
 (0x3fa5,0x10083923c,0x987b),(0x68d9,0x1009a1574,0x987b),
 (0x6a7e,0x1008f0c14,0x1d3b),(0x1e5c,0x1008d3490,0x1d3b),
 (0x3f00,0x1006d140c,0x5a94),(0x3f0d,0x10076d5d8,0x5a94),
 (0x4045,0x100924854,0x5469),(0x8aae,0x100705fb8,0x5469),
 (0xf29,0x1008c25f4,0x8eb3),(0x8eff,0x1008a2610,0xb0c4),
 (0x8e61,0x1006ad0a8,0xb0c4)]
SAVED_EDGES=[(0x10072c448,0x9325)]


def extract():
    for p,d in PINS.items():assert sha(ROOT/p)==d,p
    parent=json.loads(read(ROOT/'daemon_constructor_buffer_checks.json'))
    slices=[];loops=[];links=[];inherited=[]
    for ci,c in enumerate(parent['branches']):
        if c['pointer_return64']=='0x0':continue
        row=unpack(c['intervals'][1]['interval_packed'])
        def select(name,lo):
            a,b=SPANS[name];hi=lo+(b-a)//4
            assert [v['pc'] for v in row['source_visits'][lo:hi]]==[hex(pc) for pc in range(a,b,4)]
            s={'group':'branch','class_index':ci,'interval_index':1,'kind':name,
               'start_visit':lo,'end_visit_exclusive':hi,'entry':row['source_frames'][lo],
               'exit':row['source_frames'][hi],
               'reads':[r for r in row['source_reads'] if lo<=r['source_visit_index']<hi],
               'writes':[w for w in row['source_writes'] if lo<=w['source_visit_index']<hi]}
            slices.append(s);return s
        picked={}
        for name,(a,b) in SPANS.items():
            jj=[j for j,v in enumerate(row['source_visits']) if v['pc']==hex(a)]
            assert len(jj)==(5 if name=='loop_gate' else 4 if name=='loop_backedge' else 1)
            picked[name]=[select(name,j) for j in jj]
        gates=picked['loop_gate'];backs=picked['loop_backedge']
        assert [int(s['entry']['registers31'][15],16) for s in gates]==[0,1,2,3,4]
        assert all(s['entry']['registers31'][19]=='0x4' for s in gates)
        assert [s['exit']['pc'] for s in gates]==['0x1008f0c14']*4+['0x1008d3490']
        assert all(s['exit']['pc']=='0x1009a1574' for s in backs)
        assert picked['tag_exact'][0]['exit']['registers31'][15]=='0x0'
        assert picked['tag_exact'][0]['entry']['registers31'][12]=='0x76657273'
        loops.append({'branch_index':ci,'decoded_count32':4,'gate_indices32':[0,1,2,3,4],
            'body_indices32':[0,1,2,3],'backedge_next_indices32':[
                int(s['exit']['registers31'][15],16) for s in backs],
            'body_target':'0x1008f0c14','exit_target':'0x1008d3490'})
        def link(event,writer_pc):
            chain=custody(row,event)
            assert all(x['last_writer_in_this_interval'] is not None and
                x['last_writer_in_this_interval']['pc']==hex(writer_pc) for x in chain)
            links.append({'branch_index':ci,'read':event,'custody':chain})
        for s in backs:
            link(next(r for r in s['reads'] if r['pc']=='0x100957a7c'),0x1009a1584)
            link(next(r for r in s['reads'] if r['pc']=='0x100957a8c'),0x1007579f4)
        out=picked['output_store'][0]
        coord=next(r for r in out['reads'] if r['pc']=='0x10076d5dc');link(coord,0x10069e92c)
        assert coord['bytes_hex']=='95ead876' and out['writes'][0]['address']==hex(SP+0xd98)
        assert out['writes'][0]['after_hex']=='95ead876' and out['writes'][0]['size_bytes']==4
        status=next(r for r in picked['postprocess'][0]['reads'] if r['pc']=='0x1006d143c')
        link(status,0x100751f2c);assert status['bytes_hex']=='51c63d8b'
        for name,pc,offset,value in [
            ('optional_output',0x1008d34a0,0xd80,SP+0xd98),
            ('postprocess',0x1006d1440,0x2090,0x76657273),
            ('frame_return',0x100924864,0x8b90,0x1008c25f4),
            ('outer_return',0x1008c25f4,0x3980,0x10072c448)]:
            rr=next(r for r in picked[name][0]['reads'] if r['pc']==hex(pc))
            chain=custody(row,rr)
            assert rr['address']==hex(SP+offset) and int.from_bytes(bytes.fromhex(rr['bytes_hex']),'little')==value
            assert all(x['last_writer_in_this_interval'] is None for x in chain)
            inherited.append({'branch_index':ci,'read':rr,'custody':chain,'inherited_pinned_field_only':True})
        assert picked['postprocess'][0]['exit']['pc']=='0x100924854'
        assert picked['outer_gate'][0]['entry']['registers31'][27]=='0x8b3dc651'
        assert picked['outer_gate'][0]['exit']['pc']=='0x1008a2610'
    source=[]
    for name,(a,b) in SPANS.items():
        ins=list(DEC.disasm(IMAGE.read(a,b-a),a));assert len(ins)*4==b-a
        source.append({'name':name,'start':hex(a),'end_exclusive':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
            'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]})
    routes=[]
    for idx,target,modifier in ROUTES:
        slot=TABLE+8*idx;raw=IMAGE.read(slot,8);word=int.from_bytes(raw,'little')
        assert FIXUPS[slot]['target']==target and (word>>32)&65535==modifier and not((word>>48)&7)
        routes.append({'index32':hex(idx),'target':hex(target),'IA_modifier':hex(modifier),'slot':hex(slot),'word_hex':raw.hex()})
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'parent_pins':PINS,
        'dependencies':{p:sha(ROOT/p) for p in DEPS},'source_spans':source,'routes':routes,
        'saved_edges':[{'target':hex(t),'IA_modifier':hex(m)} for t,m in SAVED_EDGES],
        'original_fixups':verify_original_fixups(int(r['slot'],16) for r in routes),'slices':slices,
        'loop_sequences':loops,'fresh_custody_links':links,'inherited_fields':inherited,
        'verified_counts':{'source_spans':len(source),'source_instructions':sum((b-a)//4 for a,b in SPANS.values()),
            'dispatch_routes':len(routes),'selected_replay_slices':len(slices),'loop_sequences':len(loops),
            'fresh_custody_links':len(links),'inherited_fields':len(inherited)},
        'prior_admissions_rerun':False,'new_target_intervals':0,'new_guest_input_bytes':0,
        'new_API_return_premises':0,'native_target_executed':False,'full_goal_complete':False}


if __name__=='__main__':
    e=extract();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps(e['verified_counts']),flush=True)
