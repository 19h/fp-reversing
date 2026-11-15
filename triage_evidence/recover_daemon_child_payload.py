#!/usr/bin/env python3
"""Nested storage-mode gates and private-byte to packed-payload lineage.
O(parent receipt bytes + retained visits/events + custody scans) time/space.
No target interval, guest bytes, root/owner or API-return premise is added.
"""
import json
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS,verify_original_fixups
from audit_daemon_environment_outputs import DEC
from audit_daemon_network_record import state_bytes
from recover_daemon_append_fields import custody
from recover_daemon_alternative_header import unpack,SP
from verify_daemon_reader_record_payloads_publication import read,sha

P='daemon_child_payload'
PINS={
 'daemon_child_operation_checks.json':'7d7029404ffe048fff50a8ea402b9f07eb6b27bd0874ce9c5ca45f6358cbc383',
 'daemon_child_operation_audit.json':'c6012aa59d69647d190356f3825e99a72e09a9b1abc579a30cb6c594aac4182a',
 'daemon_constructor_buffer_checks.json':'fe29b3d2d39daecdd79d1d00057229f0f583b8b0ead9c4eb9bd4fd5aa7cafa07',
 'daemon_constructor_buffer_audit.json':'47108bdf5bedbb6a9aec1397ae777d6317a689cdea625638da5fb94a3c86e252',
 'daemon_record_spans_checks.json':'c86a7ff3de166cae5034ee4543dc13cd27f6fc13076221ecb94788491f1ffb99',
 'daemon_record_spans_audit.json':'2e5259ad78e740d82a91d1310d8a3c4991d0f843427bf2ac93e09144b77c1a89'}
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','audit_daemon_environment_outputs.py',
      'audit_daemon_network_record.py','recover_daemon_append_fields.py','recover_daemon_alternative_header.py']
SPANS={'nested_entry':(0x1005015e8,0x10050164c),'primary_mode':(0x10086588c,0x1008658d8),
 'masked_mode':(0x1005a72c8,0x1005a731c),'secondary_mode':(0x10057530c,0x10057532c),
 'clear_mode':(0x10080fba8,0x10080fc08),'nested_return':(0x1008f2a1c,0x1008f2a2c),
 'payload_inputs':(0x1007579dc,0x1007579f8),'byte_decode':(0x1008f0c14,0x1008f0c68),
 'scalar_spill':(0x1008f3940,0x1008f3944),'destination_read':(0x100584edc,0x100584ee0)}
ROUTES=[(0x1362,0x100751f0c,0xd08c),(0x3efa,0x10086588c,0xa298),
 (0x3eda,0x1008f2a1c,0xa298),(0x2ed8,0x1005a72c8,0x82cf),
 (0x2eb9,0x10057530c,0x82cf),(0x717c,0x10057f4ec,0xd21b),
 (0x718f,0x10057530c,0xd21b),(0x8d0e,0x10080fba8,0x4ae9),
 (0x8d0f,0x1008f2a1c,0x4ae9),(0x7492,0x10057f4ec,0x7dc1),
 (0x7429,0x1008f2a1c,0x7dc1),(0x1f62,0x1008f3914,0x4d13)]


def overlaps(a,n,e):
    b=int(e['address'],16);return b<a+n and a<b+e['size_bytes']


def extract():
    for p,digest in PINS.items():assert sha(ROOT/p)==digest,p
    cb=json.loads(read(ROOT/'daemon_constructor_buffer_checks.json'))
    rs=json.loads(read(ROOT/'daemon_record_spans_checks.json'));slices=[];links=[];survival=[]
    def select(group,ci,ii,row,name,lo=None):
        a,b=SPANS[name]
        if lo is None:lo=next(j for j,v in enumerate(row['source_visits']) if v['pc']==hex(a))
        hi=lo+(b-a)//4
        assert [v['pc'] for v in row['source_visits'][lo:hi]]==[hex(pc) for pc in range(a,b,4)]
        slices.append({'group':group,'class_index':ci,'interval_index':ii,'kind':name,'start_visit':lo,'end_visit_exclusive':hi,
            'entry':row['source_frames'][lo],'exit':row['source_frames'][hi],
            'reads':[r for r in row['source_reads'] if lo<=r['source_visit_index']<hi],
            'writes':[w for w in row['source_writes'] if lo<=w['source_visit_index']<hi]})
        return slices[-1]
    for ci,c in enumerate(cb['prefixes']):
        r=unpack(c['interval_packed'])
        for name in ['nested_entry','primary_mode','secondary_mode','clear_mode']:select('prefix',ci,0,r,name)
        assert not any(overlaps(SP+0x5378,4,w) or overlaps(SP+0x4450,8,w) for w in r['source_writes'])
    for ci,c in enumerate(cb['branches']):
        if c['pointer_return64']=='0x0':continue
        rows=[unpack(t['interval_packed']) for t in c['intervals']];r=rows[1]
        for ii,(row,item) in enumerate(zip(rows,c['intervals'])):
            m=state_bytes(row)
            assert bytes(m[SP+0x5378+j] for j in range(4)).hex()=='98999899'
            assert int.from_bytes(bytes(m[SP+0x4450+j] for j in range(8)),'little')==SP+0x5378
            assert not any(overlaps(SP+0x5378,4,w) or overlaps(SP+0x4450,8,w) for w in row['source_writes'])
            assert not any(overlaps(SP+0x5378,4,w) or overlaps(SP+0x4450,8,w) for w in item['API_return_premise']['invalidated_spans'])
            survival.append({'branch_index':ci,'interval_index':ii,'token_hex':'98999899','pointer':hex(SP+0x5378),
                'source_write_overlap':False,'ABI_invalidation_overlap':False,'inherited_conditional_admission_only':True})
        setup=select('branch',ci,1,r,'payload_inputs')
        assert setup['reads'][0]['pc']=='0x1007579dc' and setup['reads'][0]['bytes_hex']==(SP+0x5378).to_bytes(8,'little').hex()
        rr=[x for x in r['source_reads'] if x['pc']=='0x1008f0c3c'];assert len(rr)==4
        for j,read_event in enumerate(rr):
            lo=read_event['source_visit_index']-10
            s=select('branch',ci,1,r,'byte_decode',lo);idx=int(s['entry']['registers31'][10],16)
            assert idx==j and s['entry']['registers31'][8]=='0x97a'
            assert read_event['address']==hex(SP+0x5378+j) and read_event['bytes_hex']==['98','99','98','99'][j]
            assert int(s['exit']['registers31'][23],16)==([0,1,0,1][j]^0x8b3dc651)
            pointer_read=next(x for x in s['reads'] if x['pc']=='0x1008f0c38')
            chain=custody(r,pointer_read)
            assert all(b['last_writer_in_this_interval']['pc']=='0x1007579e0' for b in chain)
            f=next(f for f in rs['constructor_fields'] if f['branch_index']==ci and f['offset_bytes']==41+4*j)
            scalar_read=f['producer_read_custody'][1]['read'];fresh=custody(r,scalar_read)
            spill=fresh[0]['last_writer_in_this_interval'];assert spill['pc']=='0x1008f3940'
            assert all(b['last_writer_in_this_interval']==spill for b in fresh)
            assert all(x['registers31'][23]==s['exit']['registers31'][23] for x in
                r['source_frames'][s['end_visit_exclusive']:spill['source_visit_index']+1])
            select('branch',ci,1,r,'scalar_spill',spill['source_visit_index'])
            assert int.from_bytes(bytes.fromhex(scalar_read['bytes_hex']),'little')==([0,1,0,1][j]^0x8b3dc651)
            assert fresh==f['producer_read_custody'][1]['custody'] and f['scalar32']==[0,1,0,1][j]
            offset_read=next(x for x in r['source_reads'] if x['pc']=='0x100584edc'
                and x['source_visit_index']>scalar_read['source_visit_index'])
            position_custody=custody(r,offset_read)
            assert all(b['last_writer_in_this_interval']==s['writes'][0] for b in position_custody)
            assert int.from_bytes(bytes.fromhex(offset_read['bytes_hex']),'little')==f['offset_bytes']
            select('branch',ci,1,r,'destination_read',offset_read['source_visit_index'])
            links.append({'branch_index':ci,'element_index':j,'token_read':read_event,'pointer_read_custody':chain,
                'decoded_scalar32':f['scalar32'],'scalar_spill':spill,'producer_read':scalar_read,'producer_read_custody':fresh,
                'destination_read':offset_read,'destination_custody':position_custody,
                'destination_offset_bytes':f['offset_bytes'],'packed32':f['packed32'],'stored_hex':f['stored_hex'],
                'count32':f['count32'],'prior_field_contract_pinned':True})
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
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'parent_pins':PINS,
        'dependencies':{p:sha(ROOT/p) for p in DEPS},'source_spans':source,'routes':routes,
        'original_fixups':verify_original_fixups(int(r['slot'],16) for r in routes),'slices':slices,
        'payload_links':links,'inherited_token_survival':survival,
        'verified_counts':{'source_spans':len(source),'source_instructions':sum((b-a)//4 for a,b in SPANS.values()),
            'dispatch_routes':len(routes),'selected_replay_slices':len(slices),'payload_links':len(links),
            'successful_branch_classes':8,'inherited_token_survival_intervals':len(survival)},
        'prior_admissions_rerun':False,'new_target_intervals':0,'new_guest_input_bytes':0,
        'new_API_return_premises':0,'native_target_executed':False,'full_goal_complete':False}


if __name__=='__main__':
    e=extract();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps(e['verified_counts']),flush=True)
