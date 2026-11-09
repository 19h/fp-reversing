#!/usr/bin/env python3
"""Original-byte cleanup/output contract and exact STR64 SP+0x24F8 census.
O(text words + selected source bytes) time, O(candidates) space. No frame-epoch
join, native API execution, pointer assignment or transport identity inferred.
"""
import json,struct
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from capture_daemon_record720 import sha
from capture_daemon_record720_spill import text_section
from daemon_arena_consumer_symbolic import CS

def recover():
    a,n=text_section();rows=[]
    for j,(w,)in enumerate(struct.iter_unpack('<I',IMAGE.read(a,n))):
        if w&0xffffffe0 != 0xf90003e0|((0x24f8//8)<<10):continue
        pc=a+j*4;i=next(CS.disasm(IMAGE.read(pc,4),pc));rows.append({'pc':hex(pc),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str,'source_register':i.reg_name(i.operands[0].reg),'same_frame_epoch_established':False})
    ranges=[]
    for label,pc,size in [('free_call',0x1001c6100,24),('cleanup_epilogue',0x100270ac4,32),('outer_result_literal',0x100952aa8,12),('outer_result_spill',0x100951294,16),('output_base_load',0x100b90ec8,56),('output_field',0x10095f074,4)]:
        ranges.append({'label':label,'address':hex(pc),'bytes_hex':IMAGE.read(pc,size).hex(),'instructions':[{'pc':hex(i.address),'instruction':i.mnemonic+' '+i.op_str,'bytes_hex':bytes(i.bytes).hex()}for i in CS.disasm(IMAGE.read(pc,size),pc)]})
    raw=json.loads((ROOT/'daemon_cleanup_return_ida.json').read_text());matches=[]
    for item in raw['content']:
        if item['type']!='text':continue
        t=item['text'];assert '6b117c693e3b'in t;marker='[assist:tool-output]';start=t.index(marker)+len(marker);obj=json.loads(t[start:t.index('[/assist:tool-output]',start)])
        for r in obj['results']:
            # IDA's decoded lines may combine instructions. Compare raw buffer.
            assert r['size_read']==r['size_requested']==192
            pc=int(r['address'],16);b=bytes.fromhex(r['bytes']);assert b==IMAGE.read(pc,192);matches.append({'address':hex(pc),'matching_bytes':192})
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{'daemon_cleanup_return_ida.json':sha(ROOT/'daemon_cleanup_return_ida.json')},'ranges':ranges,'text_start':hex(a),'text_size_bytes':n,'literal_STR64_SP_24F8_candidates':rows,'candidate_count':len(rows),'X0_candidate_count':sum(r['source_register']=='x0'for r in rows),'live_IDA_matches':matches,'output_component':{'base_source':'u64(F+0x24F8)','field_offset_bytes':16,'field_width_bytes':4,'minimum_nonwrapping_extent_bytes':20,'source_store':'0x10095f074','raw_W23':'0x74c29f37','pointer_producer':'unknown','transport_identity':'unknown'},'normal_return_assumed':True,'native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
    r=recover();(ROOT/'daemon_cleanup_return_contracts.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'candidates':r['candidate_count'],'X0_candidates':r['X0_candidate_count'],'IDA_ranges':len(r['live_IDA_matches'])}));print(*r['ranges'],sep='\n')
