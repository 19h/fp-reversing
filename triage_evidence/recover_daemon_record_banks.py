#!/usr/bin/env python3
"""Static bank producers, memory epochs and descending masked-byte writer.
O(profile visits*fields + text words + retained exports + selected events)
time; O(parent receipts + profiles + frontier exports + evidence) space.
No root definitions, target intervals, imports, native IPC or IDB actions.
"""
import json
import struct
from collections import Counter
from functools import lru_cache
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,CS,TABLE
from resolve_kernel_collection_interfaces import commands
from recover_daemon_constructor_bank_origins import DC,norm
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes
import recover_daemon_record_extension as Prior

P='daemon_record_banks'
FIELDS={0x390:0x10102fa10,0x398:0x100eebf60,0x3a0:0x100fd8250}
WRITERS={0x390:0x1004c335c,0x398:0x1004c2afc,0x3a0:0x1004c28e8}
SUFFIXES={0x390:(0x1004c3344,0x1004c3360,'w16','x21',0x7c0),
          0x398:(0x1004c2ae8,0x1004c2b00,'w10','x10',0x61b),
          0x3a0:(0x1004c28c4,0x1004c28ec,'w9','x9',0x854)}
SPANS={'loop':(0x10084fcc4,0x10084fe34),'optional_output':(0x1008d3490,0x1008d34d8)}
PINS={'daemon_shared_roots_profiles.json':'c96dc345c38ad8e058b878d29ffe043382966414406adda52ee7484c75e36987',
      'daemon_constructor_bank_origins_checks.json':'f77a6546701cd5ce28243133724c659f058975c7645cb21e1028fa2dcb5eef21',
      'daemon_record_extension_checks.json':'9e89cde6b9d04019761c1f7370584e72ad85afc0aa0fd657f4cb4aa9ff0571d7',
      'daemon_record_extension_replay.json':'7ffde847a48145ad9821ab9d228a345dbd7722ab6d00179836624c202b81993d'}
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_constructor_bank_origins.py',
      'recover_daemon_record_extension.py','audit_daemon_network_record.py']


@lru_cache(None)
def instruction(pc):
    return next(DC.disasm(IMAGE.read(pc,4),pc))


def span(a,b):
    raw=IMAGE.read(a,b-a)
    return {'start':hex(a),'end_exclusive':hex(b),'bytes_hex':raw.hex(),
            'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]}


def projection(q,off):
    frame=int(q['frame_base'],16)
    target=[w for w in q['source_writes'] if int(w['address'],16)<frame+off+8 and frame+off<int(w['address'],16)+w['size_bytes']]
    assert len(target)==1 and target[0]['pc']==hex(WRITERS[off])
    target=target[0];assert target['size_bytes']==8
    assert int.from_bytes(bytes.fromhex(target['after_hex']),'little')==FIELDS[off]
    rr={};ww={}
    for x in q['source_reads']:rr.setdefault(x['source_visit_index'],[]).append(x)
    for x in q['source_writes']:ww.setdefault(x['source_visit_index'],[]).append(x)
    end=target['source_visit_index'];live={norm(instruction(WRITERS[off]).op_str.split(',')[0])}
    memory=set();selected={end}
    for j in range(end-1,-1,-1):
        v=q['source_visits'][j];pc=int(v['pc'],16)
        i=instruction(pc) if v['image']=='daemon' else next(DC.disasm(bytes.fromhex(v['bytes_hex']),pc))
        rs,ws=i.regs_access();rs={norm(i.reg_name(r)) for r in rs};ws={norm(i.reg_name(r)) for r in ws}
        killed={int(w['address'],16)+k for w in ww.get(j,[]) for k in range(w['size_bytes'])}
        if not (live&ws or memory&killed):continue
        assert v['image']=='daemon'
        selected.add(j);live-=ws;live|=rs;live.discard('sp');memory-=killed
        for r in rr.get(j,[]):memory.update(range(int(r['address'],16),int(r['address'],16)+r['size_bytes']))
    assert not live,live
    rows=[];last={};links=[];external=[]
    for j in sorted(selected):
        v=q['source_visits'][j];pc=int(v['pc'],16);i=instruction(pc)
        assert v['image']=='daemon' and v['bytes_hex']==IMAGE.read(pc,4).hex()
        loads=rr.get(j,[]);stores=ww.get(j,[])
        for r in loads:
            a=int(r['address'],16);raw=bytes.fromhex(r['bytes_hex']);origins=[]
            for k,b in enumerate(raw):
                if a+k in last:
                    w,wb=last[a+k];assert wb==b;origins.append({'byte_index':k,'writer':w})
                else:external.append({'reader':r,'byte_index':k})
            if origins:links.append({'reader':r,'origins':origins})
        for w in stores:
            for k,b in enumerate(bytes.fromhex(w['after_hex'])):last[int(w['address'],16)+k]=(w,b)
        rows.append({'source_visit_index':j,'pc':v['pc'],'bytes_hex':v['bytes_hex'],
                     'mnemonic':i.mnemonic,'operands':i.op_str,'reads':loads,'writes':stores})
    return {'field_offset':hex(off),'frame_base':hex(frame),'value':hex(FIELDS[off]),'writer':target,
            'instructions':rows,'internal_read_byte_links':links,'external_read_bytes':external,
            'incoming_register_demands':[]}


def census():
    for at,c,n in commands(IMAGE.data,0):
        if c!=0x19:continue
        for j in range(struct.unpack_from('<I',IMAGE.data,at+64)[0]):
            p=at+72+j*80
            if IMAGE.data[p:p+16].split(b'\0')[0]==b'__text':a,n=struct.unpack_from('<QQ',IMAGE.data,p+32);break
        else:continue
        break
    patterns={0xf90003e0|((o//8)<<10):o for o in FIELDS};rows={o:[] for o in FIELDS}
    for j,(w,) in enumerate(struct.iter_unpack('<I',IMAGE.read(a,n))):
        off=patterns.get(w&0xffffffe0)
        if off is not None:rows[off].append(hex(a+j*4))
    return {'text_start':hex(a),'text_size_bytes':n,'aligned_words':n//4,
            'scope':'Literal unsigned-immediate STR Xn,[SP,#offset] only; no frame equivalence or global writer completeness.',
            'candidates':{hex(o):v for o,v in rows.items()}}


def build():
    for p,d in PINS.items():assert sha(ROOT/p)==d
    frozen=json.loads(read(ROOT/'daemon_shared_roots_profiles.json'))
    old=json.loads(read(ROOT/'daemon_record_extension_checks.json'))
    profiles=[];counts=Counter();source_pcs=set();pool_slots=set()
    for q in frozen['cases']:
        pp=[projection(q,o) for o in FIELDS]
        for p in pp:
            counts['projection_instruction_instances']+=len(p['instructions'])
            counts['store_read_byte_links']+=sum(len(x['origins']) for x in p['internal_read_byte_links'])
            for x in p['instructions']:
                source_pcs.add(int(x['pc'],16))
                pool_slots.update(int(r['address'],16) for r in x['reads'] if int(r['address'],16) in FIXUPS)
        reuse=[];frame=int(q['frame_base'],16)
        for off,reader in [(0x990,0x1004c2ac4),(0x998,0x1004c3064)]:
            writes=[w for w in q['source_writes'] if int(w['address'],16)<frame+off+4 and frame+off<int(w['address'],16)+w['size_bytes']]
            reads=[r for r in q['source_reads'] if r['pc']==hex(reader)]
            assert len(writes)==2 and len(reads)==1
            assert writes[0]['source_visit_index']<reads[0]['source_visit_index']<writes[1]['source_visit_index']
            assert reads[0]['bytes_hex']==writes[0]['after_hex'][:8]
            for event in writes+reads:
                visit=q['source_visits'][event['source_visit_index']];pc=int(event['pc'],16)
                assert visit['pc']==event['pc'] and visit['image']=='daemon'
                assert visit['bytes_hex']==IMAGE.read(pc,4).hex();source_pcs.add(pc)
            reuse.append({'offset':hex(off),'read':reads[0],'writes':writes})
        profiles.append({'configuration':q['configuration'],'projections':pp,'reused_cells':reuse,'native_execution':False})
    banks={hex(o):{'address':hex(a),'extent_bytes':19 if o==0x398 else 16,
                 'bytes_hex':IMAGE.read(a,19 if o==0x398 else 16).hex()} for o,a in FIELDS.items()}
    aa,bb,cc=[bytes.fromhex(banks[hex(o)]['bytes_hex']) for o in [0x390,0x3a0,0x398]]
    mask=bytes((aa[n]^bb[n]^cc[n+3]^(n|(n<<5))^0x23)&255 for n in range(16))
    frontiers=[]
    for j,c in enumerate(old['coverage']):
        if not c['normal_branch']:continue
        s=Prior.unpack(c['derived_terminal_state_packed']);b=s['boundary'];m=state_bytes(s)
        frame=int(b['SP'],16);regs=[int(x,16) for x in b['registers31']]
        assert b['pc']=='0x10084fdcc' and all(frame+o+k not in m for o in FIELDS for k in range(8))
        assert regs[8]==165 and regs[13]==0x6613 and regs[14]^regs[15]==19 and regs[16]==8
        assert regs[11]^0x8b3dc651==19 and regs[15]==0x313680c7
        assert regs[9]==frame+0xc4b0 and regs[0]==regs[10]+184
        assert {'address':hex(regs[10]),'size_bytes':224} in s['foreign_owners']
        raw=bytes(m[regs[9]+k] for k in range(20))
        assert raw[19]==regs[17]==0xf1
        predicted=bytes(x^mask[(165+k)&15] for k,x in enumerate(raw))
        frontiers.append({'coverage_index':j,'parent_index':c['parent_index'],'ABI_clobber_pattern':c['ABI_clobber_pattern'],
            'class_index':c['class_index'],'frame_SP':hex(frame),'input_base':hex(regs[9]),'input20_hex':raw.hex(),
            'output_base':hex(regs[10]),'postdecrement_counter32':hex(regs[11]),'remaining_stores_if_admitted':20,'destination_first_offset_bytes':165,'destination_last_offset_bytes':184,
            'conditional_prediction20_hex':predicted.hex(),'pending_byte_prediction':predicted[19],
            'three_bank_fields_defined':False,'native_execution':False})
    assert len(frontiers)==608
    routes=[]
    for index in [0x6613,0x6656]:
        slot=TABLE+index*8;f=FIXUPS[slot]
        routes.append({'index':hex(index),'slot':hex(slot),'original_word_hex':IMAGE.read(slot,8).hex(),
                       'fixup':f,'target':hex(f['target'])})
    counts.update(profiles=len(profiles),bank_fields=3,field_instances=len(profiles)*3,
                  retained_frontiers=len(frontiers),mask_entries=len(mask),new_root_bytes=0,new_target_intervals=0)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
            'dependencies':{p:sha(ROOT/p) for p in DEPS},'parent_pins':PINS,'profiles':profiles,
            'banks':banks,'mask16_hex':mask.hex(),'frontiers':frontiers,'routes':routes,
            'spans':{n:span(*v) for n,v in SPANS.items()},
            'producer_suffixes':{hex(o):span(v[0],v[1]) for o,v in SUFFIXES.items()},
            'projection_source_words':[{'pc':hex(p),'bytes_hex':IMAGE.read(p,4).hex()} for p in sorted(source_pcs)],
            'pool_fixups':[{'slot':hex(p),'original_word_hex':IMAGE.read(p,8).hex(),'fixup':FIXUPS[p]} for p in sorted(pool_slots)],
            'literal_store_census':census(),'verified_counts':dict(counts),
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,
            'initializer_to_current_caller_join_established':False,'full_goal_complete':False}


if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps(e['verified_counts']),flush=True)
