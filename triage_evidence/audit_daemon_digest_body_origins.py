#!/usr/bin/env python3
"""Independent forward byte-epoch fold, source replay and writer equations.
Conservative O(P+(Q+C)*E+(E+Q)*log(E+Q)+32V+proof DAG) time; P parent
bytes, Q byte queries, C chunks, E events/fixture bytes, V selected visits.
O(largest interval+receipts+32V+proof DAG) space. Solver
search additional, 30 s/query. No native target or IDB operation.
"""
import gc
import json
from collections import Counter, defaultdict
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_record_extension import unpack
from audit_daemon_record_input_origin import replay, independent_origins
from audit_daemon_state_table_mixing import Scalar
from audit_daemon_alternative_fill import Source
from lskd_values_symbolic import mem
import recover_daemon_digest_body_origins as R

DEPS = ['audit_daemon_record_input_origin.py', 'audit_daemon_append_fields.py',
        'audit_daemon_state_table_mixing.py', 'audit_daemon_alternative_fill.py', 'lskd_values_symbolic.py']


def obligations():
    proofs = []
    def prove(label, bad):
        s=z3.SolverFor('QF_BV'); s.set(timeout=30000); assert s.check()==z3.sat
        s.add(z3.simplify(bad)); assert s.check()==z3.unsat,label
        proofs.append({'label':label,'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
    def seed(v, values):
        for n,x in values.items():v.seed(n,x)
        return v
    word,n=z3.BitVecs('body_writer_word32 body_nibble32',32)
    a,b,c=z3.BitVecs('body_bank_a8 body_bank_b8 body_bank_c8',8)
    dest=z3.BitVec('body_destination64',64)
    specs=[(0x100c70e0c,0x100c70e2c,{'w12':n,'w14':a,'w15':b,'w16':c,'w11':word,'x13':dest},24,0x12),
           (0x100c70e64,0x100c70e84,{'w12':n,'w14':a,'w15':b,'w16':c,'w11':word,'x13':dest},16,0x7e),
           (0x100c70eb0,0x100c70ed4,{'w12':n,'w14':a,'w15':b,'w16':c,'w11':word,'x13':dest},8,0x74),
           (0x100c70f00,0x100c70f1c,{'w10':n,'w12':a,'w13':b,'w14':c,'w11':word,'x9':dest},0,0xff)]
    for k,(lo,hi,values,shift,bias) in enumerate(specs):
        v=seed(Scalar(),values);v.run_block(lo,hi);w,=v.stores
        offset=(n|(n<<5)) if k==0 else n*31
        expected=z3.Extract(shift+7,shift,word)^a^b^c^z3.Extract(7,0,offset)^bias
        prove('original_word_writer_byte_'+str(k),z3.Or(w['address']!=dest,w['size_bytes']!=1,w['value']!=expected))
    i,src=z3.BitVecs('body_copy_index64 body_copy_source64',64); byte=z3.BitVec('body_copy_byte8',8)
    v=seed(Scalar(),{'x9':i+1,'x24':src,'x10':dest});mem(v,src+i,1,byte)
    v.run_block(0x100b5c9b0,0x100b5c9bc);w,=v.stores
    prove('original_growth_byte_copy',z3.Or(v.read('x9')!=i,w['address']!=dest+i,w['size_bytes']!=1,w['value']!=byte))
    payload,controller=z3.BitVecs('body_byte_payload32 body_byte_controller32',32)
    base,index=z3.BitVecs('body_bank_base64 body_bank_index64',64)
    v=seed(Source({0x100a0ca54:(1,c)}),{'x15':dest,'w13':a,'w14':payload,'w11':controller,'x0':base,'x16':index})
    v.run_block(0x100a0ca4c,0x100a0ca78);w,=v.stores
    expected=z3.Extract(7,0,payload)^a^c^(z3.Extract(7,0,dest)*31)^z3.Extract(7,0,controller)^6
    prove('original_table_encoded_byte_tail',z3.Or(v.loads[0][1]!=base+index,w['address']!=dest,w['size_bytes']!=1,w['value']!=expected))
    for k,(lo,hi,reg,address,shift,bias) in enumerate([
        (0x100b755a0,0x100b755b0,'w9','x11',8,0x98),
        (0x100b755f0,0x100b755fc,'w9','x10',0,0x87)]):
        v=seed(Scalar(),{'w8':word,reg:a,address:dest});v.run_block(lo,hi);w,=v.stores
        expected=a^z3.Extract(shift+7,shift,word)^bias
        prove('original_two_byte_writer_tail_'+str(k),z3.Or(w['address']!=dest,w['size_bytes']!=1,w['value']!=expected))
    return proofs


def audit():
    evidence=json.loads(read(ROOT/(R.P+'_checks.json')))
    for p,d in R.PINS.items():assert sha(ROOT/p)==d
    parent=json.loads(read(ROOT/'daemon_record_extension_checks.json'))
    totals=Counter(); controls=Counter(); cases=[]
    banks=[IMAGE.read(a,16) for a in R.BANK_STARTS]
    assert evidence['fixed_banks']==[{'address':hex(a),'bytes16_hex':b.hex()} for a,b in zip(R.BANK_STARTS,banks)]
    for n in range(16):
        masks=[(banks[0][n]^banks[1][n]^banks[2][n]^(n|(n<<5))^0x12)&255]
        masks += [(banks[3][n]^banks[4][n]^banks[5][n]^(n*31)^bias)&255 for bias in [0x7e,0x74,0xff]]
        assert [m^R.MASK[n] for m in masks]==[0xe4,0xb5,0xbf,0x34]
        assert evidence['word_mask_rows'][n]=={'nibble':n,'decoded_word_XOR_bytes':[0xe4,0xb5,0xbf,0x34]}
        totals['fixed_word_codec_rows_checked']+=1
    for case in evidence['cases']:
        ci=case['class_index'];raw=bytes.fromhex(case['body48_stored_hex']);decoded=bytes.fromhex(case['body48_decoded_hex'])
        assert bytes(b^R.MASK[(77+k)&15] for k,b in enumerate(raw))==decoded
        for chain in case['chains']:
            r=chain['consumer_read']; ii=9;address=r['address'];cut=r['source_visit_index']
            assert chain['stored_byte']==raw[chain['body_byte']]
            for step in chain['steps']:
                assert (step['interval_index'],step['address'],step['before_visit_exclusive'])==(ii,address,cut)
                if step['kind']=='incoming':ii-=1;cut=None
                elif step['kind']=='copy':address=step['source_read']['address'];cut=step['source_read']['source_visit_index']
                else:
                    assert step['kind']=='producer' and step is chain['steps'][-1]
                    leaf,=[x for x in case['producer_bytes'] if x['body_byte']==chain['body_byte']]
                    assert (leaf['interval_index'],leaf['writer'],leaf['writer_byte'])==(ii,step['writer'],step['writer_byte'])
            assert chain['steps'][-1]['kind']=='producer'
        for ir in case['intervals']:
            ii=ir['interval_index'];item=parent['classes'][ci]['intervals'][ii]
            assert ir['parent_interval_sha256']==item['interval_packed']['decoded_sha256'] and ir['API_return_premise']==item['API_return_premise']
            row=unpack(item['interval_packed']);queries=[]
            for chain in case['chains']:
                for s in chain['steps']:
                    if s['interval_index']==ii:
                        cut=s['before_visit_exclusive'];queries.append((len(row['source_visits']) if cut is None else cut,int(s['address'],16),chain['stored_byte'],s))
            wanted={a for cut,a,b,s in queries};writes=row['source_writes'];last={};wi=0;prior_values=defaultdict(set)
            for cut,a,b,s in sorted(queries,key=lambda q:q[0]):
                while wi<len(writes) and writes[wi]['source_visit_index']<cut:
                    w=writes[wi];wa=int(w['address'],16)
                    for k,byte in enumerate(bytes.fromhex(w['after_hex'])):
                        if wa+k in wanted:
                            last[wa+k]=(w,k,byte);prior_values[wa+k].add(byte)
                    wi+=1
                if a in last:
                    w,k,byte=last[a];assert s['kind'] in ['copy','producer'] and s['writer']==w and s['writer_byte']==k and byte==b
                    totals[s['kind']+'_byte_links_checked']+=1
                    later=[w2 for w2 in writes[wi:] if int(w2['address'],16)<=a<int(w2['address'],16)+w2['size_bytes']]
                    if later:controls['end_of_interval_writer_changes']+=1
                    if prior_values[a]-{b}:controls['earlier_different_byte_queries']+=1
                    if s['kind']=='copy':
                        rr=[r for r in row['source_reads'] if r['source_visit_index']==w['source_visit_index']-1]
                        assert rr==[s['source_read']] and rr[0]['pc']==R.COPY_READ and rr[0]['bytes_hex']==w['after_hex'] and w['pc']==R.COPY_WRITE
                else:
                    assert s['kind']=='incoming';found=[]
                    for kind in ['initial_private_fixtures','initial_image_fixtures']:
                        for f in row[kind]:
                            fa=int(f['address'],16);bs=bytes.fromhex(f['bytes_hex'])
                            if fa<=a<fa+len(bs):found.append({'fixture_kind':kind,'fixture_address':f['address'],'fixture_byte':a-fa,'byte':bs[a-fa],'provenance':f['provenance']})
                    assert found==s['fixtures'] and all(f['byte']==b for f in found) and found
                    p=ir['API_return_premise'];spans=list(p['invalidated_spans'])
                    if 'allocated_owner_premise' in p:spans.append(p['allocated_owner_premise'])
                    assert not any(int(z['address'],16)<=a<int(z['address'],16)+z['size_bytes'] for z in spans)
                    assert s['not_invalidated_by_API_premise'] is True
                    totals['incoming_boundary_links_checked']+=1
            for chunk in ir['chunks']:
                lo,hi=chunk['start_visit'],chunk['end_visit_exclusive']
                assert chunk['visits']==row['source_visits'][lo:hi]
                assert chunk['frames']==[{k:v for k,v in f.items() if k!='Q_registers32'} for f in row['source_frames'][lo:hi+1]]
                assert all(f['Q_registers32']==chunk['Q_registers32_preserved'] for f in row['source_frames'][lo:hi+1])
                for key,field in [('reads','source_reads'),('writes','source_writes'),('edges','logical_edges')]:
                    assert chunk[key]==[e for e in row[field] if lo<=e['source_visit_index']<hi]
                totals.update(replay(chunk))
                if chunk['kind']=='table_encoded_byte_writer':
                    field,=[b for b in case['byte_fields'] if b['interval_index']==ii and b['start_visit']==lo]
                    registers=chunk['frames'][0]['registers31'];w=int(registers[9],16)&0xffffffff;shift=int(registers[8],16)&31
                    write,=chunk['writes'];a=int(write['address'],16)
                    reads={r['pc']:r for r in chunk['reads'] if r['pc'] in ['0x100a0c9d8','0x100a0c9f8','0x100a0ca14','0x100a0ca30','0x100a0ca54']}
                    val=lambda pc:int.from_bytes(bytes.fromhex(reads[pc]['bytes_hex']),'little')
                    cache=val('0x100a0c9d8');mask=val('0x100a0c9f8')^0xa7a730ec;text=val('0x100a0ca14')^0x12af5504870a589f
                    assert int(registers[10],16)==0xbc66
                    r=(cache+a)&0xffffffff;addrs=[text+(((r+k)&0xffffffff)&mask) for k in [0x0ba3ccc8,0x0ba3ccca]]
                    assert [reads[p]['address'] for p in ['0x100a0ca30','0x100a0ca54']]==[hex(x) for x in addrs]
                    ta,tb=[IMAGE.read(x,1)[0] for x in addrs]
                    stored=((w>>shift)^((a*31)&0xffffffff)^ta^tb^0xd7)&255
                    assert field=={'interval_index':ii,'start_visit':lo,'source_W9':hex(w),'shift_bits':shift,
                                   'phase_W10':'0xbc66','destination':hex(a),'cached_word32':hex(cache),'r32':hex(r),
                                   'mask64':hex(mask),'text_base':hex(text),'text_addresses':[hex(p) for p in addrs],
                                   'text_bytes_hex':bytes([ta,tb]).hex(),'stored_byte_hex':bytes([stored]).hex()}
                    assert write['after_hex']==field['stored_byte_hex'];totals['complete_byte_codec_cases_checked']+=1
                if chunk['kind']=='two_byte_writer':
                    pair,=[p for p in case['two_byte_groups'] if p['interval_index']==ii and p['start_visit']==lo]
                    j=next(j for j,v in enumerate(chunk['visits']) if v['pc']=='0x100b755a0')
                    value=int(chunk['frames'][j]['registers31'][8],16)&0xffffffff
                    ws=[w for w in chunk['writes'] if w['pc'] in R.PAIR_PCS];owner=int(pair['owner'],16);off=pair['owner_offset_bytes']
                    assert owner==int(chunk['frames'][0]['registers31'][22],16) and [w['address'] for w in ws]==[hex(owner+off+k) for k in range(2)]
                    assert pair['source_W8_after_arithmetic']==hex(value) and pair['stored2_hex']==''.join(w['after_hex'] for w in ws)
                    assert pair['writer_visits']==[w['source_visit_index'] for w in ws]
                    assert pair['decoded2_hex']==((value^0x534c)&0xffff).to_bytes(2,'big').hex()
                    assert bytes(b^R.MASK[(off+k)&15] for k,b in enumerate(bytes.fromhex(pair['stored2_hex']))).hex()==pair['decoded2_hex']
                    for r in chunk['reads']:
                        if r['size_bytes']!=1:continue
                        k=0 if r['pc'] in ['0x100b75564','0x100b7557c','0x100b75588'] else 1
                        bank={'0x100b75564':3,'0x100b7557c':4,'0x100b75588':5,
                              '0x100b755c8':3,'0x100b755dc':4,'0x100b755e4':5}[r['pc']]
                        assert int(r['address'],16)==R.BANK_STARTS[bank]+((off+k)&15) and r['bytes_hex']==IMAGE.read(int(r['address'],16),1).hex()
                        totals['pair_image_bank_bytes_checked']+=1
                    totals['two_byte_groups_checked']+=1
                if chunk['kind']=='four_byte_word_writer':
                    word,=[w for w in case['word_groups'] if w['interval_index']==ii and w['start_visit']==lo]
                    ws=[w for w in chunk['writes'] if w['pc'] in R.WORD_PCS]
                    owner=int(chunk['frames'][0]['registers31'][9],16);off=int(ws[0]['address'],16)-owner
                    source=int(chunk['frames'][0]['registers31'][11],16)&0xffffffff
                    assert word['owner']==hex(owner) and word['owner_offset_bytes']==off and word['source_W11']==hex(source)
                    assert word['stored4_hex']==''.join(w['after_hex'] for w in ws)
                    assert word['writer_visits']==[w['source_visit_index'] for w in ws]
                    out=bytes.fromhex(word['decoded4_hex']);assert out==(source^0xe4b5bf34).to_bytes(4,'big')
                    assert bytes(b^R.MASK[(off+k)&15] for k,b in enumerate(bytes.fromhex(word['stored4_hex'])))==out
                    bank_pcs=[['0x100c70df4','0x100c70e00','0x100c70e08'],
                              ['0x100c70e48','0x100c70e54','0x100c70e60'],
                              ['0x100c70e9c','0x100c70ea4','0x100c70eac'],
                              ['0x100c70eec','0x100c70ef4','0x100c70efc']]
                    expected_banks={pc:R.BANK_STARTS[(0 if k==0 else 3)+t]+((off+k)&15)
                                    for k,pcs in enumerate(bank_pcs) for t,pc in enumerate(pcs)}
                    assert len([r for r in chunk['reads'] if r['size_bytes']==1])==12
                    for r in chunk['reads']:
                        if r['size_bytes']!=1:continue
                        assert int(r['address'],16)==expected_banks[r['pc']]
                        assert r['bytes_hex']==IMAGE.read(int(r['address'],16),1).hex();totals['word_image_bank_bytes_checked']+=1
                    totals['word_groups_checked']+=1
            origins=independent_origins(row,ir)
            totals.update({'selected_read_'+k:v for k,v in origins.items()})
            print(json.dumps({'audit_class':ci,'interval':ii,'chunks_checked':len(ir['chunks'])}),flush=True)
            del row;gc.collect()
        cases.append({'class_index':ci,'producer_byte_census':case['producer_byte_census'],'body48_stored_hex':case['body48_stored_hex']})
    assert controls['earlier_different_byte_queries']>0
    controls.setdefault('end_of_interval_writer_changes',0)
    controls['wrong_mask_phase_changed_bytes']=sum(b^R.MASK[k&15]!=decoded[k] for k,b in enumerate(raw))
    assert controls['wrong_mask_phase_changed_bytes']>0
    proofs=obligations();totals['source_queries_unsat']=len(proofs)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'dependencies':{p:sha(ROOT/p) for p in DEPS},
            'parent_pins':R.PINS,'independent_totals':dict(totals),'epoch_and_phase_controls':dict(controls),
            'source_proofs':proofs,'cases':cases,'retained_body_writer_lineage_established':True,
            'application_field_names_established':False,'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'full_goal_complete':False}


if __name__=='__main__':
    result=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result['independent_totals']),flush=True)
