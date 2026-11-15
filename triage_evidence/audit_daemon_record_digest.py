#!/usr/bin/env python3
"""Fresh finite source replay and independent record-digest custody/model audit.
O(parent bytes + selected visits*32 + source effects + proof DAG) time/space;
solver search additional (30 s/query). Local universal lemmas do not establish
universal compression/caller reachability. No native target or IPC execution.
"""
import gc
import json
import subprocess
from collections import Counter
from hashlib import sha1
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_alternative_fill import Source
from audit_daemon_record_input_origin import replay, independent_origins
from recover_daemon_record_extension import unpack
from daemon_sha1_core_model import IV, STATE_XOR, WORD_XOR, pad, reference
import recover_daemon_record_digest as R

DEPS = ['audit_daemon_record_input_origin.py','audit_daemon_alternative_fill.py',
        'daemon_sha1_core_model.py','recover_daemon_record_extension.py','daemon_state_splice_kernel.py']


def obligations(evidence):
    proofs=[]
    def prove(label,bad):
        s=z3.SolverFor('QF_BV');s.set(timeout=30000);assert s.check()==z3.sat
        s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        proofs.append({'label':label,'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
    context=z3.BitVec('record_digest_context64',64)
    v=Source();v.seed('x8',context);v.run_block(0x1004904b4,0x1004904c0)
    prove('fifth_initial_state_word_is_encoded_SHA1_IV',z3.Or(v.stores[0]['address']!=context+0x58,
          v.stores[0]['value']!=(IV[4]^STATE_XOR),v.stores[0]['size_bytes']!=4))
    v=Source();v.seed('x8',context);v.seed('w10',20);v.run_block(0x10031cf38,0x10031cf64)
    assert len(v.stores)==5
    prove('first_four_initial_words_and_digest_extent',z3.Or(*[
        z3.Or(s['address']!=context+off,s['value']!=want,s['size_bytes']!=4)
        for s,off,want in zip(v.stores,[0x48,0x4c,0x50,0x54,0x5c],[x^STATE_XOR for x in IV[:4]]+[20])]))
    source,dest,offset,position=z3.BitVecs('record_copy_source64 record_copy_dest64 record_copy_offset64 record_copy_position64',64)
    byte=z3.BitVec('record_copy_byte8',8)
    v=Source({0x100b55af8:(1,byte)})
    for n,x in {'x22':source,'x10':offset,'x16':dest,'x3':position}.items():v.seed(n,x)
    v.run_block(0x100b55af4,0x100b55b08)
    prove('direct_message_copy_byte_and_addresses',z3.Or(v.loads[0][1]!=source+offset,
          v.stores[0]['address']!=dest+position,v.stores[0]['value']!=byte,v.read('x3')!=position+1))
    v=Source({0x100b6dbd8:(1,byte)})
    for n,x in {'x22':source,'x8':offset,'sp':dest,'x10':position}.items():v.seed(n,x)
    v.run_block(0x100b6dbd4,0x100b6dbe8)
    prove('full_buffer_tail_copy_byte_and_addresses',z3.Or(v.loads[0][1]!=source+offset,
          v.stores[0]['address']!=dest+0x3cc+position,v.stores[0]['value']!=byte))
    byte_values=z3.BitVecs('record_codec_input8 record_codec_A8 record_codec_B8 record_codec_C8',8)
    nibble=z3.BitVec('record_codec_index64',64);bias=z3.BitVec('record_codec_bias8',8)
    input_address,bankA,bankB,bankC,frame=z3.BitVecs('record_codec_input64 record_codec_A64 record_codec_B64 record_codec_C64 record_codec_F64',64)
    out=z3.BitVec('record_codec_output64',64);index=z3.BitVec('record_codec_position32',32)
    v=Source({pc:(1,b) for pc,b in zip([0x100a7bb64,0x100a7bb74,0x100a7bb7c,0x100a7bb84],byte_values)} | {0x100a7bb94:(8,bankB)})
    for n,x in {'x5':input_address,'x4':nibble,'x6':0,'x24':bankA,'x20':bankB,'x28':bankC,
                'sp':frame,'x30':out,'w9':index,'w0':z3.ZeroExt(24,bias)}.items():v.seed(n,x)
    v.run_block(0x100a7bb64,0x100a7bba8)
    n=nibble&15;value=byte_values[0]^byte_values[1]^byte_values[2]^byte_values[3]^z3.Extract(7,0,n|(n<<5))^bias
    prove('four_byte_codec_value_and_all_input_output_addresses',z3.Or(
        *[a!=want for (pc,a,size),want in zip(v.loads,[input_address,bankA+n,bankB+n+3,bankC+n+1,frame+0x98])],
        v.stores[0]['address']!=out+z3.ZeroExt(32,index),v.stores[0]['value']!=value))
    # Fixed original cutpoint constants are checked over all 256 expansions.
    chunk=evidence['cases'][0]['source_chunks'][0]
    f=next(f for f in chunk['frames'] if f['pc']=='0x100a8b6b4')
    words=z3.BitVecs('record_schedule_a32 record_schedule_b32 record_schedule_c32 record_schedule_d32',32)
    v=Source({pc:(4,w^WORD_XOR) for pc,w in zip([0x100a8b6dc,0x100a8b6ec,0x100a8b708,0x100a8b718],words)})
    for j,x in enumerate(f['registers31']):v.seed('x'+str(j),int(x,16))
    v.seed('sp',int(f['SP'],16));v.run_block(0x100a8b6b4,0x100a8b740)
    assert len(v.stores)==1 and len(v.loads)==4
    prove('expanded_schedule_value_for_arbitrary_four_u32_words',
          v.stores[0]['value']!=(z3.RotateLeft(words[0]^words[1]^words[2]^words[3],1)^WORD_XOR))
    return proofs


def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')))
    for p,d in R.PINS.items():assert sha(ROOT/p)==d
    parent=json.loads(read(ROOT/'daemon_record_extension_checks.json')); totals=Counter();records=[]
    for case in e['cases']:
        for chunk in case['source_chunks']:totals.update(replay(chunk))
        packed=parent['classes'][case['class_index']]['intervals'][-1]['interval_packed']
        assert packed['decoded_sha256']==case['parent_interval_sha256']
        row=unpack(packed)
        for field in ['input_byte_origins','core_read_origins','copy_read_origins']:
            checked=independent_origins(row,{'selected_read_origins':case[field]})
            totals.update({field+'_'+k:v for k,v in checked.items()})
        # Compare every stored source slice with its original parent position.
        for chunk in case['source_chunks']:
            assert chunk==R.piece(row,chunk['start_visit'],chunk['end_visit_exclusive'],chunk['kind'])
        codec=case['body_codec'];owner=codec['input_owner'];first=int(owner['address'],16)+77
        assert owner in row['foreign_owners']
        incoming={}
        for field in ['initial_private_fixtures','initial_image_fixtures']:
            for f in row[field]:
                a=int(f['address'],16)
                for k,b in enumerate(bytes.fromhex(f['bytes_hex'])):
                    if first<=a+k<first+48:incoming[a+k]=b
        assert bytes(incoming[first+k] for k in range(48)).hex()==codec['input48_hex']
        del row;gc.collect()
        codec=case['body_codec'];banks=[bytes.fromhex(b['bytes16_hex']) for b in codec['fixed_bank_slices']]
        assert all(IMAGE.read(int(b['start'],16),16).hex()==b['bytes16_hex'] for b in codec['fixed_bank_slices'])
        bias=int(codec['source_bias8'],16)
        masks=bytes((banks[0][n]^banks[1][n]^banks[2][n]^(n|(n<<5))^bias^0x98)&255 for n in range(16))
        assert masks.hex()==codec['mask16_hex']=='d98c9317498b221182b3198570dd904f'
        raw=bytes.fromhex(codec['input48_hex']);decoded=bytes(x^masks[(77+j)&15] for j,x in enumerate(raw))
        assert len(raw)==48 and decoded.hex()==codec['decoded48_hex']==case['segments'][1]['decoded_hex']
        assert bytes(r['byte'] for r in codec['inherited_input_bytes'])==raw
        assert codec['input_offset_bytes']==77 and 77+48<=codec['input_owner']['size_bytes']
        body_reads=[x for x in case['copy_read_origins'] if x['reader']['pc']=='0x100a7bb64']
        assert len(body_reads)==48 and all(not x['origins'] for x in body_reads)
        assert ''.join(x['reader']['bytes_hex'] for x in body_reads)==codec['input48_hex']
        for x in case['copy_read_origins']:
            r=x['reader'];a=int(r['address'],16)
            if a<0x6000000000:
                assert r['size_bytes']==1 and IMAGE.read(a,1).hex()==r['bytes_hex']
                totals['original_image_message_codec_read_bytes_checked']+=1
        body_chunks=[p for p in case['source_chunks'] if p['kind']=='record_digest_message_byte' and p['writes'][0]['pc']=='0x100a7bba4']
        for j,p in enumerate(body_chunks):
            n=(int(p['frames'][0]['registers31'][12],16)+int(p['frames'][0]['registers31'][6],16))&15
            assert n==(77+j)&15 and int(p['frames'][0]['registers31'][0],16)&255==bias
            assert int(p['reads'][0]['address'],16)==int(codec['input_owner']['address'],16)+77+j
            assert [int(r['address'],16) for r in p['reads'][1:4]]==[int(b['start'],16)+n for b in codec['fixed_bank_slices']]
            assert int(p['writes'][0]['after_hex'],16)^0x98==decoded[j]
        totals.update(body_codec_bytes_checked=48,body_codec_mask_rows_checked=16,inherited_body_fixture_bytes_checked=48)
        state=IV[:];padded=b'';schedule_words=rounds=0
        c=int(case['context_C'],16)
        iw={int(w['address'],16):int.from_bytes(bytes.fromhex(w['after_hex']),'little') for w in case['initialization_state_writes']}
        assert [iw[c+0x48+4*j]^STATE_XOR for j in range(5)]==IV
        for bi,block in enumerate(case['blocks']):
            raw=bytes.fromhex(block['decoded_input64_hex']);encoded=bytes.fromhex(block['encoded_input64_hex'])
            assert raw==bytes(x^0x98 for x in encoded) and len(raw)==64 and block['initial_state5']==state
            ref=reference(raw,state);padded+=raw
            assert block['final_state5']==ref['final_state5']
            stores={int(w['address'],16):int.from_bytes(bytes.fromhex(w['after_hex']),'little') for w in block['state_writes']}
            assert [stores[c+0x48+4*j]^STATE_XOR for j in range(5)]==ref['final_state5']
            assert [int.from_bytes(bytes.fromhex(w['after_hex']),'little')^WORD_XOR for w in block['schedule_writes']]==ref['schedule80']
            for rec in block['round_entries']:
                t=rec['round'];regs=block['round_register_maps'][t//20]
                assert [(int(rec['registers31'][j],16)&0xffffffff)^STATE_XOR for j in regs]==ref['working_states81'][t]
                rounds+=1
            assert [(int(block['final_working_registers31'][j],16)&0xffffffff)^STATE_XOR for j in [22,10,4,12,0]]==ref['working_states81'][80]
            # All source schedule data are read after matching source stores.
            start=int(block['schedule_writes'][0]['address'],16)
            origins=[x for x in case['core_read_origins'] if block['start_visit']<=x['reader']['source_visit_index']<block['end_visit_exclusive'] and start<=int(x['reader']['address'],16)<start+320]
            assert len(origins)==336 and all(len(x['origins'])==4 for x in origins)
            assert all(block['start_visit']<=o['writer']['source_visit_index']<x['reader']['source_visit_index'] for x in origins for o in x['origins'])
            core=case['source_chunks'][bi]
            expansions=[f for f in core['frames'] if f['pc']=='0x100a8b6b4']
            assert len(expansions)==64 and all(int(f['registers31'][8],16)==STATE_XOR for f in expansions)
            expansion_visits=[core['start_visit']+j for j,f in enumerate(core['frames']) if f['pc']=='0x100a8b6b4']
            for k,j in enumerate(expansion_visits):
                end=expansion_visits[k+1] if k<63 else block['round_entries'][0]['source_visit_index']
                rr=[x['reader'] for x in origins if j<=x['reader']['source_visit_index']<end]
                assert [int(r['address'],16) for r in rr]==[start+4*(16+k-d) for d in [3,8,14,16]]
                assert [int.from_bytes(bytes.fromhex(r['bytes_hex']),'little')^WORD_XOR for r in rr]==[ref['schedule80'][16+k-d] for d in [3,8,14,16]]
            for k,entry in enumerate(block['round_entries']):
                end=block['round_entries'][k+1]['source_visit_index'] if k<79 else block['final_working_source_visit']
                rr=[x['reader'] for x in origins if entry['source_visit_index']<=x['reader']['source_visit_index']<end]
                assert len(rr)==1 and int(rr[0]['address'],16)==start+4*k
                assert int.from_bytes(bytes.fromhex(rr[0]['bytes_hex']),'little')^WORD_XOR==ref['schedule80'][k]
            totals.update(expanded_schedule_input_reads_checked=256,round_schedule_input_reads_checked=80)
            schedule_words+=80;state=ref['final_state5']
        message=bytes.fromhex(case['message67_hex'])
        assert len(message)==67 and padded==pad(message) and padded[-8:]==(536).to_bytes(8,'big')
        digest=b''.join(x.to_bytes(4,'big') for x in state)
        host=sha1(message).digest();openssl=subprocess.run(['openssl','dgst','-sha1','-binary'],input=message,capture_output=True,check=True)
        assert not openssl.stderr and openssl.stdout==host==digest==bytes.fromhex(case['digest20_hex'])
        key=bytes.fromhex('db55ebcef63f382c0cc860693c6fe140')
        aes=subprocess.run(['openssl','enc','-aes-128-ecb','-K',key.hex(),'-nopad','-nosalt'],input=digest[2:18],capture_output=True,check=True)
        assert not aes.stderr and len(aes.stdout)==16
        output=bytes(x^0x98 for x in digest[:2]+aes.stdout+digest[18:])
        assert output.hex()==case['record_input20_hex']
        controls=[message[11:59]+message[:11]+message[59:],message[11:],message[:59],bytes(x^0x98 for x in message)]
        assert all(sha1(m).digest()!=digest for m in controls)
        records.append({'class_index':case['class_index'],'message67_hex':message.hex(),'digest20_hex':digest.hex(),
                        'record_input20_hex':output.hex(),'compression_blocks':2,'round_entries_checked':rounds,
                        'schedule_words_checked':schedule_words,'host_SHA1_matches':True,'host_AES_composition_matches':True,
                        'domain_encoding_negative_controls_distinct':4})
        totals.update(complete_compression_blocks_checked=2,source_schedule_words_checked=schedule_words,
                      source_round_entries_checked=rounds,final_working_words_checked=10,initial_IV_words_checked=5,
                      message_bytes_checked=67,padded_bytes_checked=128,host_SHA1_implementations_checked=2,
                      host_AES_compositions_checked=1,domain_encoding_negative_controls_checked=4)
    proofs=obligations(e);totals.update(source_queries_unsat=len(proofs))
    return {'scope':__doc__,'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'generator_sha256':sha(R.__file__),'source_sha256':sha(SOURCE),
            'dependencies':{p:sha(ROOT/p) for p in DEPS},'independent_totals':dict(totals),'cases':records,
            'source_proofs':proofs,'host_reference':{'SHA1':['hashlib','openssl dgst'],'AES':'openssl enc',
                'openssl_version':subprocess.check_output(['openssl','version'],text=True).strip()},
            'retained_digest_message_identity_established':True,'universal_new_compression_equivalence_established':False,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}


if __name__=='__main__':
    result=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result['independent_totals']),flush=True)
