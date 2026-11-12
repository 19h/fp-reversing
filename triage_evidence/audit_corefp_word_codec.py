#!/usr/bin/env python3
"""Independent original-byte word-codec components, replay and epoch audit.

Does not import the new producer. O(C*(B+V*J+P*F+R)+4096*K)
time, bounded private maps; K is retained component visits.
30 s/SMT query. No native target/API/IPC or IDB operation.
"""
import copy,json
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
from unicorn import arm64_const as U
import audit_corefp_scan_entry as E
from verify_daemon_reader_record_payloads_publication import read
ROOT=E.ROOT;C=E.C;SHA=E.SHA;MOD=2**64;KEY=0xcccccccccccccccc;MULT=0xabdf5fe3f3ef5db9
SPECS=[('first_head',0x1b4900,0x1b4934),('first_tail',0x1b4efc,0x1b4f1c),('second_head',0x1b5738,0x1b57d0),('second_tail',0x1b5d84,0x1b5e1c)]


class Replay(E.Replay):
    def __init__(self,*a):super().__init__(*a);self.word_components=[];self.current_word=None
    def code(self,u,pc,n,d):
        self.flush()
        for name,lo,hi in SPECS:
            if pc==C.BASE+lo:
                assert self.current_word is None;self.current_word={'name':name,'entry':E.F.F.A.capture(self)}
            if pc==C.BASE+hi and self.current_word is not None and self.current_word['name']==name:
                self.current_word['end']=E.F.F.A.capture(self);self.word_components.append(self.current_word);self.current_word=None
        return super().code(u,pc,n,d)


def scalar(b,s):
    cpu=copy.deepcopy(b['entry']['CPU']);regs=list(map(lambda x:int(x,16),cpu['X31']));writes=[]
    def name(n):return {'fp':'x29','lr':'x30'}.get(n,n)
    def rr(i,o):
        n=name(i.reg_name(o.reg))if o.type==1 else None
        return regs[int(n[1:])]%2**(32 if n[0]=='w'else 64)if n else o.imm
    _,lo,hi=next(x for x in SPECS if x[0]==b['name'])
    for i in C.CS.disasm(s.read(lo,hi-lo),lo):
        m=i.mnemonic;o=i.operands;n=name(i.reg_name(o[0].reg));j=int(n[1:]);bits=32 if n[0]=='w'else 64;mask=2**bits-1
        if m=='str':writes.append((regs[int(name(i.reg_name(o[1].mem.base))[1:])]+o[1].mem.disp,regs[j].to_bytes(8,'little')));continue
        if m=='mov':v=rr(i,o[1])
        elif m=='movk':shift=o[1].shift.value;v=(regs[j]&~(65535<<shift))|(o[1].imm<<shift)
        elif m=='eor':v=rr(i,o[1])^rr(i,o[2])
        elif m=='add':v=rr(i,o[1])+rr(i,o[2])
        elif m=='mul':v=rr(i,o[1])*rr(i,o[2])
        else:assert m=='madd';v=rr(i,o[1])*rr(i,o[2])+rr(i,o[3])
        regs[j]=v&mask
    cpu['X31']=list(map(hex,regs));cpu['PC']=hex(C.BASE+hi)
    assert cpu==b['end']['CPU']and b['entry']['stack1312_hex']==b['end']['stack1312_hex']
    assert [(hex(at),raw.hex())for at,raw in writes]==[(w['address'],w['after_hex'])for w in b['writes']]


class Component:
    def __init__(self,b,s):
        self.b=b;self.kind=next(j for j,x in enumerate(SPECS)if x[0]==b['name']);_,self.lo,self.hi=SPECS[self.kind]
        self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set()
        def mapped(at,n):
            for page in range(at&~4095,(at+n+4095)&~4095,4096):
                if page not in pages:self.u.mem_map(page,4096);pages.add(page)
        self.source=s.read(self.lo,self.hi-self.lo);mapped(C.BASE+self.lo,len(self.source));self.u.mem_write(C.BASE+self.lo,self.source)
        cpu=b['entry']['CPU'];self.sp=int(cpu['SP'],16);self.stack=bytes.fromhex(b['entry']['stack1312_hex']);mapped(self.sp,len(self.stack));self.u.mem_write(self.sp,self.stack)
        self.destination=None
        if self.kind<2:
            self.destination=int(cpu['X31'][27 if self.kind==0 else 2],16);mapped(self.destination,8)
            self.before=bytes.fromhex(b['writes'][0]['before_hex'])
        C.restore(self.u,cpu);self.context=self.u.context_save()
        actual,stored=self.run();assert actual==b['end']['CPU']
        if self.kind<2:assert stored.hex()==b['writes'][0]['after_hex']
    def run(self,regs=None):
        self.u.context_restore(self.context)
        if self.destination is not None:self.u.mem_write(self.destination,self.before)
        for j,v in (regs or {}).items():self.u.reg_write(getattr(U,'UC_ARM64_REG_X'+str(j)),v)
        self.u.emu_start(C.BASE+self.lo,C.BASE+self.hi,count=(self.hi-self.lo)//4+1);assert self.u.reg_read(U.UC_ARM64_REG_PC)==C.BASE+self.hi
        assert bytes(self.u.mem_read(self.sp,len(self.stack)))==self.stack
        return C.frame(self.u),bytes(self.u.mem_read(self.destination,8))if self.destination is not None else None
    def audit(self):
        k=self.kind;entry=list(map(lambda x:int(x,16),self.b['entry']['CPU']['X31']));wordreg=28 if k==0 else 3;hashreg=19 if k<2 else 12;outreg=[19,3,12,12][k]
        word=entry[wordreg];hashed=entry[hashreg];digest=sha256();cases=0
        def check(x,h):
            nonlocal cases
            actual,stored=self.run({wordreg:x,hashreg:h});term=((x if k<2 else x^KEY)*MULT)%MOD
            assert int(actual['X31'][outreg],16)==h^term
            assert int(actual['X31'][[28,2,3,20][k]],16)==term
            if k<2:assert int.from_bytes(stored,'little')==x^KEY
            digest.update(json.dumps(actual,sort_keys=True).encode());digest.update(stored or b'');cases+=1
        for lane in range(8):
            for value in range(256):check(((value<<(8*lane))^0x9e3779b97f4a7c15)%MOD,hashed)
        for lane in range(8):
            for value in range(256):check(word,((value<<(8*lane))^0x6a09e667f3bcc909)%MOD)
        controls=[]
        if k!=1:
            reg=8 if k in [0,3]else 24;changed=entry[reg]^1;actual,stored=self.run({reg:changed});got=int(actual['X31'][outreg],16)
            common=hashed^(((word if k==0 else word^KEY)*MULT)%MOD)
            if k==0:
                assert int.from_bytes(stored,'little')==word^((changed+0xcccccccccccc4763)%MOD)and int.from_bytes(stored,'little')!=word^KEY
                assert got==common
            else:
                if k==2:
                    v=(((word^changed)+0x4497b37217f44c7d)%MOD)^(((word^0x38291b6a9d2f0c19)+0x65ac4ca89f71b17b)%MOD)^(((word^0xedf73316444931ca)+0xb07264d446178caa)%MOD);bias=0x5737958f518ee7d0
                else:
                    v=(((word^changed)+0x589e7b2fda2c2335)%MOD)^(((word^0xbd5ca898d06996d8)+0x6368ef188d202564)%MOD)^(((word^0xf73a58fb9bc0ca9b)+0x290e1f7bc6897921)%MOD);bias=0x7ff561c46e304a48
                assert got==hashed^((v*MULT+bias)%MOD)and got!=common
            controls.append({'control_register':'X'+str(reg),'retained_control_u64':hex(entry[reg]),'changed_control_u64':hex(changed),'loaded_word_u64':hex(word),'incoming_hash_u64':hex(hashed),
              'actual_hash_u64':hex(got),'common_candidate_hash_u64':hex(common),'actual_stored_word_u64':hex(int.from_bytes(stored,'little'))if stored else None,'common_contract_rejected':True})
        assert cases==4096 and bytes(self.u.mem_read(C.BASE+self.lo,len(self.source)))==self.source
        return {'name':self.b['name'],'cases':cases,'source_visits':cases*(self.hi-self.lo)//4,'ordered_frames_and_stores_sha256':digest.hexdigest(),'off_premise_controls':controls,'source_bytes_preserved':True}


def check_epochs(p,join):
    visits=p['visits'];raw={r['address']:r for r in p['reads']if visits[r['visit']]['pc']in ['0x1b48fc','0x1b4ef8']};ws={w['address']:w for w in p['writes']if visits[w['visit']]['pc']in ['0x1b4930','0x1b4f00']};rs={r['address']:r for r in p['reads']if visits[r['visit']]['pc']in ['0x1b5734','0x1b5d80']}
    assert len(raw)==len(ws)==len(rs)==len(join['epochs'])==p['configuration']['length_u32']//8
    for e in join['epochs']:
        at=e['address'];a,w,b=raw[at],ws[at],rs[at];assert a['visit']<w['visit']<b['visit']and a['bytes_hex']==w['before_hex']and w['after_hex']==b['bytes_hex']
        assert e['raw_read_visit']==a['visit']and e['store_visit']==w['visit']and e['encoded_read_visit']==b['visit']and e['size_B']==a['size_B']==w['size_B']==b['size_B']==8
        assert [e[k]for k in ['raw_read_PC','store_PC','encoded_read_PC']]==[visits[v['visit']]['pc']for v in [a,w,b]]
        assert int(e['raw_word_u64'],16)==int.from_bytes(bytes.fromhex(a['bytes_hex']),'little')and int(e['encoded_word_u64'],16)==int.from_bytes(bytes.fromhex(b['bytes_hex']),'little')
        assert int(e['raw_word_u64'],16)^int(e['encoded_word_u64'],16)==KEY
        assert e['no_intervening_overlapping_write']and not any(w['visit']<v['visit']<b['visit']and int(v['address'],16)<int(at,16)+8 and int(at,16)<int(v['address'],16)+v['size_B']for v in p['writes'])


def frozen(pins):
    wa=pins['corefp_workspace_audit.json'];pe=pins['corefp_output_packing_checks.json'];ce=pins['corefp_workspace_consumers_checks.json'];le=pins['corefp_late_preparation_checks.json'];se=pins['corefp_preparation_scans_checks.json'];ph=pins['corefp_phase_parameters_checks.json'];en=pins['corefp_scan_entry_checks.json']
    return en['source_checks']['proofs']+ph['source_checks']['proofs']+se['source_checks']['proofs']+[p for m in le['transfer_models']for p in m['proofs']]+[pe['common_inverse_proof']]+[p for m in pe['transfer_models']for p in m['proofs']]+ce['source_model']['proofs']+ce['canonical_phase_proofs']+wa['source_checks']['proofs']+[p for f in wa['frozen_source_checks']for p in f['proofs']]


def main():
    raw=read(ROOT/'corefp_word_codec_checks.json').encode();e=json.loads(raw);s=C.Pointers();assert e['generator_sha256']==SHA((ROOT/'recover_corefp_word_codec.py').read_bytes())and e['thin_sha256']==C.THIN_SHA
    pins={}
    for n,h in e['parent_pins'].items():
        rr=read(ROOT/n).encode();assert SHA(rr)==h;pins[n]=json.loads(rr)
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    for region,(name,lo,hi)in zip(e['source_regions'],SPECS):
        assert region['name']==name and region['start']==hex(lo)and region['end']==hex(hi)and region['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(s.read(lo,hi-lo),lo)]
    old=frozen(pins);assert len(old)==1144 and len(e['proofs'])==11
    for proof in old+e['proofs']:
        q=z3.Solver();q.set(timeout=30000);q.from_string(proof['query']);assert proof['result']=='unsat'and q.check()==z3.unsat,proof['label']
    print(json.dumps({'queries_unsat':len(old)+len(e['proofs'])}),flush=True)
    totals=Counter();oracles=[];offset=0;parent=pins['corefp_workspace_checks.json']
    for j,p in enumerate(parent['profiles']):
        totals.update(E.F.F.A.initial_checks(p,s));r=Replay(p,parent['source_spans'],s);totals.update(r.run());E.F.F.W.workspace_oracle(p,r,s,parent['workspace_constructions'][j]);E.F.F.W.preparation_oracle(p,r,s)
        assert r.current_word is None and len(r.word_components)==p['configuration']['length_u32']//4
        for actual in r.word_components:
            b=e['blocks'][offset];offset+=1;assert b['name']==actual['name']and b['label']==p['configuration']['label']and all(b[t]==actual[t]for t in ['entry','end'])
            lo,hi=b['entry']['source_visit'],b['end']['source_visit'];assert b['visits']==p['visits'][lo:hi]
            for k in ['reads','writes','PAC_models']:assert b[k]==[v for v in p[k]if lo<=v['visit']<hi]
            ep=next(x for x in e['joins'][j]['epochs']if x['raw_read_visit'if b['name'].startswith('first')else'encoded_read_visit']==lo-1)
            assert int(b['entry']['CPU']['X31'][28 if b['name']=='first_head'else 3],16)==int(ep['raw_word_u64'if b['name'].startswith('first')else'encoded_word_u64'],16)
            scalar(b,s);oracles.append({'label':b['label'],**Component(b,s).audit()})
        assert e['joins'][j]['label']==p['configuration']['label'];check_epochs(p,e['joins'][j]);print(json.dumps({'audited':p['configuration']['label']}),flush=True)
    assert offset==len(e['blocks'])==32 and dict(totals)==pins['corefp_scan_entry_audit.json']['result']['independent_replay']
    assert e['replay_totals']=={k:v for k,v in totals.items()if not k.startswith('initial_')}
    assert e['verified_counts']=={'profiles':6,'regions':32,'source_instructions':97,'source_B':388,'regional_visits':766,'regional_reads':0,'regional_writes':16,'regional_PAC_models':0,'stable_word_epochs':16,'new_queries_unsat':11,
      'region_counts':dict(Counter(b['name']for b in e['blocks']))}
    assert len(e['source_regions'])==4 and sum(len(v['instructions'])for v in e['source_regions'])==97
    assert sum(len(b['visits'])for b in e['blocks'])==766 and sum(len(b['writes'])for b in e['blocks'])==16 and not any(b['reads']or b['PAC_models']for b in e['blocks'])
    result={'verified_counts':e['verified_counts'],'independent_replay':dict(totals),'actual_full_frames':32,'independent_scalar_frames':32,'finite_component_cases':sum(o['cases']for o in oracles),
      'finite_source_visits':sum(o['source_visits']for o in oracles),'off_premise_controls':sum(len(o['off_premise_controls'])for o in oracles),'stable_word_epochs':16,
      'new_queries_unsat':11,'frozen_queries_unsat':1144,'total_queries_unsat':1155,'all_checks_pass':True,'native_target_executed':False}
    assert result['finite_component_cases']==131072 and result['finite_source_visits']==3137536 and result['off_premise_controls']==22
    out={'result':result,'checks_sha256':SHA(raw),'auditor_sha256':SHA(Path(__file__).read_bytes()),'generator_sha256':e['generator_sha256'],'parent_pins':e['parent_pins'],'dependencies':e['dependencies'],
      'component_oracles':oracles,'fresh_replay_completed':True,'process_exit_code':0,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,
      'earlier_arithmetic_passes_universally_reduced':False,'general_raw_preparation_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_word_codec_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
