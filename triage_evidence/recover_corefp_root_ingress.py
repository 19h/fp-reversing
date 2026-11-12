#!/usr/bin/env python3
"""Original ingress record producer, adapter/root chain and caller census.

Private original-byte executions only. Frozen API/PAC/once/lock models remain
explicit. No native target/API/IPC or IDB mutation. Conservative
O(C*(B+P*F+V*J+R)) time/space upper bound; 30000 client visits per profile.
"""
import bisect,json,struct
from pathlib import Path
from hashlib import sha256
import audit_corefp_lookup_release
from unicorn import arm64_const as A
from recover_corefp_lookup_release import Run as Frozen,configurations as previous_configurations,parent_inputs,DEPS as PREVIOUS_DEPS
from recover_corefp_lookup_initialization import frame,pack,ROOT,BASE,REC,DONE,inputs
from corefp_fixups_reader import Pointers,THIN_SHA
from daemon_receive_tools import SOURCE,CS
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M32=(1<<32)-1;M64=(1<<64)-1
ENTRY=0x5f4584;INGRESS=0x63000800;DATA=0x63000900;AUX=0x63000c00;SEED_CELL=0x1d435b0
DEPS=PREVIOUS_DEPS+['recover_corefp_lookup_release.py']


def configurations():
    base=previous_configurations()[0]
    rows=[{**c,'kind':'complete_ingress','scalar_u32':'0x0','stack_delta_B':0}for c in previous_configurations()]
    rows += [{**base,'label':label,'kind':'complete_ingress','scalar_u32':hex(v),'stack_delta_B':d}for label,v,d in
      [('scalar_one',1,0),('scalar_max',M32,0),('scalar_a5',0xa5a5a5a5,0),('stack_plus16',0,16),('stack_minus16',0,-16)]]
    rows.append({**base,'label':'other_adapter_prefix','kind':'other_adapter_prefix','scalar_u32':'0x0','stack_delta_B':0,'bootstrap_results':[]})
    return rows


def ingress_inputs(c):
    key=((INGRESS^0xd914ae5d)*0x08c5d407)&M32
    mode_preimage=(-0x30f52b5f*pow(0x59529999,-1,1<<32))&M32
    b=bytearray(b'\xa5'*48);struct.pack_into('<I',b,0,(0xc1f7-key-0x513c5990)&M32)
    struct.pack_into('<Q',b,8,AUX);struct.pack_into('<I',b,16,(mode_preimage+key)&M32)
    struct.pack_into('<I',b,20,(int(c['scalar_u32'],16)-key)&M32);struct.pack_into('<Q',b,24,DATA)
    return [(INGRESS,bytes(b))]


def literal_candidates(s,diversity):
    text=next(v for v in s.meta['sections']if v['section']=='__text');lo=text['address'];raw=s.read(lo,text['size'])
    pattern=struct.pack('<I',0xd2800000|(diversity<<5)|17);rows=[]
    for off in range(0,len(raw)-4,4):
        if raw[off:off+4]!=pattern:continue
        at=lo+off;i=next(CS.disasm(raw[off+4:off+8],at+4))
        if i.mnemonic not in ['braa','blraa']:continue
        ix=bisect.bisect_right(s.starts,at)-1
        rows.append({'modifier_site':hex(at),'callsite':hex(at+4),'bytes_hex':raw[off:off+8].hex(),
          'function_start':hex(s.starts[ix]),'function_end':hex(s.starts[ix+1])})
    return {'scope':'Aligned literal MOV X17,#diversity immediately followed by BRAA/BLRAA in complete original __text; other constructions excluded.',
      'diversity':hex(diversity),'text_address':hex(lo),'text_size_B':len(raw),'text_sha256':SHA(raw),'candidates':rows}


def bank_contracts(s):
    out=[]
    for name,ap,ad,bp,bd,xor,offset in [('candidate_9d4064',0x1d10b08,-8,0x1d09870,0,0xa5,0x1061e),
      ('candidate_1174224',0x1d09500,0,0x1d0b590,-12,0x27,0x1069b)]:
        a=s.qword(ap)+ad;b=s.qword(bp)+bd;av=s.read(a,256);bv=s.read(b,256);selected=[x^bv[av[x]^xor]for x in range(256)];assert len(set(selected))==1
        index=offset+selected[0];slot=0x1c81940+index*8
        out.append({'label':name,'assumptions':'Original cached A/B roots and dispatch base; conditional local target theorem, not whole-function reachability.',
          'A_pointer_row':s.decoded[ap],'A_adjust_B':ad,'A_address':hex(a),'A_bytes_hex':av.hex(),
          'B_pointer_row':s.decoded[bp],'B_adjust_B':bd,'B_address':hex(b),'B_bytes_hex':bv.hex(),
          'xor_u8':hex(xor),'index_bias':hex(offset),'dispatch_base':'0x1c81940','selected_low8':selected,
          'index_u32':hex(index),'target_row':s.decoded[slot]})
    return out


class Run(Frozen):
    def __init__(self,s,c):
        super().__init__(s,c)
        for a,b in ingress_inputs(c):self.u.mem_write(a,b)
        entry=ENTRY if c['kind']=='complete_ingress'else 0x77d190
        self.u.reg_write(A.UC_ARM64_REG_PC,BASE+entry);self.u.reg_write(A.UC_ARM64_REG_SP,self.reg('sp')+c['stack_delta_B'])
        self.initial=frame(self.u);self.pages[REC&~4095]=bytes(self.u.mem_read(REC&~4095,4096))
        self.root_record=None;self.outer_word=None;self.inner_word=None;self.ingress_points=[];self.parent_return=None
    def ingress_point(self,label):
        u=self.u
        return {'label':label,'CPU':frame(u),'ingress_record48_hex':bytes(u.mem_read(INGRESS,48)).hex(),
          'root_record_address':None if self.root_record is None else hex(self.root_record),
          'root_record40_hex':None if self.root_record is None else bytes(u.mem_read(self.root_record,40)).hex(),
          'adapter_word_address':None if self.outer_word is None else hex(self.outer_word),
          'adapter_word_u64':None if self.outer_word is None else hex(int.from_bytes(u.mem_read(self.outer_word,8),'little')),
          'internal_word_address':None if self.inner_word is None else hex(self.inner_word),
          'internal_word_u64':None if self.inner_word is None else hex(int.from_bytes(u.mem_read(self.inner_word,8),'little')),'visits_so_far':len(self.visits)}
    def code(self,u,pc,n,d):
        self.flush();at=pc-BASE
        if at==0x5f48c0:
            self.root_record=self.reg('x0');self.outer_word=self.reg('x1');self.ingress_points.append(self.ingress_point('before_adapter_call'))
        if at==0x8fd1b8:self.inner_word=self.reg('x1');self.ingress_points.append(self.ingress_point('before_root_call'))
        if at in [0x8e81c8,0x8fd1bc,0x5f48c4,0x5f48d8]:
            self.ingress_points.append(self.ingress_point({0x8e81c8:'root_entry',0x8fd1bc:'root_return',0x5f48c4:'adapter_return',0x5f48d8:'before_ingress_result_store'}[at]))
        if self.c['kind']=='other_adapter_prefix'and at==0x77d398:self.ingress_points.append(self.ingress_point('before_other_callee_call'))
        if self.c['kind']=='other_adapter_prefix'and at==0x779ff0:
            self.ingress_points.append(self.ingress_point('before_other_callee_body'));self.frontier={'reason':'before_other_callee_body','CPU':frame(u)};u.emu_stop();return
        if pc==DONE:self.ingress_points.append(self.ingress_point('outer_return'))
        return super().code(u,pc,n,d)
    def run(self):
        entry=ENTRY if self.c['kind']=='complete_ingress'else 0x77d190
        self.u.emu_start(BASE+entry,0,count=30001);self.flush();assert hasattr(self,'frontier')and not self.once
        assert self.boots==len(self.c['bootstrap_results'])
        return {'configuration':self.c,'initial_CPU':self.initial,'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.visits,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,'frontier':self.frontier,
          'final_state':self.snapshot('frontier'),'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'allocations_attempted':self.allocs,'metadata_returns':self.metadata_returns,'daemon_children':self.children,'bootstrap_calls':self.boots,
          'handoffs':self.handoffs,'lock_events':self.lock_events,'certificate_allocation_attempts':self.certificate_attempts,
          'parent_return':self.parent_return,'ingress_points':self.ingress_points}


def main():
    s=Pointers();rows=[];spans={}
    for c in configurations():
        run=Run(s,c);rows.append(run.run());spans.update(run.functions)
    for a in [0x9d34d4,0x1173af0]:spans.setdefault(a,s.function(a))
    counts={'profiles':len(rows),'complete_ingress_returns':12,'other_adapter_prefixes':1,
      **{k:sum(len(p[k])for p in rows)for k in ['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children','handoffs','lock_events','ingress_points']},
      'bootstrap_calls':sum(p['bootstrap_calls']for p in rows),'certificate_allocation_attempts':sum(p['certificate_allocation_attempts']for p in rows)}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,'daemon_thin_sha256':SHA(SOURCE.read_bytes()),
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'source_spans':list(spans.values()),
      'declared_base_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()+parent_inputs()],
      'profile_ingress_inputs':[[{'address':hex(a),'bytes_hex':b.hex()}for a,b in ingress_inputs(c)]for c in configurations()],
      'adapter_literal_census':literal_candidates(s,0x281b),'conditional_bank_contracts':bank_contracts(s),
      'adapter_reference_rows':[r for r in s.decoded.values()if not r['bind']and r['target']=='0x8fcfa0'],
      'ingress_reference_rows':[r for r in s.decoded.values()if not r['bind']and r['target']=='0x5f4584'],
      'profiles':rows,'verified_counts':counts,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'corefp_root_ingress_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
