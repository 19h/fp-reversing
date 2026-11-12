#!/usr/bin/env python3
"""Original selector-gated reset with private slot fixtures and bounded imports.

No native target/API/IPC or IDB operation. Sequential CASAL, PAC and backed
private allocation retirement are declared models. Stop before any unbacked
free and before a second failed-token attempt. O(C*(B+P*F+V*J+R)) conservative
time/space, 4000 source visits/profile; C cases, B source bytes, P pages,
F fixups, V visits, J journals, R retained state.
"""
import json
from pathlib import Path
from hashlib import sha256
import corefp_library_reader as L
L.SOURCE=Path(__file__).resolve().parent.parent/'CoreFP'
from unicorn import arm64_const as A
from recover_corefp_lookup_initialization import Run as Frozen,frame,pack,inputs,BASE,BIND,REC,HEAP,DONE,ROOT
from corefp_fixups_reader import Pointers,THIN_SHA
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest()
ENTRY=0x1f530c;TOKEN=0x1d33108;SELECTOR=0x1d44409;COUNT=0x1d36090;SLOTS=0x1d32dd0
POINTS={0x1f5594:'selector_read',0x1f55a4:'selector_compare',0x1f57c4:'slot_pointer_read',0x1f5688:'common_reset',0x1f5650:'selector_clear',0x1f5664:'token_restore'}
DEPS=['recover_corefp_lookup_initialization.py','recover_fpsd1201_predicates.py','corefp_library_reader.py','corefp_fixups_reader.py','corefp_fixups_inventory.json','probe_corefp_exports.py','daemon_receive_tools.py']


def configurations():
    return [
      {'label':'original_selector_zero'},
      {'label':'selector_two','selector_u8':2},
      {'label':'selector_255','selector_u8':255},
      {'label':'empty','selector_u8':1,'count_u32':0,'slot_kinds':[]},
      {'label':'one_null','selector_u8':1,'count_u32':1,'slot_kinds':['null']},
      {'label':'three_null','selector_u8':1,'count_u32':3,'slot_kinds':['null']*3},
      {'label':'one_backed','selector_u8':1,'count_u32':1,'slot_kinds':['backed']},
      {'label':'backed_clobber','selector_u8':1,'count_u32':1,'slot_kinds':['backed'],'clobber_callers':True,'void_free_x0':0xfeedfacecafebeef},
      {'label':'mixed_three','selector_u8':1,'count_u32':3,'slot_kinds':['null','backed','backed']},
      {'label':'original_slot_free_frontier','selector_u8':1},
      {'label':'busy_token','token_u32':0xa94ef}]


def overlay(c):
    key=(((REC&0xffffffff)^0x341dc0b1)*0xdb676c6f)&0xffffffff
    rows=[(REC,(0xf7a5^key).to_bytes(4,'little'))]
    for name,a,n in [('selector_u8',SELECTOR,1),('count_u32',COUNT,4),('token_u32',TOKEN,4)]:
        if name in c:rows.append((BASE+a,c[name].to_bytes(n,'little')))
    for j,kind in enumerate(c.get('slot_kinds',[])):
        slot=bytearray(bytes([0x31+j])*88);pointer=HEAP+0x100+j*0x80 if kind=='backed'else 0
        slot[8:16]=pointer.to_bytes(8,'little');rows.append((BASE+SLOTS+j*88,bytes(slot)))
        if pointer:rows.append((pointer,bytes([0x53+j])*64))
    return rows


class Run(Frozen):
    def __init__(self,s,c):
        super().__init__(s,c)
        for a,b in overlay(c):self.touch(a,len(b));self.u.mem_write(a,b)
        for a,n in [(BASE+SLOTS,264),(BASE+TOKEN,4),(BASE+SELECTOR,1),(BASE+COUNT,4)]:self.touch(a,n)
        for a in self.pages:self.pages[a]=bytes(self.u.mem_read(a,4096))
        self.u.reg_write(A.UC_ARM64_REG_PC,BASE+ENTRY);self.initial=frame(self.u)
        self.functions={ENTRY:s.function(ENTRY)};self.casal_attempts=0;self.frees=[];self.active={HEAP+0x100+j*0x80 for j,k in enumerate(c.get('slot_kinds',[]))if k=='backed'}
    def snapshot(self,label):
        return {'label':label,'CPU':frame(self.u),'record32_hex':bytes(self.u.mem_read(REC,32)).hex(),
          'selector_u8':self.u.mem_read(BASE+SELECTOR,1)[0],'token_u32':int.from_bytes(self.u.mem_read(BASE+TOKEN,4),'little'),
          'count_u32':int.from_bytes(self.u.mem_read(BASE+COUNT,4),'little'),'slots264_hex':bytes(self.u.mem_read(BASE+SLOTS,264)).hex()}
    def stop(self,reason,**extra):
        self.frontier={'reason':reason,'CPU':frame(self.u),**extra};self.u.emu_stop()
    def code(self,u,pc,n,d):
        self.flush()
        if pc==DONE:return self.stop('ordinary_return')
        if pc==BASE+0x1f54fc:
            if self.casal_attempts:return self.stop('before_second_CASAL',concurrent_ordering_validated=False)
            raw=bytes(u.mem_read(pc,4));assert raw.hex()=='4efff188'
            self.visits.append({'pc':'0x1f54fc','bytes_hex':raw.hex(),'instruction':'casal w17, w14, [x26]'})
            a=self.reg('x26');old=int.from_bytes(u.mem_read(a,4),'little');compare=self.reg('w17');replacement=self.reg('w14')
            assert a==BASE+TOKEN and compare==0x5d96 and replacement==0xa94ef
            self.casal_attempts+=1;e={'kind':'declared_sequential_CASAL','visit':len(self.visits)-1,'before':frame(u),'pointer':hex(a),
              'old_u32':old,'compare_u32':compare,'replacement_u32':replacement,'memory':[],'concurrent_ordering_validated':False};self.models.append(e)
            if old==compare:
                self.touch(a,4);b=replacement.to_bytes(4,'little');e['memory']=[{'address':hex(a),'before_hex':bytes(u.mem_read(a,4)).hex(),'after_hex':b.hex()}];u.mem_write(a,b)
            u.reg_write(A.UC_ARM64_REG_W17,old);u.reg_write(A.UC_ARM64_REG_PC,pc+4);e['after']=frame(u);return
        if pc in self.imports:
            name=self.imports[pc];assert name=='_free'and self.reg('lr')-4-BASE==0x1f5854
            pointer=self.reg('x0')
            if pointer not in self.active:return self.stop('before_unbacked_free',name=name,callsite='0x1f5854',pointer=hex(pointer),native_free_executed=False)
            e={'kind':'declared_API','name':name,'before':frame(u),'args_x0_x7':[hex(self.reg('x'+str(j)))for j in range(8)],'callsite':'0x1f5854','memory':[],
              'private_backing64_hex':bytes(u.mem_read(pointer,64)).hex(),'model':'mark private allocation inactive; retain mapped bytes; no native free','void_result_fixture':hex(self.c.get('void_free_x0',0))}
            self.models.append(e);self.active.remove(pointer);self.frees.append(hex(pointer));self.returned(self.c.get('void_free_x0',0));e['after']=frame(u);return
        if pc-BASE in POINTS:self.points.append(self.snapshot(POINTS[pc-BASE]))
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=4001);self.flush();assert hasattr(self,'frontier')and self.casal_attempts==1
        return {'configuration':self.c,'declared_overlay':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in overlay(self.c)],'initial_CPU':self.initial,
          'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.visits,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,'frontier':self.frontier,
          'final_state':self.snapshot('frontier'),'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'private_free_pointers':self.frees,'private_active_pointers':list(map(hex,sorted(self.active)))}


def main():
    s=Pointers();runs=[Run(s,c)for c in configurations()];profiles=[p.run()for p in runs]
    counts={'profiles':len(profiles),**{k:sum(len(p[k])for p in profiles)for k in ['visits','reads','writes','PAC_models','models','points','private_free_pointers']}}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'source_spans':list(runs[0].functions.values()),
      'base_declared_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()], 'profiles':profiles,'verified_counts':counts,
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'full_goal_complete':False,'source_PC_gap':False,
      'live_IDA_status':'unknown: authenticated bridge unavailable in this investigation; no live evidence returned'}
    assert all(p.functions==runs[0].functions for p in runs)
    (ROOT/'corefp_optional_reset_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
