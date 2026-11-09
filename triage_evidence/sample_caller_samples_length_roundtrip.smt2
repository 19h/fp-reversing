; benchmark generated from python API
(set-info :status unknown)
(declare-fun samples_length64 () (_ BitVec 64))
(declare-fun record64 () (_ BitVec 64))
(assert
 (let ((?x14 (bvxor (bvsub (bvor record64 (_ bv17296737207265256260 64)) (bvand record64 (_ bv17296737207265256260 64))) (_ bv18403133184148142212 64))))
(let ((?x16 (bvmul ?x14 (_ bv4015325029 64))))
(let ((?x170 (bvsub (bvsub samples_length64 ?x16) (_ bv17056954994772615508 64))))
(and (distinct (bvadd (bvadd ?x170 ?x16) (_ bv17056954994772615508 64)) samples_length64) true)))))
(check-sat)
