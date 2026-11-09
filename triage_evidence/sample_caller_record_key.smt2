; benchmark generated from python API
(set-info :status unknown)
(declare-fun record64 () (_ BitVec 64))
(assert
 (let ((?x22 (bvmul (bvxor ((_ extract 31 0) record64) (_ bv2533989312 32)) (_ bv4015325029 32))))
(let ((?x14 (bvxor (bvsub (bvor record64 (_ bv17296737207265256260 64)) (bvand record64 (_ bv17296737207265256260 64))) (_ bv18403133184148142212 64))))
(let ((?x16 (bvmul ?x14 (_ bv4015325029 64))))
(let ((?x17 ((_ extract 31 0) ?x16)))
(and (distinct ?x17 ?x22) true))))))
(check-sat)
