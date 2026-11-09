; benchmark generated from python API
(set-info :status unknown)
(declare-fun record64 () (_ BitVec 64))
(assert
 (let ((?x210 (bvxor record64 (_ bv1112190068825103296 64))))
(let ((?x14 (bvxor (bvsub (bvor record64 (_ bv17296737207265256260 64)) (bvand record64 (_ bv17296737207265256260 64))) (_ bv18403133184148142212 64))))
(and (distinct ?x14 ?x210) true))))
(check-sat)
