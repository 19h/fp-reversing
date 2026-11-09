; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_mba64 () (_ BitVec 64))
(assert
 (let ((?x1649 (bvadd (bvsub (bvand (bvshl init_mba64 (_ bv1 64)) (_ bv9022571006053868230 64)) init_mba64) (_ bv4712086533827841692 64))))
(and true (and (distinct ?x1649 (bvsub (_ bv9223372036854775807 64) (bvxor init_mba64 (_ bv4511285503026934115 64)))) true))))
(check-sat)
