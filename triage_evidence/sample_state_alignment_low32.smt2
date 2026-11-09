; benchmark generated from python API
(set-info :status unknown)
(declare-fun destination64 () (_ BitVec 64))
(assert
 (let ((?x11 (bvand (bvneg destination64) (_ bv7 64))))
(and (distinct (bvand ((_ zero_extend 32) (bvneg ((_ extract 31 0) destination64))) (_ bv7 64)) ?x11) true)))
(check-sat)
