; benchmark generated from python API
(set-info :status unknown)
(declare-fun ready_byte8 () (_ BitVec 8))
(assert
 (and (distinct (and (distinct (bvand ((_ zero_extend 24) ready_byte8) (_ bv1 32)) (_ bv0 32)) true) (= (bvurem ready_byte8 (_ bv2 8)) (_ bv1 8))) true))
(check-sat)
