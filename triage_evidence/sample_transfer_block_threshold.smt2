; benchmark generated from python API
(set-info :status unknown)
(declare-fun size32 () (_ BitVec 32))
(assert
 (and (distinct (bvugt size32 (_ bv15 32)) (bvuge (bvand ((_ zero_extend 32) size32) (_ bv4294967280 64)) (_ bv16 64))) true))
(check-sat)
