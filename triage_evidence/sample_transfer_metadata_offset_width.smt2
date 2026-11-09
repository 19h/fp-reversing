; benchmark generated from python API
(set-info :status unknown)
(declare-fun index32 () (_ BitVec 32))
(assert
 (and (distinct (bvshl ((_ zero_extend 32) index32) (_ bv2 64)) (bvmul ((_ zero_extend 32) index32) (_ bv4 64))) true))
(check-sat)
