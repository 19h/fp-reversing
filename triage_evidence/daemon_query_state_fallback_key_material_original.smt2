; benchmark generated from python API
(set-info :status unknown)
(declare-fun fallback_prekey32 () (_ BitVec 32))
(assert
 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (bvmul (_ bv3354844327 32) fallback_prekey32))) (bvmul fallback_prekey32 (_ bv3354844327 32))) true))
(check-sat)
