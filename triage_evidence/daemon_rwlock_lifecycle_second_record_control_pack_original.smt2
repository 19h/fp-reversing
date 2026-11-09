; benchmark generated from python API
(set-info :status unknown)
(declare-fun rw_key32 () (_ BitVec 32))
(assert
 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (bvadd (_ bv44759 32) (bvmul (_ bv2794216839 32) rw_key32)))) (bvsub (_ bv44759 32) (bvmul rw_key32 (_ bv1500750457 32)))) true))
(check-sat)
