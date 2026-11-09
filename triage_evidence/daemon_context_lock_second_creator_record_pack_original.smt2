; benchmark generated from python API
(set-info :status unknown)
(declare-fun ctxlock_key32 () (_ BitVec 32))
(declare-fun ctxlock_global64 () (_ BitVec 64))
(assert
 (let (($x83 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv44759 32) (bvmul (_ bv2794216839 32) ctxlock_key32)))) (bvsub (_ bv44759 32) (bvmul ctxlock_key32 (_ bv1500750457 32)))) true)))
(and true (or (and (distinct ctxlock_global64 ctxlock_global64) true) $x83))))
(check-sat)
