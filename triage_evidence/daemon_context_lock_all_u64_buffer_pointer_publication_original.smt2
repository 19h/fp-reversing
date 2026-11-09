; benchmark generated from python API
(set-info :status unknown)
(declare-fun ctxlock_pointer64 () (_ BitVec 64))
(assert
 (and true (and (distinct ctxlock_pointer64 ctxlock_pointer64) true)))
(check-sat)
