; benchmark generated from python API
(set-info :status unknown)
(declare-fun sync_pointer64 () (_ BitVec 64))
(assert
 (let (($x147 (and (distinct sync_pointer64 sync_pointer64) true)))
(or (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv22845 32))) (_ bv22845 32)) true) $x147)))
(check-sat)
