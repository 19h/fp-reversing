; benchmark generated from python API
(set-info :status unknown)
(declare-fun sync_pointer64 () (_ BitVec 64))
(assert
 (let (($x147 (and (distinct sync_pointer64 sync_pointer64) true)))
(or $x147 (and (distinct (_ bv19533 64) (_ bv19533 64)) true))))
(check-sat)
