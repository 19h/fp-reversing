; benchmark generated from python API
(set-info :status unknown)
(declare-fun destruct_counter64 () (_ BitVec 64))
(assert
 (let (($x22 (and (distinct ((_ extract 31 0) (_ bv18204 64)) (_ bv18204 32)) true)))
(and true (or $x22 (and (distinct destruct_counter64 destruct_counter64) true)))))
(check-sat)
