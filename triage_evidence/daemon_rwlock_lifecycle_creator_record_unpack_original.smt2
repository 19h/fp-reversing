; benchmark generated from python API
(set-info :status unknown)
(declare-fun rw_cell_address64 () (_ BitVec 64))
(assert
 (let (($x41 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv44759 32))) (_ bv44759 32)) true)))
(or $x41 (and (distinct rw_cell_address64 rw_cell_address64) true))))
(check-sat)
