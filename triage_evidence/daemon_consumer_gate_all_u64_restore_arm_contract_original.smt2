; benchmark generated from python API
(set-info :status unknown)
(declare-fun gate_phase64 () (_ BitVec 64))
(declare-fun gate_saved_continuation64 () (_ BitVec 64))
(assert
 (or (and (distinct ((_ extract 31 0) (_ bv23958 64)) (_ bv23958 32)) true) (and (distinct ((_ extract 31 0) (_ bv1958911365 64)) (_ bv1958911365 32)) true) (and (distinct gate_saved_continuation64 gate_saved_continuation64) true) (and (distinct gate_phase64 gate_phase64) true) (and (distinct (_ bv20684 64) (_ bv20684 64)) true)))
(check-sat)
