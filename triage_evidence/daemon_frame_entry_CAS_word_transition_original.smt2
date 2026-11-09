; benchmark generated from python API
(set-info :status unknown)
(declare-fun gate_state32 () (_ BitVec 32))
(assert
 (let (($x66 (= gate_state32 (_ bv23958 32))))
(let ((?x43 (ite $x66 (_ bv693487 32) gate_state32)))
(let ((?x123 (ite (= gate_state32 ((_ extract 31 0) ((_ zero_extend 32) (_ bv23958 32)))) ((_ extract 31 0) (_ bv693487 64)) gate_state32)))
(and (distinct ?x123 ?x43) true)))))
(check-sat)
