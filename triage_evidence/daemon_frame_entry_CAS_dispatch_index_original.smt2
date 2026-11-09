; benchmark generated from python API
(set-info :status unknown)
(declare-fun gate_state32 () (_ BitVec 32))
(assert
 (let (($x66 (= gate_state32 (_ bv23958 32))))
(let ((?x70 (ite $x66 (_ bv34598 32) (_ bv34592 32))))
(let ((?x167 (ite $x66 (_ bv1 1) (_ bv0 1))))
(let ((?x170 (ite $x66 (_ bv1 3) (_ bv0 3))))
(let ((?x173 (concat (_ bv1081 27) ?x170 ?x167 (_ bv0 1))))
(and (distinct ((_ extract 31 0) ((_ zero_extend 32) ?x173)) ?x70) true)))))))
(check-sat)
