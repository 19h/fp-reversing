; benchmark generated from python API
(set-info :status unknown)
(declare-fun gate_runtime_flag32 () (_ BitVec 32))
(declare-fun gate_readiness_byte8 () (_ BitVec 8))
(assert
 (let (($x53 (= gate_readiness_byte8 (_ bv1 8))))
(let ((?x76 (ite (or (not $x53) (= gate_runtime_flag32 (_ bv0 32))) (_ bv0 1) (_ bv1 1))))
(let (($x318 (= (concat (_ bv1297 27) ?x76 (_ bv0 2) ?x76 (_ bv0 1)) (ite (and $x53 (not (= gate_runtime_flag32 (_ bv0 32)))) (_ bv41522 32) (_ bv41504 32)))))
(not $x318)))))
(check-sat)
