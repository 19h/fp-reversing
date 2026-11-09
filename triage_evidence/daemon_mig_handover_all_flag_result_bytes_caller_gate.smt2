; benchmark generated from python API
(set-info :status unknown)
(declare-fun handover_return_byte8 () (_ BitVec 8))
(declare-fun handover_return_flag8 () (_ BitVec 8))
(declare-fun handover_gate_phase32 () (_ BitVec 32))
(assert
 (let (($x425 (or (= handover_return_flag8 (_ bv0 8)) (= handover_return_byte8 (_ bv91 8)))))
(let ((?x426 (bvxor handover_gate_phase32 (ite $x425 (_ bv18 32) (_ bv0 32)))))
(let ((?x398 ((_ extract 0 0) handover_gate_phase32)))
(let ((?x404 (bvxor ((_ extract 3 1) handover_gate_phase32) (ite $x425 (_ bv1 3) (_ bv0 3)))))
(let ((?x394 (bvxor ((_ extract 31 4) handover_gate_phase32) (ite $x425 (_ bv1 28) (_ bv0 28)))))
(not (= (concat ?x394 ?x404 ?x398) ?x426))))))))
(check-sat)
