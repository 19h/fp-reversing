; benchmark generated from python API
(set-info :status unknown)
(declare-fun readback_payload_pointer64 () (_ BitVec 64))
(assert
 (let (($x71 (= readback_payload_pointer64 (_ bv0 64))))
(let ((?x43 (ite (or $x71 (= readback_payload_pointer64 (_ bv1375731728 64))) (_ bv1 32) (_ bv0 32))))
(let (($x19 (not (= (_ bv0 64) readback_payload_pointer64))))
(let ((?x72 ((_ zero_extend 32) (ite (ite $x19 (= (_ bv1375731728 64) readback_payload_pointer64) true) (_ bv1 32) (_ bv0 32)))))
(and (distinct ((_ extract 31 0) ?x72) ?x43) true))))))
(check-sat)
