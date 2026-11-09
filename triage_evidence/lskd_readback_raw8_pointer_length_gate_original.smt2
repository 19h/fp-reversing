; benchmark generated from python API
(set-info :status unknown)
(declare-fun readback_length16 () (_ BitVec 16))
(declare-fun readback_payload_pointer64 () (_ BitVec 64))
(assert
 (let (($x36 (= readback_length16 (_ bv8 16))))
(let (($x11 (and (distinct readback_payload_pointer64 (_ bv0 64)) true)))
(let (($x19 (not (= (_ bv0 64) readback_payload_pointer64))))
(let (($x25 (ite $x19 (= (_ bv8 32) ((_ extract 31 0) ((_ zero_extend 32) (concat (_ bv0 16) readback_length16)))) false)))
(and (distinct ((_ extract 31 0) ((_ zero_extend 32) (ite $x25 (_ bv1 32) (_ bv0 32)))) (ite (and $x11 $x36) (_ bv1 32) (_ bv0 32))) true))))))
(check-sat)
