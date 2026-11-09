; benchmark generated from python API
(set-info :status unknown)
(declare-fun qr_receiver_status32 () (_ BitVec 32))
(declare-fun qr_message_pointer64 () (_ BitVec 64))
(assert
 (let (($x591 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) qr_receiver_status32)) qr_receiver_status32) true)))
(let (($x45 (and (distinct qr_message_pointer64 qr_message_pointer64) true)))
(or $x45 $x591))))
(check-sat)
