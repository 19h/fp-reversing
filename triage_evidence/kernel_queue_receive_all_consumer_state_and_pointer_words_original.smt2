; benchmark generated from python API
(set-info :status unknown)
(declare-fun qr_message_pointer64 () (_ BitVec 64))
(declare-fun qr_receiver_status32 () (_ BitVec 32))
(declare-fun qr_consumer_options64 () (_ BitVec 64))
(assert
 (let (($x45 (and (distinct qr_message_pointer64 qr_message_pointer64) true)))
(let (($x77 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) qr_receiver_status32)) qr_receiver_status32) true)))
(or $x77 (and (distinct qr_consumer_options64 qr_consumer_options64) true) $x45 $x77 $x45))))
(check-sat)
