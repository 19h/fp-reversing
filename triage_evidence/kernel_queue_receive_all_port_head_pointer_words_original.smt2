; benchmark generated from python API
(set-info :status unknown)
(declare-fun qr_waitq64 () (_ BitVec 64))
(declare-fun qr_message_pointer64 () (_ BitVec 64))
(assert
 (let (($x45 (and (distinct qr_message_pointer64 qr_message_pointer64) true)))
(or $x45 (and (distinct (bvadd (_ bv18446744073709551600 64) qr_waitq64) (bvsub qr_waitq64 (_ bv16 64))) true))))
(check-sat)
