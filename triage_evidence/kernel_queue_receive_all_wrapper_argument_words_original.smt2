; benchmark generated from python API
(set-info :status unknown)
(declare-fun qr_waitq64 () (_ BitVec 64))
(declare-fun qr_timeout64 () (_ BitVec 64))
(declare-fun qr_interrupt64 () (_ BitVec 64))
(declare-fun qr_thread64 () (_ BitVec 64))
(declare-fun qr_continuation64 () (_ BitVec 64))
(assert
 (let (($x19 (and (distinct qr_waitq64 qr_waitq64) true)))
(let (($x18 (and (distinct qr_timeout64 qr_timeout64) true)))
(let (($x17 (and (distinct qr_interrupt64 qr_interrupt64) true)))
(let (($x16 (and (distinct qr_thread64 qr_thread64) true)))
(or (and (distinct qr_continuation64 qr_continuation64) true) $x16 $x17 $x18 $x19))))))
(check-sat)
