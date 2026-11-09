; benchmark generated from python API
(set-info :status unknown)
(declare-fun qr_sequence32 () (_ BitVec 32))
(assert
 (let (($x610 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv1 32) qr_sequence32))) (bvadd qr_sequence32 (_ bv1 32))) true)))
(or $x610 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) qr_sequence32)) qr_sequence32) true))))
(check-sat)
