; benchmark generated from python API
(set-info :status unknown)
(declare-fun qr_receive_counter64 () (_ BitVec 64))
(assert
 (let ((?x663 (bvadd qr_receive_counter64 (_ bv1 64))))
(or (and (distinct ?x663 ?x663) true) (and (distinct qr_receive_counter64 qr_receive_counter64) true))))
(check-sat)
