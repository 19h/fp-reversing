; benchmark generated from python API
(set-info :status unknown)
(declare-fun qr_waitq_bits32 () (_ BitVec 32))
(assert
 (let (($x41 (= (bvsub ((_ extract 31 0) (concat (_ bv0 61) ((_ extract 2 0) qr_waitq_bits32))) (_ bv3 32)) (_ bv0 32))))
(let ((?x27 (bvand qr_waitq_bits32 (_ bv7 32))))
(let ((?x31 ((_ extract 31 0) (concat (_ bv0 61) ((_ extract 2 0) qr_waitq_bits32)))))
(or (and (distinct ?x31 ?x27) true) (and (distinct $x41 (= ?x27 (_ bv3 32))) true))))))
(check-sat)
