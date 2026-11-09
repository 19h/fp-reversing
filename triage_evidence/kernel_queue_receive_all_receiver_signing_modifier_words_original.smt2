; benchmark generated from python API
(set-info :status unknown)
(declare-fun qr_receiver_pointer64 () (_ BitVec 64))
(assert
 (let ((?x647 ((_ extract 47 0) qr_receiver_pointer64)))
(let ((?x650 (bvadd (_ bv952 48) ?x647)))
(let ((?x667 (concat (_ bv13311 16) ?x650)))
(and (distinct ?x667 (bvor (bvand (bvadd qr_receiver_pointer64 (_ bv952 64)) (_ bv281474976710655 64)) (_ bv3746713414995542016 64))) true)))))
(check-sat)
