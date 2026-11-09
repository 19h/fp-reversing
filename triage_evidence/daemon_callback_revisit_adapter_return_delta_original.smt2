; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_state64 () (_ BitVec 64))
(declare-fun callback_temp64 () (_ BitVec 64))
(assert
 (let ((?x74 ((_ zero_extend 32) (bvand ((_ extract 31 0) (bvsub callback_temp64 callback_state64)) (_ bv65535 32)))))
(let ((?x65 (bvshl ?x74 (_ bv4 64))))
(let ((?x92 ((_ extract 15 0) callback_state64)))
(let ((?x95 (bvmul (_ bv65535 16) ?x92)))
(let ((?x88 ((_ extract 15 0) callback_temp64)))
(let ((?x96 (bvadd ?x88 ?x95)))
(let ((?x110 (concat (_ bv0 44) ?x96 (_ bv0 4))))
(and true (and (distinct ?x110 ?x65) true))))))))))
(check-sat)
