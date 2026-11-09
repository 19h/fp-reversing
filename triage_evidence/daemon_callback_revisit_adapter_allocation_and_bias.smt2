; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_state64 () (_ BitVec 64))
(assert
 (let ((?x38 ((_ extract 63 60) callback_state64)))
(let ((?x222 (concat (_ bv0 60) ?x38)))
(let ((?x228 (bvmul (_ bv18446744073709551600 64) ?x222)))
(let ((?x244 (bvadd (_ bv18446744073709551600 64) ?x228)))
(let ((?x62 (concat (_ bv0 55) ((_ extract 8 4) (bvadd (_ bv31 32) (concat (_ bv0 24) ?x38 (_ bv0 4)))) (_ bv0 4))))
(let ((?x58 (bvmul (_ bv18446744073709551615 64) ?x62)))
(not (= ?x58 ?x244)))))))))
(check-sat)
