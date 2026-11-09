; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_word64 () (_ BitVec 64))
(assert
 (let ((?x333 ((_ extract 63 60) producer_word64)))
(let ((?x294 (concat (_ bv0 60) ?x333)))
(let ((?x707 (bvmul (_ bv18446744073709551600 64) ?x294)))
(let ((?x730 (bvadd (_ bv18446744073709551600 64) ?x707)))
(let ((?x355 (concat (_ bv0 55) ((_ extract 8 4) (bvadd (_ bv31 32) (concat (_ bv0 24) ?x333 (_ bv0 4)))) (_ bv0 4))))
(let ((?x352 (bvmul (_ bv18446744073709551615 64) ?x355)))
(not (= ?x352 ?x730)))))))))
(check-sat)
