; benchmark generated from python API
(set-info :status unknown)
(declare-fun handoff_result64 () (_ BitVec 64))
(assert
 (let ((?x360 ((_ extract 63 60) handoff_result64)))
(let ((?x96 (concat (_ bv0 60) ?x360)))
(let ((?x47 (bvmul (_ bv18446744073709551600 64) ?x96)))
(let ((?x124 (bvadd (_ bv18446744073709551600 64) ?x47)))
(let ((?x392 (concat (_ bv0 55) ((_ extract 8 4) (bvadd (_ bv31 32) (concat (_ bv0 24) ?x360 (_ bv0 4)))) (_ bv0 4))))
(let ((?x390 (bvmul (_ bv18446744073709551615 64) ?x392)))
(not (= ?x390 ?x124)))))))))
(check-sat)
