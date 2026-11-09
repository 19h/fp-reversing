; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_M64 () (_ BitVec 64))
(declare-fun registry_j64 () (_ BitVec 64))
(assert
 (let ((?x293 (ite (= registry_j64 (bvadd (_ bv18446744073709551615 64) registry_M64)) (_ bv43839 32) (_ bv43799 32))))
(let ((?x357 ((_ extract 63 63) (bvadd (_ bv1 64) registry_j64 (bvmul (_ bv18446744073709551615 64) registry_M64)))))
(let ((?x423 (bvor ?x357 ((_ extract 63 63) (bvadd (_ bv18446744073709551615 64) registry_M64 (bvmul (_ bv18446744073709551615 64) registry_j64))))))
(let ((?x371 (bvnot ?x423)))
(not (= (concat (_ bv684 26) ?x371 (_ bv1 1) ?x371 (_ bv7 3)) ?x293)))))))
(check-sat)
