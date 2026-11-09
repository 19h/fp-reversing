; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_M64 () (_ BitVec 64))
(declare-fun registry_j64 () (_ BitVec 64))
(assert
 (let ((?x357 ((_ extract 63 63) (bvadd (_ bv1 64) registry_j64 (bvmul (_ bv18446744073709551615 64) registry_M64)))))
(let ((?x423 (bvor ?x357 ((_ extract 63 63) (bvadd (_ bv18446744073709551615 64) registry_M64 (bvmul (_ bv18446744073709551615 64) registry_j64))))))
(let ((?x371 (bvnot ?x423)))
(let (($x485 (and (distinct ((_ extract 31 0) (concat (_ bv684 58) ?x371 (_ bv1 1) ?x371 (_ bv7 3))) (ite (= (bvadd registry_j64 (_ bv1 64)) registry_M64) (_ bv43839 32) (_ bv43799 32))) true)))
(let (($x287 (or (and (distinct (bvadd (_ bv1 64) registry_j64) (bvadd registry_j64 (_ bv1 64))) true) $x485)))
(and true $x287)))))))
(check-sat)
