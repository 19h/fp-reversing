; benchmark generated from python API
(set-info :status unknown)
(declare-fun output_length32 () (_ BitVec 32))
(assert
 (let ((?x617 (bvmul (_ bv20 32) (concat (_ bv0 31) (ite (= output_length32 (_ bv0 32)) (_ bv0 1) (_ bv1 1))))))
(let ((?x551 ((_ extract 31 31) ?x617)))
(let ((?x604 (concat ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ?x551 ((_ extract 31 13) ?x617) (bvnot ((_ extract 12 11) ?x617)) ((_ extract 10 9) ?x617) (bvnot ((_ extract 8 7) ?x617)) ((_ extract 6 6) ?x617) (bvnot ((_ extract 5 5) ?x617)) ((_ extract 4 1) ?x617) (_ bv8 4))))
(not (= ?x604 (bvadd (_ bv18446744069397569808 64) (ite (= output_length32 (_ bv0 32)) (_ bv4312034296 64) (_ bv4312034456 64)))))))))
(check-sat)
