; benchmark generated from python API
(set-info :status unknown)
(declare-fun output_length32 () (_ BitVec 32))
(assert
 (let (($x539 (= output_length32 (_ bv0 32))))
(let ((?x554 (ite $x539 (_ bv0 1) (_ bv1 1))))
(let ((?x454 (bvmul (_ bv57 32) (ite $x539 (_ bv1 32) (_ bv0 32)))))
(let ((?x255 ((_ extract 31 31) ?x454)))
(let ((?x652 (concat ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ?x255 ((_ extract 31 15) ?x454) (bvnot ((_ extract 14 13) ?x454)) ((_ extract 12 12) ?x454) (bvnot ((_ extract 11 10) ?x454)) ((_ extract 9 9) ?x454) (bvnot ((_ extract 8 8) ?x454)) ((_ extract 7 5) ?x454) (bvnot ((_ extract 4 3) ?x454)) ((_ extract 2 1) ?x454) ?x554 (_ bv0 3))))
(not (= ?x652 (bvadd (_ bv18446744069397569808 64) (ite $x539 (_ bv4312205296 64) (_ bv4312205240 64)))))))))))
(check-sat)
