; benchmark generated from python API
(set-info :status unknown)
(declare-fun clock_value32 () (_ BitVec 32))
(assert
 (let (($x258 (= clock_value32 (_ bv0 32))))
(let ((?x277 (ite $x258 (_ bv31467 32) (_ bv31468 32))))
(let ((?x245 (bvnot (bvmul (_ bv3 2) (concat (_ bv0 1) (ite $x258 (_ bv0 1) (_ bv1 1)))))))
(let ((?x208 (ite $x258 (_ bv0 1) (_ bv1 1))))
(let ((?x225 (concat (_ bv0 28) ?x208 (_ bv0 3))))
(let ((?x257 (bvmul (_ bv4294967295 32) (concat (_ bv0 31) ?x208))))
(let ((?x252 (bvadd ?x257 ?x225)))
(let ((?x235 (concat (_ bv0 32) ((_ extract 31 15) ?x252) (bvnot ((_ extract 14 11) ?x252)) ((_ extract 10 10) ?x252) (bvnot ((_ extract 9 9) ?x252)) ((_ extract 8 8) ?x252) (bvnot ((_ extract 7 5) ?x252)) ((_ extract 4 4) ?x252) (bvnot ((_ extract 3 3) ?x252)) ((_ extract 2 2) ?x252) ?x245)))
(and (distinct ((_ extract 31 0) ?x235) ?x277) true))))))))))
(check-sat)
