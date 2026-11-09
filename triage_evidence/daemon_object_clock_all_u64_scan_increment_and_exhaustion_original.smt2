; benchmark generated from python API
(set-info :status unknown)
(declare-fun clock_B64 () (_ BitVec 64))
(declare-fun clock_index64 () (_ BitVec 64))
(assert
 (let ((?x318 ((_ extract 63 63) (bvadd (_ bv18446744073709551615 64) clock_B64 (bvmul (_ bv18446744073709551615 64) clock_index64)))))
(let ((?x311 (bvor ((_ extract 63 63) (bvadd (_ bv1 64) clock_index64 (bvmul (_ bv18446744073709551615 64) clock_B64))) ?x318)))
(let ((?x290 (bvnot ?x311)))
(let (($x361 (and (distinct ((_ extract 31 0) (concat (_ bv684 58) ?x290 (_ bv1 1) ?x290 (_ bv7 3))) (ite (= (bvadd clock_index64 (_ bv1 64)) clock_B64) (_ bv43839 32) (_ bv43799 32))) true)))
(or (and (distinct (bvadd (_ bv1 64) clock_index64) (bvadd clock_index64 (_ bv1 64))) true) $x361))))))
(check-sat)
