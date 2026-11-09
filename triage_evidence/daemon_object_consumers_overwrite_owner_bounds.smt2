; benchmark generated from python API
(set-info :status unknown)
(declare-fun destruct_remaining64 () (_ BitVec 64))
(assert
 (let (($x611 (and (= ((_ extract 63 10) (bvadd (_ bv18446744073709551615 64) destruct_remaining64)) (_ bv0 54)) (bvule (bvadd (_ bv1023 10) ((_ extract 9 0) destruct_remaining64)) (_ bv871 10)))))
(let ((?x15 ((_ extract 9 0) destruct_remaining64)))
(let (($x675 (bvule ?x15 (_ bv872 10))))
(let (($x705 (= ((_ extract 63 10) destruct_remaining64) (_ bv0 54))))
(let (($x116 (or (not (and $x705 $x675)) (not $x611))))
(let (($x440 (or (not (= ((_ extract 63 1) destruct_remaining64) (_ bv0 63))) (= ((_ extract 0 0) destruct_remaining64) (_ bv1 1)))))
(and $x440 $x705 $x675 $x116))))))))
(check-sat)
