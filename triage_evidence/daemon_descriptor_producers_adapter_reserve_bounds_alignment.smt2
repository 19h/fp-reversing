; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_word64 () (_ BitVec 64))
(assert
 (let (($x771 (bvule (bvadd (_ bv16 9) (bvmul (_ bv16 9) (concat (_ bv0 5) ((_ extract 63 60) producer_word64)))) (_ bv256 9))))
(let ((?x643 ((_ extract 63 9) (bvadd (_ bv16 64) (bvmul (_ bv16 64) (concat (_ bv0 60) ((_ extract 63 60) producer_word64)))))))
(let (($x644 (not (bvule (bvmul (_ bv16 64) (concat (_ bv0 60) ((_ extract 63 60) producer_word64))) (_ bv18446744073709551599 64)))))
(or $x644 (not (and (= ?x643 (_ bv0 55)) $x771)))))))
(check-sat)
