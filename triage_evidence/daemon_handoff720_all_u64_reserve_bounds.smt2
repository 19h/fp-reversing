; benchmark generated from python API
(set-info :status unknown)
(declare-fun handoff_result64 () (_ BitVec 64))
(assert
 (let (($x63 (bvule (bvadd (_ bv16 9) (bvmul (_ bv16 9) (concat (_ bv0 5) ((_ extract 63 60) handoff_result64)))) (_ bv256 9))))
(let ((?x74 ((_ extract 63 9) (bvadd (_ bv16 64) (bvmul (_ bv16 64) (concat (_ bv0 60) ((_ extract 63 60) handoff_result64)))))))
(let (($x170 (not (bvule (bvmul (_ bv16 64) (concat (_ bv0 60) ((_ extract 63 60) handoff_result64))) (_ bv18446744073709551599 64)))))
(or $x170 (not (and (= ?x74 (_ bv0 55)) $x63)))))))
(check-sat)
