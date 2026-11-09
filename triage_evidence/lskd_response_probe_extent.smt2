; benchmark generated from python API
(set-info :status unknown)
(declare-fun displacement_seed64 () (_ BitVec 64))
(assert
 (let ((?x315 ((_ extract 63 60) (bvadd (_ bv1 64) (bvmul (_ bv11973 64) displacement_seed64)))))
(let ((?x445 (concat (_ bv0 1) ?x315 (_ bv0 4))))
(let ((?x401 (bvadd (_ bv16 9) ?x445)))
(let (($x133 (= ((_ extract 63 9) (bvadd (_ bv16 64) (concat (_ bv0 56) ?x315 (_ bv0 4)))) (_ bv0 55))))
(let (($x1415 (and $x133 (bvule ?x401 (_ bv256 9)))))
(not $x1415)))))))
(check-sat)
