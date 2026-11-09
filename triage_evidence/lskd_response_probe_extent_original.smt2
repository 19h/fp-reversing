; benchmark generated from python API
(set-info :status unknown)
(declare-fun displacement_seed64 () (_ BitVec 64))
(assert
 (let ((?x315 ((_ extract 63 60) (bvadd (_ bv1 64) (bvmul (_ bv11973 64) displacement_seed64)))))
(let ((?x347 (concat (_ bv0 56) ?x315 (_ bv0 4))))
(let ((?x313 (bvadd (_ bv16 64) ?x347)))
(or (bvult ?x313 (_ bv16 64)) (bvugt ?x313 (_ bv256 64)) (and (distinct (bvand ?x313 (_ bv15 64)) (_ bv0 64)) true))))))
(check-sat)
