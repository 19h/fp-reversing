(set-option :timeout 30000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun pointer64 () (_ BitVec 64))
(assert
 (let ((?x219 (bvnot (_ bv15786398729779183848 64))))
(let ((?x225 (bvxor (bvadd (bvsub (bvor pointer64 (_ bv15786398729779183848 64)) (bvor pointer64 ?x219)) ?x219) (_ bv5720465416795250940 64))))
(let ((?x227 (bvmul ?x225 (_ bv1803966767 64))))
(and (distinct ((_ extract 31 0) ?x227) (bvmul (bvxor ((_ extract 31 0) pointer64) (_ bv3335938068 32)) (_ bv1803966767 32))) true)))))
(check-sat)
