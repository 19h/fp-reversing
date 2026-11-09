(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun pointer32 () (_ BitVec 32))
(assert
 (let ((?x11 (bvmul (bvxor pointer32 (_ bv3878867554 32)) (_ bv3122700023 32))))
(let ((?x41 (bvor (bvand (_ bv40695 32) (_ bv65535 32)) (bvshl (_ bv47648 32) (_ bv16 32)))))
(let ((?x22 (bvand (_ bv1 32) (_ bv31 32))))
(let ((?x23 (bvshl (bvand pointer32 (bvor (bvand (_ bv14936 32) (_ bv65535 32)) (bvshl (_ bv22501 32) (_ bv16 32)))) ?x22)))
(let ((?x30 (bvadd (bvsub ?x23 pointer32) (bvor (bvand (_ bv50599 32) (_ bv65535 32)) (bvshl (_ bv10266 32) (_ bv16 32))))))
(let ((?x36 (bvxor ?x30 (bvor (bvand (_ bv6085 32) (_ bv65535 32)) (bvshl (_ bv53032 32) (_ bv16 32))))))
(let ((?x42 (bvmul ?x36 ?x41)))
(and (distinct ?x42 ?x11) true)))))))))
(check-sat)
