(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun pointer32 () (_ BitVec 32))
(assert
 (let ((?x181 (bvor (bvor (bvand (_ bv11886 32) (_ bv65535 32)) (bvshl (_ bv24917 32) (_ bv16 32))) (bvshl pointer32 (_ bv1 32)))))
(let ((?x188 (bvadd (bvsub ?x181 pointer32) (bvor (bvand (_ bv26825 32) (_ bv65535 32)) (bvshl (_ bv53077 32) (_ bv16 32))))))
(let ((?x194 (bvxor ?x188 (bvor (bvand (_ bv3651 32) (_ bv65535 32)) (bvshl (_ bv51582 32) (_ bv16 32))))))
(let ((?x200 (bvmul ?x194 (bvor (bvand (_ bv43047 32) (_ bv65535 32)) (bvshl (_ bv55889 32) (_ bv16 32))))))
(and (distinct ?x200 (bvmul (bvxor pointer32 (_ bv4191459700 32)) (_ bv3662784551 32))) true))))))
(check-sat)
