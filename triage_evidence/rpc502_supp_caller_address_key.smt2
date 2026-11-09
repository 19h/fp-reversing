(set-option :timeout 30000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun pointer_low32 () (_ BitVec 32))
(assert
 (let ((?x215 (bvor (bvand (_ bv22831 32) (_ bv65535 32)) (bvshl (_ bv27526 32) (_ bv16 32)))))
(let ((?x197 (bvor (bvor (bvand (_ bv35492 32) (_ bv65535 32)) (bvshl (_ bv49646 32) (_ bv16 32))) (bvshl pointer_low32 (_ bv1 32)))))
(let ((?x204 (bvadd (bvsub ?x197 pointer_low32) (bvor (bvand (_ bv47790 32) (_ bv65535 32)) (bvshl (_ bv7944 32) (_ bv16 32))))))
(let ((?x216 (bvmul (bvxor ?x204 (bvor (bvand (_ bv9542 32) (_ bv65535 32)) (bvshl (_ bv9761 32) (_ bv16 32)))) ?x215)))
(and (distinct ?x216 (bvmul (bvxor pointer_low32 (_ bv3335938068 32)) (_ bv1803966767 32))) true))))))
(check-sat)
