(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun saved_word32 () (_ BitVec 32))
(assert
 (let ((?x59 (bvor (bvand (_ bv40330 32) (_ bv65535 32)) (bvshl (_ bv29890 32) (_ bv16 32)))))
(let ((?x64 (bvor (bvand (_ bv50769 32) (_ bv65535 32)) (bvshl (_ bv35645 32) (_ bv16 32)))))
(let ((?x72 (bvlshr saved_word32 (bvand (_ bv4 32) (_ bv31 32)))))
(let ((?x85 (bvand (bvxor ?x72 (bvor (bvand (_ bv4069 32) (_ bv65535 32)) (bvshl (_ bv64498 32) (_ bv16 32)))) (bvxor saved_word32 (bvor (bvand (_ bv32875 32) (_ bv65535 32)) (bvshl (_ bv13544 32) (_ bv16 32)))))))
(let ((?x97 (bvxor (bvand ?x72 (bvor (bvand (_ bv32310 32) (_ bv65535 32)) (bvshl (_ bv3016 32) (_ bv16 32)))) (bvor (bvand (_ bv61915 32) (_ bv65535 32)) (bvshl (_ bv29759 32) (_ bv16 32))))))
(let ((?x98 (bvxor ?x97 ?x85)))
(let ((?x104 (bvadd (bvsub (bvand (bvor ?x98 (bvlshr ?x98 (_ bv2 32))) (bvadd (_ bv1 32) (_ bv2 32))) (_ bv1 32)) (_ bv1 32))))
(and (distinct (ite (= (_ bv0 32) ?x104) ?x64 ?x59) (ite (= (bvand saved_word32 (_ bv255 32)) (_ bv162 32)) (_ bv2336081489 32) (_ bv1958911370 32))) true)))))))))
(check-sat)
