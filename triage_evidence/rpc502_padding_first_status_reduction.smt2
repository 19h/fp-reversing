(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun raw_status32 () (_ BitVec 32))
(assert
 (let ((?x224 (bvlshr raw_status32 (bvand (_ bv4 32) (_ bv31 32)))))
(let ((?x237 (bvand (bvxor ?x224 (bvor (bvand (_ bv4069 32) (_ bv65535 32)) (bvshl (_ bv64498 32) (_ bv16 32)))) (bvxor raw_status32 (bvor (bvand (_ bv32875 32) (_ bv65535 32)) (bvshl (_ bv13544 32) (_ bv16 32)))))))
(let ((?x249 (bvxor (bvand ?x224 (bvor (bvand (_ bv32310 32) (_ bv65535 32)) (bvshl (_ bv3016 32) (_ bv16 32)))) (bvor (bvand (_ bv61915 32) (_ bv65535 32)) (bvshl (_ bv29759 32) (_ bv16 32))))))
(let ((?x250 (bvxor ?x249 ?x237)))
(let ((?x257 (bvadd (bvsub (bvand (bvor ?x250 (bvlshr ?x250 (_ bv2 32))) (bvadd (_ bv1 32) (_ bv2 32))) (_ bv1 32)) (_ bv1 32))))
(let ((?x270 (ite (= (_ bv0 32) ?x257) (bvor (bvand (_ bv50769 32) (_ bv65535 32)) (bvshl (_ bv35645 32) (_ bv16 32))) (bvor (bvand (_ bv40330 32) (_ bv65535 32)) (bvshl (_ bv29890 32) (_ bv16 32))))))
(and (distinct ?x270 (ite (= (bvand raw_status32 (_ bv255 32)) (_ bv162 32)) (_ bv2336081489 32) (_ bv1958911370 32))) true))))))))
(check-sat)
