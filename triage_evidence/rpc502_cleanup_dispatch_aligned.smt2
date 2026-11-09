(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun low32_argument_address () (_ BitVec 32))
(declare-fun stored_mode_byte () (_ BitVec 8))
(assert
 (= (bvand low32_argument_address (_ bv7 32)) (_ bv0 32)))
(assert
 (let ((?x34 (bvor (bvand (_ bv12151 32) (_ bv65535 32)) (bvshl (_ bv22830 32) (_ bv16 32)))))
(let ((?x15 (bvshl low32_argument_address (_ bv1 32))))
(let ((?x22 (bvsub (bvor (bvor (bvand (_ bv11998 32) (_ bv65535 32)) (bvshl (_ bv15460 32) (_ bv16 32))) ?x15) low32_argument_address)))
(let ((?x29 (bvxor (bvadd ?x22 (bvor (bvand (_ bv59537 32) (_ bv65535 32)) (bvshl (_ bv57805 32) (_ bv16 32)))) (bvor (bvand (_ bv20349 32) (_ bv65535 32)) (bvshl (_ bv34908 32) (_ bv16 32))))))
(let ((?x35 (bvmul ?x29 ?x34)))
(let ((?x104 (bvxor (bvmul (bvand (bvxor ?x35 ((_ zero_extend 24) stored_mode_byte)) (_ bv1 32)) (_ bv54051 32)) (bvxor (bvxor ?x35 (_ bv26914 32)) ?x35))))
(and (distinct ?x104 (bvxor (_ bv26914 32) (bvmul ((_ zero_extend 24) (bvand stored_mode_byte (_ bv1 8))) (_ bv54051 32)))) true))))))))
(check-sat)
