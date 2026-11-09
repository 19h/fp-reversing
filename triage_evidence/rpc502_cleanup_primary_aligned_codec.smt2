(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun low32_argument_address () (_ BitVec 32))
(assert
 (= (bvand low32_argument_address (_ bv7 32)) (_ bv0 32)))
(assert
 (let ((?x34 (bvor (bvand (_ bv12151 32) (_ bv65535 32)) (bvshl (_ bv22830 32) (_ bv16 32)))))
(let ((?x15 (bvshl low32_argument_address (_ bv1 32))))
(let ((?x22 (bvsub (bvor (bvor (bvand (_ bv11998 32) (_ bv65535 32)) (bvshl (_ bv15460 32) (_ bv16 32))) ?x15) low32_argument_address)))
(let ((?x29 (bvxor (bvadd ?x22 (bvor (bvand (_ bv59537 32) (_ bv65535 32)) (bvshl (_ bv57805 32) (_ bv16 32)))) (bvor (bvand (_ bv20349 32) (_ bv65535 32)) (bvshl (_ bv34908 32) (_ bv16 32))))))
(let ((?x35 (bvmul ?x29 ?x34)))
(let ((?x76 (bvand low32_argument_address (bvor (bvand (_ bv52056 32) (_ bv65535 32)) (bvshl (_ bv5151 32) (_ bv16 32))))))
(let ((?x89 (bvadd (bvsub low32_argument_address (bvshl ?x76 (_ bv1 32))) (bvor (bvand (_ bv52060 32) (_ bv65535 32)) (bvshl (_ bv37919 32) (_ bv16 32))))))
(and (distinct (bvmul (bvxor ?x89 (bvor (bvand (_ bv37710 32) (_ bv65535 32)) (bvshl (_ bv625 32) (_ bv16 32)))) ?x34) ?x35) true)))))))))
(check-sat)
