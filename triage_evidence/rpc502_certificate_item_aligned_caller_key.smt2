(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun pointer32 () (_ BitVec 32))
(assert
 (let ((?x11 (bvmul (bvxor pointer32 (_ bv3878867554 32)) (_ bv3122700023 32))))
(let ((?x41 (bvor (bvand (_ bv40695 32) (_ bv65535 32)) (bvshl (_ bv47648 32) (_ bv16 32)))))
(let ((?x22 (bvand (_ bv1 32) (_ bv31 32))))
(let ((?x49 (bvshl (bvand pointer32 (bvor (bvand (_ bv8016 32) (_ bv65535 32)) (bvshl (_ bv9936 32) (_ bv16 32)))) ?x22)))
(let ((?x56 (bvadd (bvsub ?x49 pointer32) (bvor (bvand (_ bv57512 32) (_ bv65535 32)) (bvshl (_ bv55599 32) (_ bv16 32))))))
(let ((?x63 (bvmul (bvxor ?x56 (bvor (bvand (_ bv13002 32) (_ bv65535 32)) (bvshl (_ bv15901 32) (_ bv16 32)))) ?x41)))
(and (= (bvand pointer32 (_ bv7 32)) (_ bv0 32)) (and (distinct ?x63 ?x11) true)))))))))
(check-sat)
