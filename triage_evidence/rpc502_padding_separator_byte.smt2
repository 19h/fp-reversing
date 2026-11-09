(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun reference_byte8 () (_ BitVec 8))
(declare-fun prior_error8 () (_ BitVec 8))
(assert
 (let ((?x10 ((_ zero_extend 24) prior_error8)))
(let ((?x90 (bvadd (bvxor (bvsub (_ bv26576 32) (_ bv1037 32)) (_ bv61187 32)) (bvor (bvand (_ bv26748 32) (_ bv65535 32)) (bvshl (_ bv7606 32) (_ bv16 32))))))
(let ((?x8 ((_ zero_extend 24) reference_byte8)))
(let ((?x80 (bvxor ?x8 (_ bv4294967143 32))))
(let ((?x81 (bvand ?x80 (bvxor (bvxor (_ bv3493252768 32) ?x10) (bvor (bvand (_ bv15014 32) (_ bv65535 32)) (bvshl (_ bv36191 32) (_ bv16 32)))))))
(and (distinct (bvxor (bvxor ?x81 (bvand ?x8 (_ bv4294967289 32))) ?x90) (bvxor (_ bv1088356770 32) (bvor ?x10 (bvxor ?x8 (_ bv152 32))))) true)))))))
(check-sat)
