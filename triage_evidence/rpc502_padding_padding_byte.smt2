(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun reference_byte8 () (_ BitVec 8))
(declare-fun prior_error8 () (_ BitVec 8))
(assert
 (let ((?x10 ((_ zero_extend 24) prior_error8)))
(let ((?x56 (bvand (bvxor ((_ zero_extend 24) reference_byte8) (bvadd (_ bv26576 32) (_ bv4294940616 32))) (bvxor (bvxor (_ bv3493252768 32) ?x10) (bvor (bvand (_ bv21072 32) (_ bv65535 32)) (bvshl (_ bv9716 32) (_ bv16 32)))))))
(let ((?x62 (bvxor (bvand ((_ zero_extend 24) reference_byte8) (_ bv15 32)) (bvor (bvand (_ bv21079 32) (_ bv65535 32)) (bvshl (_ bv9716 32) (_ bv16 32))))))
(and (distinct (bvxor ?x62 ?x56) (bvxor (_ bv3493252768 32) (bvor ?x10 (bvxor ((_ zero_extend 24) reference_byte8) (_ bv103 32))))) true)))))
(check-sat)
