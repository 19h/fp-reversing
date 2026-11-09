(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun reference_byte8 () (_ BitVec 8))
(declare-fun candidate_byte8 () (_ BitVec 8))
(assert
 (let ((?x41 (bvor (bvxor ((_ zero_extend 24) candidate_byte8) (_ bv152 32)) (bvxor ((_ zero_extend 24) reference_byte8) (_ bv153 32)))))
(let ((?x8 ((_ zero_extend 24) reference_byte8)))
(let ((?x19 (bvxor ?x8 (_ bv4294967262 32))))
(let ((?x26 (bvxor (bvxor (bvand ?x19 (_ bv35 32)) (bvand ((_ zero_extend 24) candidate_byte8) (_ bv184 32))) (bvand (bvxor (bvsub (_ bv29257 32) (_ bv2565 32)) ((_ zero_extend 24) candidate_byte8)) ?x19))))
(and (distinct (bvxor (bvand ?x26 (_ bv255 32)) (bvor (bvand (_ bv52863 32) (_ bv65535 32)) (bvshl (_ bv53302 32) (_ bv16 32)))) (bvxor (_ bv3493252768 32) ?x41)) true))))))
(check-sat)
