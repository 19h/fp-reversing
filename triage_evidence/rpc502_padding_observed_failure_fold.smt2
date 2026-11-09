(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun reference_byte8 () (_ BitVec 8))
(assert
 (let ((?x8 ((_ zero_extend 24) reference_byte8)))
(let ((?x80 (bvxor ?x8 (_ bv4294967143 32))))
(let ((?x218 (bvxor (bvxor (bvand ?x8 (_ bv215 32)) (bvor (bvand (_ bv29210 32) (_ bv65535 32)) (bvshl (_ bv1129 32) (_ bv16 32)))) (bvand ?x80 (bvxor (_ bv1088356701 32) (bvor (bvand (_ bv29322 32) (_ bv65535 32)) (bvshl (_ bv1129 32) (_ bv16 32))))))))
(and (distinct ?x218 (_ bv1088356701 32)) true)))))
(check-sat)
