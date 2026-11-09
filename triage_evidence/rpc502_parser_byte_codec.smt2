(set-option :timeout 30000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun byte8 () (_ BitVec 8))
(assert
 (and (distinct (bvsub (bvsub byte8 (bvand (bvshl byte8 (_ bv1 8)) (_ bv48 8))) (_ bv104 8)) (bvxor byte8 (_ bv152 8))) true))
(check-sat)
