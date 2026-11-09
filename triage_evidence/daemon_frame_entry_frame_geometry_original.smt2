; benchmark generated from python API
(set-info :status unknown)
(declare-fun frame_SP64 () (_ BitVec 64))
(assert
 (or (and (distinct frame_SP64 frame_SP64) true) (and (distinct (bvadd (_ bv3024 64) frame_SP64) (bvadd frame_SP64 (_ bv3024 64))) true)))
(check-sat)
