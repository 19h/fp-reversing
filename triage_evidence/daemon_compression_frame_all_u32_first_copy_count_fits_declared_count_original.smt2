; benchmark generated from python API
(set-info :status unknown)
(declare-fun frame_H32 () (_ BitVec 32))
(declare-fun frame_N32 () (_ BitVec 32))
(assert
 (and (bvuge (bvadd frame_N32 (bvand frame_H32 (_ bv63 32))) (_ bv64 32)) (bvult frame_N32 (bvsub (_ bv64 32) (bvand frame_H32 (_ bv63 32))))))
(check-sat)
