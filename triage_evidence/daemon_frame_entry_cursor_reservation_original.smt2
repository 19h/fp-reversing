; benchmark generated from python API
(set-info :status unknown)
(declare-fun frame_SP64 () (_ BitVec 64))
(declare-fun cursor64 () (_ BitVec 64))
(assert
 (let (($x208 (and (distinct (bvadd (_ bv1632 64) cursor64 frame_SP64) (bvadd (bvadd frame_SP64 (_ bv1632 64)) cursor64)) true)))
(or (and (distinct (bvadd (_ bv64 64) cursor64) (bvadd cursor64 (_ bv64 64))) true) $x208 (and (distinct (bvadd frame_SP64 (_ bv1776 64)) (bvadd frame_SP64 (_ bv1776 64))) true))))
(check-sat)
