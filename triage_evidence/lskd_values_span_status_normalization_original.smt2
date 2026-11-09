; benchmark generated from python API
(set-info :status unknown)
(declare-fun lookup_status32 () (_ BitVec 32))
(assert
 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (bvadd (_ bv2712266679 32) lookup_status32))) (bvsub lookup_status32 (_ bv1582700617 32))) true))
(check-sat)
