; benchmark generated from python API
(set-info :status unknown)
(declare-fun rd_receive_name32 () (_ BitVec 32))
(assert
 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) ((_ extract 31 0) (concat (_ bv0 32) rd_receive_name32)))) rd_receive_name32) true))
(check-sat)
