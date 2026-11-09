; benchmark generated from python API
(set-info :status unknown)
(declare-fun outer_readback_status32 () (_ BitVec 32))
(assert
 (let ((?x300 ((_ extract 31 0) ((_ zero_extend 32) (bvadd (_ bv2678597260 32) (bvmul (_ bv3501296387 32) outer_readback_status32))))))
(and (distinct ?x300 (bvmul (bvsub outer_readback_status32 (_ bv2071735420 32)) (_ bv3501296387 32))) true)))
(check-sat)
