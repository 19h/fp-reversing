; benchmark generated from python API
(set-info :status unknown)
(declare-fun mask_slots32 () (_ BitVec 32))
(assert
 (and (bvule mask_slots32 (_ bv512 32)) (bvugt (bvmul ((_ zero_extend 32) mask_slots32) (_ bv16 64)) (_ bv8192 64))))
(check-sat)
