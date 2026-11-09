; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_counter64 () (_ BitVec 64))
(assert
 (and (bvult init_counter64 (_ bv48 64)) (bvugt init_counter64 (_ bv47 64))))
(check-sat)
