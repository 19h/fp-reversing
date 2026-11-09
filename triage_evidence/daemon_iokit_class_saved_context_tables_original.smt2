; benchmark generated from python API
(set-info :status unknown)
(declare-fun outer_input64 () (_ BitVec 64))
(assert
 (or (and (distinct outer_input64 outer_input64) true) (and (distinct (_ bv4310276096 64) (_ bv4310276096 64)) true) (and (distinct (_ bv4311016080 64) (_ bv4311016080 64)) true)))
(check-sat)
