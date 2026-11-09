; benchmark generated from python API
(set-info :status unknown)
(declare-fun handoff_cursor64 () (_ BitVec 64))
(assert
 (let (($x300 (and (distinct (bvadd (_ bv1 64) (bvmul (_ bv11933 64) handoff_cursor64)) (bvadd (bvmul handoff_cursor64 (_ bv11933 64)) (_ bv1 64))) true)))
(and true $x300)))
(check-sat)
