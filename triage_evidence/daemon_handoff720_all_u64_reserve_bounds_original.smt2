; benchmark generated from python API
(set-info :status unknown)
(declare-fun handoff_result64 () (_ BitVec 64))
(assert
 (let (($x385 (and (distinct (bvand (bvmul (_ bv16 64) (bvadd (bvlshr handoff_result64 (_ bv60 64)) (_ bv1 64))) (_ bv15 64)) (_ bv0 64)) true)))
(let (($x333 (or (bvult (bvmul (_ bv16 64) (bvadd (bvlshr handoff_result64 (_ bv60 64)) (_ bv1 64))) (_ bv16 64)) (bvugt (bvmul (_ bv16 64) (bvadd (bvlshr handoff_result64 (_ bv60 64)) (_ bv1 64))) (_ bv256 64)) $x385)))
(and true $x333))))
(check-sat)
