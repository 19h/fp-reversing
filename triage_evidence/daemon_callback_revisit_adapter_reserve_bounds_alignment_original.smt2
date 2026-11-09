; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_state64 () (_ BitVec 64))
(assert
 (let (($x47 (and (distinct (bvand (bvmul (_ bv16 64) (bvadd (bvlshr callback_state64 (_ bv60 64)) (_ bv1 64))) (_ bv15 64)) (_ bv0 64)) true)))
(let (($x49 (or (bvult (bvmul (_ bv16 64) (bvadd (bvlshr callback_state64 (_ bv60 64)) (_ bv1 64))) (_ bv16 64)) (bvugt (bvmul (_ bv16 64) (bvadd (bvlshr callback_state64 (_ bv60 64)) (_ bv1 64))) (_ bv256 64)) $x47)))
(and true $x49))))
(check-sat)
