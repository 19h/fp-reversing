; benchmark generated from python API
(set-info :status unknown)
(declare-fun buffered_bytes32 () (_ BitVec 32))
(declare-fun size32 () (_ BitVec 32))
(assert
 (and (bvule size32 (_ bv8192 32)) (bvule buffered_bytes32 (_ bv8192 32)) (bvule (bvadd size32 buffered_bytes32) (_ bv8192 32)) (bvugt (bvadd (bvand size32 (_ bv4294967280 32)) buffered_bytes32) (_ bv8192 32))))
(check-sat)
