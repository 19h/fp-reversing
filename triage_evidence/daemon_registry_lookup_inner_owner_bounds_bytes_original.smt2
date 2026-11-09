; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_M64 () (_ BitVec 64))
(declare-fun registry_j64 () (_ BitVec 64))
(assert
 (let (($x488 (bvugt (bvadd (bvshl registry_j64 (_ bv5 64)) (_ bv32 64)) (bvshl registry_M64 (_ bv5 64)))))
(and (and (bvult registry_j64 registry_M64) (bvule registry_M64 (_ bv4294967295 64))) $x488)))
(check-sat)
