; benchmark generated from python API
(set-info :status unknown)
(declare-fun storage_owner64 () (_ BitVec 64))
(declare-fun storage_frame64 () (_ BitVec 64))
(assert
 (let (($x47 (and (distinct storage_owner64 storage_owner64) true)))
(let (($x148 (and (distinct (_ bv4312489760 64) (_ bv4312489760 64)) true)))
(let (($x28 (or (bvule (bvadd storage_frame64 (_ bv3040 64)) storage_owner64) (bvule (bvadd storage_owner64 (_ bv90000 64)) storage_frame64))))
(let (($x21 (bvule storage_owner64 (_ bv18446744073709461615 64))))
(let (($x19 (bvule storage_frame64 (_ bv18446744073709548575 64))))
(let (($x29 (and (= (bvand storage_frame64 (_ bv15 64)) (_ bv0 64)) (= (bvand storage_owner64 (_ bv15 64)) (_ bv0 64)) (bvuge storage_frame64 (_ bv8589934592 64)) (bvuge storage_owner64 (_ bv8589934592 64)) $x19 $x21 $x28)))
(and $x29 (or $x148 $x148 $x47 $x47)))))))))
(check-sat)
