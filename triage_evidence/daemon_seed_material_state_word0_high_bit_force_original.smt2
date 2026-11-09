; benchmark generated from python API
(set-info :status unknown)
(declare-fun material_frame64 () (_ BitVec 64))
(assert
 (let (($x31 (bvule material_frame64 (_ bv18446744073709548575 64))))
(let (($x29 (bvuge material_frame64 (_ bv8589934592 64))))
(let (($x27 (= (bvand material_frame64 (_ bv15 64)) (_ bv0 64))))
(let (($x360 (and $x27 $x29 $x31)))
(and $x360 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv2147483648 32))) (_ bv2147483648 32)) true)))))))
(check-sat)
