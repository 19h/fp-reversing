; benchmark generated from python API
(set-info :status unknown)
(declare-fun record_low32 () (_ BitVec 32))
(assert
 (let ((?x10 (bvmul (bvxor record_low32 (_ bv2059139461 32)) (_ bv3738342961 32))))
(let ((?x34 (bvxor (bvsub (bvor record_low32 (_ bv2587426224 32)) (bvand record_low32 (_ bv2587426224 32))) (_ bv3766682677 32))))
(let ((?x35 (bvmul ?x34 (_ bv3738342961 32))))
(and (distinct ?x35 ?x10) true)))))
(check-sat)
