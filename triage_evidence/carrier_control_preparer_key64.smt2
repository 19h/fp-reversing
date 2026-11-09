; benchmark generated from python API
(set-info :status unknown)
(declare-fun record_pointer64 () (_ BitVec 64))
(assert
 (let ((?x20 (bvmul (bvxor record_pointer64 (_ bv16215550093535476101 64)) (_ bv3738342961 64))))
(let ((?x13 (bvadd (bvsub (bvmul (bvand record_pointer64 (_ bv2521043694873332465 64)) (_ bv2 64)) record_pointer64) (_ bv15925700378836219150 64))))
(let ((?x17 (bvmul (bvxor ?x13 (_ bv4326341828848503947 64)) (_ bv3738342961 64))))
(and (distinct ?x17 ?x20) true)))))
(check-sat)
