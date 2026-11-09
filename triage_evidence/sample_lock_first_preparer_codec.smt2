; benchmark generated from python API
(set-info :status unknown)
(declare-fun record_low32 () (_ BitVec 32))
(assert
 (let ((?x10 (bvmul (bvxor record_low32 (_ bv2059139461 32)) (_ bv3738342961 32))))
(let ((?x25 (bvadd (bvsub (bvor (bvshl record_low32 (_ bv1 32)) (_ bv3962319306 32)) record_low32) (_ bv166323995 32))))
(let ((?x28 (bvmul (bvxor ?x25 (_ bv2360205664 32)) (_ bv3738342961 32))))
(and (distinct ?x28 ?x10) true)))))
(check-sat)
