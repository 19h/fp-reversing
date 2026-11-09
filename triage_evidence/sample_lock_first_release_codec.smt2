; benchmark generated from python API
(set-info :status unknown)
(declare-fun record_low32 () (_ BitVec 32))
(assert
 (let ((?x18 (bvmul (bvxor record_low32 (_ bv1934238386 32)) (_ bv2351076881 32))))
(let ((?x61 (bvadd (bvsub (bvmul (bvand record_low32 (_ bv995898412 32)) (_ bv2 32)) record_low32) (_ bv3299068883 32))))
(let ((?x64 (bvmul (bvxor ?x61 (_ bv3085560161 32)) (_ bv2351076881 32))))
(and (distinct ?x64 ?x18) true)))))
(check-sat)
