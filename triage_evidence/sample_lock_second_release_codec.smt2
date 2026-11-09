; benchmark generated from python API
(set-info :status unknown)
(declare-fun record_low32 () (_ BitVec 32))
(assert
 (let ((?x18 (bvmul (bvxor record_low32 (_ bv1934238386 32)) (_ bv2351076881 32))))
(let ((?x70 (bvadd (bvsub (_ bv2715225941 32) (bvor record_low32 (_ bv2715225941 32))) (bvor record_low32 (_ bv1579741354 32)))))
(let ((?x73 (bvmul (bvxor ?x70 (_ bv761451032 32)) (_ bv2351076881 32))))
(and (distinct ?x73 ?x18) true)))))
(check-sat)
