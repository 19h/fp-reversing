; benchmark generated from python API
(set-info :status unknown)
(declare-fun record_low32 () (_ BitVec 32))
(assert
 (let ((?x23 (bvxor record_low32 (_ bv2424394917 32))))
(let ((?x19 (bvsub (_ bv4294967294 32) (bvadd (bvor record_low32 (_ bv479619134 32)) (bvor (_ bv3815348161 32) (bvnot record_low32))))))
(let ((?x21 (bvxor ?x19 (_ bv1944634212 32))))
(and (distinct ?x21 ?x23) true)))))
(check-sat)
