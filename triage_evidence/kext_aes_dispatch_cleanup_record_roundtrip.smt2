; benchmark generated from python API
(set-info :status unknown)
(declare-fun state32 () (_ BitVec 32))
(declare-fun record_low32 () (_ BitVec 32))
(assert
 (let ((?x19 (bvsub (_ bv4294967294 32) (bvadd (bvor record_low32 (_ bv479619134 32)) (bvor (_ bv3815348161 32) (bvnot record_low32))))))
(let ((?x21 (bvxor ?x19 (_ bv1944634212 32))))
(let ((?x28 (bvadd (bvadd (bvmul (bvxor record_low32 (_ bv2424394917 32)) (_ bv1369949563 32)) state32) (_ bv1105 32))))
(let ((?x30 (bvsub ?x28 (bvmul ?x21 (_ bv1369949563 32)))))
(and (distinct ?x30 (bvadd state32 (_ bv1105 32))) true))))))
(check-sat)
