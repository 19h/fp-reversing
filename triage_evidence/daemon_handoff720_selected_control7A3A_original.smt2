; benchmark generated from python API
(set-info :status unknown)
(assert
 (let ((?x173 (bvmul (bvxor (_ bv188048 32) (_ bv2096270304 32)) (_ bv2207351123 32))))
(and true (and (distinct (bvxor (bvxor (bvadd (_ bv23429 32) (_ bv7861 32)) ?x173) ?x173) (_ bv31290 32)) true))))
(check-sat)
