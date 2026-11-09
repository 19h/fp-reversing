; benchmark generated from python API
(set-info :status unknown)
(declare-fun record_low32 () (_ BitVec 32))
(assert
 (let ((?x45 (bvxor (bvor (bvand record_low32 (_ bv1081072914 32)) (bvnot (bvor record_low32 (_ bv1081072914 32)))) (_ bv999068840 32))))
(and (distinct ?x45 (bvxor record_low32 (_ bv2216474181 32))) true)))
(check-sat)
