; benchmark generated from python API
(set-info :status unknown)
(declare-fun record_low32 () (_ BitVec 32))
(assert
 (let ((?x14 (bvmul (bvxor record_low32 (_ bv1630773448 32)) (_ bv2228712307 32))))
(let ((?x53 (bvxor (bvor (bvand record_low32 (_ bv3545569085 32)) (bvnot (bvor record_low32 (_ bv3545569085 32)))) (_ bv1301891082 32))))
(let ((?x54 (bvmul ?x53 (_ bv2228712307 32))))
(and (distinct ?x54 ?x14) true)))))
(check-sat)
