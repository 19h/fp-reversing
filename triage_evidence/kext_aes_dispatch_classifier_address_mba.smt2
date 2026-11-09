; benchmark generated from python API
(set-info :status unknown)
(declare-fun record_low32 () (_ BitVec 32))
(assert
 (let ((?x36 (bvsub (bvadd record_low32 (_ bv1274499873 32)) (bvshl (bvand record_low32 (_ bv1274499873 32)) (_ bv1 32)))))
(let ((?x38 (bvxor ?x36 (_ bv1172676039 32))))
(and (distinct ?x38 (bvxor record_low32 (_ bv236113638 32))) true))))
(check-sat)
