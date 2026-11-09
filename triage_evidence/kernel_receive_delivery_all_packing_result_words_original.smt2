; benchmark generated from python API
(set-info :status unknown)
(declare-fun rd_packing_result32 () (_ BitVec 32))
(assert
 (let ((?x996 (concat (_ bv0 32) rd_packing_result32)))
(and (distinct ?x996 ((_ zero_extend 32) rd_packing_result32)) true)))
(check-sat)
