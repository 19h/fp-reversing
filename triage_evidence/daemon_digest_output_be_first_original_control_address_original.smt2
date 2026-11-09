; benchmark generated from python API
(set-info :status unknown)
(declare-fun output_index32 () (_ BitVec 32))
(assert
 (let (($x175 (and (bvuge output_index32 (_ bv0 32)) (bvule output_index32 (_ bv0 32)))))
(and $x175 (and (distinct (_ bv4312197880 64) (_ bv4312197880 64)) true))))
(check-sat)
