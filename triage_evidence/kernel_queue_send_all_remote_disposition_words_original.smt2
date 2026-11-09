; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_header_bits32 () (_ BitVec 32))
(assert
 (let (($x93 (= (bvsub ((_ extract 31 0) (concat (_ bv0 59) ((_ extract 4 0) qs_header_bits32))) (_ bv18 32)) (_ bv0 32))))
(and (distinct $x93 (= (bvand qs_header_bits32 (_ bv31 32)) (_ bv18 32))) true)))
(check-sat)
