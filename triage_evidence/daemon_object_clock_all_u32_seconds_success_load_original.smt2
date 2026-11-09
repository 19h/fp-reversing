; benchmark generated from python API
(set-info :status unknown)
(declare-fun clock_value32 () (_ BitVec 32))
(assert
 (let (($x61 (and (distinct ((_ extract 31 0) (_ bv2036 64)) (_ bv2036 32)) true)))
(or (and (distinct ((_ extract 31 0) (concat (_ bv0 32) clock_value32)) clock_value32) true) $x61)))
(check-sat)
