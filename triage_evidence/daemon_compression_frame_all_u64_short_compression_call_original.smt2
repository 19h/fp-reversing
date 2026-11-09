; benchmark generated from python API
(set-info :status unknown)
(declare-fun frame_C64 () (_ BitVec 64))
(assert
 (let (($x115 (and (distinct (_ bv4306234948 64) (_ bv4306234948 64)) true)))
(let (($x49 (and (distinct frame_C64 frame_C64) true)))
(and true (or (and (distinct ((_ extract 31 0) (_ bv88 64)) (_ bv88 32)) true) $x49 $x115)))))
(check-sat)
