; benchmark generated from python API
(set-info :status unknown)
(declare-fun frame_C64 () (_ BitVec 64))
(declare-fun frame_V32 () (_ BitVec 32))
(assert
 (let (($x115 (and (distinct (_ bv4306234948 64) (_ bv4306234948 64)) true)))
(let (($x49 (and (distinct frame_C64 frame_C64) true)))
(let (($x100 (or $x49 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) frame_V32)) frame_V32) true) $x49 (and (distinct ((_ extract 31 0) (_ bv18204 64)) (_ bv18204 32)) true) $x115)))
(and true $x100)))))
(check-sat)
