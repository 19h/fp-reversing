; benchmark generated from python API
(set-info :status unknown)
(declare-fun clock_cursor64 () (_ BitVec 64))
(declare-fun clock_tag64 () (_ BitVec 64))
(declare-fun clock_value32 () (_ BitVec 32))
(assert
 (let (($x18 (and (distinct clock_tag64 clock_tag64) true)))
(let (($x125 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) clock_value32)) clock_value32) true)))
(or (and (distinct ((_ extract 31 0) (_ bv18204 64)) (_ bv18204 32)) true) $x125 $x18 (and (distinct (_ bv0 64) (_ bv0 64)) true) (and (distinct (bvadd (_ bv18446744073709550960 64) clock_cursor64) (bvsub clock_cursor64 (_ bv656 64))) true) (and (distinct (_ bv0 32) (_ bv0 32)) true)))))
(check-sat)
