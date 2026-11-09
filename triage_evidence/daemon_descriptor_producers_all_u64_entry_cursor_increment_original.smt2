; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_cursor64 () (_ BitVec 64))
(assert
 (let (($x200 (and (distinct (bvadd (_ bv160 64) producer_cursor64) (bvadd producer_cursor64 (_ bv160 64))) true)))
(and true $x200)))
(check-sat)
