; benchmark generated from python API
(set-info :status unknown)
(declare-fun reader_pointer64 () (_ BitVec 64))
(assert
 (let (($x365 (and (distinct (bvadd (_ bv160 64) reader_pointer64) (bvadd reader_pointer64 (_ bv160 64))) true)))
(and true $x365)))
(check-sat)
