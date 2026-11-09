; benchmark generated from python API
(set-info :status unknown)
(declare-fun publication_flag8 () (_ BitVec 8))
(declare-fun publication_cursor64 () (_ BitVec 64))
(assert
 (let ((?x3619 (ite (= publication_flag8 (_ bv0 8)) (_ bv0 32) (_ bv20 32))))
(let ((?x3273 (concat (_ bv0 32) ?x3619)))
(let ((?x3714 (bvadd (_ bv18446744073709551552 64) publication_cursor64)))
(let (($x3440 (or (and (distinct ((_ extract 31 0) ?x3273) ?x3619) true) (and (distinct ?x3714 (bvsub publication_cursor64 (_ bv64 64))) true) (and (distinct ?x3273 ((_ zero_extend 32) ?x3619)) true))))
(and true $x3440))))))
(check-sat)
