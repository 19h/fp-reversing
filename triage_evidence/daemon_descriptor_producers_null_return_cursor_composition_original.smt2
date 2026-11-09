; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_counter64 () (_ BitVec 64))
(assert
 (let ((?x325 (bvsub producer_counter64 (_ bv160 64))))
(let ((?x371 (bvadd ?x325 (_ bv160 64))))
(let (($x372 (and (distinct (bvshl ((_ zero_extend 48) ((_ extract 15 0) (bvsub ?x371 producer_counter64))) (_ bv4 64)) (_ bv0 64)) true)))
(and true (or (and (distinct ?x371 producer_counter64) true) $x372))))))
(check-sat)
