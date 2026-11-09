; benchmark generated from python API
(set-info :status unknown)
(declare-fun rs_second_hash_return64 () (_ BitVec 64))
(declare-fun rs_existing_tag32 () (_ BitVec 32))
(assert
 (let ((?x1625 ((_ extract 63 32) rs_second_hash_return64)))
(let (($x1678 (= rs_existing_tag32 ?x1625)))
(let ((?x1624 ((_ extract 31 0) (concat (_ bv0 32) ?x1625))))
(and (distinct (= (bvsub ((_ extract 31 0) (concat (_ bv0 32) rs_existing_tag32)) ?x1624) (_ bv0 32)) $x1678) true)))))
(check-sat)
