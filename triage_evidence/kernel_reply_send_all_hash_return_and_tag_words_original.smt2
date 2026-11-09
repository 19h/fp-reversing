; benchmark generated from python API
(set-info :status unknown)
(declare-fun rs_second_hash_return64 () (_ BitVec 64))
(declare-fun rs_first_hash_return64 () (_ BitVec 64))
(declare-fun rs_header_pointer64 () (_ BitVec 64))
(assert
 (let ((?x1625 ((_ extract 63 32) rs_second_hash_return64)))
(let ((?x1624 ((_ extract 31 0) (concat (_ bv0 32) ?x1625))))
(let (($x58 (and (distinct rs_header_pointer64 rs_header_pointer64) true)))
(or $x58 (and (distinct (_ bv68 64) (_ bv68 64)) true) (and (distinct rs_first_hash_return64 rs_first_hash_return64) true) (and (distinct (_ bv1 64) (_ bv1 64)) true) (and (distinct ?x1624 ?x1625) true))))))
(check-sat)
