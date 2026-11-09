; benchmark generated from python API
(set-info :status unknown)
(declare-fun rs_destination_byte8 () (_ BitVec 8))
(assert
 (let ((?x18 ((_ extract 31 0) (concat (_ bv0 32) (ite (= ((_ extract 2 0) rs_destination_byte8) (_ bv0 3)) (_ bv268435459 32) (_ bv0 32))))))
(let (($x14 (and (distinct ?x18 (ite (= (bvand rs_destination_byte8 (_ bv7 8)) (_ bv0 8)) (_ bv268435459 32) (_ bv0 32))) true)))
(or $x14 (and (distinct ((_ extract 31 0) (_ bv1 64)) (_ bv1 32)) true)))))
(check-sat)
