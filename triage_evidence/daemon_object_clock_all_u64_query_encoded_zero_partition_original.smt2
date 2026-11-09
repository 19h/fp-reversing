; benchmark generated from python API
(set-info :status unknown)
(declare-fun clock_return64 () (_ BitVec 64))
(assert
 (let (($x169 (= clock_return64 (_ bv16409013220067847612 64))))
(let ((?x218 (ite $x169 (_ bv24342 32) (_ bv24402 32))))
(let ((?x199 ((_ extract 31 0) (concat (_ bv95 56) (ite $x169 (_ bv0 2) (_ bv1 2)) (_ bv2 3) (ite $x169 (_ bv1 1) (_ bv0 1)) (_ bv2 2)))))
(or (and (distinct ((_ extract 31 0) (_ bv7447 64)) (_ bv7447 32)) true) (and (distinct ?x199 ?x218) true))))))
(check-sat)
