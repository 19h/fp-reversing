; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_map_word64 () (_ BitVec 64))
(assert
 (let (($x572 (or (not (= ((_ extract 63 32) qs_map_word64) (_ bv0 32))) (bvule (_ bv4026531841 32) ((_ extract 31 0) qs_map_word64)))))
(let ((?x578 (ite $x572 (_ bv68 32) (_ bv64 32))))
(let (($x542 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x578)) (ite (bvult qs_map_word64 (_ bv4026531841 64)) (_ bv64 32) (_ bv68 32))) true)))
(let (($x529 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (ite $x572 (_ bv60 32) (_ bv56 32)))) (ite (bvult qs_map_word64 (_ bv4026531841 64)) (_ bv56 32) (_ bv60 32))) true)))
(or $x529 $x542))))))
(check-sat)
