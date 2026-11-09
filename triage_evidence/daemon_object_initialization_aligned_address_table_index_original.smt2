; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_address64 () (_ BitVec 64))
(assert
 (let ((?x124 (bvadd (_ bv56 8) (concat ((_ extract 7 3) init_address64) (_ bv0 3)))))
(let ((?x109 (concat (_ bv1744831232 56) ?x124)))
(let ((?x100 (bvadd (_ bv18446743627032756224 64) ?x109)))
(let (($x98 (and (distinct ?x100 ((_ zero_extend 32) (bvand (bvadd ((_ extract 31 0) init_address64) (_ bv1181566520 32)) (_ bv255 32)))) true)))
(and (= (bvand init_address64 (_ bv7 64)) (_ bv0 64)) $x98))))))
(check-sat)
