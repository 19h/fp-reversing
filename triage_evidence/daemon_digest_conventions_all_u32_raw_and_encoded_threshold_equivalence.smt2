; benchmark generated from python API
(set-info :status unknown)
(declare-fun conventions_counter32 () (_ BitVec 32))
(declare-fun conventions_count32 () (_ BitVec 32))
(assert
 (let ((?x139 ((_ extract 5 0) conventions_counter32)))
(let ((?x142 (concat (_ bv0 26) ?x139)))
(let (($x133 (bvule (_ bv4294967232 32) (bvadd (_ bv4294967232 32) conventions_count32 ?x142))))
(let (($x231 (not (= ((_ extract 31 7) (bvadd conventions_count32 ?x142)) (_ bv0 25)))))
(let (($x321 (or $x231 (bvule (_ bv64 7) (bvadd ((_ extract 6 0) conventions_count32) (concat (_ bv0 1) ?x139))))))
(= $x321 $x133)))))))
(check-sat)
