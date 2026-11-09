; benchmark generated from python API
(set-info :status unknown)
(declare-fun rd_object_counter32 () (_ BitVec 32))
(assert
 (let (($x21 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) rd_object_counter32)) rd_object_counter32) true)))
(let ((?x18 (bvsub rd_object_counter32 (_ bv1 32))))
(let (($x19 (and (distinct (bvadd rd_object_counter32 ((_ extract 31 0) (_ bv4294967295 64))) ?x18) true)))
(or $x19 $x21 $x19 $x21)))))
(check-sat)
