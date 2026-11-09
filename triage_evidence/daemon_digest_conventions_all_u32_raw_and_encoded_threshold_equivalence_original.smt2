; benchmark generated from python API
(set-info :status unknown)
(declare-fun conventions_counter32 () (_ BitVec 32))
(declare-fun conventions_count32 () (_ BitVec 32))
(assert
 (let ((?x78 (bvand conventions_counter32 (_ bv63 32))))
(let ((?x83 (bvadd conventions_count32 ?x78)))
(and (distinct (bvult ?x83 (_ bv64 32)) (not (bvult (bvsub ?x83 (_ bv64 32)) (_ bv4294967232 32)))) true))))
(check-sat)
