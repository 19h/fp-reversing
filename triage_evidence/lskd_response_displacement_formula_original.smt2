; benchmark generated from python API
(set-info :status unknown)
(declare-fun displacement_seed64 () (_ BitVec 64))
(declare-fun displacement_cell32 () (_ BitVec 32))
(assert
 (let ((?x374 ((_ zero_extend 32) (bvand (bvsub displacement_cell32 ((_ extract 31 0) displacement_seed64)) (_ bv65535 32)))))
(let ((?x340 ((_ extract 15 0) displacement_seed64)))
(let ((?x318 (bvmul (_ bv65535 16) ?x340)))
(let ((?x330 ((_ extract 15 0) displacement_cell32)))
(let ((?x319 (bvadd ?x330 ?x318)))
(let ((?x365 (concat (_ bv0 44) ?x319 (_ bv0 4))))
(and (distinct ?x365 (bvshl ?x374 (_ bv4 64))) true))))))))
(check-sat)
