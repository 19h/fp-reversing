; benchmark generated from python API
(set-info :status unknown)
(declare-fun frame_H32 () (_ BitVec 32))
(assert
 (let ((?x61 (bvadd (_ bv64 32) (bvmul (_ bv4294967295 32) (concat (_ bv0 26) ((_ extract 5 0) frame_H32))))))
(let ((?x52 (concat (_ bv0 32) ?x61)))
(let ((?x53 (bvadd (_ bv18446744073709551615 64) ?x52)))
(let (($x57 (and (distinct ?x53 (bvsub ((_ zero_extend 32) (bvsub (_ bv64 32) (bvand frame_H32 (_ bv63 32)))) (_ bv1 64))) true)))
(let (($x47 (or (and (distinct ((_ extract 31 0) (_ bv29111 64)) (_ bv29111 32)) true) (and (distinct ((_ extract 31 0) (_ bv14 64)) (_ bv14 32)) true) (and (distinct ((_ extract 31 0) ?x52) (bvsub (_ bv64 32) (bvand frame_H32 (_ bv63 32)))) true) $x57 (and (distinct (_ bv4306736140 64) (_ bv4306736140 64)) true))))
(and true $x47)))))))
(check-sat)
