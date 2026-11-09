; benchmark generated from python API
(set-info :status unknown)
(declare-fun API_status32 () (_ BitVec 32))
(assert
 (let ((?x180 (concat ((_ extract 31 31) API_status32) (bvnot ((_ extract 30 23) API_status32)) ((_ extract 22 22) API_status32) (bvnot ((_ extract 21 15) API_status32)) ((_ extract 14 13) API_status32) (bvnot ((_ extract 12 10) API_status32)) ((_ extract 9 9) API_status32) (bvnot ((_ extract 8 8) API_status32)) ((_ extract 7 6) API_status32) (bvnot ((_ extract 5 4) API_status32)) ((_ extract 3 3) API_status32) (bvnot ((_ extract 2 0) API_status32)))))
(let ((?x178 ((_ extract 2 0) API_status32)))
(let ((?x176 ((_ extract 5 4) API_status32)))
(let ((?x174 ((_ extract 8 8) API_status32)))
(let ((?x172 ((_ extract 12 10) API_status32)))
(let ((?x170 ((_ extract 21 15) API_status32)))
(let ((?x168 ((_ extract 30 23) API_status32)))
(let ((?x212 (concat ?x168 (_ bv0 1) ?x170 (_ bv0 2) ?x172 (_ bv0 1) ?x174 (_ bv0 2) ?x176 (_ bv0 1) ?x178 (_ bv0 1))))
(and (distinct ((_ extract 31 0) ((_ zero_extend 32) (bvadd (_ bv3967646700 32) ?x212 ?x180))) (bvadd API_status32 (_ bv1815943459 32))) true))))))))))
(check-sat)
