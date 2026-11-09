; benchmark generated from python API
(set-info :status unknown)
(declare-fun destruct_counter64 () (_ BitVec 64))
(assert
 (let ((?x548 ((_ extract 0 0) destruct_counter64)))
(let ((?x1036 (concat (bvnot ((_ extract 7 7) (bvadd (_ bv366 32) ((_ extract 31 0) destruct_counter64)))) ((_ extract 6 6) (bvadd (_ bv366 32) ((_ extract 31 0) destruct_counter64))) (bvnot ((_ extract 5 3) (bvadd (_ bv366 32) ((_ extract 31 0) destruct_counter64)))) ((_ extract 2 2) (bvadd (_ bv366 32) ((_ extract 31 0) destruct_counter64))) (bvnot ((_ extract 1 1) (bvadd (_ bv366 32) ((_ extract 31 0) destruct_counter64)))) ?x548)))
(let ((?x235 ((_ extract 7 0) destruct_counter64)))
(let ((?x177 (bvadd (_ bv127 8) ?x235)))
(let ((?x248 (concat (bvnot ((_ extract 7 7) (bvadd (_ bv110 32) ((_ extract 31 0) destruct_counter64)))) ((_ extract 6 6) (bvadd (_ bv110 32) ((_ extract 31 0) destruct_counter64))) (bvnot ((_ extract 5 3) (bvadd (_ bv110 32) ((_ extract 31 0) destruct_counter64)))) ((_ extract 2 2) (bvadd (_ bv110 32) ((_ extract 31 0) destruct_counter64))) (bvnot ((_ extract 1 1) (bvadd (_ bv110 32) ((_ extract 31 0) destruct_counter64)))) ?x548)))
(not (= (bvmul ?x177 ?x248) (bvmul ?x177 ?x1036)))))))))
(check-sat)
