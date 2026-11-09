(set-option :timeout 30000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun derived_address64 () (_ BitVec 64))
(assert
 (let ((?x7 (bvnot (_ bv7 64))))
(let ((?x14 ((_ sign_extend 32) (bvand (bvadd ((_ extract 31 0) (bvand derived_address64 ?x7)) (_ bv3372290134 32)) (_ bv255 32)))))
(let ((?x15 (bvand ?x14 ?x7)))
(or (and (distinct ?x15 (bvand (bvadd derived_address64 (_ bv80 64)) (_ bv248 64))) true) (bvugt ?x15 (_ bv248 64)) (and (distinct (bvand ?x15 (_ bv7 64)) (_ bv0 64)) true) (bvugt (bvadd ?x15 (_ bv8 64)) (_ bv256 64)))))))
(check-sat)
