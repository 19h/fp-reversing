; benchmark generated from python API
(set-info :status unknown)
(declare-fun reader_phase32 () (_ BitVec 32))
(declare-fun reader_pointer64 () (_ BitVec 64))
(assert
 (let (($x352 (= reader_pointer64 (_ bv0 64))))
(let ((?x359 (ite $x352 (_ bv1 32) (_ bv0 32))))
(let ((?x316 (bvand reader_phase32 (_ bv1 32))))
(let ((?x378 (bvxor (bvsub reader_phase32 (_ bv19567 32)) (bvmul (bvxor ?x316 ?x359) (bvsub reader_phase32 (_ bv35461 32))))))
(let ((?x357 (concat (_ bv0 31) (bvxor ((_ extract 0 0) reader_phase32) (ite $x352 (_ bv1 1) (_ bv0 1))))))
(let ((?x382 (bvadd (_ bv4294931835 32) reader_phase32)))
(let ((?x358 (bvadd (_ bv4294947729 32) reader_phase32)))
(and true (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvxor ?x358 (bvmul ?x382 ?x357)))) ?x378) true))))))))))
(check-sat)
