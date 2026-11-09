; benchmark generated from python API
(set-info :status unknown)
(declare-fun reader_saved26_32 () (_ BitVec 32))
(declare-fun reader_saved24_32 () (_ BitVec 32))
(declare-fun reader_count32 () (_ BitVec 32))
(declare-fun reader_phase32 () (_ BitVec 32))
(assert
 (let ((?x225 (bvadd (_ bv4294900884 32) reader_saved24_32 reader_saved26_32)))
(let (($x218 (= reader_count32 (_ bv0 32))))
(let ((?x496 (bvxor reader_phase32 (ite $x218 ?x225 (_ bv0 32)))))
(let ((?x217 (bvxor reader_phase32 (bvmul ?x225 (ite $x218 (_ bv1 32) (_ bv0 32))))))
(not (= ?x217 ?x496)))))))
(check-sat)
