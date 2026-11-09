; benchmark generated from python API
(set-info :status unknown)
(declare-fun reader_saved24_32 () (_ BitVec 32))
(declare-fun reader_saved26_32 () (_ BitVec 32))
(declare-fun reader_count32 () (_ BitVec 32))
(declare-fun reader_phase32 () (_ BitVec 32))
(assert
 (let (($x218 (= reader_count32 (_ bv0 32))))
(let ((?x224 (ite $x218 (bvadd (bvadd reader_saved26_32 reader_saved24_32) (_ bv4294900884 32)) (_ bv0 32))))
(let ((?x219 (ite $x218 (_ bv1 32) (_ bv0 32))))
(let ((?x225 (bvadd (_ bv4294900884 32) reader_saved24_32 reader_saved26_32)))
(let ((?x223 ((_ extract 31 0) (concat (_ bv0 32) (bvxor reader_phase32 (bvmul ?x225 ?x219))))))
(and true (and (distinct ?x223 (bvxor reader_phase32 ?x224)) true))))))))
(check-sat)
