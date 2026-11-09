; benchmark generated from python API
(set-info :status unknown)
(declare-fun frame_J64 () (_ BitVec 64))
(declare-fun frame_C64 () (_ BitVec 64))
(declare-fun frame_byte8 () (_ BitVec 8))
(assert
 (let ((?x63 (bvadd frame_C64 frame_J64)))
(let ((?x86 ((_ extract 4 3) frame_byte8)))
(let ((?x88 (concat (_ bv0 26) ?x86 (_ bv0 4))))
(let ((?x72 (bvmul (_ bv4294967295 32) ?x88)))
(let ((?x65 (concat (_ bv0 24) frame_byte8)))
(let (($x28 (and (distinct ((_ extract 7 0) ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv4294967192 32) ?x65 ?x72)))) (bvxor frame_byte8 (_ bv152 8))) true)))
(and true (or $x28 (and (distinct ?x63 ?x63) true))))))))))
(check-sat)
