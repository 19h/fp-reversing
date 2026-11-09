; benchmark generated from python API
(set-info :status unknown)
(declare-fun reader_pointer64 () (_ BitVec 64))
(declare-fun reader_phase32 () (_ BitVec 32))
(assert
 (let (($x62 (and (distinct reader_pointer64 reader_pointer64) true)))
(let ((?x124 (bvadd reader_phase32 (_ bv5492 32))))
(let (($x169 (or (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv5492 32) reader_phase32))) ?x124) true) $x62)))
(and true $x169)))))
(check-sat)
