; benchmark generated from python API
(set-info :status unknown)
(declare-fun output_word32 () (_ BitVec 32))
(declare-fun output_root64 () (_ BitVec 64))
(assert
 (let (($x628 (= output_word32 (_ bv2336081489 32))))
(let ((?x540 (ite $x628 (_ bv1 8) (_ bv0 8))))
(let (($x562 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) output_word32)) output_word32) true)))
(let (($x620 (and (distinct output_root64 output_root64) true)))
(let (($x490 (or $x620 $x562 (and (distinct ((_ extract 7 0) ((_ extract 31 0) (concat (_ bv0 32) (ite $x628 (_ bv1 32) (_ bv0 32))))) ?x540) true))))
(and true $x490)))))))
(check-sat)
