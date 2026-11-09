; benchmark generated from python API
(set-info :status unknown)
(declare-fun conventions_A64 () (_ BitVec 64))
(declare-fun conventions_cursor64 () (_ BitVec 64))
(declare-fun conventions_context64 () (_ BitVec 64))
(assert
 (let (($x190 (and (distinct (bvadd (_ bv32 64) conventions_cursor64) (bvadd conventions_cursor64 (_ bv32 64))) true)))
(let ((?x218 (bvadd (_ bv450971843056 64) conventions_cursor64)))
(let (($x58 (and (distinct conventions_context64 conventions_context64) true)))
(or $x58 (and (distinct ?x218 ?x218) true) $x190 (and (distinct conventions_A64 conventions_A64) true))))))
(check-sat)
