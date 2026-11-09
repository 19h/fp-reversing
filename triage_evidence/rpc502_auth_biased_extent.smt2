(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun extent64 () (_ BitVec 64))
(declare-fun next_index64 () (_ BitVec 64))
(assert
 (let ((?x124 (bvadd extent64 (_ bv1344417994 64))))
(let (($x127 (bvult ?x124 (_ bv1344417994 64))))
(let (($x135 (ite (and (distinct (bvugt (bvadd (bvsub next_index64 (_ bv1 64)) (_ bv1 64)) (_ bv18446744072365133621 64)) $x127) true) $x127 (bvult (bvadd (bvsub next_index64 (_ bv1 64)) (_ bv1344417995 64)) ?x124))))
(and (distinct $x135 (bvult next_index64 extent64)) true)))))
(check-sat)
