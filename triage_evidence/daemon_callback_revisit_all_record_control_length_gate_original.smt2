; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_length16 () (_ BitVec 16))
(declare-fun callback_output64 () (_ BitVec 64))
(declare-fun callback_control32 () (_ BitVec 32))
(assert
 (let (($x233 (and (and (distinct callback_output64 (_ bv0 64)) true) (and (distinct callback_length16 (_ bv0 16)) true))))
(let (($x267 (= ((_ extract 31 0) (_ bv5435 64)) ((_ extract 31 0) (concat (_ bv0 48) (bvadd (_ bv5435 16) callback_length16))))))
(let (($x247 (and (distinct (ite (not (= (_ bv0 64) callback_output64)) $x267 true) (not $x233)) true)))
(let (($x220 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) callback_control32)) callback_control32) true)))
(and true (or $x220 $x247)))))))
(check-sat)
