; benchmark generated from python API
(set-info :status unknown)
(declare-fun kmig_converted_map64 () (_ BitVec 64))
(declare-fun kmig_VM_return64 () (_ BitVec 64))
(assert
 (let (($x126 (and (distinct (_ bv4294967296 64) (_ bv4294967296 64)) true)))
(let (($x104 (and (distinct kmig_converted_map64 kmig_converted_map64) true)))
(or (and (distinct ((_ extract 31 0) kmig_VM_return64) ((_ extract 31 0) kmig_VM_return64)) true) $x104 $x126))))
(check-sat)
