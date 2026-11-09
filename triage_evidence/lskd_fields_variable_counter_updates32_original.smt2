; benchmark generated from python API
(set-info :status unknown)
(declare-fun wire_length16 () (_ BitVec 16))
(declare-fun field_cursor32 () (_ BitVec 32))
(declare-fun field_count32 () (_ BitVec 32))
(assert
 (let ((?x2891 ((_ extract 31 0) ((_ zero_extend 32) (bvadd (_ bv4 32) field_cursor32 (concat (_ bv0 16) wire_length16))))))
(let (($x2748 (and (distinct ?x2891 (bvadd (bvadd field_cursor32 (_ bv4 32)) ((_ zero_extend 16) wire_length16))) true)))
(let (($x2733 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (bvadd (_ bv1 32) field_count32))) (bvadd field_count32 (_ bv1 32))) true)))
(or $x2733 $x2748)))))
(check-sat)
