(set-logic QF_LIA)
(declare-fun size () Int)
(assert (and (<= 28 size) (<= size 4294967295)))
(define-fun n () Int (- size 28))
; UMULH by 0xaaaaaaaaaaaaaaab followed by LSR 3 is integer division by 2^67.
; n is nonnegative and 32-bit, so the original 128-bit product cannot overflow.
(define-fun native () Int (div (* n 12297829382473034411) 147573952589676412928))
(assert (not (= native (div n 12))))
(check-sat)
