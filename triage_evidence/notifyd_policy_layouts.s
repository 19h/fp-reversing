	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_source_access                  ; -- Begin function source_access
	.p2align	2
_source_access:                         ; @source_access
	.cfi_startproc
; %bb.0:
	tst	w1, w0
	b.eq	LBB0_3
; %bb.1:
	cmp	w2, w4
	b.ne	LBB0_3
; %bb.2:
	mov	w0, #1                          ; =0x1
	ret
LBB0_3:
	cmp	w3, w5
	b.ne	LBB0_6
; %bb.4:
	tst	w0, w1, lsl #4
	b.eq	LBB0_6
; %bb.5:
	mov	w0, #1                          ; =0x1
	ret
LBB0_6:
	tst	w0, w1, lsl #8
	cset	w0, ne
	ret
	.cfi_endproc
                                        ; -- End function
	.globl	_audit_by_value_shape           ; -- Begin function audit_by_value_shape
	.p2align	2
_audit_by_value_shape:                  ; @audit_by_value_shape
	.cfi_startproc
; %bb.0:
	pacibsp
	sub	sp, sp, #48
	stp	x29, x30, [sp, #32]             ; 16-byte Folded Spill
	add	x29, sp, #32
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	ldp	q0, q1, [x0]
	stp	q0, q1, [sp]
	mov	x0, sp
	bl	_audit_token_to_euid
	ldp	x29, x30, [sp, #32]             ; 16-byte Folded Reload
	add	sp, sp, #48
	retab
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
