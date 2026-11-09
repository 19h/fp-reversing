	.build_version macos, 11, 0	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_extract_pid                    ; -- Begin function extract_pid
	.p2align	2
_extract_pid:                           ; @extract_pid
	.cfi_startproc
; %bb.0:
	pacibsp
	sub	sp, sp, #64
	stp	x29, x30, [sp, #48]             ; 16-byte Folded Spill
	add	x29, sp, #48
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	mov	x6, x1
	ldp	q0, q1, [x0]
	stp	q0, q1, [sp, #16]
	str	xzr, [sp]
	add	x0, sp, #16
	mov	x1, #0                          ; =0x0
	mov	x2, #0                          ; =0x0
	mov	x3, #0                          ; =0x0
	mov	x4, #0                          ; =0x0
	mov	x5, #0                          ; =0x0
	mov	x7, #0                          ; =0x0
	bl	_audit_token_to_au32
	ldp	x29, x30, [sp, #48]             ; 16-byte Folded Reload
	add	sp, sp, #64
	retab
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
