	.build_version macos, 13, 0	sdk_version 27, 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_rpc502_audit_abi_probe         ; -- Begin function rpc502_audit_abi_probe
	.p2align	2
_rpc502_audit_abi_probe:                ; @rpc502_audit_abi_probe
	.cfi_startproc
; %bb.0:
	pacibsp
	.cfi_negate_ra_state
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
