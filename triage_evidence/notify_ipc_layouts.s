	.build_version macos, 15, 0	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_notify_contract                ; -- Begin function notify_contract
	.p2align	2
_notify_contract:                       ; @notify_contract
	.cfi_startproc
; %bb.0:
	pacibsp
	stp	x22, x21, [sp, #-48]!           ; 16-byte Folded Spill
	stp	x20, x19, [sp, #16]             ; 16-byte Folded Spill
	stp	x29, x30, [sp, #32]             ; 16-byte Folded Spill
	add	x29, sp, #32
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	.cfi_offset w19, -24
	.cfi_offset w20, -32
	.cfi_offset w21, -40
	.cfi_offset w22, -48
	mov	x19, x2
	mov	x20, x1
	bl	_notify_register_check
	mov	x21, x0
	ldr	w0, [x20]
	mov	x1, x19
	bl	_notify_check
	orr	w0, w0, w21
	ldp	x29, x30, [sp, #32]             ; 16-byte Folded Reload
	ldp	x20, x19, [sp, #16]             ; 16-byte Folded Reload
	ldp	x22, x21, [sp], #48             ; 16-byte Folded Reload
	retab
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
