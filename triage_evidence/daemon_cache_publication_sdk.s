	.build_version macos, 13, 0	sdk_version 27, 2
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_release_then_free              ; -- Begin function release_then_free
	.p2align	2
_release_then_free:                     ; @release_then_free
	.cfi_startproc
; %bb.0:
	stp	x20, x19, [sp, #-32]!           ; 16-byte Folded Spill
	stp	x29, x30, [sp, #16]             ; 16-byte Folded Spill
	add	x29, sp, #16
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	.cfi_offset w19, -24
	.cfi_offset w20, -32
	mov	x19, x1
	bl	_CFRelease
	mov	x0, x19
	ldp	x29, x30, [sp, #16]             ; 16-byte Folded Reload
	ldp	x20, x19, [sp], #32             ; 16-byte Folded Reload
	b	_free
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
