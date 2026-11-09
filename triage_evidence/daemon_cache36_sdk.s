	.build_version macos, 13, 0	sdk_version 27, 2
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_chip_format_abi                ; -- Begin function chip_format_abi
	.p2align	2
_chip_format_abi:                       ; @chip_format_abi
	.cfi_startproc
; %bb.0:
	sub	sp, sp, #32
	stp	x29, x30, [sp, #16]             ; 16-byte Folded Spill
	add	x29, sp, #16
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	str	x0, [sp]
Lloh0:
	adrp	x2, l__unnamed_cfstring_@PAGE
Lloh1:
	add	x2, x2, l__unnamed_cfstring_@PAGEOFF
	mov	x0, #0                          ; =0x0
	mov	x1, #0                          ; =0x0
	bl	_CFStringCreateWithFormat
	ldp	x29, x30, [sp, #16]             ; 16-byte Folded Reload
	add	sp, sp, #32
	ret
	.loh AdrpAdd	Lloh0, Lloh1
	.cfi_endproc
                                        ; -- End function
	.globl	_identity_format_abi            ; -- Begin function identity_format_abi
	.p2align	2
_identity_format_abi:                   ; @identity_format_abi
	.cfi_startproc
; %bb.0:
	sub	sp, sp, #64
	stp	x29, x30, [sp, #48]             ; 16-byte Folded Spill
	add	x29, sp, #48
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	stp	x3, x4, [sp, #24]
	stp	x1, x2, [sp, #8]
	str	x0, [sp]
Lloh2:
	adrp	x2, l__unnamed_cfstring_.2@PAGE
Lloh3:
	add	x2, x2, l__unnamed_cfstring_.2@PAGEOFF
	mov	x0, #0                          ; =0x0
	mov	x1, #0                          ; =0x0
	bl	_CFStringCreateWithFormat
	ldp	x29, x30, [sp, #48]             ; 16-byte Folded Reload
	add	sp, sp, #64
	ret
	.loh AdrpAdd	Lloh2, Lloh3
	.cfi_endproc
                                        ; -- End function
	.section	__DATA,__data
	.globl	_number_signature               ; @number_signature
	.p2align	3, 0x0
_number_signature:
	.quad	_CFNumberGetValue

	.globl	_format_signature               ; @format_signature
	.p2align	3, 0x0
_format_signature:
	.quad	_CFStringCreateWithFormat

	.section	__TEXT,__cstring,cstring_literals
l_.str:                                 ; @.str
	.asciz	"%qi"

	.section	__DATA,__cfstring
	.p2align	3, 0x0                          ; @_unnamed_cfstring_
l__unnamed_cfstring_:
	.quad	___CFConstantStringClassReference
	.long	1992                            ; 0x7c8
	.space	4
	.quad	l_.str
	.quad	3                               ; 0x3

	.section	__TEXT,__cstring,cstring_literals
l_.str.1:                               ; @.str.1
	.asciz	"%@%@%@%@%@"

	.section	__DATA,__cfstring
	.p2align	3, 0x0                          ; @_unnamed_cfstring_.2
l__unnamed_cfstring_.2:
	.quad	___CFConstantStringClassReference
	.long	1992                            ; 0x7c8
	.space	4
	.quad	l_.str.1
	.quad	10                              ; 0xa

.subsections_via_symbols
