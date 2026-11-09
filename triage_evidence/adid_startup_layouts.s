	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_adid_backup_query_ABI          ; -- Begin function adid_backup_query_ABI
	.p2align	2
_adid_backup_query_ABI:                 ; @adid_backup_query_ABI
	.cfi_startproc
; %bb.0:
	mov	x1, #0                          ; =0x0
	b	_CSBackupIsItemExcluded
	.cfi_endproc
                                        ; -- End function
	.globl	_adid_backup_set_ABI            ; -- Begin function adid_backup_set_ABI
	.p2align	2
_adid_backup_set_ABI:                   ; @adid_backup_set_ABI
	.cfi_startproc
; %bb.0:
	mov	w1, #1                          ; =0x1
	mov	w2, #0                          ; =0x0
	b	_CSBackupSetItemExcluded
	.cfi_endproc
                                        ; -- End function
	.globl	_adid_open_source_ABI           ; -- Begin function adid_open_source_ABI
	.p2align	2
_adid_open_source_ABI:                  ; @adid_open_source_ABI
	.cfi_startproc
; %bb.0:
	mov	w1, #272                        ; =0x110
	b	_open
	.cfi_endproc
                                        ; -- End function
	.globl	_adid_open_destination_ABI      ; -- Begin function adid_open_destination_ABI
	.p2align	2
_adid_open_destination_ABI:             ; @adid_open_destination_ABI
	.cfi_startproc
; %bb.0:
	pacibsp
	sub	sp, sp, #32
	stp	x29, x30, [sp, #16]             ; 16-byte Folded Spill
	add	x29, sp, #16
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	mov	w8, #438                        ; =0x1b6
	str	x8, [sp]
	mov	w1, #801                        ; =0x321
	bl	_open
	ldp	x29, x30, [sp, #16]             ; 16-byte Folded Reload
	add	sp, sp, #32
	retab
	.cfi_endproc
                                        ; -- End function
	.globl	_adid_vmm_byte                  ; -- Begin function adid_vmm_byte
	.p2align	2
_adid_vmm_byte:                         ; @adid_vmm_byte
	.cfi_startproc
; %bb.0:
	cmp	w1, #1
	ccmp	w0, #0, #0, eq
	mov	w8, #9                          ; =0x9
	cinc	w0, w8, eq
	ret
	.cfi_endproc
                                        ; -- End function
	.section	__TEXT,__const
	.globl	_adid_startup_layout            ; @adid_startup_layout
	.p2align	3, 0x0
_adid_startup_layout:
	.quad	2168                            ; 0x878
	.quad	64                              ; 0x40
	.quad	72                              ; 0x48
	.quad	88                              ; 0x58
	.quad	1112                            ; 0x458
	.quad	61440                           ; 0xf000
	.quad	16384                           ; 0x4000
	.quad	32768                           ; 0x8000
	.quad	-4                              ; 0xfffffffffffffffc
	.quad	1                               ; 0x1
	.quad	32                              ; 0x20
	.quad	2                               ; 0x2
	.quad	32                              ; 0x20
	.quad	1                               ; 0x1
	.quad	1                               ; 0x1
	.quad	0                               ; 0x0
	.quad	1                               ; 0x1
	.quad	16                              ; 0x10
	.quad	32                              ; 0x20
	.quad	256                             ; 0x100
	.quad	512                             ; 0x200
	.quad	32768                           ; 0x8000
	.quad	16777216                        ; 0x1000000
	.quad	-6                              ; 0xfffffffffffffffa
	.quad	4                               ; 0x4
	.quad	15                              ; 0xf

.subsections_via_symbols
