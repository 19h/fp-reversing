; ModuleID = '/Users/___/dev/dylex/extracted/triage_evidence/daemon_client_object_sdk.c'
source_filename = "/Users/___/dev/dylex/extracted/triage_evidence/daemon_client_object_sdk.c"
target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"
target triple = "arm64e-apple-macosx11.0.0"

; Function Attrs: mustprogress nofree norecurse nosync nounwind ssp willreturn memory(argmem: write) uwtable(sync)
define void @initialize32(ptr noundef writeonly captures(none) initializes((0, 28)) %0) local_unnamed_addr #0 {
  store ptr null, ptr %0, align 8, !tbaa !9
  %2 = getelementptr inbounds nuw i8, ptr %0, i64 24, !annotation !15
  store i32 -1958885807, ptr %2, align 8, !tbaa !16
  %3 = getelementptr inbounds nuw i8, ptr %0, i64 16, !annotation !15
  store i32 -1958885807, ptr %3, align 8, !tbaa !17
  %4 = getelementptr inbounds nuw i8, ptr %0, i64 12, !annotation !15
  store i32 -1958885807, ptr %4, align 4, !tbaa !18
  %5 = getelementptr inbounds nuw i8, ptr %0, i64 8, !annotation !15
  store i32 -1958885807, ptr %5, align 8, !tbaa !19
  %6 = getelementptr inbounds nuw i8, ptr %0, i64 20, !annotation !15
  store i32 1300829916, ptr %6, align 4, !tbaa !20
  ret void
}

; Function Attrs: mustprogress nofree norecurse nosync nounwind ssp willreturn memory(argmem: write) uwtable(sync)
define void @initialize16(ptr noundef writeonly captures(none) initializes((0, 16)) %0) local_unnamed_addr #0 {
  tail call void @llvm.memset.p0.i64(ptr noundef nonnull align 8 dereferenceable(16) %0, i8 0, i64 16, i1 false)
  ret void
}

; Function Attrs: nounwind ssp uwtable(sync)
define i32 @cleanup_signature_probe(i32 noundef %0, ptr noundef readonly captures(none) %1) local_unnamed_addr #1 {
  %3 = load ptr, ptr %1, align 8, !tbaa !9
  %4 = ptrtoint ptr %3 to i64
  %5 = getelementptr inbounds nuw i8, ptr %1, i64 8, !annotation !15
  %6 = load i32, ptr %5, align 8, !tbaa !19
  %7 = xor i32 %6, -1958885807
  %8 = zext i32 %7 to i64
  %9 = tail call i32 @vm_deallocate(i32 noundef %0, i64 noundef %4, i64 noundef %8) #4
  ret i32 %9
}

declare i32 @vm_deallocate(i32 noundef, i64 noundef, i64 noundef) local_unnamed_addr #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr writeonly captures(none), i8, i64, i1 immarg) #3

attributes #0 = { mustprogress nofree norecurse nosync nounwind ssp willreturn memory(argmem: write) uwtable(sync) "checked-pointer-arith"="compatible" "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-indirect-gotos" "ptrauth-returns" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+altnzcv,+bti,+ccdp,+ccidx,+ccpp,+complxnum,+crc,+dit,+dotprod,+flagm,+fp-armv8,+fp16fml,+fptoint,+fullfp16,+jsconv,+lse,+neon,+pauth,+perfmon,+predres,+ras,+rcpc,+rdm,+sb,+sha2,+sha3,+specrestrict,+ssbs,+v8.1a,+v8.2a,+v8.3a,+v8.4a,+v8.5a,+v8a" }
attributes #1 = { nounwind ssp uwtable(sync) "checked-pointer-arith"="compatible" "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-indirect-gotos" "ptrauth-returns" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+altnzcv,+bti,+ccdp,+ccidx,+ccpp,+complxnum,+crc,+dit,+dotprod,+flagm,+fp-armv8,+fp16fml,+fptoint,+fullfp16,+jsconv,+lse,+neon,+pauth,+perfmon,+predres,+ras,+rcpc,+rdm,+sb,+sha2,+sha3,+specrestrict,+ssbs,+v8.1a,+v8.2a,+v8.3a,+v8.4a,+v8.5a,+v8a" }
attributes #2 = { "checked-pointer-arith"="compatible" "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-indirect-gotos" "ptrauth-returns" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+altnzcv,+bti,+ccdp,+ccidx,+ccpp,+complxnum,+crc,+dit,+dotprod,+flagm,+fp-armv8,+fp16fml,+fptoint,+fullfp16,+jsconv,+lse,+neon,+pauth,+perfmon,+predres,+ras,+rcpc,+rdm,+sb,+sha2,+sha3,+specrestrict,+ssbs,+v8.1a,+v8.2a,+v8.3a,+v8.4a,+v8.5a,+v8a" }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #4 = { nounwind }

!llvm.module.flags = !{!0, !1, !2, !5, !6, !7}
!llvm.ident = !{!8}

!0 = !{i32 2, !"SDK Version", [2 x i32] [i32 27, i32 2]}
!1 = !{i32 1, !"wchar_size", i32 4}
!2 = !{i32 6, !"ptrauth.abi-version", !3}
!3 = !{!4}
!4 = !{i32 0, i1 false}
!5 = !{i32 8, !"PIC Level", i32 2}
!6 = !{i32 7, !"uwtable", i32 1}
!7 = !{i32 7, !"frame-pointer", i32 1}
!8 = !{!"Apple clang version 21.0.0 (clang-2100.3.34.2)"}
!9 = !{!10, !11, i64 0}
!10 = !{!"client_object32", !11, i64 0, !14, i64 8, !14, i64 12, !14, i64 16, !14, i64 20, !14, i64 24, !12, i64 28}
!11 = !{!"any pointer", !12, i64 0}
!12 = !{!"omnipotent char", !13, i64 0}
!13 = !{!"Simple C/C++ TBAA"}
!14 = !{!"int", !12, i64 0}
!15 = !{!"cpa-safe"}
!16 = !{!10, !14, i64 24}
!17 = !{!10, !14, i64 16}
!18 = !{!10, !14, i64 12}
!19 = !{!10, !14, i64 8}
!20 = !{!10, !14, i64 20}
