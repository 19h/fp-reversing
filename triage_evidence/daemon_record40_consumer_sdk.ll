; ModuleID = '/Users/___/dev/dylex/extracted/triage_evidence/daemon_record40_consumer_sdk.c'
source_filename = "/Users/___/dev/dylex/extracted/triage_evidence/daemon_record40_consumer_sdk.c"
target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"
target triple = "arm64e-apple-macosx11.0.0"

%struct.audit_token_t = type { [8 x i32] }

; Function Attrs: nounwind ssp uwtable(sync)
define ptr @record40_string(ptr noundef %0, ptr noundef %1, ptr noundef %2) local_unnamed_addr #0 {
  %4 = tail call ptr @CFStringCreateWithCStringNoCopy(ptr noundef %0, ptr noundef %1, i32 noundef 1536, ptr noundef %2) #4
  ret ptr %4
}

declare ptr @CFStringCreateWithCStringNoCopy(ptr noundef, ptr noundef, i32 noundef, ptr noundef) local_unnamed_addr #1

; Function Attrs: nounwind ssp uwtable(sync)
define ptr @record40_task(ptr noundef %0, ptr noundef readonly captures(none) %1) local_unnamed_addr #0 {
  %3 = alloca %struct.audit_token_t, align 4
  call void @llvm.lifetime.start.p0(i64 32, ptr nonnull %3) #4
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 4 dereferenceable(32) %3, ptr noundef nonnull align 4 dereferenceable(32) %1, i64 32, i1 false), !tbaa.struct !9
  %4 = call ptr @SecTaskCreateWithAuditToken(ptr noundef %0, ptr noundef nonnull %3) #4
  call void @llvm.lifetime.end.p0(i64 32, ptr nonnull %3) #4
  ret ptr %4
}

declare ptr @SecTaskCreateWithAuditToken(ptr noundef, ptr noundef) local_unnamed_addr #1

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg, ptr captures(none)) #2

; Function Attrs: mustprogress nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias writeonly captures(none), ptr noalias readonly captures(none), i64, i1 immarg) #3

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg, ptr captures(none)) #2

; Function Attrs: nounwind ssp uwtable(sync)
define ptr @record40_query(ptr noundef %0, ptr noundef %1, ptr noundef %2) local_unnamed_addr #0 {
  %4 = tail call ptr @SecTaskCopyValueForEntitlement(ptr noundef %0, ptr noundef %1, ptr noundef %2) #4
  ret ptr %4
}

declare ptr @SecTaskCopyValueForEntitlement(ptr noundef, ptr noundef, ptr noundef) local_unnamed_addr #1

attributes #0 = { nounwind ssp uwtable(sync) "checked-pointer-arith"="compatible" "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-indirect-gotos" "ptrauth-returns" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+altnzcv,+bti,+ccdp,+ccidx,+ccpp,+complxnum,+crc,+dit,+dotprod,+flagm,+fp-armv8,+fp16fml,+fptoint,+fullfp16,+jsconv,+lse,+neon,+pauth,+perfmon,+predres,+ras,+rcpc,+rdm,+sb,+sha2,+sha3,+specrestrict,+ssbs,+v8.1a,+v8.2a,+v8.3a,+v8.4a,+v8.5a,+v8a" }
attributes #1 = { "checked-pointer-arith"="compatible" "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-indirect-gotos" "ptrauth-returns" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+altnzcv,+bti,+ccdp,+ccidx,+ccpp,+complxnum,+crc,+dit,+dotprod,+flagm,+fp-armv8,+fp16fml,+fptoint,+fullfp16,+jsconv,+lse,+neon,+pauth,+perfmon,+predres,+ras,+rcpc,+rdm,+sb,+sha2,+sha3,+specrestrict,+ssbs,+v8.1a,+v8.2a,+v8.3a,+v8.4a,+v8.5a,+v8a" }
attributes #2 = { mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { mustprogress nocallback nofree nounwind willreturn memory(argmem: readwrite) }
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
!9 = !{i64 0, i64 32, !10}
!10 = !{!11, !11, i64 0}
!11 = !{!"omnipotent char", !12, i64 0}
!12 = !{!"Simple C/C++ TBAA"}
