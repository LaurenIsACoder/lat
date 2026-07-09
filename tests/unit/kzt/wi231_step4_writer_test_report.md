# WI-231 Step4 writer 接线白盒测试报告

## Summary

- worktree: `/home/loongson/work/code/latu-worktrees/kzt-step4-wi231-writer-tests-20260709093324`
- branch: `lauren/kzt-step4-wi231-writer-tests-20260709093324`
- base commit: `20dec00bac069e77a07d30a6d43a24ce34882f17`
- 测试目标: `kzt-rela-immediate-candidate`
- 结论: debug 与 release-style 构建下均通过，`WI231_TC` trace 覆盖 writer success、planner 非批准/错误、writer fail-open、GLOB_DAT/非目标/lazy skip writer。
- 草案说明: 当前基线中 `RelocateElfRELAPlanImmediateJumpSlot()` 只调用 immediate planner，尚未暴露 WI-230 的生产接线接口。本报告对应的测试在 unit 中用白盒 contract harness 模拟 Step4 接线顺序，后续 WI-230 提供真实接口后，应将 harness 替换为生产入口调用。

## Checklist

- [x] 测试证据包含 command。
- [x] 测试证据包含 summary。
- [x] 测试证据包含 stdout/raw output。
- [x] 测试证据包含 exit_code。
- [x] 测试点直接覆盖 WI-230/WI-231 writer 接线验收，不只复用 Step3 writer 通用单测。
- [x] 未修改生产逻辑文件。
- [x] 未 push，未创建远端 PR，未直接修改 AgentsFlow gate。

## Debug Command

```sh
cd /home/loongson/work/code/latu-worktrees/kzt-step4-wi231-writer-tests-20260709093324
rm -rf build64-dbg
mkdir -p build64-dbg
cd build64-dbg
export CFLAGS="-Wno-error=unused-but-set-variable -Wno-error=unused-function  -Wformat -Werror=format-y2k"
../configure --target-list=x86_64-linux-user --enable-latx --enable-debug --optimize-O1 --extra-ldflags=-ldl --enable-kzt --disable-docs
ninja tests/unit/kzt-rela-immediate-candidate
cd ..
meson test -C build64-dbg kzt-rela-immediate-candidate --print-errorlogs -v
```

## Debug Exit Code

```text
0
```

## Debug Stdout Raw Output

```text
ninja: Entering directory `/home/loongson/work/code/latu-worktrees/kzt-step4-wi231-writer-tests-20260709093324/build64-dbg'
ninja: no work to do.
1/1 kzt-rela-immediate-candidate RUNNING
>>> MALLOC_PERTURB_=97 MSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_summary=1:print_stacktrace=1 UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_summary=1:print_stacktrace=1 MESON_TEST_ITERATION=1 ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_summary=1 /home/loongson/work/code/latu-worktrees/kzt-step4-wi231-writer-tests-20260709093324/build64-dbg/tests/unit/kzt-rela-immediate-candidate
WI231_TC tc=approved-writer-success-skips-legacy plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=0 skip_legacy=1 result=APPLIED failure=NONE reads=2 writer_writes=1 final=0x7200004560
WI231_TC tc=planner-unsupported-keeps-legacy plan_status=1 plan_reason=0 decision=UNSUPPORTED writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300003333
WI231_TC tc=planner-rejected-keeps-legacy plan_status=1 plan_reason=0 decision=REJECTED writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300003333
WI231_TC tc=planner-deferred-keeps-legacy plan_status=1 plan_reason=0 decision=DEFERRED writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300003333
WI231_TC tc=planner-error-keeps-legacy plan_status=2 plan_reason=8 decision=ERROR writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300003333
WI231_TC tc=writer-expected-mismatch-fail-open plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=1 skip_legacy=0 result=FAIL_OPEN failure=EXPECTED_MISMATCH reads=1 writer_writes=0 final=0x7300004444
WI231_TC tc=writer-write-fail-fail-open plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=1 skip_legacy=0 result=FAIL_OPEN failure=WRITE_FAILED reads=1 writer_writes=1 final=0x7300004444
WI231_TC tc=writer-verify-fail-fail-open plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=1 skip_legacy=0 result=FAIL_OPEN failure=VERIFY_FAILED reads=2 writer_writes=2 final=0x7300004444
WI231_TC tc=writer-rollback-fail-fail-open plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=1 skip_legacy=0 result=FAIL_OPEN failure=ROLLBACK_FAILED reads=2 writer_writes=2 final=0x7300004444
WI231_TC tc=non-target-relocation-skips-writer plan_status=0 plan_reason=2 decision=(none) writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300005555
WI231_TC tc=glob-dat-skips-writer plan_status=0 plan_reason=2 decision=(none) writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300005555
WI231_TC tc=lazy-deferred-skips-writer plan_status=0 plan_reason=3 decision=(none) writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300005555
1/1 kzt-rela-immediate-candidate OK              0.01s

Ok:                 1
Expected Fail:      0
Fail:               0
Unexpected Pass:    0
Skipped:            0
Timeout:            0
```

## Release-Style Command

```sh
cd /home/loongson/work/code/latu-worktrees/kzt-step4-wi231-writer-tests-20260709093324
rm -rf build64
mkdir -p build64
cd build64
export CFLAGS="-Wno-error=unused-but-set-variable -Wno-error=unused-function  -Wformat -Werror=format-y2k"
../configure --target-list=x86_64-linux-user --enable-latx --disable-debug-info --optimize-O1 --extra-ldflags=-ldl --enable-kzt --disable-docs
ninja tests/unit/kzt-rela-immediate-candidate
cd ..
meson test -C build64 kzt-rela-immediate-candidate --print-errorlogs -v
```

## Release-Style Exit Code

```text
0
```

## Release-Style Stdout Raw Output

```text
ninja: Entering directory `/home/loongson/work/code/latu-worktrees/kzt-step4-wi231-writer-tests-20260709093324/build64'
ninja: no work to do.
1/1 kzt-rela-immediate-candidate RUNNING
>>> UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_summary=1:print_stacktrace=1 MESON_TEST_ITERATION=1 MSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_summary=1 ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_summary=1 MALLOC_PERTURB_=68 /home/loongson/work/code/latu-worktrees/kzt-step4-wi231-writer-tests-20260709093324/build64/tests/unit/kzt-rela-immediate-candidate
WI231_TC tc=approved-writer-success-skips-legacy plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=0 skip_legacy=1 result=APPLIED failure=NONE reads=2 writer_writes=1 final=0x7200004560
WI231_TC tc=planner-unsupported-keeps-legacy plan_status=1 plan_reason=0 decision=UNSUPPORTED writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300003333
WI231_TC tc=planner-rejected-keeps-legacy plan_status=1 plan_reason=0 decision=REJECTED writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300003333
WI231_TC tc=planner-deferred-keeps-legacy plan_status=1 plan_reason=0 decision=DEFERRED writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300003333
WI231_TC tc=planner-error-keeps-legacy plan_status=2 plan_reason=8 decision=ERROR writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300003333
WI231_TC tc=writer-expected-mismatch-fail-open plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=1 skip_legacy=0 result=FAIL_OPEN failure=EXPECTED_MISMATCH reads=1 writer_writes=0 final=0x7300004444
WI231_TC tc=writer-write-fail-fail-open plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=1 skip_legacy=0 result=FAIL_OPEN failure=WRITE_FAILED reads=1 writer_writes=1 final=0x7300004444
WI231_TC tc=writer-verify-fail-fail-open plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=1 skip_legacy=0 result=FAIL_OPEN failure=VERIFY_FAILED reads=2 writer_writes=2 final=0x7300004444
WI231_TC tc=writer-rollback-fail-fail-open plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=1 skip_legacy=0 result=FAIL_OPEN failure=ROLLBACK_FAILED reads=2 writer_writes=2 final=0x7300004444
WI231_TC tc=non-target-relocation-skips-writer plan_status=0 plan_reason=2 decision=(none) writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300005555
WI231_TC tc=glob-dat-skips-writer plan_status=0 plan_reason=2 decision=(none) writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300005555
WI231_TC tc=lazy-deferred-skips-writer plan_status=0 plan_reason=3 decision=(none) writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300005555
1/1 kzt-rela-immediate-candidate OK              0.00s

Ok:                 1
Expected Fail:      0
Fail:               0
Unexpected Pass:    0
Skipped:            0
Timeout:            0
```

## WI-230 集成建议

WI-230 提供生产接线接口后，建议将 `wi231_apply_step4_request_contract()` 中的本地 contract harness 替换为真实入口调用，并保留当前 `WI231_TC` 输出字段，便于 AgentsFlow AI QA 对照：

- `writer_called=1 legacy_writes=0 skip_legacy=1 result=APPLIED` 仅允许出现在 approved writer success。
- planner `UNSUPPORTED`、`REJECTED`、`DEFERRED`、`ERROR` 必须保持 `writer_called=0 legacy_writes=1`。
- writer `EXPECTED_MISMATCH`、`WRITE_FAILED`、`VERIFY_FAILED`、`ROLLBACK_FAILED` 必须保持 `legacy_writes=1`。
- `R_X86_64_GLOB_DAT`、非目标 relocation、lazy/deferred 必须保持 `writer_called=0`。
