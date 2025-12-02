# Git 提交规范（基于历史提交总结）

为了使代码有良好的可追溯性，根据项目现有提交记录和内部约定补充如下规范，便于新人快速对齐。

## 标题基础格式
- **推荐结构**：`<范围>[, <类型>]: <简洁描述>`。
- **范围（Scope）**：模块或子项目名称（如 `LATX`、`lat`、`KZT`、`cpus`、`linux-user`），与路径或子系统保持一致。
- **类型（Type）**：常用 `feat`（新特性）、`fix`（修复）、`opt`（优化）；特殊场景使用 `temporary fix`（临时修复）、`Build(deps)`（依赖或 CI 维护）。
- **描述（Subject）**：一句话概括改动，祈使/陈述语气的简短英文描述，避免句号结尾。

## Type 约定（可按需扩充）
| Type             | 含义 / 适用场景                           | 示例标题片段                       |
| ---------------- | ----------------------------------------- | ---------------------------------- |
| `LATX, infra`    | 基础设施、tracing、profiling 等            | `LATX, infra: Add tracing for ...` |
| `LATX, fix`      | bug 修复                                   | `LATX, fix: Handle null ...`       |
| `LATX, opt`      | 性能或实现优化                             | `LATX, opt: Refine glue ...`       |
| `LATX, refactor` | 函数 / 功能重构                            | `LATX, refactor: Split ...`        |
| `LATX, style`    | 不影响功能的格式、注释调整                 | `LATX, style: Reflow comments`     |
| `LATX-X64, *`    | 改动仅针对 64 位，`*` 同上各类（如 fix）    | `LATX-X64, fix: ...`               |
| `linux-user`     | linux-user 相关（如 syscall 改动）         | `linux-user, fix: ...`             |
| `LATX, docs`     | 文档                                       | `LATX, docs: Update convention`    |
| 其他历史类型     | `feat`、`temporary fix`、`Build(deps)` 等   | `Build(deps): Bump ...`            |

> 范围与类型之间用逗号分隔，类型与描述之间用冒号；无类型时直接用冒号，例如 `cpus: Make {start,end}_exclusive() recursive`。

## 标题示例（可直接套用）
- `LATX, feat: Support CONFIG_LATX_GLUE_MASK in indirect jmp glue`
- `cpus, fix: Always exit from exclusive state in fork_end()`
- `lat, opt: Reduce thread contention in fast path`
- `KZT, temporary fix: Disable feature gate during migration`
- `Build(deps): Update meson to 1.3.0`

## commit body 要求
1. **建议保留正文**：除 `style`、`docs` 类型，或极其简单且首行即可描述清楚的提交外，不接受只有一行的提交。
2. **fix 类型必须指明修复对象**：正文中写明修复了哪个程序 / 测试或 issue（例如 gcc、glibc 测试项，或本仓库 issue 编号），便于追溯。
3. **正文内容建议**：
   - 补充背景、动机、方案与验证方式，不必在标题展开细节。
   - 单个提交聚焦单一主题，避免一次提交多个无关改动。
   - 对临时修复或风险点，正文说明影响范围、替代方案与清理计划，方便后续跟进。

## 提交前检查清单
- 标题不超过 72 字符，描述末尾不加句号。
- 是否包含范围且范围名称与子系统一致？
- 类型是否符合场景，是否需要 `temporary fix` 或 `Build(deps)` 等特殊标识？
- 描述是否清晰指向改动 / 原因，避免模糊词（如 “update code”、“fix bug”）。
- 是否按上述要求填写 commit body（尤其对 `fix` 类型）？
- 若为临时方案或有后续计划，正文是否注明 TODO / 后续跟进？
