KZT Loader 重构计划
===================

目标
----

KZT loader 重构是一组分阶段设计调整，目标是重新划分 LATX 如何观察 guest
ELF 对象，以及如何决定 guest GOT 槽位是否应重定向到 native wrapper
bridge。

现有 loader 路径可以工作，但多个职责混在少数路径里：

* 观察 guest loader 事件；
* 从宿主侧状态重建 guest 对象身份；
* 加载 wrapper 依赖；
* 通过 ``maplib`` 解析符号；
* 决定 GOT 槽位是否需要 patch；
* 立即写 GOT 或通过 lazy binding 写 GOT。

这种结构使代码难以推理，也让正确性依赖于宿主侧对 guest loader 决策的
重新构造。尤其是在 wrapper 选择上，宿主侧全局符号搜索可能与当前 guest
GOT 值所代表的最终 owner 不一致。

重构的方向是把这些职责拆开，并逐步落实一个原则：guest loader 状态应作为
guest 对象身份的权威来源；宿主侧 wrapper 状态只用于寻找 native bridge
目标。

为什么需要重构
--------------

旧路径存在几个结构性问题。

Guest 对象身份是隐式的
~~~~~~~~~~~~~~~~~~~~~~

很多决策都依赖“某个地址属于哪个 guest 对象”，但旧路径经常通过
``elfheader_t``、``maplib`` 结果或重复的全局符号查找间接推断这个身份。
这样很难判断 GOT 当前值是否真的指向 guest loader 最终选择的对象。

符号解析重复发生在错误层次
~~~~~~~~~~~~~~~~~~~~~~~~~~

guest loader 已经完成依赖和符号绑定。LATX 再通过全局 ``maplib`` 搜索重复
这件事，可能会选到另一个 owner。对于库直通和 wrapper 选择来说，这会带来
跨对象 mismatch 风险。

Patch 决策不是一等数据
~~~~~~~~~~~~~~~~~~~~~~

历史上 relocation 代码解析到目标后直接写 GOT。这样很难观察为什么写了某个
槽位、旧目标属于谁、选择了哪个 wrapper、为什么某个槽位没有 patch。

Loader 同步过度集中
~~~~~~~~~~~~~~~~~~~

glibc 私有 hook 当前承担了太多职责。即使最终仍需要一个小 hook，它也应该只
发布 loader 事件；对象跟踪、dynamic 解析、符号对比和 patch planning 应该
由独立模块承担。

可行性
------

这个重构可行，是因为 guest 进程运行时已经暴露了足够的信息来建立更清晰的
边界：

* ``link_map`` 提供对象名、加载地址和 Dynamic Table 指针；
* ``l_ld`` 指向内存中的 Dynamic Table，可以不依赖 Section Header 解析
  symbol、relocation 和 version 信息；
* 已有 GOT 值可以通过 guest 对象加载范围反查所属对象；
* wrapper library 仍可用于查询 native bridge 地址；
* 旧 ``maplib`` 路径可以在每个新边界验证稳定前继续作为 fallback。

工程上的关键选择是避免一次性重写。每个阶段只引入一个明确边界，并保留旧
行为作为 fallback，直到替代路径具备足够的可观察性。

设计原则
--------

分阶段设计遵循以下原则：

* guest 对象身份只记录一次，并通过显式 API 传递；
* 从 guest 内存解析 loader 数据，而不是重新打开 guest ELF 文件；
* 每次 GOT patch 先形成决策，再写槽位；
* wrapper 选择优先参考 guest loader 已经选出的最终 owner；
* 新路径稳定前保留 ``maplib`` fallback；
* lazy binding 与普通 relocation 清理分开处理；
* 模块边界稳定后，将 glibc hook 降级为事件源。

阶段划分
--------

阶段 1：Guest object registry
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

引入 ``GuestObjectRegistry``，记录 loader callback 观察到的 guest 对象。
Registry 负责对象身份：名称、基址、加载范围和 Dynamic Table 地址。

callback 只注册对象信息，然后进入旧兼容路径。这样可以先建立对象身份层，
而不改变 loader 对外行为。

阶段 2：内存 Dynamic Parser
~~~~~~~~~~~~~~~~~~~~~~~~~~~

从 ``l_ld`` 解析 guest Dynamic Table。parser 需要构建 symbol、relocation、
version index、version need、version definition 和 string table 的视图。

初期内存 parser 与旧文件 parser 并行运行。差异应在测试中断言，或在运行时
比较路径中记录。只有比较稳定后，才删除旧的 ``fopen()`` 和 Section Header
依赖。

阶段 3：Patch Planner
~~~~~~~~~~~~~~~~~~~~~

为每一次 GOT 修改引入 planner record。一个 patch decision 应包含：

* guest object；
* relocation 地址和类型；
* symbol 名称和 version；
* 旧 GOT target；
* old owner 和 old guest object；
* ``maplib`` bridge 和 owner；
* 可用时的 guest-owner bridge 和 owner；
* 最终选择的 target source；
* decision reason。

这个阶段不必改变 target 选择。它的主要价值是让现有行为可观察、可测试。

阶段 4：Guest-owner target selection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

使用当前 guest GOT 值识别已解析目标所属的 guest 对象，再通过该对象的
wrapper library 解析同一 symbol。

安全规则是：

* guest-owner probe 成功时，可以替代该槽位的重复全局 ``maplib`` 解析；
* guest-owner probe 失败时，继续使用原有 ``maplib`` fallback。

这个阶段先覆盖普通 relocation 路径。lazy binding 单独放到后续阶段。

阶段 5：移除普通 guest 依赖旁路加载
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

停止通过 wrapper 路径递归 ``LoadNeededLibs()`` 普通 x86 guest 依赖。宿主侧
加载应只保留 native wrapper 自身依赖，或者在适合时交给宿主 ``dlopen()``。

这个阶段依赖前四个阶段，因为在删除旁路加载前，guest 对象身份和 patch 目标
决策必须已经显式化。

阶段 6：简化 lazy binding
~~~~~~~~~~~~~~~~~~~~~~~~~~

尽量让 guest loader 先完成 lazy binding，然后在 guest 绑定结果可见后再
patch 槽位。

如果仍必须支持首次调用即时替换，也应放在独立模块中，而不是继续往通用
relocation 代码里塞策略。

阶段 7：重构 dlopen/dlsym/dlclose
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

让 guest loader handle 成为权威结果。删除合成 handle、重复引用计数和绕过
guest loader 状态的 reload 路径。

阶段 8：替换 glibc 私有 hook 的职责
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

前面模块边界稳定后，再减少或替换 glibc 私有 hook。可选事件来源包括
``r_debug`` 通知、RELRO ``mprotect``、QEMU mmap/loader 事件，或极小且版本
隔离的 fallback hook。

即使最终仍保留 hook，它也只应发布事件，不应承担 guest 对象解析、依赖加载
或 GOT patch planning。

补丁组织建议
------------

可审阅的实现补丁应按设计边界分组，而不是按机械 helper 拆分。建议组织为：

1. 文档和路线图；
2. Guest object registry；
3. 内存 Dynamic Parser 与双轨比较；
4. Patch planner records 与 GOT 写入路由；
5. Guest-owner target comparison；
6. Guest-owner target selection。

每个补丁的 commit body 应说明：

* 属于哪个阶段；
* 保留了哪个旧行为作为 fallback；
* 引入了什么新的边界或数据模型；
* 该阶段预期如何验证。

进度报告、最新 CTS 数字和临时 rollout 说明不应放进这份设计文档，因为它们会
随着补丁推进而变化。
