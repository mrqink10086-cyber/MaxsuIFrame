# 执行逻辑、性能与安全审核

## 本次修改

伤害调用仍同步读取当前状态，不增加轮询任务或异步调度。动画时间、Actor 判定结果和行为图布尔变量每次读取，避免缓存上一帧的无敌状态。保留原顺序：动画注释 → 两个旧版行为变量 → 原始 `Actor::IsGhost`。

- 按 JSON 内容缓存 `Duration`，键为插件拥有的字符串。相同文本可跨动画复用，文本变化立即使用新结果；不以游戏对象地址作为缓存身份。
- 每线程独立缓存，最多 128 项，每项输入不超过 4096 字节；字符串内容合计最多 512 KiB/线程，另有容器和分配器开销。缓存满后清空，再插入当前项。线程退出时释放；不保留游戏对象或延长动画资源寿命。
- 缓存项使用连续 `vector` 存储并按文本排序，命中时二分查找，不重新解析或分配。无效 JSON 也缓存；每次首次发现或重新缓存时汇总一次警告，日志在释放游戏锁后写入。
- 尚未到注释开始时间就跳过。注释前缀不匹配时快速退出，不扫描完整字符串。
- 节点和注释按引用遍历，避免复制 `0x90` 字节的节点信息；每个节点只调用一次 `GetClassType`，检查类名指针后转换。
- 第一个活动片段不在无敌区间时继续检查后续活动片段，修复混合动画下的提前返回。沿用第一张图和第 0 条注释轨的范围。
- 两个旧版行为变量名使用静态 `BSFixedString`，避免反复进入字符串池。

缓存未命中时，首次 JSON 解析和插入仍发生在管理器锁内，会延长这次持锁时间；输入长度和嵌套深度有明确上限。命中后只做查找和区间判断。将解析移到锁外需要先复制注释数据，当前实现保留这一取舍。

## 安全检查

| 项目 | 处理与边界 |
| --- | --- |
| Actor 指针 | 空 Actor 立即返回 false。有效非空 Actor 的生命周期由原游戏调用点保证；`Is3DLoaded()` 只用于检查 3D 是否存在。 |
| 管理器与图 | 用 `BSAnimationGraphManagerPtr` 保留管理器；取得 `updateLock` 后检查图数组，并复制图的智能指针。 |
| 游戏内部指针 | 图、行为图、活动节点、片段、binding、animation、注释只在当前锁作用域访问；逐层空检查。缓存不保存这些指针或借用的字符串视图。 |
| 锁与线程 | 只获取管理器 `GetRuntimeData().updateLock`，通过 RAII 释放；释放后才查询旧版行为变量和写日志。不引入共享缓存锁或额外线程。 |
| 输入与堆栈 | JSON 最大 4096 字节、嵌套深度最大 16，避免异常复杂的注释生成无界解析数据。空文本、错误 JSON、缺少或非数值 `Duration` 均跳过。 |
| 时间数值 | 拒绝非有限时长、时间与区间终点溢出；负时长沿用钳制为 0 的行为；区间两端仍包含。 |
| 内存分配失败 | 自定义逻辑出现 `std::bad_alloc` 时，RAII 释放锁并回到原始 `IsGhost`。不捕获访问违规，也不将非空指针视为已验证有效。 |
| Hook 写入 | 写入前核验全部三处 E8 指令及原始目标，原函数指针在写入前初始化。只在 SKSE 加载阶段安装，不在运行中重复替换。 |

## 1170 锁证据与剩余范围

对同一份 1170 EXE 的只读反汇编确认：

1. `IAnimationGraphManagerHolder::UpdateAnimationGraphManager`，Address Library ID `32899`、RVA `0x54C1F0`，在 `0x54C243` 调用管理器更新例程 `0xBA3C50`。
2. 该例程取得管理器 `+0xA0` 的锁，与本地 NG 的 `GetRuntimeData().updateLock` 对应。持锁访问图容器，并在 `0xBA3DC1–0xBA3DE3` 调用每图例程 `0xBB2370`，至 `0xBA3DE5` 开始释放锁；另一次持锁循环在 `0xBA3F62–0xBA3F75` 调用 `0xBB2A40`。
3. `0xBB2370` 内的 `0xBB283F` 读取 `graph+0x208` 的行为图，`0xBB2852` 调用其虚表 `+0x28`，对应 NG 声明的 `hkbBehaviorGraph::Update` 槽位 5。

因此，本次读取与已确认的管理器容器操作及行为图 Update 路径使用同一把锁。没有单独获取变量缓存锁、依赖管理器锁或未知 Havok 内部锁。

这条证据未覆盖所有 Havok 工作线程、第三方插件写入，以及每条 `activeNodes` / `localTime` 写路径。智能指针也不能修复调用前已经失效的 Actor。这里完成的是插件自身缓存隔离和已知更新路径的同步改进，尚不能据此宣称所有游戏对象访问已获得完整线程安全证明。需要游戏内并发场景测试补足这一范围。

## CPU 指令与实测

主要开销是指针遍历、虚调用、文本处理与 JSON 分配，时间判定只有少量标量比较。当前采用 Release 优化和短路判断；没有足够的批量数值计算支持专用 AVX2 / SIMD / FMA 内核，也不要求 CPU 支持 AVX2。FMA 对这里的区间判断没有收益，还可能改变边界舍入。

本机 MSVC 19.44、Release、200,000 次同一 `{"Duration":0.5}` 查询的微基准：重复 JSON 解析平均约 **561 ns**，已热身缓存平均约 **8.2 ns**，约 **68 倍**。此结果只衡量时长查询，未包含游戏锁、节点扫描和完整伤害路径，不代表帧率或整条 Hook 提速倍数。

## 验证与复现

Release DLL 已从本地 CommonLibSSE-NG 源码编译。独立回归测试覆盖区间边界、负时长、非有限数、终点溢出、错误类型、无效 JSON、深层嵌套、过长文本、空字符串、源文本修改、缓存容量、缓存复用和 8 线程的独立缓存访问。Release 和 AddressSanitizer 两种构建均通过；ASan 检测范围仅为独立解析/缓存测试，不包含运行中的游戏。

在 VS x64 Developer PowerShell 中运行：

```powershell
cmake -S tests -B build/tests -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/tests
ctest --test-dir build/tests --output-on-failure

cmake -S tests -B build/tests-asan -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_ASAN=ON
cmake --build build/tests-asan
ctest --test-dir build/tests-asan --output-on-failure
```

仍需在游戏内验证：多片段混合、翻滚起止边界、正常受击、原始 Ghost 状态、旧版行为变量、3D 卸载/重建、存读档、切换场景和战斗模组组合。未运行游戏实测，也未进行游戏进程内的线程检测。
