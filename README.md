# MaxsuIFrame

此分支使用本地 [alandtse/CommonLibSSE-NG](https://github.com/alandtse/CommonLibSSE-NG) 源码构建，默认路径为相邻目录 `../CommonLibSSE-NG-ng`。不再依赖 DKUtil 或外部 SKSEPlugins 工程。

## 运行要求

- Skyrim SE / AE **Steam 1.6.1170.0**。
- 对应的 **SKSE64 2.2.6**。
- Address Library for SKSE Plugins 的 AE 版本，包含 `Data/SKSE/Plugins/versionlib-1-6-1170-0.bin`。

本次构建只声明 1.6.1170.0 兼容性。SE 1.5.97、VR、GOG 和其他 AE 运行时不在此构建的支持范围内。

## 构建

使用 Visual Studio 2022 的 **x64 Native Tools / Developer PowerShell**，安装 C++ 工具、Windows SDK、CMake、Ninja 和 vcpkg。依赖在 `vcpkg.json` 中声明，CommonLibSSE-NG 直接从指定的本地目录编译。

```powershell
$env:VCPKG_ROOT = "E:/BuildTools/VC/vcpkg"
cmake --preset ae1170
cmake --build --preset ae1170 --parallel 8
cmake --install build/ae1170 --prefix package
```

如 Ninja 未加入 PATH，可在配置时增加 `-DCMAKE_MAKE_PROGRAM=C:/Users/15219/AppData/Local/Programs/Python/Python310/Scripts/ninja.exe`。可用 `-DCOMMONLIBSSE_NG_PATH=其他路径` 指定 CommonLibSSE-NG。

安装时将 `package/SKSE/Plugins/MaxsuIFrame.dll` 放入游戏的 `Data/SKSE/Plugins/`，或将 `package` 目录作为模组安装。无需复制开发用的 `.lib` 文件。

## 偏移检查

三处 Hook 的 1170 指令偏移和 Havok / 动画图虚函数检查见 [1170 ABI 核验记录](docs/ABI-1170.md)。插件在写入任何 Hook 前检查三处指令必须为调用原始 `Actor::IsGhost` 的 `E8 rel32`；若游戏文件不匹配或其他插件已改写这些调用，记录错误并返回加载失败。

原有动画注释格式和行为图变量保持可用，参见 [动画制作说明](doc/en/tutorial.md)。运行日志为 SKSE 日志目录中的 `MaxsuIFrame.log`。

## 性能与安全

已增加有界的线程本地注释缓存，减少 JSON 解析和重复虚调用；修复多个活动片段的提前返回，并对图容器和遍历使用经 1170 二进制核对的管理器更新锁。缓存不保存游戏对象指针。修改、微基准、测试和引擎并发保证的范围见 [性能与安全审核](docs/PERFORMANCE-SAFETY.md)。
