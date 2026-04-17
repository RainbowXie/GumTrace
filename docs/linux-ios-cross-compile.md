# Linux 下交叉编译 iOS 版 GumTrace

这份文档记录当前仓库已经跑通的一条 Linux 构建链路：在 Linux 主机上使用系统 `clang`、本地 `iPhoneOS.sdk` 和 `osxcross` 提供的 Mach-O linker，生成可部署到越狱 iOS 设备上的 `libGumTrace.dylib`。

当前已经验证通过的产物：

```bash
file build_ios/libGumTrace.dylib
# build_ios/libGumTrace.dylib: Mach-O 64-bit arm64 dynamically linked shared library
```

## 适用范围

- 主机：Linux
- 目标：iPhoneOS arm64
- 产物：`build_ios/libGumTrace.dylib`
- 设备部署路径：`/var/jb/usr/lib/frida/libGumTrace.dylib`

这条流程的目标不是生成 `.app`，而是生成一个 Frida 脚本里通过 `dlopen()` 加载的 Mach-O 动态库。

## 依赖

最小依赖如下：

- 系统 `clang` / `clang++`
- `cmake`
- 完整的 iPhoneOS SDK
- `osxcross` 构建出的 Darwin cctools/ld64
- 仓库内自带的 Frida Gum iOS 静态库：`libs/FridaGum-IOS-17.8.3-fix.a`

当前本地已验证的路径：

```bash
export PROJECTS_ROOT=/path/to/your/projects
export IOS_SDK_PATH="$PROJECTS_ROOT/iPhoneOS16.1.sdk"
export OSXCROSS_ROOT="$PROJECTS_ROOT/osxcross"
export OSXCROSS_TARGET_ROOT="$OSXCROSS_ROOT/target"
export OSXCROSS_BIN="$OSXCROSS_TARGET_ROOT/bin"
export OSXCROSS_LD="$OSXCROSS_BIN/arm64-apple-darwin25-ld"
export OSXCROSS_INSTALL_NAME_TOOL="$OSXCROSS_BIN/arm64-apple-darwin25-install_name_tool"
```

## 为什么不用旧的 Xcode-only 路线

仓库原来的 iOS 构建逻辑默认依赖：

- `xcrun --sdk iphoneos --show-sdk-path`
- `/Applications/Xcode.app/.../clang`

这在 macOS 上没问题，但在 Linux 上直接失效：

- Linux 主机通常没有 `xcrun`
- 就算装了 `osxcross`，它的包装器默认面向 macOS SDK 工作流，不等于完整的 iPhoneOS 构建环境
- 旧脚本还会硬编码 Xcode 下的 clang 路径，这在 Linux 上不存在

所以现在这条可用路线是：

1. 使用系统 `clang` / `clang++`
2. 通过 `-target arm64-apple-ios16.0` 指定 iOS 目标
3. 通过 `-isysroot` / `CMAKE_OSX_SYSROOT` 指向本地 `iPhoneOS.sdk`
4. 通过 `-fuse-ld=/path/to/arm64-apple-darwin25-ld` 强制使用 Mach-O linker

## 先准备 iPhoneOS SDK

- 获取 [iPhoneOS SDK](https://github.com/xybp888/iOS-SDKs/tree/master)

## 准备 `arm64-apple-darwin25-ld`

GumTrace 这条链路不需要整套 `osxcross` 包装编译器，但必须要一个能链接 Mach-O 动态库的 linker。这里直接使用 `osxcross` 产出的 `ld64`：

```bash
$OSXCROSS_LD
```

如果你本地还没有这个文件，按 `osxcross/README.md` 的流程先构建。

## 构建 macOS ToolChain

先获取 `macOS SDK`，参考 `osxcross/README.md`。

最小步骤是：

```bash
cd $PROJECTS_ROOT/osxcross

# 1. 获取 macOS SDK，放到 tarballs/
# 2. 构建 osxcross 工具链
UNATTENDED=1 ENABLE_ARCHS="arm64" ./build.sh
```

构建完成后，默认产物会在：

```bash
$PROJECTS_ROOT/osxcross/target/bin/
```

可以这样确认 linker 已经就位：

```bash
ls -l $PROJECTS_ROOT/osxcross/target/bin/arm64-apple-darwin25-ld
```

这里的关键点是：我们借用的是 `osxcross` 的 Darwin cctools/ld64，而不是必须使用它整套 `*-apple-darwin-clang` 包装器。

## 当前仓库的工作方式

仓库里的 `linux_crossbuild_ios.sh` 负责 Linux 交叉编译，核心策略是：

- 用系统 `clang`
- 目标 triple 固定成 `arm64-apple-ios16.0`
- `CMAKE_OSX_SYSROOT` 指向本地 `iPhoneOS.sdk`
- `-fuse-ld` 指到 `arm64-apple-darwin25-ld`
- `CMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY`，避免 CMake 在探测阶段做不可执行的目标程序链接

脚本中的关键变量：

```bash
PROJECTS_ROOT="${PROJECTS_ROOT:?PROJECTS_ROOT is required}"
PROJECTS_ROOT="${PROJECTS_ROOT%/}"
OSXCROSS_ROOT="${OSXCROSS_ROOT:-${PROJECTS_ROOT}/osxcross}"
OSXCROSS_TARGET_ROOT="${OSXCROSS_TARGET_ROOT:-${OSXCROSS_ROOT}/target}"
OSXCROSS_BIN="${OSXCROSS_BIN:-${OSXCROSS_TARGET_ROOT}/bin}"
OSXCROSS_LD="${OSXCROSS_LD:-${OSXCROSS_BIN}/arm64-apple-darwin25-ld}"
OSXCROSS_INSTALL_NAME_TOOL="${OSXCROSS_INSTALL_NAME_TOOL:-${OSXCROSS_BIN}/arm64-apple-darwin25-install_name_tool}"
IOS_SDK_PATH="${IOS_SDK_PATH:-${PROJECTS_ROOT}/iPhoneOS16.1.sdk}"
IOS_TARGET="${IOS_TARGET:-arm64-apple-ios16.0}"
```

## 一键构建

在仓库根目录执行：

```bash
cd /path/to/GumTrace
PROJECTS_ROOT=/path/to/your/projects ./linux_crossbuild_ios.sh
```

如果你不使用默认派生路径，可以显式覆盖：

```bash
cd /path/to/GumTrace

PROJECTS_ROOT=/path/to/your/projects \
OSXCROSS_ROOT=/another/path/to/osxcross \
OSXCROSS_TARGET_ROOT=/another/path/to/osxcross/target \
OSXCROSS_BIN=/another/path/to/osxcross/target/bin \
OSXCROSS_LD=/another/path/to/osxcross/target/bin/arm64-apple-darwin25-ld \
OSXCROSS_INSTALL_NAME_TOOL=/another/path/to/osxcross/target/bin/arm64-apple-darwin25-install_name_tool \
IOS_SDK_PATH=/path/to/iPhoneOS.sdk \
./linux_crossbuild_ios.sh
```

成功后产物在：

```bash
build_ios/libGumTrace.dylib
```

## CMake 里的 Linux 特殊处理

这条链路有两个关键修正。

### 1. 不再强依赖 `xcrun`

`CMakeLists.txt` 现在优先使用外部传入的 `CMAKE_OSX_SYSROOT`。只有没传时才尝试执行：

```bash
xcrun --sdk iphoneos --show-sdk-path
```

这让同一份 CMakeLists 既能在 macOS 上工作，也能在 Linux 上走本地 SDK 路线。

### 2. Linux 上不直接链接 Foundation/CoreFoundation framework

在这台 Linux 主机上，`ld64` 对 SDK 里的新 `.tbd` framework stub 解析不稳定，直接链接：

```bash
-framework Foundation
-framework CoreFoundation
```

会卡在链接阶段。

当前仓库的处理方式是：

- 始终链接 `libs/FridaGum-IOS-17.8.3-fix.a`
- Linux 主机额外加：

```bash
-undefined dynamic_lookup
```

这样可以先把 `libGumTrace.dylib` 链出来，再在设备侧由 dyld 解析系统符号。构建时会看到一条 warning：

```bash
ld: warning: -undefined dynamic_lookup is deprecated on iOS
```

这条 warning 当前是预期行为，不影响 `dlopen()` 场景下的部署与使用。

## 验证产物

至少做这三个检查。

### 1. 检查文件类型

```bash
file build_ios/libGumTrace.dylib
```

预期输出类似：

```bash
build_ios/libGumTrace.dylib: Mach-O 64-bit arm64 dynamically linked shared library
```

### 2. 给 `dylib` 签名

如果目标是越狱 iOS 设备上的 `dlopen()` 场景，构建出的 `build_ios/libGumTrace.dylib` 在推送前通常还需要补一次 ad-hoc 签名。当前本地已验证可用的是 `ldid`。

先准备 `ldid`，例如本地路径：

```bash
$PROJECTS_ROOT/ldid/ldid
```

先确认它可执行：

```bash
LDID_BIN="$PROJECTS_ROOT/ldid/ldid"
test -x "$LDID_BIN"
```

签名：

```bash
LDID_BIN="$PROJECTS_ROOT/ldid/ldid"
"$LDID_BIN" -S build_ios/libGumTrace.dylib
```

这里的 `-S` 会写入一个最小 entitlement/signature blob，适合当前这种越狱设备上的动态库加载场景。

签名后至少确认文件仍然存在、类型没有变：

```bash
ls -lh build_ios/libGumTrace.dylib
file build_ios/libGumTrace.dylib
```

预期仍然是：

```bash
build_ios/libGumTrace.dylib: Mach-O 64-bit arm64 dynamically linked shared library
```

下面这些情况都应该重新跑一次 `ldid -S`：

- 重新编译出了新的 `libGumTrace.dylib`
- 用 `install_name_tool`、`strip`、二进制 patch 等方式修改过产物
- 从别的目录复制/替换后，不确定当前文件是否还是签名后的版本

### 3. 检查设备侧是否能加载

这不是纯编译验证，但它能尽快发现：

- 架构不匹配
- deploy 路径不对
- `dlopen()` 失败

由 Frida 脚本在目标进程里执行：

```c
dlopen("/var/jb/usr/lib/frida/libGumTrace.dylib", RTLD_NOW)
```

## 相关文件

- macOS/iOS 本机构建脚本：[build_ios.sh](../build_ios.sh)
- Linux 交叉编译脚本：[linux_crossbuild_ios.sh](../linux_crossbuild_ios.sh)
- 主构建文件：[CMakeLists.txt](../CMakeLists.txt)
- `osxcross` 参考文档：`<your-projects-root>/osxcross/README.md`
