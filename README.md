<div align="center">

# traceless-frida

**Frida frontend for traceless AArch64 inline hooks on Android**

[English](#english) · [简体中文](#简体中文)

[![License](https://img.shields.io/badge/license-GPL--2.0--or--later-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Android%20AArch64-green?style=flat-square)](#requirements)

</div>

---

<a id="english"></a>

## English

Stock Frida `Interceptor` installs an inline patch: an `rwx` trampoline and a modified `.text`. That is easy to catch with CRC checks, `/proc/<pid>/maps` scans, and `mincore`.

**traceless-frida** keeps the familiar Frida API (`replace` / `attach` / `revert`), but installs each hook through the **shpte KPM** (a KernelPatch module):

1. The target code page is marked `UXN`.
2. Faults are routed via `do_page_fault` into a whole-region, position-independent DBI clone.
3. The function entry is redirected to your replacement.

**The hooked library's `.text` is never written.** Its maps stay byte-identical and non-writable. The write path lives in the kernel page-table shadow, not on the target.

A small native shim (`libtracelessfrida.so`) is loaded into the process by Frida and drives the same `lib/kpmhook` / `lib/dbi` backend used elsewhere in this stack ([stealth-core](https://github.com/1013503897/stealth-core)). No full Frida rebuild is required.

### How it works

```
Frida (frontend)                       libtracelessfrida.so (in target)      shpte KPM (kernel)
────────────────                       ───────────────────────────────      ──────────────────
Traceless.replace(target, cb)
  cb = NativeCallback  ─────────────►  tlf_hook(target, cb)
  Module.load(.so)                       └ kpm_inline_hooker(target, cb)
                                            ├ dbi_recompile_range()   (PIC region clone)
                                            └ syscall(179,"SHPTBRDG","pghook …") ──► do_pghook:
                                                                                       set target page PTE_UXN
returns backup ◄─────────────────────  backup (in-clone copy)                        install fault route
                                                                                       entry override → cb
  orig = NativeFunction(backup)                                               target .text: UNTOUCHED
```

Native side (`native/`): `tlf_api.c` (five-symbol ABI) over vendored `kpmhook.c` + `dbi.c`. Frida stays the frontend — target selection, symbol resolution, and `NativeCallback` replacements.

### Requirements

- AArch64 Android with **APatch / KernelPatch**, **shpte KPM loaded**, and its **sysinfo bridge armed** (see [stealth-core](https://github.com/1013503897/stealth-core)). Runtime does **not** need a superkey — the bridge uses `sysinfo(179)`.
- Matching `frida-server` on device and `frida` / `frida-tools` on the host.
- Android NDK (r26 / 26.1 known-good) to build the `.so` and the test target.

### Build

```powershell
# native backend → native/libtracelessfrida.so (arm64)
powershell native/build.ps1

# test target → test/tlf_target (arm64, exports secret())
powershell test/build_target.ps1
```

### Usage (REPL or `-l`)

```js
// load agent/traceless.js first (defines global `Traceless`)
Traceless.init();
// Traceless.init({ ghost: true });  // host clone in VMA-less memory (recommended)

const secret = Module.findGlobalExportByName('secret');

// Interceptor.replace-style — orig() runs via the KPM backup clone:
Traceless.replace(secret, {
  retType: 'int', argTypes: ['int'],
  onCall(args, orig) { return orig(args[0]) + 1000; }
});

// Interceptor.attach-style:
Traceless.attach(secret, {
  onEnter(args) { console.log('secret(', args[0], ')'); },
  onLeave(ret)  { return ret; }  // return a value to override
}, { retType: 'int', argTypes: ['int'] });

Traceless.revert(secret);
Traceless.dispose();  // revert all + release mappings (see Safety)
```

`argTypes` / `retType` use Frida `NativeFunction` type strings. Omit the signature to use `Traceless.SIG_GENERIC` (8 pointer args, pointer return) — fine for ≤8 integer/pointer args and an integer/pointer return. Pass an explicit signature for float / double or variadic functions.

### End-to-end test

```powershell
python test/run.py            # spawn tlf_target under Frida, hook secret(), verify
python test/run.py --ghost    # same, ghost (VMA-less clone) mode
```

The harness checks **liveness** (`secret(n)` returns `orig + 1000`) and **tracelessness** (first `.text` word unchanged; page stays `r-x`; no `rwx` over it).

### Tracelessness scope

| Covered | Not covered |
| :--- | :--- |
| Target library: byte-identical, non-writable, no inline branch, no `rwx` on `.text` | `frida-agent` maps |
| CRC / `/proc/maps` / `mincore` on the target | Your replacement (lives in Frida's gum allocator) |
| With `ghost: true`, the recompiled clone is VMA-less | Hiding Frida itself (out of scope) |

### Safety

- shpte must already be loaded and the bridge armed. This tool does **not** load kernel modules; it only drives the existing bridge.
- **Draining live regions to zero can panic a busy device.** Reverting the *last* region reconfigures shpte's global maps-hide (`show_map`) hook and can race another process reading `/proc/maps`. Prefer **ghost mode**, and avoid teardown under load.

### Layout

```
native/   tlf_api.c + vendored kpmhook/dbi + build.ps1  → libtracelessfrida.so
agent/    traceless.js                                  Frida frontend
test/     target.c, test.js, run.py, build_target.ps1   end-to-end proof
docs/     DESIGN.md
```

### Related

- [stealth-core](https://github.com/1013503897/stealth-core) — shpte KPM and the `lib/kpmhook` / `lib/dbi` backend this frontend drives
- [Vector](https://github.com/1013503897/Vector) — Zygisk ART-hook framework on the same KPM backend

`native/kpmhook.c`, `dbi.c`, `dbi.h`, `kpmhook.h`, and `aarch64_decode.h` are vendored from **stealth-core** — see [SYNC.md](SYNC.md). License: **GPL-2.0-or-later**.

---

<a id="简体中文"></a>

## 简体中文

原生 Frida `Interceptor` 会写 inline patch：留下 `rwx` 蹦床和被改过的 `.text`，容易被 CRC、`/proc/<pid>/maps` 扫描和 `mincore` 发现。

**traceless-frida** 保持熟悉的 Frida API（`replace` / `attach` / `revert`），但每个 hook 由 **shpte KPM**（KernelPatch 模块）安装：

1. 目标代码页置 `UXN`
2. 经 `do_page_fault` 路由到整区域、位置无关的 DBI 克隆
3. 函数入口 override 到你的替换函数

**被 hook 的库 `.text` 一字不写**，maps 保持逐字节一致且不可写。写入发生在内核页表影子里，而不是覆盖目标本身。

Frida 只需加载一个小的 native shim（`libtracelessfrida.so`），去驱动本仓库栈里同一套 `lib/kpmhook` / `lib/dbi` 后端（见 [stealth-core](https://github.com/1013503897/stealth-core)）。**不必重编整个 Frida。**

### 工作原理

```
Frida（前端）                          libtracelessfrida.so（目标进程内）     shpte KPM（内核）
────────────                          ───────────────────────────────     ──────────────────
Traceless.replace(target, cb)
  cb = NativeCallback  ─────────────►  tlf_hook(target, cb)
  Module.load(.so)                       └ kpm_inline_hooker(target, cb)
                                            ├ dbi_recompile_range()   （PIC 区域克隆）
                                            └ syscall(179,"SHPTBRDG","pghook …") ──► do_pghook:
                                                                                       目标页置 PTE_UXN
返回 backup ◄────────────────────────  backup（克隆内原函数副本）                    装 fault 路由
                                                                                       入口 override → cb
  orig = NativeFunction(backup)                                               目标 .text：一字未改
```

Native 侧（`native/`）：`tlf_api.c`（5 符号 ABI）+ vendored 的 `kpmhook.c` / `dbi.c`。Frida 只做前端：选目标、解析符号、构造 `NativeCallback`。

### 前置条件

- AArch64 Android，已装 **APatch / KernelPatch**，**shpte KPM 已加载**且 **sysinfo 桥已武装**（见 [stealth-core](https://github.com/1013503897/stealth-core)）。运行期**不需要 superkey**，桥走 `sysinfo(179)`。
- 设备上有匹配的 `frida-server`，host 有 `frida` / `frida-tools`。
- Android NDK（r26 / 26.1 已验证）用于编译 `.so` 和测试样本。

### 构建

```powershell
# native 后端 → native/libtracelessfrida.so (arm64)
powershell native/build.ps1

# 测试样本 → test/tlf_target (arm64，导出 secret())
powershell test/build_target.ps1
```

### 使用（REPL 或 `-l`）

```js
// 先加载 agent/traceless.js（定义全局 `Traceless`）
Traceless.init();
// Traceless.init({ ghost: true });  // 克隆放到 VMA-less 内存（推荐）

const secret = Module.findGlobalExportByName('secret');

// Interceptor.replace 风格 —— orig() 经 KPM backup 克隆调用原函数：
Traceless.replace(secret, {
  retType: 'int', argTypes: ['int'],
  onCall(args, orig) { return orig(args[0]) + 1000; }
});

// Interceptor.attach 风格：
Traceless.attach(secret, {
  onEnter(args) { console.log('secret(', args[0], ')'); },
  onLeave(ret)  { return ret; }  // 返回值即可覆盖返回
}, { retType: 'int', argTypes: ['int'] });

Traceless.revert(secret);
Traceless.dispose();  // 撤销全部 + 释放映射（见「安全」）
```

`argTypes` / `retType` 使用 Frida `NativeFunction` 类型字符串。不传签名则用 `Traceless.SIG_GENERIC`（8 个指针参数、指针返回）—— 适合 ≤8 个整型/指针参数且返回整型/指针的函数。浮点 / double 或变参请显式传签名。

### 端到端测试

```powershell
python test/run.py            # 在 Frida 下 spawn tlf_target，hook secret()，验证
python test/run.py --ghost    # 同上，ghost（VMA-less 克隆）模式
```

脚手架同时验证**生效性**（`secret(n)` 返回 `orig + 1000`）和**无痕性**（`.text` 首字未变；页保持 `r-x`；无 `rwx` 覆盖）。

### 无痕范围

| 覆盖 | 不覆盖 |
| :--- | :--- |
| 目标库：逐字节一致、不可写、无 inline 跳转、`.text` 无 `rwx` | `frida-agent` 的 maps |
| 针对目标的 CRC / `/proc/maps` / `mincore` | 你的替换函数（在 Frida gum 分配器里） |
| `ghost: true` 时克隆为 VMA-less | 隐藏 Frida 自身（不在本项目范围） |

### 安全

- 设备必须已加载 shpte 且桥已武装。本工具**不**加载内核模块，只驱动已有桥。
- **把存活 region 撤到零可能让繁忙设备 panic。** 撤掉*最后一个* region 会重配 shpte 的全局 maps-hide（`show_map`），可能与另一进程读 `/proc/maps` 竞态。优先用 **ghost 模式**，避免在负载下拆除。

### 目录结构

```
native/   tlf_api.c + vendored kpmhook/dbi + build.ps1  → libtracelessfrida.so
agent/    traceless.js                                  Frida 前端
test/     target.c, test.js, run.py, build_target.ps1   端到端验证
docs/     DESIGN.md
```

### 相关项目

- [stealth-core](https://github.com/1013503897/stealth-core) — 本前端驱动的 shpte KPM 与 `lib/kpmhook` / `lib/dbi`
- [Vector](https://github.com/1013503897/Vector) — 同一 KPM 后端上的 Zygisk ART-hook 框架

`native/kpmhook.c`、`dbi.c`、`dbi.h`、`kpmhook.h`、`aarch64_decode.h` 来自 **stealth-core**（见 [SYNC.md](SYNC.md)）。许可证：**GPL-2.0-or-later**。
