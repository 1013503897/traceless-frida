# traceless-frida

**English** | [简体中文](#traceless-frida-简体中文)

A **Frida frontend for traceless inline hooking on AArch64 Android.** Instead of
writing an inline patch (which leaves an `rwx` trampoline and a modified `.text` that
anti-tamper CRCs, `/proc/<pid>/maps` scans and `mincore` catch), each hook is installed
by the **shpte KPM** (a KernelPatch module): the target's code page is `UXN`-trapped and
every instruction on it is routed — via the kernel `do_page_fault` handler — through a
whole-region, position-independent DBI clone; the target function's entry is overridden
to your replacement. **The hooked library's `.text` is never written and its maps stay
byte-identical and non-writable.**

The API mirrors Frida's `Interceptor` (`replace` / `attach` / `revert`), so it feels like
stock Frida — but the code write happens in the kernel's page-table shadow, not over the
target.

> This is the "traceless Frida" idea from the kanxue thread
> [*Frida 无痕 Hook*](https://bbs.kanxue.com/thread-291266.htm) (integrating a page-table
> shadow / `wxshadow` into Frida). Rather than patching `frida-gum`'s `Interceptor`
> internals (which needs a full frida rebuild), it drives an already-proven traceless
> backend — the same `lib/kpmhook` glue [Vector](https://github.com/1013503897/Vector)
> uses — from a small native shim that Frida loads into the target.

## How it works

```
Frida (frontend)                          libtracelessfrida.so (in target)         shpte KPM (kernel)
────────────────                          ─────────────────────────────────        ──────────────────
Traceless.replace(target, cb)
  cb = NativeCallback  ───────────────►   tlf_hook(target, cb)
  Module.load(.so)                          └ kpm_inline_hooker(target, cb)
                                               ├ dbi_recompile_range()  (clone the region, PIC)
                                               └ syscall(179,"SHPTBRDG","pghook …") ──► do_pghook:
                                                                                          set target page PTE_UXN
returns backup ◄──────────────────────── backup (in-clone copy)                           install do_page_fault route
                                                                                          entry override → cb
  orig = NativeFunction(backup)                                                    target .text: UNTOUCHED
```

The native side (`native/`) is `tlf_api.c` (a five-symbol ABI) over vendored
`kpmhook.c` + `dbi.c` (the AArch64 recompiler). Frida is purely the frontend: target
selection, symbol resolution, and `NativeCallback` replacements.

## Requirements

- AArch64 Android device with **APatch / KernelPatch** and the **shpte KPM loaded + its
  sysinfo bridge armed** (see [stealth-poc](https://github.com/1013503897/stealth-poc)).
  No superkey needed at runtime — the bridge rides `sysinfo(179)`.
- A running `frida-server` and a matching `frida` / `frida-tools` on the host.
- Android NDK (r26/26.1 known-good) to build the `.so` and the test target.

## Build

```powershell
# native backend -> native/libtracelessfrida.so (arm64)
powershell native/build.ps1
# test target -> test/tlf_target (arm64, exports secret())
powershell test/build_target.ps1
```

## Use (Frida REPL or `-l`)

```js
// load agent/traceless.js first (defines global `Traceless`)
Traceless.init();                       // arm the backend; throws if the bridge is off
// Traceless.init({ ghost: true });     // host the clone in VMA-less memory (recommended)

const secret = Module.findGlobalExportByName('secret');

// Interceptor.replace-style — orig() runs the original via the KPM backup clone:
Traceless.replace(secret, {
  retType: 'int', argTypes: ['int'],
  onCall(args, orig) { return orig(args[0]) + 1000; }
});

// Interceptor.attach-style:
Traceless.attach(secret, {
  onEnter(args) { console.log('secret(', args[0], ')'); },
  onLeave(ret)  { return ret; }          // return a value to override
}, { retType: 'int', argTypes: ['int'] });

Traceless.revert(secret);
Traceless.dispose();                     // revert all + release mappings (see ⚠️ below)
```

`argTypes`/`retType` follow Frida's NativeFunction type strings. Omit the signature to
use `Traceless.SIG_GENERIC` (8 pointer args, pointer return) — correct for any function
with ≤8 integer/pointer args and an integer/pointer return; pass an explicit signature
for float/double or variadic functions.

## End-to-end test

```powershell
python test/run.py            # spawn tlf_target under frida, hook secret(), verify
python test/run.py --ghost    # same, ghost (VMA-less clone) mode
```

The harness proves both **liveness** (`secret(n)` returns `orig+1000`) and
**tracelessness** (the target's first `.text` word is unchanged; its page stays `r-x`;
no `rwx` covers it).

## Tracelessness scope

**Hidden:** the target library — byte-identical, non-writable, no inline branch, no
`rwx` over its `.text`; passes CRC / `/proc/maps` / `mincore`. With `ghost:true` the
recompiled clone is also VMA-less (invisible to maps + `mincore`).

**Not hidden:** Frida's own presence (`frida-agent` maps) and your replacement function,
which lives in Frida's gum code allocator. Hiding `frida-agent` itself is out of scope —
combine with a Frida-hiding stack if you need that.

## ⚠️ Safety

- The device must already have shpte loaded + the bridge armed. This tool does **not**
  load kernel modules; it only drives the existing bridge.
- **Draining to zero live regions can panic a busy device.** Reverting the *last* region
  makes shpte reconfigure its global maps-hide (`show_map`) hook, which can race a
  concurrent `/proc/maps` read in another process. Prefer **ghost mode**, and don't tear
  down under load.

## Layout

```
native/   tlf_api.c + vendored kpmhook.c/dbi.c/… + build.ps1  -> libtracelessfrida.so
agent/    traceless.js                                          the Frida frontend
test/     target.c, test.js, run.py, build_target.ps1          end-to-end proof
docs/     DESIGN.md
```

## References

- kanxue — [*Frida 无痕 Hook*](https://bbs.kanxue.com/thread-291266.htm) — the
  page-table-shadow-into-Frida idea this project realizes with the shpte backend.
- [stealth-poc](https://github.com/1013503897/stealth-poc) — the shpte KPM plus the
  `lib/kpmhook` / `lib/dbi` backend this frontend drives.
- [Vector](https://github.com/1013503897/Vector) — a Zygisk ART-hook framework using the
  same KPM backend.

`native/kpmhook.c`, `dbi.c`, `dbi.h`, `kpmhook.h`, `aarch64_decode.h` are vendored
verbatim from **stealth-poc** — see [SYNC.md](SYNC.md). License: GPL-2.0-or-later.

---

# traceless-frida (简体中文)

[English](#traceless-frida) | **简体中文**

**AArch64 Android 上的无痕 inline hook —— Frida 前端。** 不再写 inline patch（那会留下
`rwx` 蹦床和被改的 `.text`，被反篡改 CRC、`/proc/<pid>/maps` 扫描、`mincore` 抓到）；
每个 hook 由 **shpte KPM**（一个 KernelPatch 模块）安装：把目标代码页置 `UXN` 陷阱，页上
每条指令经内核 `do_page_fault` 路由进一个**整区域、位置无关的 DBI 克隆**，并把目标函数入口
override 到你的替换函数。**被 hook 的库 `.text` 一字不写，其 maps 保持逐字节一致且不可写。**

API 对齐 Frida 的 `Interceptor`（`replace` / `attach` / `revert`），用起来跟原生 Frida 一样
—— 但代码写入发生在内核页表影子里，而不是覆盖到目标上。

> 这就是看雪帖
> [*Frida 无痕 Hook*](https://bbs.kanxue.com/thread-291266.htm)（把页表影子 / `wxshadow`
> 集成进 Frida）的思路。区别在于：不去改 `frida-gum` 的 `Interceptor` 内部（那要重编整个
> frida），而是从一个 Frida 加载进目标的小 native shim，去驱动一个**已被验证过的无痕后端**
> —— 即 [Vector](https://github.com/1013503897/Vector) 用的同一套 `lib/kpmhook` 胶水。

## 工作原理

```
Frida（前端）                             libtracelessfrida.so（目标进程内）        shpte KPM（内核）
────────────                             ─────────────────────────────────        ──────────────────
Traceless.replace(target, cb)
  cb = NativeCallback  ───────────────►   tlf_hook(target, cb)
  Module.load(.so)                          └ kpm_inline_hooker(target, cb)
                                               ├ dbi_recompile_range()  （克隆区域，位置无关）
                                               └ syscall(179,"SHPTBRDG","pghook …") ──► do_pghook:
                                                                                          目标页置 PTE_UXN
返回 backup ◄──────────────────────────── backup（克隆内的原函数副本）                     装 do_page_fault 路由
                                                                                          入口 override → cb
  orig = NativeFunction(backup)                                                    目标 .text：一字未改
```

Native 侧（`native/`）是 `tlf_api.c`（5 个符号的 ABI）加上 vendored 的 `kpmhook.c` +
`dbi.c`（AArch64 重编译器）。Frida 纯做前端：选目标、解析符号、构造 `NativeCallback` 替换。

## 前置条件

- AArch64 Android 设备，装 **APatch / KernelPatch**，且 **shpte KPM 已加载、sysinfo 桥已武装**
  （见 [stealth-poc](https://github.com/1013503897/stealth-poc)）。运行期**不需要 superkey**
  —— 桥搭在 `sysinfo(179)` 上。
- 设备上跑着 `frida-server`，host 侧有版本匹配的 `frida` / `frida-tools`。
- Android NDK（r26/26.1 已验证）用于编 `.so` 和测试样本。

## 构建

```powershell
# native 后端 -> native/libtracelessfrida.so (arm64)
powershell native/build.ps1
# 测试样本 -> test/tlf_target (arm64，导出 secret())
powershell test/build_target.ps1
```

## 使用（Frida REPL 或 `-l`）

```js
// 先加载 agent/traceless.js（定义全局 `Traceless`）
Traceless.init();                       // 武装后端；桥没开会抛异常
// Traceless.init({ ghost: true });     // 把克隆托管到 VMA-less 内存（推荐）

const secret = Module.findGlobalExportByName('secret');

// Interceptor.replace 风格 —— orig() 经 KPM backup 克隆调用原函数：
Traceless.replace(secret, {
  retType: 'int', argTypes: ['int'],
  onCall(args, orig) { return orig(args[0]) + 1000; }
});

// Interceptor.attach 风格：
Traceless.attach(secret, {
  onEnter(args) { console.log('secret(', args[0], ')'); },
  onLeave(ret)  { return ret; }          // 返回一个值即可覆盖返回值
}, { retType: 'int', argTypes: ['int'] });

Traceless.revert(secret);
Traceless.dispose();                     // 撤销全部 + 释放映射（见下方 ⚠️）
```

`argTypes`/`retType` 用 Frida NativeFunction 的类型字符串。不传签名则用
`Traceless.SIG_GENERIC`（8 个指针参数、指针返回）—— 对参数 ≤8 个整型/指针、返回整型/指针的
函数都正确；浮点/double 或变参函数请显式传签名。

## 端到端测试

```powershell
python test/run.py            # 在 frida 下 spawn tlf_target，hook secret()，验证
python test/run.py --ghost    # 同上，ghost（VMA-less 克隆）模式
```

脚手架同时证明**生效性**（`secret(n)` 返回 `orig+1000`）和**无痕性**（目标 `.text` 首字未变；
其页保持 `r-x`；无 `rwx` 覆盖它）。

## 无痕范围

**被隐藏的：** 目标库 —— 逐字节一致、不可写、无 inline 跳转、`.text` 上无 `rwx`；过 CRC /
`/proc/maps` / `mincore`。开 `ghost:true` 时，重编译出的克隆也是 VMA-less（对 maps + `mincore`
不可见）。

**不隐藏的：** Frida 自身存在（`frida-agent` 的 maps）以及你的替换函数（在 Frida 的 gum 代码
分配器里）。隐藏 `frida-agent` 本身不在本项目范围内 —— 需要的话请配合专门的 Frida 隐藏方案。

## ⚠️ 安全

- 设备必须已加载 shpte 且桥已武装。本工具**不**加载内核模块，只驱动已有的桥。
- **把存活 region 撤到零可能让繁忙设备 panic。** 撤掉*最后一个* region 会让 shpte 重配它的
  全局 maps-hide（`show_map`）hook，可能与另一进程并发读 `/proc/maps` 形成竞态。优先用
  **ghost 模式**，且别在负载下拆除。

## 目录结构

```
native/   tlf_api.c + vendored kpmhook.c/dbi.c/… + build.ps1  -> libtracelessfrida.so
agent/    traceless.js                                          Frida 前端
test/     target.c, test.js, run.py, build_target.ps1          端到端验证
docs/     DESIGN.md
```

## 参考

- 看雪 —— [*Frida 无痕 Hook*](https://bbs.kanxue.com/thread-291266.htm) —— 本项目用 shpte
  后端实现的「页表影子接进 Frida」思路来源。
- [stealth-poc](https://github.com/1013503897/stealth-poc) —— 本前端驱动的 shpte KPM 及
  `lib/kpmhook` / `lib/dbi` 后端。
- [Vector](https://github.com/1013503897/Vector) —— 使用同一 KPM 后端的 Zygisk ART-hook 框架。

`native/kpmhook.c`、`dbi.c`、`dbi.h`、`kpmhook.h`、`aarch64_decode.h` 逐字 vendored 自
**stealth-poc** —— 见 [SYNC.md](SYNC.md)。许可证：GPL-2.0-or-later。
