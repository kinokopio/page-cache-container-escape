# PCCE — Page Cache Container Escape

利用 Linux 内核 Copy Fail 漏洞（CVE-2026-31431），通过覆写 page cache 在容器内实现宿主机 root 代码执行。不修改磁盘文件，不需要任何特权。

## 原理

Copy Fail 允许通过 AF_ALG splice 向内核 page cache 写入任意 4 字节，而不修改磁盘文件。PCCE 利用这个原语：

1. 将容器内目标二进制的 page cache 覆写为 `#!/proc/self/exe`，使内核递归调用 `/proc/self/exe`（即宿主机的 runc）
2. 通过 `/proc/<pid>/exe` 拿到 runc 的 fd，覆写其 page cache 为 payload（`#!/bin/bash\n<cmd>`）
3. 下次宿主机调用 runc 时，内核读取被篡改的 page cache，以 root 执行 payload
4. payload 执行后自动 drop page cache，runc 恢复正常

## 两种模式

### exec 模式

覆写 exec target（默认 `/bin/sh`），等待 `kubectl exec` 触发 runc 进入容器，捕获 runc fd 并覆写。

```
pcce exec --cmd 'id > /tmp/pwned'
```

触发方式：
- Pod 配置 `livenessProbe: exec`（自动，每 5 秒）
- 手动 `kubectl exec <pod> -- <cmd>`

### restart 模式

覆写动态链接器（ld.so）为 injector，覆写容器入口点为 shebang，然后 crash 容器。重启时内核加载 injector，injector 再覆写 runc page cache 为 payload。

```
pcce restart --cmd 'id > /tmp/pwned'
```

不需要外部触发，exploit 自己 crash 容器后等待 kubelet 重启。

## Preflight 检查

```
pcce restart --preflight --cmd 'true'
```

输出逃逸可行性判定：

```
[+] ESCAPE: viable (restart)                       # 绿色
[+] ESCAPE: viable (exec only)                     # 绿色
[-] ESCAPE: not viable                             # 红色
```

判定逻辑：
- Copy Fail 不可用 → 不可行
- 动态链接器存在 → restart 可行
- 动态链接器不存在，当前 root → 可创建 placeholder，restart 可行
- 动态链接器不存在，非 root，有 SUID → 提权后创建，restart 可行
- 都不行 → fallback 到 exec only

## Crash 方法

按顺序尝试：

| 方法 | 原理 |
|---|---|
| cgroup-kill | 写 `1` 到 cgroup v2 的 `cgroup.kill` |
| sigint | 发 SIGINT 给 PID 1（多数 init 进程会干净退出） |
| sigkill | 发 SIGKILL 给 PID 1（内核保护，通常无效） |
| kill-all | 杀所有非自身非目标进程 |
| oom | 拉高目标 oom_score_adj，耗尽内存触发 OOM killer |

## 构建

```bash
make                  # 构建 injector + pcce
make verify           # 构建并检查产物（marker、payload len、ELF）
CROSS_PREFIX=x86_64-linux-gnu- make  # 交叉编译
```

需要 `gcc` / `ld`（或交叉工具链）和 `go 1.22+`。

## 前置条件

- 内核 < 6.12（存在 Copy Fail 漏洞）
- restart 模式需要 runc 动态链接（有 PT_INTERP）
- 不需要 privileged、hostPID、hostNetwork、capabilities

## 项目结构

```
cmd/pcce/            # Go 主程序
  cli.go             # 参数解析
  crash.go           # 容器崩溃方法
  elf_interp.go      # ELF PT_INTERP 读取
  entrypoint.go      # 容器入口点解析
  escape_assessment  # 逃逸可行性判定
  exec_mode.go       # exec 模式
  restart_mode.go    # restart 模式
  linker.go          # 动态链接器选择与创建
  payload.go         # payload 构造与 injector patch
  write_targets.go   # page cache 写入
internal/copyfail/   # Copy Fail 写原语
injector.c           # C injector（纯 syscall，单 RWX LOAD 段）
doc/                 # 部署 demo 和流程图
```

## 恢复

攻击只修改 page cache，不修改磁盘。恢复方式：

```bash
echo 3 > /proc/sys/vm/drop_caches
```

payload 默认自动追加 drop_caches（`--no-restore` 禁用）。
