# BPF Informer

BPF Informer 是一个类似于 Kubernetes Informer 的 eBPF 监控工具，可以实时监控系统中的 eBPF 程序和映射资源。它支持两种监控机制（kprobe 和 tracepoint）并提供一致的 list/watch 接口。

## 功能特性

- **资源版本管理**：实现类似 Kubernetes 的 ResourceVersion 机制，确保 list/watch 之间的数据一致性
- **事件通知**：实时监控 eBPF 程序和映射的生命周期事件（添加、更新、删除）
- **缓冲区机制**：使用 RingBuffer 高效传输事件，并缓存历史事件
- **双重监控机制**：同时支持 kprobe 和 tracepoint 两种挂载方式
- **类 K8s 客户端接口**：提供熟悉的 list/watch 接口和事件处理机制

## 系统要求

- Linux 内核 5.10+ (推荐)
- Clang 和 LLVM
- Go 1.22+
- 内核头文件
- libbpf

## 安装依赖

```bash
# Ubuntu/Debian
sudo apt-get install clang llvm libelf-dev linux-headers-$(uname -r) build-essential
sudo apt-get install libbpf-dev
```

## 编译和运行

```bash
# 生成 eBPF 对象文件
TARGET_GOARCH=amd64 go generate

# 编译项目
go build -o bpf-informer

# 运行（需要 root 权限）
sudo ./bpf-informer
```

## 命令行选项

```
-obj string
    BPF 对象文件路径 (默认 "./binary/informer_x86_bpfel.o")
-debug
    启用调试日志
```

## 项目结构

- **bpf/**：eBPF C 代码
  - **informer.c**：eBPF 程序，负责捕获内核事件
- **pkg/**：Go 代码
  - **informer/**：核心 Informer 实现
  - **client/**：客户端和事件处理器
- **main.go**：程序入口

## 工作原理

### 资源版本一致性

为了解决 list/watch 之间的版本一致性问题，我们实现了类似 Kubernetes 的 ResourceVersion 机制：

1. 每个资源事件都分配一个单调递增的版本号
2. List 操作返回当前的资源版本号
3. Watch 操作从指定的资源版本开始观察事件
4. 使用环形缓冲区存储最近的事件历史

### 典型流程

1. **List 操作**：获取当前所有资源和资源版本
2. **处理初始列表**：客户端处理初始资源列表
3. **Watch 操作**：从 List 返回的资源版本开始监听后续事件
4. **事件处理**：客户端接收并处理事件流

## 使用示例

```go
// 创建客户端
bpfClient, err := client.NewBPFClient("./binary/informer_x86_bpfel.o", logger)
if err != nil {
    log.Fatal(err)
}

// 添加事件处理器
bpfClient.AddEventHandler(&MyEventHandler{})

// 启动客户端
bpfClient.Start()
defer bpfClient.Stop()

// 自定义事件处理器
type MyEventHandler struct{}

// 处理添加事件
func (h *MyEventHandler) OnAdd(resourceType string, obj interface{}) {
    // 处理添加事件
}

// 处理更新事件
func (h *MyEventHandler) OnUpdate(resourceType string, obj interface{}) {
    // 处理更新事件
}

// 处理删除事件
func (h *MyEventHandler) OnDelete(resourceType string, id uint32) {
    // 处理删除事件
}
```

## 许可证

本项目采用 GPL 许可证。 