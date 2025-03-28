#include "vmlinux.h"
#include "vmlinux-x86.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_ipv6.h"

char LICENSE[] SEC("license") = "GPL";

// 资源版本结构，类似 K8s ResourceVersion
struct resource_version
{
    __u64 version;   // 全局递增的版本号
    __u64 timestamp; // 时间戳，用于排序
};

// 事件类型定义
#define EVENT_TYPE_ADD 1        // 程序加载
#define EVENT_TYPE_UPDATE 2     // 程序更新
#define EVENT_TYPE_DELETE 3     // 程序卸载
#define EVENT_TYPE_MAP_ADD 4    // Map 创建
#define EVENT_TYPE_MAP_UPDATE 5 // Map 更新
#define EVENT_TYPE_MAP_DELETE 6 // Map 删除

// 全局版本号管理
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_version SEC(".maps");

// 程序状态结构
struct bpf_prog_state
{
    __u32 prog_id;              // 程序ID
    __u64 load_time;            // 加载时间
    char func_name[16];         // 加载程序的函数名
    char comm[16];              // 加载程序的进程名
    __u32 pid;                  // 加载程序的进程ID
    struct resource_version rv; // 资源版本
};

struct bpf_map_state
{
    __u32 map_id;
    __u64 load_time;
    char map_name[16];
    char comm[16];
    __u32 pid;
    int fd;
    struct resource_version rv; // 资源版本
};

struct bpf_prog_state *unused_bpf_prog_state __attribute__((unused));
struct bpf_map_state *unused_bpf_map_state __attribute__((unused));
// 事件记录结构，用于 ringbuffer
struct bpf_prog_event
{
    __u32 event_type;            // 事件类型(ADD/UPDATE/DELETE)
    struct bpf_prog_state state; // 程序状态
    struct resource_version rv;  // 资源版本号
};

struct bpf_prog_event *unused_bpf_prog_event __attribute__((unused));

struct bpf_map_event
{
    __u32 event_type;           // 事件类型(MAP_ADD/MAP_UPDATE/MAP_DELETE)
    struct bpf_map_state state; // Map状态
    struct resource_version rv; // 资源版本号
};

struct bpf_map_event *unused_bpf_map_event __attribute__((unused));

// 定义 ringbuffer map - 用于所有事件的传输
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

// 定义程序状态跟踪 hash map (prog_id -> state)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct bpf_prog_state);
} prog_states SEC(".maps");

// 定义复合键结构
struct pid_func_key
{
    __u32 pid;
    char func_name[16]; // 函数名最大长度
    u8 tag[8];          // 标签，用于区分不同的函数
    u64 load_time;
};

// 定义 pid + funcname 的映射
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct pid_func_key);
    __type(value, struct bpf_prog_state);
} pid_prog_states SEC(".maps");

// 定义 map_id + comm 的映射
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct pid_func_key);
    __type(value, struct bpf_map_state);
} pid_map_states SEC(".maps");

// 创建临时存储表记录 map_create 调用信息
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct bpf_map_state);
} map_create_calls SEC(".maps");

typedef u64 stack[100];
struct
{
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __type(key, u32);
    __type(value, stack);
    __uint(max_entries, 1 << 14);
} stack_traces SEC(".maps");

// 辅助函数：获取并递增全局版本号
static __always_inline __u64 get_next_version(void)
{
    __u32 key = 0;
    __u64 *version = bpf_map_lookup_elem(&global_version, &key);
    __u64 new_version = 1;

    if (version)
    {
        new_version = *version + 1;
        bpf_map_update_elem(&global_version, &key, &new_version, BPF_ANY);
    }
    else
    {
        bpf_map_update_elem(&global_version, &key, &new_version, BPF_ANY);
    }

    return new_version;
}

// 辅助函数: 发送 BPF 程序事件到 ringbuffer
static int send_event(__u32 event_type, struct bpf_prog_state *state)
{
    struct bpf_prog_event *event;

    // 从 ringbuffer 分配内存
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
    {
        return -1;
    }

    // 更新资源版本
    state->rv.version = get_next_version();
    state->rv.timestamp = bpf_ktime_get_ns();

    // 填充事件信息
    event->event_type = event_type;
    __builtin_memcpy(&event->state, state, sizeof(*state));
    event->rv = state->rv;

    // 提交事件
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// 辅助函数: 发送 Map 事件到 ringbuffer
static int send_map_event(__u32 event_type, struct bpf_map_state *state)
{
    struct bpf_map_event *event;

    // 从 ringbuffer 分配内存
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
    {
        return -1;
    }

    // 更新资源版本
    state->rv.version = get_next_version();
    state->rv.timestamp = bpf_ktime_get_ns();

    // 填充事件信息
    event->event_type = event_type;
    __builtin_memcpy(&event->state, state, sizeof(*state));
    event->rv = state->rv;

    // 提交事件
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// 监控程序加载
SEC("kprobe/bpf_prog_kallsyms_add")
int BPF_KPROBE(trace_bpf_prog_load)
{
    // 获取返回的 bpf_prog 指针
    struct bpf_prog *prog = (struct bpf_prog *)PT_REGS_PARM1(ctx);
    if (!prog)
        return 0;

    // 准备程序状态结构
    struct bpf_prog_state state = {0};

    // 获取当前进程信息
    state.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&state.comm, sizeof(state.comm));
    state.load_time = bpf_ktime_get_ns();

    // 初始化资源版本
    state.rv.timestamp = state.load_time;

    // 获取 aux 指针以读取 id
    struct bpf_prog_aux *aux;
    bpf_probe_read_kernel(&aux, sizeof(aux), &prog->aux);
    if (!aux)
        return 0;

    // 读取程序 ID
    bpf_probe_read_kernel(&state.prog_id, sizeof(state.prog_id), &aux->id);
    if (state.prog_id == 0)
        return 0;

    char func_name[16];
    bpf_probe_read_kernel(&func_name, sizeof(func_name), &aux->name);
    __builtin_memcpy(state.func_name, func_name, sizeof(func_name));

    struct pid_func_key key = {0};
    key.pid = state.pid;
    __builtin_memcpy(key.func_name, func_name, sizeof(func_name));
    bpf_probe_read_kernel(&key.tag, sizeof(key.tag), &prog->tag);
    bpf_probe_read_kernel(&key.load_time, sizeof(key.load_time), &aux->load_time);

    // 检查是否存在，确定是ADD还是UPDATE
    struct bpf_prog_state *existing;
    existing = bpf_map_lookup_elem(&pid_prog_states, &key);

    __u32 event_type;
    if (existing)
    {
        event_type = EVENT_TYPE_UPDATE;
        // 保留已有的资源版本信息，但将获取新版本
        state.rv.version = existing->rv.version;
    }
    else
    {
        event_type = EVENT_TYPE_ADD;
    }

    // 发送事件到ringbuffer
    send_event(event_type, &state);

    // 更新程序状态map
    bpf_map_update_elem(&prog_states, &state.prog_id, &state, BPF_ANY);
    bpf_map_update_elem(&pid_prog_states, &key, &state, BPF_ANY);

    // 打印基本信息
    bpf_printk("BPF program %s: id=%u pid=%d comm=%s func_name=%s rv=%llu\n",
               event_type == EVENT_TYPE_ADD ? "loaded" : "updated",
               state.prog_id, state.pid, state.comm, func_name, state.rv.version);

    return 0;
}

// 监控程序释放
SEC("kprobe/bpf_prog_kallsyms_del_all")
int BPF_KPROBE(trace_bpf_prog_release)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct bpf_prog *prog;
    prog = (struct bpf_prog *)PT_REGS_PARM1(ctx);
    if (!prog)
    {
        bpf_printk("fail to get bpf_prog: pid=%u comm=%s\n", pid, comm);
        return 0;
    }

    // 读取程序信息
    struct bpf_prog_aux *aux;
    bpf_probe_read_kernel(&aux, sizeof(aux), &prog->aux);
    if (!aux)
    {
        bpf_printk("fail to get bpf_prog_aux: pid=%u comm=%s\n", pid, comm);
        return 0;
    }

    char func_name[16];
    if (bpf_probe_read_kernel(&func_name, sizeof(func_name), &aux->name) != 0)
    {
        bpf_printk("fail to read func_name: pid=%u comm=%s\n", pid, comm);
        return 0;
    }

    // 尝试从状态map中查找
    struct bpf_prog_state *state;
    struct pid_func_key key = {0};
    key.pid = pid;
    __builtin_memcpy(key.func_name, func_name, sizeof(func_name));
    bpf_probe_read_kernel(&key.tag, sizeof(key.tag), &prog->tag);
    bpf_probe_read_kernel(&key.load_time, sizeof(key.load_time), &aux->load_time);

    state = bpf_map_lookup_elem(&pid_prog_states, &key);
    if (!state)
    {
        bpf_printk("BPF program deleted (unknown load): pid=%u comm=%s\n", pid, comm);
        return 0;
    }

    // 读取当前引用计数
    atomic_t ref_cnt;
    if (bpf_probe_read_kernel(&ref_cnt, sizeof(ref_cnt), &aux->refcnt) != 0)
    {
        bpf_printk("fail to read ref_cnt: pid=%u comm=%s\n", pid, comm);
        return 0;
    }
    int count = 0;
    if (bpf_probe_read_kernel(&count, sizeof(count), &ref_cnt) != 0)
    {
        bpf_printk("fail to read count: pid=%u comm=%s\n", pid, comm);
        return 0;
    }

    // 更新状态中的引用计数
    struct bpf_prog_state updated_state = *state;

    // 检查是否为最后一个引用（释放）
    if (count <= 0)
    {
        // 发送删除事件
        send_event(EVENT_TYPE_DELETE, &updated_state);

        // 从map中删除
        bpf_map_delete_elem(&prog_states, &state->prog_id);
        bpf_map_delete_elem(&pid_prog_states, &key);

        bpf_printk("BPF program released: id=%u rv=%llu\n", state->prog_id, updated_state.rv.version);
    }

    return 0;
}

struct bpf_map_attr
{
    __u32 map_type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
    __u32 inner_map_fd;
    __u32 numa_node;
    char map_name[16];
    __u32 map_ifindex;
    __u32 btf_fd;
    __u32 btf_key_type_id;
    __u32 btf_value_type_id;
    __u32 btf_vmlinux_value_type_id;
};

static __always_inline int is_map_name_match(const char *name, const char *target, int max_len)
{
    for (int i = 0; i < max_len; i++)
    {
        if (name[i] != target[i])
            return 0;
        if (name[i] == '\0')
            return 1;
    }
    return 1;
}

// 监控 map 创建
SEC("kprobe/map_create")
int BPF_KPROBE(trace_kprobe_map_create)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    void *attr = (void *)PT_REGS_PARM1(ctx);
    struct bpf_map_attr bpf_attr;

    // 使用 bpf_probe_read_kernel 来安全地读取内存
    if (bpf_probe_read_kernel(&bpf_attr, sizeof(bpf_attr), attr) != 0)
    {
        bpf_printk("fail to read attr: pid=%u comm=%s\n", pid, comm);
        return 0;
    }

    char map_name[16];
    bpf_probe_read_kernel(&map_name, sizeof(map_name), &bpf_attr.map_name);
    if (map_name[0] == '\0')
    {
        bpf_printk("map_name is empty: pid=%u comm=%s\n", pid, comm);
        return 0;
    }

    if (is_map_name_match(map_name, "feature_test", sizeof(map_name)) ||
        is_map_name_match(map_name, ".test", sizeof(map_name)))
    {
        bpf_printk("skip map_create: pid=%u comm=%s map_name=%s\n", pid, comm, map_name);
        return 0;
    }

    // 创建 map 状态结构
    struct bpf_map_state map_state = {0};
    map_state.load_time = bpf_ktime_get_ns();
    map_state.rv.timestamp = map_state.load_time;
    __builtin_memcpy(map_state.comm, comm, sizeof(comm));
    map_state.pid = pid;
    __builtin_memcpy(map_state.map_name, map_name, sizeof(map_name));

    __u32 zero = 0;
    // 存储调用信息，以便在 kretprobe 中使用
    bpf_map_update_elem(&map_create_calls, &zero, &map_state, BPF_ANY);

    bpf_printk("kprobe map_create: pid=%u comm=%s map_name=%s rv=%llu\n",
               pid, comm, map_name, map_state.rv.version);

    return 0;
}

SEC("kretprobe/map_create")
int BPF_KRETPROBE(trace_kretprobe_map_create, int fd)
{
    // 获取当前进程标识
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u32 zero = 0;

    // 查找对应的调用信息
    struct bpf_map_state *map_state = bpf_map_lookup_elem(&map_create_calls, &zero);
    if (!map_state || fd < 0)
    {
        bpf_printk("fail to get map_create_info: pid=%u fd=%d\n", pid, fd);
        // 清理临时存储
        bpf_map_delete_elem(&map_create_calls, &zero);
        return 0;
    }

    map_state->fd = fd;

    // 创建 map 状态结构 key
    struct pid_func_key key = {0};
    key.pid = pid;
    __builtin_memcpy(key.func_name, map_state->map_name, sizeof(map_state->map_name));

    // 发送事件
    send_map_event(EVENT_TYPE_MAP_ADD, map_state);

    // 更新状态
    bpf_map_update_elem(&pid_map_states, &key, map_state, BPF_ANY);
    bpf_map_delete_elem(&map_create_calls, &zero);

    bpf_printk("kretprobe map_create: pid=%u fd=%d map_name=%s rv=%llu\n",
               pid, fd, map_state->map_name, map_state->rv.version);

    return 0;
}

// 监控 map 释放
SEC("kprobe/bpf_map_release")
int BPF_KPROBE(trace_bpf_map_release)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct file *filp = (struct file *)PT_REGS_PARM2(ctx);
    if (!filp)
    {
        bpf_printk("fail to get file: pid=%u comm=%s\n", pid, comm);
        return 0;
    }

    struct bpf_map *map;
    bpf_probe_read_kernel(&map, sizeof(map), &filp->private_data);
    if (!map)
    {
        bpf_printk("fail to get map: pid=%u comm=%s\n", pid, comm);
        return 0;
    }

    u32 map_id;
    bpf_probe_read_kernel(&map_id, sizeof(map_id), &map->id);

    char map_name[16];
    bpf_probe_read_kernel(&map_name, sizeof(map_name), &map->name);

    struct pid_func_key key = {0};
    key.pid = pid;
    __builtin_memcpy(key.func_name, map_name, sizeof(map_name));

    struct bpf_map_state *map_state;
    map_state = bpf_map_lookup_elem(&pid_map_states, &key);
    if (!map_state)
    {
        bpf_printk("fail to get map_state from pid_map_states: pid=%u comm=%s map_name=%s\n", pid, comm, map_name);
        return 0;
    }

    map_state->map_id = map_id;

    // 制作副本用于发送事件
    struct bpf_map_state *state_copy = map_state;

    // 发送删除事件
    send_map_event(EVENT_TYPE_MAP_DELETE, state_copy);

    // 从map中删除状态
    bpf_map_delete_elem(&pid_map_states, &key);

    bpf_printk("BPF map released: pid=%u comm=%s map_id=%u map_name=%s rv=%llu\n",
               pid, comm, map_id, map_name, state_copy->rv.version);

    return 0;
}
