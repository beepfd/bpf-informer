package informer

import (
	"fmt"
	"syscall"
	"unsafe"
)

// 定义常量
const (
	BPF_OBJ_GET_INFO_BY_FD = 15
	SYS_BPF                = 321 // x86_64 上的 BPF 系统调用号
)

// BPF map 信息结构
type MapInfo struct {
	Type         uint32
	ID           uint32
	KeySize      uint32
	ValueSize    uint32
	MaxEntries   uint32
	MapFlags     uint32
	Name         [16]byte
	IfIndex      uint32
	BTFVmlinuxID uint32
	Netns        uint64
	// 更多字段取决于内核版本
}

// BPF 系统调用的参数结构
type bpfAttr struct {
	BpfFD   uint32
	InfoLen uint32
	Info    uint64
}

// 从 fd 获取 BPF map 信息
func GetMapInfoByFD(fd int) (*MapInfo, error) {
	// 创建用于接收信息的结构
	info := &MapInfo{}
	infoLen := uint32(unsafe.Sizeof(*info))

	// 准备系统调用参数
	var attr struct {
		Info bpfAttr
		Pad  [24]byte // 确保结构体大小足够
	}

	attr.Info.BpfFD = uint32(fd)
	attr.Info.InfoLen = infoLen
	attr.Info.Info = uint64(uintptr(unsafe.Pointer(info)))

	// 执行系统调用
	_, _, err := syscall.Syscall(
		SYS_BPF,
		uintptr(BPF_OBJ_GET_INFO_BY_FD),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if err != 0 {
		return nil, fmt.Errorf("BPF_OBJ_GET_INFO_BY_FD failed: %v", err)
	}

	return info, nil
}
