package informer

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// 定义常量
const (
	BPF_OBJ_GET_INFO_BY_FD = 15
	SYS_BPF                = 321 // x86_64 上的 BPF 系统调用号
	sys_pidfd_open         = 434 // x86_64 系统上 pidfd_open 的系统调用号
	sys_pidfd_getfd        = 438 // x86_64 系统上 pidfd_getfd 的系统调用号
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

func GetMapInfoByPidFD(pid int, fd int) (*MapInfo, error) {
	pidfd := NewPidFD(pid, fd)
	newfd, err := pidfd.GetFD()
	if err != nil {
		return nil, err
	}
	defer pidfd.Close()

	info := &MapInfo{}
	infoLen := uint32(unsafe.Sizeof(*info))

	var infoAttr struct {
		BpfFD   uint32
		InfoLen uint32
		Info    uint64
	}

	infoAttr.BpfFD = uint32(newfd)
	infoAttr.InfoLen = infoLen
	infoAttr.Info = uint64(uintptr(unsafe.Pointer(info)))

	_, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		unix.BPF_OBJ_GET_INFO_BY_FD,
		uintptr(unsafe.Pointer(&infoAttr)),
		unsafe.Sizeof(infoAttr),
	)

	if errno != 0 {
		return nil, fmt.Errorf("BPF_OBJ_GET_INFO_BY_FD 失败: %v", errno)
	}

	return info, nil
}
