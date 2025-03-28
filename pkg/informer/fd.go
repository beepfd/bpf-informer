package informer

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

type FD interface {
	GetFD() (int, error)
	Close() error
}

type PidFD struct {
	TargetPID  int
	TargetFD   int
	PidFDPoint uintptr
	FDPoint    uintptr
}

func (p *PidFD) GetFD() (int, error) {
	return -1, fmt.Errorf("未实现的基类方法")
}

func (p *PidFD) Close() error {
	if p.PidFDPoint != 0 {
		syscall.Close(int(p.PidFDPoint))
	}
	if p.FDPoint != 0 {
		syscall.Close(int(p.FDPoint))
	}
	return nil
}

func NewPidFD(pid int, fd int) FD {
	version, err := getKernelVersion()
	if err != nil {
		return &KernelLower56{
			PidFD: PidFD{TargetPID: pid, TargetFD: fd},
		}
	}

	if version[0] > 5 || (version[0] == 5 && version[1] >= 6) {
		return &KernelHigher56{
			PidFD: PidFD{TargetPID: pid, TargetFD: fd},
		}
	} else {
		// 低于5.6的版本使用兼容实现
		return &KernelLower56{
			PidFD: PidFD{TargetPID: pid, TargetFD: fd},
		}
	}
}

type KernelHigher56 struct {
	PidFD
}

func (k *KernelHigher56) GetFD() (int, error) {
	pidfd, _, errno := syscall.Syscall(sys_pidfd_open, uintptr(k.TargetPID), 0, 0)
	if errno != 0 {
		return 0, errno
	}
	k.PidFDPoint = pidfd

	newfd, _, errno := syscall.Syscall(sys_pidfd_getfd, uintptr(pidfd), uintptr(k.TargetFD), uintptr(0))
	if errno != 0 {
		return 0, errno
	}

	k.FDPoint = newfd

	return int(newfd), nil
}

// 内核版本低于5.6的兼容实现
type KernelLower56 struct {
	PidFD
}

func (k *KernelLower56) GetFD() (int, error) {
	fdPath := fmt.Sprintf("/proc/%d/fd/%d", k.TargetPID, k.TargetFD)
	// 使用系统调用复制文件描述符
	dupFd, err := syscall.Openat(unix.AT_FDCWD, fdPath, syscall.O_RDWR, 0)
	if err != nil {
		return -1, fmt.Errorf("无法复制文件描述符: %v", err)
	}

	k.FDPoint = uintptr(dupFd)
	return dupFd, nil
}

// 获取内核版本
func getKernelVersion() ([]int, error) {
	versionFile, err := os.ReadFile("/proc/version")
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`Linux version (\d+)\.(\d+)\.(\d+)`)
	matches := re.FindSubmatch(versionFile)
	if len(matches) < 4 {
		return nil, fmt.Errorf("无法解析内核版本")
	}

	major, _ := strconv.Atoi(string(matches[1]))
	minor, _ := strconv.Atoi(string(matches[2]))
	patch, _ := strconv.Atoi(string(matches[3]))

	return []int{major, minor, patch}, nil
}
