package informer

import (
	"sync"
	"time"
)

// 资源类型常量
const (
	ResourceTypeProgram = "BPFProgram"
	ResourceTypeMap     = "BPFMap"
)

// 事件类型常量
const (
	EventTypeAdd    = "ADDED"
	EventTypeUpdate = "MODIFIED"
	EventTypeDelete = "DELETED"
)

// ResourceVersion 表示资源版本
type ResourceVersion struct {
	Version   uint64 `json:"version"`
	Timestamp uint64 `json:"timestamp"`
}

// BPFProgInfo 表示 BPF 程序信息
type BPFProgInfo struct {
	ProgID    uint32          `json:"prog_id"`
	LoadTime  uint64          `json:"load_time"`
	Comm      string          `json:"comm"`
	PID       uint32          `json:"pid"`
	RV        ResourceVersion `json:"resource_version"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// BPFMapInfo 表示 BPF 映射信息
type BPFMapInfo struct {
	MapID     uint32          `json:"map_id"`
	LoadTime  uint64          `json:"load_time"`
	Comm      string          `json:"comm"`
	PID       uint32          `json:"pid"`
	FD        int             `json:"fd"`
	RV        ResourceVersion `json:"resource_version"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// EventRecord 表示从环形缓冲区读取的事件
type EventRecord struct {
	EventType  uint8           // 事件类型
	ResourceID uint32          // 资源ID
	RV         ResourceVersion // 资源版本
}

// Event 表示通知给客户端的事件
type Event struct {
	Type         string          `json:"type"`             // 事件类型：ADDED, MODIFIED, DELETED
	ResourceType string          `json:"resource_type"`    // 资源类型：BPFProgram, BPFMap
	Pid          uint32          `json:"pid"`              // 进程ID
	FuncName     string          `json:"func_name"`        // 函数名
	ResourceID   uint32          `json:"resource_id"`      // 资源ID
	RV           ResourceVersion `json:"resource_version"` // 资源版本
	Object       interface{}     `json:"object"`           // 对象数据：BPFProgInfo 或 BPFMapInfo
}

// Store 定义资源存储接口
type Store interface {
	// 获取单个资源
	Get(resourceType string, id uint32) (interface{}, bool)

	// 列出所有资源
	List(resourceType string) []interface{}

	// 添加资源
	Add(resourceType string, id uint32, obj interface{})

	// 更新资源
	Update(resourceType string, id uint32, obj interface{})

	// 删除资源
	Delete(resourceType string, id uint32)

	// 获取当前资源版本
	GetResourceVersion() ResourceVersion
}

// InMemoryStore 实现内存中的资源存储
type InMemoryStore struct {
	mu        sync.RWMutex
	programs  map[uint32]BPFProgInfo
	maps      map[uint32]BPFMapInfo
	currentRV ResourceVersion
}

// NewInMemoryStore 创建新的内存存储
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		programs:  make(map[uint32]BPFProgInfo),
		maps:      make(map[uint32]BPFMapInfo),
		currentRV: ResourceVersion{Version: 0, Timestamp: uint64(time.Now().UnixNano())},
	}
}

// Get 获取资源
func (s *InMemoryStore) Get(resourceType string, id uint32) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch resourceType {
	case ResourceTypeProgram:
		prog, exists := s.programs[id]
		return prog, exists
	case ResourceTypeMap:
		m, exists := s.maps[id]
		return m, exists
	default:
		return nil, false
	}
}

// List 列出资源
func (s *InMemoryStore) List(resourceType string) []interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []interface{}

	switch resourceType {
	case ResourceTypeProgram:
		for _, prog := range s.programs {
			result = append(result, prog)
		}
	case ResourceTypeMap:
		for _, m := range s.maps {
			result = append(result, m)
		}
	}

	return result
}

// Add 添加资源
func (s *InMemoryStore) Add(resourceType string, id uint32, obj interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch resourceType {
	case ResourceTypeProgram:
		if prog, ok := obj.(BPFProgInfo); ok {
			s.programs[id] = prog
			if prog.RV.Version > s.currentRV.Version {
				s.currentRV = prog.RV
			}
		}
	case ResourceTypeMap:
		if m, ok := obj.(BPFMapInfo); ok {
			s.maps[id] = m
			if m.RV.Version > s.currentRV.Version {
				s.currentRV = m.RV
			}
		}
	}
}

// Update 更新资源
func (s *InMemoryStore) Update(resourceType string, id uint32, obj interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch resourceType {
	case ResourceTypeProgram:
		if prog, ok := obj.(BPFProgInfo); ok {
			s.programs[id] = prog
			if prog.RV.Version > s.currentRV.Version {
				s.currentRV = prog.RV
			}
		}
	case ResourceTypeMap:
		if m, ok := obj.(BPFMapInfo); ok {
			s.maps[id] = m
			if m.RV.Version > s.currentRV.Version {
				s.currentRV = m.RV
			}
		}
	}
}

// Delete 删除资源
func (s *InMemoryStore) Delete(resourceType string, id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch resourceType {
	case ResourceTypeProgram:
		delete(s.programs, id)
	case ResourceTypeMap:
		delete(s.maps, id)
	}
}

// GetResourceVersion 获取当前资源版本
func (s *InMemoryStore) GetResourceVersion() ResourceVersion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentRV
}

// Informer 接口定义
type Informer interface {
	// List 列出资源并返回资源版本
	List() ([]interface{}, []interface{}, ResourceVersion)

	// Watch 从指定资源版本开始监听事件
	Watch(fromRV ResourceVersion) (<-chan Event, error)

	// Start 启动 Informer
	Start() error

	// Stop 停止 Informer
	Stop()
}

// EventHandler 定义事件处理接口
type EventHandler interface {
	// OnAdd 处理添加事件
	OnAdd(resourceType string, obj interface{})

	// OnUpdate 处理更新事件
	OnUpdate(resourceType string, obj interface{})

	// OnDelete 处理删除事件
	OnDelete(resourceType string, id uint32)
}
