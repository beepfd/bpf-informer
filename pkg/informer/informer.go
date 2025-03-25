package informer

import (
	"bytes"
	"encoding/binary"
	"strings"

	b "github.com/cen-ngc5139/bpf-informer/binary"

	"fmt"
	"sync"
	"time"

	"github.com/cen-ngc5139/BeePF/loader/lib/src/observability/topology"

	loader "github.com/cen-ngc5139/BeePF/loader/lib/src/cli"
	"github.com/cen-ngc5139/BeePF/loader/lib/src/meta"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

// BPF 事件类型常量
const (
	EventTypeProgramAdd    = 1
	EventTypeProgramUpdate = 2
	EventTypeProgramDelete = 3
	EventTypeMapAdd        = 4
	EventTypeMapUpdate     = 5
	EventTypeMapDelete     = 6
)

// BPFProgEvent eBPF 事件结构体 (与 C 结构对应)
type BPFProgEvent struct {
	EventType uint32
	State     struct {
		ProgID   uint32
		LoadTime uint64
		Comm     [16]byte
		PID      uint32
		RV       ResourceVersion
	}
	RV ResourceVersion
}

// BPFMapEvent Map 事件结构体
type BPFMapEvent struct {
	EventType uint32
	State     struct {
		MapID    uint32
		LoadTime uint64
		Comm     [16]byte
		PID      uint32
		FD       int32
		RV       ResourceVersion
	}
	RV ResourceVersion
}

// BPFInformer 实现 eBPF 监控的 Informer
type BPFInformer struct {
	store         Store
	eventChan     chan Event
	stopChan      chan struct{}
	logger        *zap.Logger
	wg            sync.WaitGroup
	eventBuffer   []Event // 用于存储历史事件，实现从特定版本开始 watch
	bufferLock    sync.RWMutex
	maxBufferSize int
	l             *loader.BPFLoader
}

type SkipHandler struct {
}

func (h *SkipHandler) HandleEvent(ctx *meta.UserContext, data *meta.ReceivedEventData) error {
	return nil
}

// NewBPFInformer 创建新的 BPF Informer
func NewBPFInformer(objectPath string, logger *zap.Logger) (*BPFInformer, error) {
	// 提高 rlimit
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock failed: %w", err)
	}

	config := &loader.Config{
		ObjectPath:  objectPath,
		Logger:      logger,
		PollTimeout: 100 * time.Millisecond,
		Properties: meta.Properties{
			Maps: map[string]*meta.Map{
				"global_version": {
					Name:          "global_version",
					ExportHandler: &SkipHandler{},
				},
				"events": {
					Name:          "events",
					ExportHandler: &SkipHandler{},
				},
				"prog_states": {
					Name:          "prog_states",
					ExportHandler: &SkipHandler{},
				},
				"pid_map_states": {
					Name:          "pid_map_states",
					ExportHandler: &SkipHandler{},
				},
				"pid_func_name_states": {
					Name:          "map_states",
					ExportHandler: &SkipHandler{},
				},
			},
		},
	}
	l := loader.NewBPFLoader(config)

	err := l.Init()
	if err != nil {
		return nil, fmt.Errorf("init BPF loader failed: %w", err)
	}

	err = l.Load()
	if err != nil {
		return nil, fmt.Errorf("load BPF program failed: %w", err)
	}

	return &BPFInformer{
		store:         NewInMemoryStore(),
		l:             l,
		eventChan:     make(chan Event, 100),
		stopChan:      make(chan struct{}),
		logger:        logger,
		eventBuffer:   make([]Event, 0, 1000),
		maxBufferSize: 1000, // 最多保存1000个历史事件
	}, nil
}

// Start 启动 Informer
func (i *BPFInformer) Start() error {
	i.wg.Add(1)
	go i.processEvents()
	if err := i.l.Start(); err != nil {
		return fmt.Errorf("start BPF loader failed: %w", err)
	}

	if err := i.l.Stats(); err != nil {
		return fmt.Errorf("stats BPF loader failed: %w", err)
	}

	if err := i.l.Metrics(); err != nil {
		return fmt.Errorf("metrics BPF loader failed: %w", err)
	}

	return nil
}

// Stop 停止 Informer
func (i *BPFInformer) Stop() {
	close(i.stopChan)
	i.wg.Wait()
	close(i.eventChan)
	i.l.Stop()
}

// List 实现 list 操作
func (i *BPFInformer) List() ([]interface{}, []interface{}, ResourceVersion) {
	programs := i.store.List(ResourceTypeProgram)
	maps := i.store.List(ResourceTypeMap)
	rv := i.store.GetResourceVersion()
	return programs, maps, rv
}

// Watch 实现 watch 操作
func (i *BPFInformer) Watch(fromRV ResourceVersion) (<-chan Event, error) {
	// 首先检查是否需要从缓冲区恢复事件
	bufferedEvents := i.getEventsFromVersion(fromRV)

	if len(bufferedEvents) > 0 {
		// 创建一个新的通道来发送缓冲的事件和新事件
		ch := make(chan Event, 100)

		go func() {
			// 先发送缓冲的事件
			for _, event := range bufferedEvents {
				select {
				case ch <- event:
				case <-i.stopChan:
					close(ch)
					return
				}
			}

			// 然后转发新事件
			for {
				select {
				case event, ok := <-i.eventChan:
					if !ok {
						close(ch)
						return
					}
					ch <- event
				case <-i.stopChan:
					close(ch)
					return
				}
			}
		}()

		return ch, nil
	}

	// 如果没有缓冲的事件，直接返回事件通道
	return i.eventChan, nil
}

// getEventsFromVersion 获取从特定版本开始的事件
func (i *BPFInformer) getEventsFromVersion(fromRV ResourceVersion) []Event {
	i.bufferLock.RLock()
	defer i.bufferLock.RUnlock()

	var result []Event

	for _, event := range i.eventBuffer {
		if event.RV.Version > fromRV.Version {
			result = append(result, event)
		}
	}

	return result
}

// addEventToBuffer 添加事件到缓冲区
func (i *BPFInformer) addEventToBuffer(event Event) {
	i.bufferLock.Lock()
	defer i.bufferLock.Unlock()

	i.eventBuffer = append(i.eventBuffer, event)

	// 如果缓冲区超过最大容量，删除最旧的事件
	if len(i.eventBuffer) > i.maxBufferSize {
		i.eventBuffer = i.eventBuffer[1:]
	}
}

// loadInitialState 加载初始状态
func (i *BPFInformer) loadInitialState() error {
	progMap, err := topology.ListAllPrograms()
	if err != nil {
		i.logger.Warn("Fail to list all maps", zap.Error(err))
	}

	for progID, progInfo := range progMap {
		now := time.Now()
		loadTime, ok := progInfo.LoadTime()
		if !ok {
			i.logger.Warn("Fail to get loadTime", zap.String("name", progInfo.Name))
			continue
		}

		info := BPFProgInfo{
			ProgID:    uint32(progID),
			LoadTime:  uint64(loadTime),
			Comm:      progInfo.Name,
			RV:        ResourceVersion{Version: 1, Timestamp: uint64(now.UnixNano())},
			CreatedAt: now,
			UpdatedAt: now,
		}
		i.store.Add(ResourceTypeProgram, uint32(progID), info)
	}

	mapStates, err := topology.ListAllMaps()
	if err != nil {
		i.logger.Warn("Fail to list all maps", zap.Error(err))
	}

	for mapID, mapInfo := range mapStates {
		now := time.Now()
		info := BPFMapInfo{
			MapID:     uint32(mapID),
			LoadTime:  uint64(now.UnixNano()),
			Comm:      mapInfo.Name,
			RV:        ResourceVersion{Version: 1, Timestamp: uint64(now.UnixNano())},
			CreatedAt: now,
			UpdatedAt: now,
		}
		i.store.Add(ResourceTypeMap, uint32(mapID), info)
	}

	return nil
}

// processEvents 处理 eBPF 事件
func (i *BPFInformer) processEvents() {
	defer i.wg.Done()
	// 加载初始状态
	if err := i.loadInitialState(); err != nil {
		i.logger.Warn("Failed to load initial state", zap.Error(err))
	}

	// 获取环形缓冲区
	events, ok := i.l.Collection.Maps["events"]
	if !ok {
		i.logger.Error("Events ringbuf not found")
		return
	}

	// 创建 ringbuf 读取器
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		i.logger.Error("Failed to create ringbuf reader", zap.Error(err))
		return
	}
	defer rd.Close()

	i.logger.Info("BPF Informer started, listening for events...")

	// 处理事件循环
	for {
		select {
		case <-i.stopChan:
			i.logger.Info("Stopping BPF Informer")
			return
		default:
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				i.logger.Error("Error reading from ringbuf", zap.Error(err))
				continue
			}

			// 处理事件
			if err := i.handleEvent(record.RawSample); err != nil {
				i.logger.Error("Error handling event", zap.Error(err))
			}
		}
	}
}

// handleEvent 处理单个事件
func (i *BPFInformer) handleEvent(data []byte) error {
	// 首先检查事件类型
	if len(data) < 4 {
		return fmt.Errorf("invalid event data: too short")
	}

	eventType := binary.LittleEndian.Uint32(data[:4])

	switch eventType {
	case EventTypeProgramAdd, EventTypeProgramUpdate, EventTypeProgramDelete:
		return i.handleProgramEvent(eventType, data)
	case EventTypeMapAdd, EventTypeMapUpdate, EventTypeMapDelete:
		return i.handleMapEvent(eventType, data)
	default:
		return fmt.Errorf("unknown event type: %d", eventType)
	}
}

// handleProgramEvent 处理 BPF 程序事件
func (i *BPFInformer) handleProgramEvent(eventType uint32, data []byte) error {
	var event b.InformerBpfProgEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return fmt.Errorf("error parsing program event: %w", err)
	}

	now := time.Now()
	progInfo := BPFProgInfo{
		ProgID:    event.State.ProgId,
		LoadTime:  event.State.LoadTime,
		Comm:      convertInt8ToString(event.State.Comm[:]),
		PID:       event.State.Pid,
		RV:        ResourceVersion{Version: event.Rv.Version, Timestamp: event.Rv.Timestamp},
		UpdatedAt: now,
	}

	var eventTypeStr string
	var action func(string, uint32, interface{})

	switch eventType {
	case EventTypeProgramAdd:
		eventTypeStr = EventTypeAdd
		action = i.store.Add
		progInfo.CreatedAt = now
	case EventTypeProgramUpdate:
		eventTypeStr = EventTypeUpdate
		action = i.store.Update
		// 保留原有的创建时间
		if existing, ok := i.store.Get(ResourceTypeProgram, event.State.ProgId); ok {
			if prog, ok := existing.(BPFProgInfo); ok {
				progInfo.CreatedAt = prog.CreatedAt
			}
		}
	case EventTypeProgramDelete:
		eventTypeStr = EventTypeDelete
		action = func(resourceType string, id uint32, _ interface{}) {
			i.store.Delete(resourceType, id)
		}
	}

	// 执行存储操作
	if action != nil {
		action(ResourceTypeProgram, event.State.ProgId, progInfo)
	}

	// 创建事件对象
	e := Event{
		Type:         eventTypeStr,
		ResourceType: ResourceTypeProgram,
		Pid:          event.State.Pid,
		FuncName:     convertInt8ToString(event.State.Comm[:]),
		ResourceID:   event.State.ProgId,
		RV:           ResourceVersion{Version: event.Rv.Version, Timestamp: event.Rv.Timestamp},
		Object:       progInfo,
	}

	// 添加到缓冲区
	i.addEventToBuffer(e)

	// 发送事件
	select {
	case i.eventChan <- e:
	default:
		i.logger.Warn("Event channel full, dropping event",
			zap.String("type", eventTypeStr),
			zap.String("resource", ResourceTypeProgram),
			zap.Uint32("id", event.State.ProgId))
	}

	return nil
}

func convertInt8ToString(data []int8) string {
	var result strings.Builder
	for _, b := range data {
		if b == 0 {
			break
		}
		result.WriteByte(byte(b))
	}
	return result.String()
}

// handleMapEvent 处理 BPF Map 事件
func (i *BPFInformer) handleMapEvent(eventType uint32, data []byte) error {
	var event b.InformerBpfMapEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return fmt.Errorf("error parsing map event: %w", err)
	}

	now := time.Now()
	mapInfo := BPFMapInfo{
		MapID:     event.State.MapId,
		LoadTime:  event.State.LoadTime,
		Comm:      convertInt8ToString(event.State.Comm[:]),
		PID:       event.State.Pid,
		FD:        int(event.State.Fd),
		RV:        ResourceVersion{Version: event.Rv.Version, Timestamp: event.Rv.Timestamp},
		UpdatedAt: now,
	}

	var eventTypeStr string
	var action func(string, uint32, interface{})

	switch eventType {
	case EventTypeMapAdd:
		eventTypeStr = EventTypeAdd
		action = i.store.Add
		mapInfo.CreatedAt = now
	case EventTypeMapUpdate:
		eventTypeStr = EventTypeUpdate
		action = i.store.Update
		// 保留原有的创建时间
		if existing, ok := i.store.Get(ResourceTypeMap, event.State.Pid); ok {
			if m, ok := existing.(BPFMapInfo); ok {
				mapInfo.CreatedAt = m.CreatedAt
			}
		}
	case EventTypeMapDelete:
		eventTypeStr = EventTypeDelete
		action = func(resourceType string, id uint32, _ interface{}) {
			i.store.Delete(resourceType, id)
		}
	}

	// 执行存储操作
	if action != nil {
		action(ResourceTypeMap, event.State.Pid, mapInfo)
	}

	// 创建事件对象
	e := Event{
		Type:         eventTypeStr,
		ResourceType: ResourceTypeMap,
		Pid:          event.State.Pid,
		FuncName:     convertInt8ToString(event.State.Comm[:]),
		ResourceID:   event.State.MapId,
		RV:           ResourceVersion{Version: event.Rv.Version, Timestamp: event.Rv.Timestamp},
		Object:       mapInfo,
	}

	// 添加到缓冲区
	i.addEventToBuffer(e)

	// 发送事件
	select {
	case i.eventChan <- e:
	default:
		i.logger.Warn("Event channel full, dropping event",
			zap.String("type", eventTypeStr),
			zap.String("resource", ResourceTypeMap),
			zap.Uint32("id", event.State.Pid))
	}

	return nil
}
