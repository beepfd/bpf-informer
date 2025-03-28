package client

import (
	"fmt"
	"strings"
	"time"

	"github.com/cen-ngc5139/bpf-informer/pkg/informer"
	"go.uber.org/zap"
)

// BPFClient 是 BPF 资源的客户端
type BPFClient struct {
	informer informer.Informer
	logger   *zap.Logger
	handlers []informer.EventHandler
}

// NewBPFClient 创建新的 BPF 客户端
func NewBPFClient(bpfObjPath string, logger *zap.Logger) (*BPFClient, error) {
	inf, err := informer.NewBPFInformer(bpfObjPath, logger)
	if err != nil {
		return nil, err
	}

	return &BPFClient{
		informer: inf,
		logger:   logger,
		handlers: make([]informer.EventHandler, 0),
	}, nil
}

// Start 启动客户端
func (c *BPFClient) Start() error {
	if err := c.informer.Start(); err != nil {
		return err
	}

	// 执行初始化的 list 操作
	c.runListAndWatch()

	return nil
}

// Stop 停止客户端
func (c *BPFClient) Stop() {
	c.informer.Stop()
}

// AddEventHandler 添加事件处理器
func (c *BPFClient) AddEventHandler(handler informer.EventHandler) {
	c.handlers = append(c.handlers, handler)
}

// runListAndWatch 实现 list-watch 模式
func (c *BPFClient) runListAndWatch() {
	go func() {
		// 第1步：执行 list 操作
		programs, maps, resourceVersion := c.informer.List()

		c.logger.Info("Initial list completed",
			zap.Int("programs_count", len(programs)),
			zap.Int("maps_count", len(maps)),
			zap.Uint64("resource_version", resourceVersion.Version))

		// 处理初始列表
		for _, prog := range programs {
			for _, handler := range c.handlers {
				handler.OnAdd(informer.ResourceTypeProgram, prog)
			}
		}

		for _, m := range maps {
			for _, handler := range c.handlers {
				handler.OnAdd(informer.ResourceTypeMap, m)
			}
		}

		// 第2步：从 list 获取的资源版本开始执行 watch 操作
		events, err := c.informer.Watch(resourceVersion)
		if err != nil {
			c.logger.Error("Watch failed", zap.Error(err))
			return
		}

		c.logger.Info("Starting watch from resource version", zap.Uint64("version", resourceVersion.Version))

		// 处理事件流
		for event := range events {
			c.logger.Debug("Received event",
				zap.String("type", event.Type),
				zap.String("resource_type", event.ResourceType),
				zap.Uint32("pid", event.Pid),
				zap.String("comm", event.Comm),
				zap.String("func_name", event.FuncName),
				zap.Uint32("resource_id", event.ResourceID),
				zap.Uint64("resource_version", event.RV.Version))

			// 调用所有处理器
			for _, handler := range c.handlers {
				switch event.Type {
				case informer.EventTypeAdd:
					handler.OnAdd(event.ResourceType, event.Object)
				case informer.EventTypeUpdate:
					handler.OnUpdate(event.ResourceType, event.Object)
				case informer.EventTypeDelete:
					handler.OnDelete(event.ResourceType, event.ResourceID)
				}
			}
		}
	}()
}

// DefaultEventHandler 是一个默认的事件处理器实现
type DefaultEventHandler struct {
	logger *zap.Logger
}

// NewDefaultEventHandler 创建一个默认的事件处理器
func NewDefaultEventHandler(logger *zap.Logger) *DefaultEventHandler {
	return &DefaultEventHandler{
		logger: logger,
	}
}

// OnAdd 处理添加事件
func (h *DefaultEventHandler) OnAdd(resourceType string, obj interface{}) {
	switch resourceType {
	case informer.ResourceTypeProgram:
		if prog, ok := obj.(informer.BPFProgInfo); ok {
			h.logger.Info("BPF程序已添加",
				zap.Uint32("prog_id", prog.ProgID),
				zap.String("comm", prog.Comm),
				zap.Uint32("pid", prog.PID),
				zap.Time("created_at", prog.CreatedAt))
		}
	case informer.ResourceTypeMap:
		if m, ok := obj.(informer.BPFMapInfo); ok {
			h.logger.Info("BPF映射已添加",
				zap.Uint32("map_id", m.MapID),
				zap.String("comm", m.Comm),
				zap.Uint32("pid", m.PID),
				zap.Time("created_at", m.CreatedAt))
		}
	}
}

// OnUpdate 处理更新事件
func (h *DefaultEventHandler) OnUpdate(resourceType string, obj interface{}) {
	switch resourceType {
	case informer.ResourceTypeProgram:
		if prog, ok := obj.(informer.BPFProgInfo); ok {
			h.logger.Info("BPF程序已更新",
				zap.Uint32("prog_id", prog.ProgID),
				zap.String("comm", prog.Comm),
				zap.Uint32("pid", prog.PID),
				zap.Time("updated_at", prog.UpdatedAt))
		}
	case informer.ResourceTypeMap:
		if m, ok := obj.(informer.BPFMapInfo); ok {
			h.logger.Info("BPF映射已更新",
				zap.Uint32("map_id", m.MapID),
				zap.String("comm", m.Comm),
				zap.Uint32("pid", m.PID),
				zap.Time("updated_at", m.UpdatedAt))
		}
	}
}

// OnDelete 处理删除事件
func (h *DefaultEventHandler) OnDelete(resourceType string, id uint32) {
	switch resourceType {
	case informer.ResourceTypeProgram:
		h.logger.Info("BPF程序已删除", zap.Uint32("prog_id", id))
	case informer.ResourceTypeMap:
		h.logger.Info("BPF映射已删除", zap.Uint32("map_id", id))
	}
}

// SimpleListerWatcher 实现一个简单的周期性 List 示例
type SimpleListerWatcher struct {
	client *BPFClient
	logger *zap.Logger
	stop   chan struct{}
}

// NewSimpleListerWatcher 创建一个简单的 Lister-Watcher
func NewSimpleListerWatcher(client *BPFClient, logger *zap.Logger) *SimpleListerWatcher {
	return &SimpleListerWatcher{
		client: client,
		logger: logger,
		stop:   make(chan struct{}),
	}
}

// Start 启动周期性 list 操作
func (lw *SimpleListerWatcher) Start() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				lw.doList()
			case <-lw.stop:
				return
			}
		}
	}()
}

// Stop 停止
func (lw *SimpleListerWatcher) Stop() {
	close(lw.stop)
}

// doList 执行一次 list 操作并打印摘要
func (lw *SimpleListerWatcher) doList() {
	programs, maps, rv := lw.client.informer.List()

	var progSummary []string
	for _, p := range programs {
		if prog, ok := p.(informer.BPFProgInfo); ok {
			progSummary = append(progSummary, fmt.Sprintf("ID=%d/PID=%d", prog.ProgID, prog.PID))
		}
	}

	var mapSummary []string
	for _, m := range maps {
		if mapInfo, ok := m.(informer.BPFMapInfo); ok {
			mapSummary = append(mapSummary, fmt.Sprintf("ID=%d/PID=%d", mapInfo.MapID, mapInfo.PID))
		}
	}

	lw.logger.Info("当前活动的 BPF 资源",
		zap.String("resource_version", fmt.Sprintf("%d@%s", rv.Version,
			time.Unix(0, int64(rv.Timestamp)).Format(time.RFC3339))),
		zap.String("programs", strings.Join(progSummary, ", ")),
		zap.String("maps", strings.Join(mapSummary, ", ")))
}
