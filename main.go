package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/cen-ngc5139/bpf-informer/binary"
	"github.com/cen-ngc5139/bpf-informer/pkg/client"
	"github.com/cen-ngc5139/bpf-informer/pkg/informer"
	server "github.com/cen-ngc5139/bpf-informer/router"
	"go.uber.org/zap"
)

//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type bpf_prog_state -type bpf_map_state -type bpf_prog_event -type bpf_map_event -target $TARGET_GOARCH -go-package binary -output-dir ./binary -cc clang -no-strip Informer ./bpf/informer.c -- -I./headers -Wno-address-of-packed-member

func main() {
	// 初始化日志
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic("初始化日志失败: " + err.Error())
	}
	defer logger.Sync()

	c, err := client.NewBPFClient(binary.ExportRaw(), logger,
		[]informer.EventHandler{client.NewDefaultEventHandler(logger)})
	if err != nil {
		panic("初始化 BPF 客户端失败: " + err.Error())
	}

	err = c.Start()
	if err != nil {
		panic("启动 BPF 客户端失败: " + err.Error())
	}

	defer c.Stop()

	server := server.NewServer(c)
	server.Start()

	// 等待退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("正常关闭")
}
