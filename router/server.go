package router

import (
	"net/http"

	"log"

	"github.com/cen-ngc5139/bpf-informer/pkg/client"
	"github.com/gin-contrib/pprof"

	"github.com/gin-gonic/gin"
)

var (
	InitCompleted bool
)

type Server struct {
	router *gin.Engine
	server http.Server
	client *client.BPFClient
}

func NewServer(client *client.BPFClient) *Server {
	r := gin.Default()

	pprof.Register(r, "pprof")

	return &Server{
		router: r,
		server: http.Server{
			Addr:    ":8080",
			Handler: r,
		},
		client: client,
	}
}

func (s *Server) Start() error {
	// register api
	s.initRouter()

	// Initializing the server in a goroutine so that it won't block the graceful shutdown handling below
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Panicf("Listen: %s\n", err)
		}
	}()

	InitCompleted = true

	return nil
}
