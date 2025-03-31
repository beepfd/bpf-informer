package router

import (
	"fmt"
	"net/http"

	"github.com/cen-ngc5139/bpf-informer/pkg/informer"
	"github.com/gin-gonic/gin"
)

func (s *Server) initRouter() *gin.Engine {
	v1 := s.router.Group("/api/v1")
	{
		v1.GET("/bpf/programs", s.listPrograms)
		v1.GET("/bpf/maps", s.listMaps)
	}

	return s.router
}

func (s *Server) listPrograms(c *gin.Context) {
	programs, _, _ := s.client.List()

	programsMap := make(map[string]interface{})
	for _, program := range programs {
		info, ok := program.(informer.BPFProgInfo)
		if !ok {
			continue
		}
		programsMap[fmt.Sprintf("%d", info.ProgID)] = info
	}

	c.JSON(http.StatusOK, programsMap)
}

func (s *Server) listMaps(c *gin.Context) {
	_, maps, _ := s.client.List()

	mapsMap := make(map[string]interface{})
	for _, m := range maps {
		info, ok := m.(informer.BPFMapInfo)
		if !ok {
			continue
		}
		mapsMap[fmt.Sprintf("%d", info.MapID)] = info
	}

	c.JSON(http.StatusOK, mapsMap)
}
