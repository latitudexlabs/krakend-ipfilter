package ipfilter

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"

	krakendgin "github.com/luraproject/lura/v2/router/gin"
)

func IpFilterFactory(ipFilter IPFilter, handlerFunc gin.HandlerFunc, logger logging.Logger) gin.HandlerFunc {

	return func(c *gin.Context) {
		ip := c.ClientIP()
		if ipFilter.Deny(ip) {
			logger.Error(fmt.Sprintf("krakend-ipfilter deny request from: %s", ip))
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		handlerFunc(c)
	}
}

func HandlerFactory(next krakendgin.HandlerFactory, logger logging.Logger) krakendgin.HandlerFactory {
	return func(remote *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		handlerFunc := next(remote, p)

		cfg := ConfigGetter(remote.ExtraConfig)
		if cfg == nil {
			return handlerFunc
		}

		ipFilter := NewIPFilter(cfg)

		logger.Info(fmt.Sprintf("ip-filter krakend-ipfilter: allow %v deny %v", cfg.Allow, cfg.Deny))

		return IpFilterFactory(ipFilter, handlerFunc, logger)
	}
}
