package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

func (app *application) serve() error {
	r := gin.New()
	handler := app.routes()

	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// Avoid "trusted all proxies" warning by setting trusted proxies to nil
	r.SetTrustedProxies(nil)

	addr := fmt.Sprintf(":%s", app.port)
	return handler.(*gin.Engine).Run(addr)
}
