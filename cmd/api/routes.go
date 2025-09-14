package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)
func (app *application) routes() http.Handler{
	g:=gin.Default()


	v1:=g.Group("api/v1")
	{
		v1.GET("/", app.ping)
		v1.POST("/register", app.register)
		// v1.POST("/login", app.login)
		// v1.POST("/activate", app.activate)
		// v1.POST("/forgotPassword", app.forgotPassword)
		// v1.POST("/resetPassword", app.resetPassword)
	}
	return g
}