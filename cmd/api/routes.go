package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (app *application) routes() http.Handler {
	g := gin.Default()

	v1 := g.Group("api/v1")
	{
		v1.GET("/", app.ping)
		v1.POST("/register", app.register)
		v1.POST("/login", app.login)

		// auth := v1.Group("/")
		// auth.Use(middleware.AuthMiddleware(app.models.DB))
		// {
		// 	auth.GET("/user", app.getuser)
		// 	auth.POST("/logout", app.logout)

		// }
		

		// v1.POST("/forgotPassword", app.forgotPassword)
		// v1.POST("/resetPassword", app.resetPassword)
	}
	return g
}
