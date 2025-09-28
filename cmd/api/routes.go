package main

import (
	"goAuth/cmd/middleware"
	"goAuth/internal/database"
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
		v1.POST("/refresh", app.refresh)
		v1.POST("/user/activate/:email", app.activateUser)
		v1.POST("/forgot-password-otp", app.forgotPassword)
		v1.POST("/change-forgot-password/:email/:otp", app.changeForgotPassword)
		auth := v1.Group("/")
		auth.Use(middleware.AuthMiddleware(&database.UserModel{DB: app.models.DB, Redis: app.redis}))
		{
			auth.GET("/user", app.getuser)
			auth.POST("/logout", app.logout)
			auth.POST("/change-password", app.changePassword)
			auth.POST("/user/update", app.updateUser)
			auth.GET("/user/sessions", app.getAllSessions)
		}
	}
	return g
}
