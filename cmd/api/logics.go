package main

import (
	"goAuth/internal/database"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func (app *application) ping(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "hi manas",
	})
}

func (app *application) register(c *gin.Context) {
	var req database.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	// Get user agent
	userAgent := c.GetHeader("User-Agent")

	// hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Could not hash password.",
		})
		return
	}
	req.Password = string(hashedPassword)
	// create the user
	user, err := app.models.Users.CreateUser(&req, userAgent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Could not create user.",
		})
		return
	}
	c.JSON(http.StatusCreated, user)
}

func (app *application) login(c *gin.Context) {
	var req database.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	user, accessToken, refreshToken, err := app.models.Users.LoginUser(&req, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user":          user,
		"access-token":  accessToken,
		"refresh-token": refreshToken,
	})
}
