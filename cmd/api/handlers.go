package main

import (
	"goAuth/internal/database"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
	ipAddress := c.ClientIP()
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
	user, err := app.models.Users.CreateUser(&req, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Could not create user.",
		})
		return
	}
	c.JSON(http.StatusCreated, user)
}

func (app *application) activateUser(c *gin.Context) {
	userIDStr := c.Param("user_id")
	if userIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required in URL"})
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id format"})
		return
	}

	var req struct {
		OTP string `json:"otp" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	err = app.models.Users.ActivateUser(userID, req.OTP)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User activated successfully"})
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

func (app *application) getuser(c *gin.Context) {
	accessToken := c.GetHeader("Authorization")
	if accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "No Authorization header provided",
		})
		return
	}
	user, err := app.models.Users.GetUser(accessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh" binding:"required"`
}

func (app *application) logout(c *gin.Context) {
	accessToken := c.GetHeader("Authorization")
	if accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "No Authorization header provided",
		})
		return
	}
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing or invalid refresh token",
		})
		return
	}
	refreshToken := req.RefreshToken

	user, err := app.models.Users.Logout(accessToken, refreshToken, c.GetHeader("User-Agent"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}
