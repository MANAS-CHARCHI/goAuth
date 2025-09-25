package database

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func GetJtiFromToken(tokenString string) (string, error) {
	tokenString = strings.TrimSpace(strings.TrimPrefix(tokenString, "Bearer "))
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to parse access token: %w", err)
	}
	var jti string
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if val, ok := claims["jti"].(string); ok {
			jti = val
		}
	}
	if jti == "" {
		return "", fmt.Errorf("jti not found in access token")
	}

	return jti, nil
}
