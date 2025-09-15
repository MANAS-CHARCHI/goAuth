package database

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type UserModel struct {
	DB *sql.DB
}

var jwtSecret = []byte("super-secret-key-change-this")

func GenerateAccessToken(userID int) (string, error) {
	claims := jwt.MapClaims{
		"userId": userID,
		"type":   "access",
		"exp":    time.Now().Add(24 * time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}
func GenerateRefreshToken(userID int) (string, error) {
	claims := jwt.MapClaims{
		"userId": userID,
		"type":   "refresh",
		"exp":    time.Now().Add(7 * 24 * time.Hour).Unix(), // 7 days
		"iat":    time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func (m *UserModel) CreateUser(user *RegisterRequest, userAgent string) (*UserResponse, error) {

	createdAt := time.Now().UTC().Format(time.RFC3339)
	LastLogin := createdAt
	LastModified := createdAt
	RoleId := 1
	query := `INSERT INTO users (username, email, password, firstname, lastname, createdAt, roleId, lastLogin, lastModified, userAgent)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, username, email, firstname, lastname, avatar, website, createdAt;`

	row := m.DB.QueryRow(query, user.Username, user.Email, user.Password, user.FirstName, user.LastName, createdAt, RoleId, LastLogin, LastModified, userAgent)
	var resp UserResponse
	var avatar sql.NullString
	var website sql.NullString
	err := row.Scan(&resp.Id, &resp.Username, &resp.Email, &resp.FirstName, &resp.LastName, &avatar, &website, &resp.CreatedAt)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	resp.Avatar = avatar.String
	resp.Website = website.String

	return &resp, nil
}

func (m *UserModel) LoginUser(user *LoginRequest, ipAddress string, userAgent string) (*UserResponse, string, string, error) {
	lastLogin := time.Now().UTC().Format(time.RFC3339)
	query := `SELECT id, username, email, firstname, lastname, avatar, website, createdAt, password FROM users WHERE email=$1;`

	row := m.DB.QueryRow(query, user.Email)

	var resp UserResponse
	var avatar sql.NullString
	var website sql.NullString
	var hashedPassword string
	err := row.Scan(&resp.Id, &resp.Username, &resp.Email, &resp.FirstName, &resp.LastName, &avatar, &website, &resp.CreatedAt, &hashedPassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", "", fmt.Errorf("invalid email or password")
		}
		return nil, "", "", err
	}
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
	if err != nil {
		return nil, "", "", fmt.Errorf("invalid email or password")
	}
	resp.Avatar = avatar.String
	resp.Website = website.String
	updateQuery := `UPDATE users SET lastLogin=$1 WHERE id=$2;`
	_, err = m.DB.Exec(updateQuery, lastLogin, resp.Id)
	accessToken, err := GenerateAccessToken(resp.Id)
	if err != nil {
		return nil, "", "", err
	}
	refreshToken, err := GenerateRefreshToken(resp.Id)
	if err != nil {
		return nil, "", "", err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(24 * time.Hour)
	updateSessionQuery := `INSERT INTO sessions (userId, sessionToken, userAgent, ipAddress, createdAt, lastActiveAt, isActive, expiresAt) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);`
	_, err = m.DB.Exec(updateSessionQuery, resp.Id, refreshToken, userAgent, ipAddress, now, now, true, expiresAt)
	if err != nil {
		return nil, "", "", err
	}
	return &resp, accessToken, refreshToken, nil
}
