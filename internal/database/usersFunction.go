package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserModel struct {
	DB *sql.DB
}

var jwtSecret = []byte("super-secret-key-change-this")

func GenerateAccessToken(userID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"userId": userID,
		"type":   "access",
		"exp":    time.Now().Add(24 * time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}
func GenerateRefreshToken(userID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"userId": userID,
		"type":   "refresh",
		"exp":    time.Now().Add(7 * 24 * time.Hour).Unix(), // 7 days
		"iat":    time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func (m *UserModel) CreateUser(user *RegisterRequest, ipAddress string, userAgent string) (*UserResponse, error) {

	createdAt := time.Now().UTC().Format(time.RFC3339)
	LastLogin := createdAt
	LastModified := createdAt
	RoleId := 1
	query := `INSERT INTO users (username, email, password, firstname, lastname, createdAt, roleId, lastLogin, lastModified, userAgent, signupip)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, username, email, firstname, lastname, avatar, website, createdAt;`

	row := m.DB.QueryRow(query, user.Username, user.Email, user.Password, user.FirstName, user.LastName, createdAt, RoleId, LastLogin, LastModified, userAgent, ipAddress)
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
	updateQuery := `UPDATE users SET lastlogin=$1, lastloginip=$2  WHERE id=$3;`
	_, err = m.DB.Exec(updateQuery, lastLogin, ipAddress, resp.Id)
	accessToken, err := GenerateAccessToken(resp.Id)
	if err != nil {
		return nil, "", "", err
	}
	refreshToken, err := GenerateRefreshToken(resp.Id)
	if err != nil {
		return nil, "", "", err
	}
	verifyDuplicateSession := `SELECT EXISTS (SELECT 1 FROM sessions WHERE userid=$1 AND useragent=$2 AND ipaddress=$3 AND isactive=true);`
	var exists bool
	err = m.DB.QueryRow(verifyDuplicateSession, resp.Id, userAgent, ipAddress).Scan(&exists)
	if err != nil {
		return nil, "", "", err
	}
	if !exists {
		now := time.Now().UTC()
		expiresAt := now.Add(7 * 24 * time.Hour)
		updateSessionQuery := `INSERT INTO sessions (userId, sessionToken, userAgent, ipAddress, createdAt, lastActiveAt, isActive, expiresAt) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);`
		_, err = m.DB.Exec(updateSessionQuery, resp.Id, refreshToken, userAgent, ipAddress, now, now, true, expiresAt)
		if err != nil {
			return nil, "", "", err
		}
	}

	return &resp, accessToken, refreshToken, nil
}

func GetUserIDFromBearerToken(bearerToken string, secret string) (string, error) {
	if !strings.HasPrefix(bearerToken, "Bearer ") {
		return "", fmt.Errorf("invalid token format")
	}
	tokenString := strings.TrimPrefix(bearerToken, "Bearer ")
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return "", fmt.Errorf("Failed to parse token.")
	}
	if !token.Valid {
		return "", fmt.Errorf("Invalid token.")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("Failed to parse claims.")
	}
	userID, ok := claims["userId"].(string)
	if !ok {
		return "", errors.New("userId not found in token claims.")
	}
	return userID, nil
}

func (m *UserModel) GetUser(accessToken string) (*UserInfo, error) {
	userId, err := GetUserIDFromBearerToken(accessToken, string(jwtSecret))
	if err != nil {
		return nil, err
	}
	query := `SELECT username, email, firstname, lastname, avatar, website, roleid, gender, dob, phonenumberone, phonenumbertwo, address, createdat, lastLogin, lastmodified, useractivatedat FROM users WHERE id=$1;`
	row := m.DB.QueryRow(query, userId)

	var resp UserInfo
	var avatar sql.NullString
	var website sql.NullString
	var gender sql.NullString
	var dob sql.NullString
	var roleId int
	var phoneOne sql.NullString
	var phoneTwo sql.NullString
	var address sql.NullString
	var useractivatedat sql.NullString
	err = row.Scan(&resp.Username, &resp.Email, &resp.FirstName, &resp.LastName, &avatar, &website, &roleId, &gender, &dob, &phoneOne, &phoneTwo, &address, &resp.CreatedAt, &resp.LastLogin, &resp.LastModified, &useractivatedat)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	getRoleQuery := `SELECT name FROM roles WHERE id=$1;`
	err = m.DB.QueryRow(getRoleQuery, &roleId).Scan(&resp.Role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("role not found")
		}
		return nil, err
	}
	resp.Avatar = avatar.String
	resp.Website = website.String
	resp.Gender = gender.String
	resp.Dob = dob.String
	resp.PhoneOne = phoneOne.String
	resp.PhoneTwo = phoneTwo.String
	resp.Address = address.String
	resp.UserActivatedAt = useractivatedat.String

	return &resp, nil
}
